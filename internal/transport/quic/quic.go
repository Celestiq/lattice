// Package quictransport implements the transport.Dialer and transport.Listener
// interfaces over QUIC (RFC 9000). Each peer connection uses one QUIC
// connection with a single bidirectional stream. The existing wire framing
// (4-byte BE length + 1-byte FrameType + protobuf payload) runs unchanged on
// top of the QUIC stream.
//
// QUIC stream visibility: a stream only becomes visible to the server once the
// client has written data. AcceptPeer therefore starts AcceptStream in a
// background goroutine and returns a lazyServerStream that blocks on the first
// Read/Write/SetDeadline call until the stream has been accepted.
package quictransport

import (
	"context"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"

	"lattice/internal/transport"
)

const (
	quicKeepAlivePeriod = 15 * time.Second
	quicMaxIdleTimeout  = 5 * time.Minute
)

func quicCfg() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod: quicKeepAlivePeriod,
		MaxIdleTimeout:  quicMaxIdleTimeout,
	}
}

// ─── Dialer-side stream (stream opened eagerly by the client) ─────────────────

type quicStream struct {
	stream    *quic.Stream
	conn      *quic.Conn
	closeOnce sync.Once
}

var _ transport.Stream = (*quicStream)(nil)

func (s *quicStream) Read(p []byte) (int, error)    { return s.stream.Read(p) }
func (s *quicStream) Write(p []byte) (int, error)   { return s.stream.Write(p) }
func (s *quicStream) SetDeadline(t time.Time) error { return s.stream.SetDeadline(t) }
func (s *quicStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.stream.Close()
		err = s.conn.CloseWithError(0, "")
	})
	return err
}

// ─── Listener-side stream (AcceptStream deferred until first use) ─────────────

type streamResult struct {
	stream *quic.Stream
	err    error
}

// lazyServerStream wraps a QUIC connection from the listener's perspective.
// AcceptStream is started in a background goroutine inside newLazyServerStream;
// the actual stream pointer is resolved on the first Read, Write, or
// SetDeadline call. This avoids blocking AcceptPeer while waiting for the
// remote client to write its first bytes.
type lazyServerStream struct {
	conn      *quic.Conn
	resultCh  <-chan streamResult // buffered(1); receives exactly one value
	once      sync.Once
	stream    *quic.Stream
	streamErr error
	closeOnce sync.Once
}

var _ transport.Stream = (*lazyServerStream)(nil)

func newLazyServerStream(conn *quic.Conn) *lazyServerStream {
	ch := make(chan streamResult, 1)
	go func() {
		s, err := conn.AcceptStream(context.Background())
		ch <- streamResult{s, err}
	}()
	return &lazyServerStream{conn: conn, resultCh: ch}
}

func (s *lazyServerStream) getStream() (*quic.Stream, error) {
	s.once.Do(func() {
		r := <-s.resultCh
		s.stream, s.streamErr = r.stream, r.err
	})
	return s.stream, s.streamErr
}

func (s *lazyServerStream) Read(p []byte) (int, error) {
	stream, err := s.getStream()
	if err != nil {
		return 0, err
	}
	return stream.Read(p)
}

func (s *lazyServerStream) Write(p []byte) (int, error) {
	stream, err := s.getStream()
	if err != nil {
		return 0, err
	}
	return stream.Write(p)
}

func (s *lazyServerStream) SetDeadline(t time.Time) error {
	stream, err := s.getStream()
	if err != nil {
		return err
	}
	return stream.SetDeadline(t)
}

// Close terminates the underlying QUIC connection, which also unblocks any
// pending AcceptStream call in the background goroutine (it will error and
// send to the buffered resultCh, so the goroutine exits without leaking).
func (s *lazyServerStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.conn.CloseWithError(0, "")
	})
	return err
}

// ─── Listener ────────────────────────────────────────────────────────────────

// Listener accepts inbound QUIC connections from federation peers.
type Listener struct {
	l *quic.Listener
}

var _ transport.Listener = (*Listener)(nil)

// Listen binds addr ("host:port") and starts accepting QUIC connections with
// ALPN "lattice-fed-v1". Use addr "127.0.0.1:0" for a random port in tests.
func Listen(addr string) (*Listener, error) {
	tlsConf, err := newServerTLSConfig()
	if err != nil {
		return nil, err
	}
	l, err := quic.ListenAddr(addr, tlsConf, quicCfg())
	if err != nil {
		return nil, err
	}
	return &Listener{l: l}, nil
}

// AcceptPeer blocks until a QUIC connection is established, then returns
// immediately with a lazy stream. The stream's AcceptStream is resolved
// in the background and will unblock on the first Read/Write.
func (l *Listener) AcceptPeer(ctx context.Context) (transport.Stream, error) {
	conn, err := l.l.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return newLazyServerStream(conn), nil
}

func (l *Listener) Addr() net.Addr { return l.l.Addr() }
func (l *Listener) Close() error   { return l.l.Close() }

// ─── Dialer ──────────────────────────────────────────────────────────────────

// Dialer opens outbound QUIC connections to federation peers.
// A single Dialer may be shared across goroutines.
type Dialer struct{}

var _ transport.Dialer = (*Dialer)(nil)

// NewDialer creates a Dialer. Trust is established by the FedHello Ed25519
// handshake (Session 2); the TLS certificate is not verified.
func NewDialer() *Dialer { return &Dialer{} }

// DialPeer connects to peerAddr, completes the QUIC handshake, and opens
// a bidirectional stream (stream 0). The stream is visible to the server only
// after the first Write call.
func (d *Dialer) DialPeer(ctx context.Context, peerAddr string) (transport.Stream, error) {
	conn, err := quic.DialAddr(ctx, peerAddr, newClientTLSConfig(), quicCfg())
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "open stream failed")
		return nil, err
	}
	return &quicStream{stream: stream, conn: conn}, nil
}
