package quictransport_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"lattice/internal/transport"
	quictransport "lattice/internal/transport/quic"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// pair establishes a connected (server stream, client stream) pair on loopback.
//
// In QUIC, a stream only becomes visible to the server after the client writes
// data. AcceptPeer therefore returns a lazyServerStream that defers AcceptStream
// until the first Read/Write call — so pair() can return both sides without
// goroutine coordination or trigger frames.
func pair(t *testing.T) (server, client transport.Stream) {
	t.Helper()
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal("Listen:", err)
	}
	t.Cleanup(func() { l.Close() })

	ctx := context.Background()
	d := quictransport.NewDialer()

	// DialPeer completes the TLS handshake with the server's background goroutine.
	// The connection is queued on the server side.
	clientStream, err := d.DialPeer(ctx, l.Addr().String())
	if err != nil {
		t.Fatal("DialPeer:", err)
	}
	t.Cleanup(func() { clientStream.Close() })

	// AcceptPeer dequeues the queued connection and returns a lazy stream.
	// AcceptStream is resolved in the background goroutine when the client writes.
	serverStream, err := l.AcceptPeer(ctx)
	if err != nil {
		t.Fatal("AcceptPeer:", err)
	}
	t.Cleanup(func() { serverStream.Close() })

	return serverStream, clientStream
}

// ─── Topology Verification ────────────────────────────────────────────────────

func TestQUICBasicFrameRoundTrip(t *testing.T) {
	srv, cli := pair(t)

	payload := []byte(`{"temperature":21.5}`)
	if err := wire.Write(cli, pb.FrameType_FRAME_TYPE_PUBLISH, payload); err != nil {
		t.Fatal("Write:", err)
	}

	frame, err := wire.Read(srv)
	if err != nil {
		t.Fatal("Read:", err)
	}
	if frame.Type != pb.FrameType_FRAME_TYPE_PUBLISH {
		t.Fatalf("frame type: got %v, want PUBLISH", frame.Type)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", frame.Payload, payload)
	}
}

func TestQUICBidirectionalFrames(t *testing.T) {
	srv, cli := pair(t)

	// client → server
	if err := wire.Write(cli, pb.FrameType_FRAME_TYPE_SUBSCRIBE, []byte("sensors.>")); err != nil {
		t.Fatal(err)
	}
	f1, err := wire.Read(srv)
	if err != nil {
		t.Fatal(err)
	}
	if f1.Type != pb.FrameType_FRAME_TYPE_SUBSCRIBE {
		t.Fatalf("got %v, want SUBSCRIBE", f1.Type)
	}

	// server → client
	if err := wire.Write(srv, pb.FrameType_FRAME_TYPE_DELIVER, []byte("response")); err != nil {
		t.Fatal(err)
	}
	f2, err := wire.Read(cli)
	if err != nil {
		t.Fatal(err)
	}
	if f2.Type != pb.FrameType_FRAME_TYPE_DELIVER {
		t.Fatalf("got %v, want DELIVER", f2.Type)
	}
}

func TestQUICALPNIsolation(t *testing.T) {
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	wrongALPN := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"wrong-alpn"},
		MinVersion:         tls.VersionTLS13,
	}
	_, err = quic.DialAddr(ctx, l.Addr().String(), wrongALPN, nil)
	if err == nil {
		t.Fatal("expected ALPN mismatch error, got nil")
	}
}

func TestQUICConcurrentDialSamePeer(t *testing.T) {
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	const n = 5
	addr := l.Addr().String()
	ctx := context.Background()

	// Server accepts n connections in background.
	go func() {
		for range n {
			s, err := l.AcceptPeer(ctx)
			if err != nil {
				return
			}
			go s.Close()
		}
	}()

	d := quictransport.NewDialer()
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := d.DialPeer(ctx, addr)
			errs[i] = err
			if s != nil {
				s.Close()
			}
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Errorf("dial[%d]: %v", i, e)
		}
	}
}

// ─── Network Fault Injection ─────────────────────────────────────────────────

func TestQUICStreamDropMidFrame(t *testing.T) {
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()
	d := quictransport.NewDialer()

	// Dial and get lazy server stream before client writes.
	cli, err := d.DialPeer(ctx, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := l.AcceptPeer(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Write only the 4-byte length header (no type byte or payload), then close.
	var hdr [4]byte
	hdr[3] = 10 // claim payload length = 10
	cli.Write(hdr[:])
	cli.Close()

	// wire.Read should fail: either ErrUnexpectedEOF or connection closed.
	_, err = wire.Read(srv)
	if err == nil {
		t.Fatal("expected error reading truncated frame, got nil")
	}
	srv.Close()
}

func TestQUICDialContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	d := quictransport.NewDialer()
	_, err := d.DialPeer(ctx, "127.0.0.1:19999")
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
}

func TestQUICListenerClose(t *testing.T) {
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = l.AcceptPeer(ctx)
	if err == nil {
		t.Fatal("expected error from closed listener, got nil")
	}
}

// ─── State Invalidation & Distributed Race Conditions ────────────────────────

func TestQUICKeepaliveRoundTrip(t *testing.T) {
	srv, cli := pair(t)

	// Server echoes PING with PONG.
	go func() {
		for {
			f, err := wire.Read(srv)
			if err != nil {
				return
			}
			if f.Type == pb.FrameType_FRAME_TYPE_PING {
				wire.Write(srv, pb.FrameType_FRAME_TYPE_PONG, nil)
			}
		}
	}()

	timeoutFired := make(chan struct{})
	k := quictransport.NewKeepalive(cli, 30*time.Millisecond, 100*time.Millisecond, func() {
		close(timeoutFired)
	})
	defer k.Stop()

	// Forward PONG from server to keepalive.
	go func() {
		for {
			f, err := wire.Read(cli)
			if err != nil {
				return
			}
			if f.Type == pb.FrameType_FRAME_TYPE_PONG {
				k.GotPong()
			}
		}
	}()

	select {
	case <-timeoutFired:
		t.Fatal("keepalive timeout fired unexpectedly while PONGs were being returned")
	case <-time.After(200 * time.Millisecond):
		// healthy
	}
}

func TestQUICKeepaliveTimeout(t *testing.T) {
	srv, cli := pair(t)
	_ = srv

	done := make(chan struct{})
	k := quictransport.NewKeepalive(cli, 20*time.Millisecond, 50*time.Millisecond, func() {
		close(done)
	})
	defer k.Stop()

	select {
	case <-done:
		// onTimeout fired as expected
	case <-time.After(500 * time.Millisecond):
		t.Fatal("keepalive timeout did not fire")
	}
}

func TestQUICKeepaliveStopRace(t *testing.T) {
	srv, cli := pair(t)
	_ = srv

	k := quictransport.NewKeepalive(cli, 20*time.Millisecond, 50*time.Millisecond, func() {})

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(2)
		go func() { defer wg.Done(); k.GotPong() }()
		go func() { defer wg.Done(); k.Stop() }()
	}
	wg.Wait()
}

func TestQUICKeepaliveRaceClose(t *testing.T) {
	srv, cli := pair(t)
	_ = srv

	k := quictransport.NewKeepalive(cli, 10*time.Millisecond, 30*time.Millisecond, func() {})
	time.Sleep(15 * time.Millisecond)
	cli.Close()
	k.Stop()
}

// ─── E2E Distributed Workflows ────────────────────────────────────────────────

func TestQUICFedFrameTypesInBand(t *testing.T) {
	srv, cli := pair(t)

	fedTypes := []pb.FrameType{
		pb.FrameType_FRAME_TYPE_FED_HELLO,
		pb.FrameType_FRAME_TYPE_FED_HELLO_ACK,
		pb.FrameType_FRAME_TYPE_FED_REJECT,
		pb.FrameType_FRAME_TYPE_FED_POLICY,
		pb.FrameType_FRAME_TYPE_FED_DELIVER,
	}
	for _, ft := range fedTypes {
		payload := []byte("test")
		if err := wire.Write(cli, ft, payload); err != nil {
			t.Fatalf("Write(%v): %v", ft, err)
		}
		f, err := wire.Read(srv)
		if err != nil {
			t.Fatalf("Read(%v): %v", ft, err)
		}
		if f.Type != ft {
			t.Fatalf("type mismatch: got %v, want %v", f.Type, ft)
		}
	}
}

func TestQUICMaxFrameSize(t *testing.T) {
	srv, cli := pair(t)

	maxPayload := make([]byte, wire.MaxPayload)
	for i := range maxPayload {
		maxPayload[i] = byte(i & 0xFF)
	}
	if err := wire.Write(cli, pb.FrameType_FRAME_TYPE_PUBLISH, maxPayload); err != nil {
		t.Fatal("Write max payload:", err)
	}
	f, err := wire.Read(srv)
	if err != nil {
		t.Fatal("Read max payload:", err)
	}
	if len(f.Payload) != wire.MaxPayload {
		t.Fatalf("payload length: got %d, want %d", len(f.Payload), wire.MaxPayload)
	}

	// One byte over the limit must be rejected before any bytes are written.
	tooBig := make([]byte, wire.MaxPayload+1)
	if err := wire.Write(cli, pb.FrameType_FRAME_TYPE_PUBLISH, tooBig); err == nil {
		t.Fatal("expected ErrPayloadTooLarge, got nil")
	}
}

func TestQUICMultiStreamSequencing(t *testing.T) {
	srv, cli := pair(t)

	const n = 20
	go func() {
		for i := range n {
			wire.Write(cli, pb.FrameType_FRAME_TYPE_PUBLISH, []byte{byte(i)})
		}
	}()

	for i := range n {
		f, err := wire.Read(srv)
		if err != nil {
			t.Fatalf("Read[%d]: %v", i, err)
		}
		if len(f.Payload) != 1 || f.Payload[0] != byte(i) {
			t.Fatalf("frame[%d]: got payload %v, want [%d]", i, f.Payload, i)
		}
	}
}

func TestQUICListenerAddrAvailable(t *testing.T) {
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	addr := l.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil")
	}
	if addr.String() == "" {
		t.Fatal("Addr().String() is empty")
	}
}
