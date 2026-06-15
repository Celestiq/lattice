package transport

import (
	"context"
	"net"
	"time"
)

// Stream is a bidirectional ordered byte stream between two federation peers.
// Implementations must be safe for concurrent Read/Write/SetDeadline/Close.
type Stream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	// SetDeadline sets the read and write deadlines simultaneously.
	SetDeadline(t time.Time) error
	Close() error
}

// Dialer opens outbound connections to federation peers.
type Dialer interface {
	DialPeer(ctx context.Context, peerAddr string) (Stream, error)
}

// Listener accepts inbound connections from federation peers.
type Listener interface {
	AcceptPeer(ctx context.Context) (Stream, error)
	Addr() net.Addr
	Close() error
}

// TLSExporter is an optional interface that Stream implementations backed by a
// real TLS connection may satisfy. The federation manager uses it to derive the
// nonce passed to DoFederatedHandshake. Test streams provide a fixed nonce by
// implementing this interface.
type TLSExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// ConnectFunc is the function signature used by the Manager for peer connections
// when three-layer connect (registry + relay) is configured. Unlike Dialer.DialPeer,
// it also receives peerPubkey so the relay rendezvous token can be derived.
type ConnectFunc func(ctx context.Context, peerPubkey []byte, peerAddr string) (Stream, error)
