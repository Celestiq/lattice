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
