// Package peer implements the federation peer connection state machine.
//
// Legal transitions:
//
//	Pending → Active  (Activate)
//	Active  → Paused  (Pause)
//	Paused  → Active  (Resume)
//	Active  → Revoked (Revoke)
//	Paused  → Revoked (Revoke)
package peer

import (
	"errors"
	"fmt"
	"sync"

	"lattice/internal/transport"
)

// State is the lifecycle state of a federation peer connection.
type State int

const (
	StatePending State = iota
	StateActive
	StatePaused
	StateRevoked
)

func (s State) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateActive:
		return "active"
	case StatePaused:
		return "paused"
	case StateRevoked:
		return "revoked"
	default:
		return fmt.Sprintf("State(%d)", int(s))
	}
}

var (
	ErrIllegalTransition = errors.New("peer: illegal state transition")
	ErrAlreadyRevoked    = errors.New("peer: already revoked")
)

// PeerConn tracks the lifecycle of a single federation peer connection.
// All exported methods are safe to call from multiple goroutines.
type PeerConn struct {
	pubkey []byte
	name   string
	addr   string

	mu     sync.Mutex
	state  State
	stream transport.Stream
}

// New creates a PeerConn in the Pending state.
// pubkey is copied on construction.
func New(pubkey []byte, name, addr string) *PeerConn {
	return &PeerConn{
		pubkey: append([]byte(nil), pubkey...),
		name:   name,
		addr:   addr,
		state:  StatePending,
	}
}

// Activate transitions Pending → Active and attaches stream.
func (p *PeerConn) Activate(stream transport.Stream) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != StatePending {
		return fmt.Errorf("%w: %s → Active (requires Pending)", ErrIllegalTransition, p.state)
	}
	p.stream = stream
	p.state = StateActive
	return nil
}

// Pause transitions Active → Paused.
func (p *PeerConn) Pause() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != StateActive {
		return fmt.Errorf("%w: %s → Paused (requires Active)", ErrIllegalTransition, p.state)
	}
	p.state = StatePaused
	return nil
}

// Resume transitions Paused → Active and attaches (a potentially new) stream.
func (p *PeerConn) Resume(stream transport.Stream) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != StatePaused {
		return fmt.Errorf("%w: %s → Active (requires Paused)", ErrIllegalTransition, p.state)
	}
	p.stream = stream
	p.state = StateActive
	return nil
}

// Revoke transitions Active or Paused → Revoked and closes the stream.
// Revoke on an already-Revoked PeerConn returns ErrAlreadyRevoked.
// The lock is released before calling stream.Close() to avoid holding it
// during I/O.
func (p *PeerConn) Revoke() error {
	p.mu.Lock()
	if p.state == StateRevoked {
		p.mu.Unlock()
		return ErrAlreadyRevoked
	}
	s := p.stream
	p.stream = nil
	p.state = StateRevoked
	p.mu.Unlock()

	if s != nil {
		s.Close() //nolint:errcheck
	}
	return nil
}

// State returns the current lifecycle state.
func (p *PeerConn) State() State {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// PeerPubkey returns the peer's Ed25519 public key (immutable after creation).
func (p *PeerConn) PeerPubkey() []byte { return p.pubkey }

// PeerName returns the human-readable peer name (immutable).
func (p *PeerConn) PeerName() string { return p.name }

// Addr returns the peer's dial address (immutable).
func (p *PeerConn) Addr() string { return p.addr }

// Stream returns the current attached stream, or nil if Pending or Revoked.
func (p *PeerConn) Stream() transport.Stream {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stream
}
