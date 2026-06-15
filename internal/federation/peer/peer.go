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
	"log/slog"
	"sync"
	"time"

	"lattice/internal/transport"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// fedMsg is a queued outbound federation frame.
type fedMsg struct {
	ft      pb.FrameType
	payload []byte
}

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

	// ctrl carries high-priority frames (FedPolicy, FedStatus); cap 32.
	// data carries data-plane frames (FedDeliver, FedRequest, FedResponse); cap 256.
	// Both are drained by a RunWriteLoop goroutine started by the Manager on Activate.
	ctrl chan fedMsg
	data chan fedMsg
}

// New creates a PeerConn in the Pending state.
// pubkey is copied on construction.
func New(pubkey []byte, name, addr string) *PeerConn {
	return &PeerConn{
		pubkey: append([]byte(nil), pubkey...),
		name:   name,
		addr:   addr,
		state:  StatePending,
		ctrl:   make(chan fedMsg, 32),
		data:   make(chan fedMsg, 256),
	}
}

// SendCtrl enqueues a high-priority control frame (FedPolicy, FedStatus).
// Returns false if the ctrl channel is full (rare; logs at the caller level).
func (p *PeerConn) SendCtrl(ft pb.FrameType, payload []byte) bool {
	select {
	case p.ctrl <- fedMsg{ft, payload}:
		return true
	default:
		return false
	}
}

// SendData enqueues a data-plane frame (FedDeliver, FedRequest, FedResponse).
// Non-blocking: returns false if the data channel is full (drop + caller logs).
func (p *PeerConn) SendData(ft pb.FrameType, payload []byte) bool {
	select {
	case p.data <- fedMsg{ft, payload}:
		return true
	default:
		return false
	}
}

// RunWriteLoop drains ctrl and data channels, writing frames to the current
// stream. It mirrors the sessionWriter priority-channel design: a fast
// non-blocking ctrl check precedes every fair select, so FedPolicy/FedStatus
// frames are never starved by FedDeliver floods.
//
// The goroutine exits when done is closed (manager.Stop) or a write error
// occurs (stream closed by Revoke or disconnection). onWriteError is called
// once on a write failure.
//
// Must be started as a goroutine after Activate(); the Manager tracks it via
// its own WaitGroup.
func (p *PeerConn) RunWriteLoop(done <-chan struct{}, log *slog.Logger, onWriteError func()) {
	for {
		// Fast, non-blocking ctrl check (priority lane).
		select {
		case msg := <-p.ctrl:
			if !p.writeFrame(msg) {
				onWriteError()
				return
			}
			continue
		default:
		}
		// Fair select across ctrl, data, and done.
		select {
		case <-done:
			return
		case msg := <-p.ctrl:
			if !p.writeFrame(msg) {
				onWriteError()
				return
			}
		case msg := <-p.data:
			if !p.writeFrame(msg) {
				if log != nil {
					log.Warn("fed: peer write error on data frame", "peer", p.name)
				}
				onWriteError()
				return
			}
		}
	}
}

// writeFrame writes one frame to the current stream with a 5-second deadline.
// Returns true on success, false on error (nil stream counts as success/drop).
func (p *PeerConn) writeFrame(msg fedMsg) bool {
	p.mu.Lock()
	s := p.stream
	p.mu.Unlock()
	if s == nil {
		return true // paused or not yet active — silently drop
	}
	s.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	err := wire.Write(s, msg.ft, msg.payload)
	s.SetDeadline(time.Time{}) //nolint:errcheck
	return err == nil
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
