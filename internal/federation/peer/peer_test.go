package peer_test

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"lattice/internal/federation/peer"
)

// noopStream is a no-op transport.Stream implementation for state-machine tests
// that don't need real I/O.
type noopStream struct{}

func (n *noopStream) Read(p []byte) (int, error)    { return 0, io.EOF }
func (n *noopStream) Write(p []byte) (int, error)   { return len(p), nil }
func (n *noopStream) SetDeadline(_ time.Time) error { return nil }
func (n *noopStream) Close() error                  { return nil }

// ─── Topology Verification ────────────────────────────────────────────────────

func TestPeerConnAllLegalTransitions(t *testing.T) {
	pub := []byte("ed25519-pubkey-32-bytes-pad-----")
	pc := peer.New(pub, "node-b", "10.0.0.2:4224")

	if pc.State() != peer.StatePending {
		t.Fatalf("initial state: got %s, want pending", pc.State())
	}

	// Pending → Active
	s := &noopStream{}
	if err := pc.Activate(s); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if pc.State() != peer.StateActive {
		t.Fatalf("after Activate: got %s, want active", pc.State())
	}
	if pc.Stream() != s {
		t.Fatal("stream not set after Activate")
	}

	// Active → Paused
	if err := pc.Pause(); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if pc.State() != peer.StatePaused {
		t.Fatalf("after Pause: got %s, want paused", pc.State())
	}

	// Paused → Active (with new stream)
	s2 := &noopStream{}
	if err := pc.Resume(s2); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if pc.State() != peer.StateActive {
		t.Fatalf("after Resume: got %s, want active", pc.State())
	}
	if pc.Stream() != s2 {
		t.Fatal("stream not updated after Resume")
	}

	// Active → Revoked (stream must be closed)
	closed := make(chan struct{})
	trackStream := &trackCloseStream{done: closed}
	if err := pc.Activate(pc.Stream()); err == nil {
		// Can't Activate again (already Active) — that's fine, use Resume trick
	}
	// Re-set stream via Pause + Resume
	if err := pc.Pause(); err != nil {
		t.Fatalf("Pause (2nd): %v", err)
	}
	if err := pc.Resume(trackStream); err != nil {
		t.Fatalf("Resume (2nd): %v", err)
	}

	if err := pc.Revoke(); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if pc.State() != peer.StateRevoked {
		t.Fatalf("after Revoke: got %s, want revoked", pc.State())
	}

	// Stream.Close must have been called by Revoke.
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Revoke did not close the stream")
	}
}

func TestPeerConnIllegalTransitions(t *testing.T) {
	pub := []byte("ed25519-pubkey-32-bytes-pad-----")
	pc := peer.New(pub, "node-b", "addr")

	// Drive to Revoked.
	pc.Activate(&noopStream{}) //nolint:errcheck
	pc.Revoke()                //nolint:errcheck

	// Revoked → Active must fail.
	if err := pc.Activate(&noopStream{}); !errors.Is(err, peer.ErrIllegalTransition) {
		t.Errorf("Activate on Revoked: want ErrIllegalTransition, got %v", err)
	}
	// Revoked → Paused must fail.
	if err := pc.Pause(); !errors.Is(err, peer.ErrIllegalTransition) {
		t.Errorf("Pause on Revoked: want ErrIllegalTransition, got %v", err)
	}
	// Revoke again must return ErrAlreadyRevoked.
	if err := pc.Revoke(); !errors.Is(err, peer.ErrAlreadyRevoked) {
		t.Errorf("double Revoke: want ErrAlreadyRevoked, got %v", err)
	}
	// State unchanged.
	if pc.State() != peer.StateRevoked {
		t.Errorf("state after failed transitions: %s", pc.State())
	}
}

// ─── State Invalidation & Distributed Race Conditions ────────────────────────

func TestPeerConnConcurrentTransitions(t *testing.T) {
	pub := []byte("ed25519-pubkey-32-bytes-pad-----")
	pc := peer.New(pub, "node-b", "addr")
	// Start in Active.
	pc.Activate(&noopStream{}) //nolint:errcheck

	const n = 10
	var wg sync.WaitGroup
	for range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			pc.Pause() //nolint:errcheck
		}()
		go func() {
			defer wg.Done()
			pc.Resume(&noopStream{}) //nolint:errcheck
		}()
	}
	wg.Wait()

	// State must be a valid value — never a corrupted integer.
	s := pc.State()
	if s != peer.StateActive && s != peer.StatePaused {
		t.Errorf("unexpected state after concurrent transitions: %s", s)
	}
}

func TestPeerConnRevokeWhileWriting(t *testing.T) {
	// Use a real pipe so Write actually blocks until Close.
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	pub := []byte("ed25519-pubkey-32-bytes-pad-----")
	pc := peer.New(pub, "node-b", "addr")
	pc.Activate(clientConn) //nolint:errcheck

	// Drain the server side so writes succeed until Revoke.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := serverConn.Read(buf); err != nil {
				return
			}
		}
	}()

	writeErr := make(chan error, 1)
	go func() {
		// Write until the stream is closed by Revoke.
		for {
			_, err := clientConn.Write([]byte("data"))
			if err != nil {
				writeErr <- err
				return
			}
		}
	}()

	// Give the write goroutine a moment to get going.
	time.Sleep(2 * time.Millisecond)

	if err := pc.Revoke(); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if pc.State() != peer.StateRevoked {
		t.Errorf("state after Revoke: %s", pc.State())
	}

	// Write goroutine must return an error — not panic.
	select {
	case err := <-writeErr:
		if err == nil {
			t.Fatal("expected write error after Revoke, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write goroutine did not return after Revoke")
	}
}

// trackCloseStream records when Close is called.
type trackCloseStream struct {
	noopStream
	done chan struct{}
	once sync.Once
}

func (t *trackCloseStream) Close() error {
	t.once.Do(func() { close(t.done) })
	return nil
}
