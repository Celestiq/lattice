package node

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lattice/internal/wire"
	pb "lattice/proto"
)

// wrappedConn embeds a net.Conn and overrides Write and SetWriteDeadline,
// allowing tests to inject write behaviour without implementing the full interface.
type wrappedConn struct {
	net.Conn
	writeFunc func([]byte) (int, error)
}

func (c *wrappedConn) Write(b []byte) (int, error) { return c.writeFunc(b) }

// SetWriteDeadline is a no-op; wrappedConn controls write lifecycle via writeFunc.
func (c *wrappedConn) SetWriteDeadline(t time.Time) error { return nil }

// readFrameTimeout reads one frame from conn with a deadline. Fails the test on error.
func readFrameTimeout(t *testing.T, conn net.Conn, timeout time.Duration) *wire.Frame {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	f, err := wire.Read(conn)
	if err != nil {
		t.Fatalf("readFrameTimeout: %v", err)
	}
	return f
}

func TestWriterDeliversData(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	w := newSessionWriter(server, "s1", nil, nil)
	defer w.close()

	want := []byte("hello world")
	if !w.enqueue(pb.FrameType_FRAME_TYPE_DELIVER, want) {
		t.Fatal("enqueue returned false unexpectedly")
	}
	f := readFrameTimeout(t, client, time.Second)
	if f.Type != pb.FrameType_FRAME_TYPE_DELIVER {
		t.Fatalf("expected DELIVER, got %v", f.Type)
	}
	if string(f.Payload) != string(want) {
		t.Fatalf("payload mismatch: got %q want %q", f.Payload, want)
	}
}

func TestWriterDeliversCtrl(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	w := newSessionWriter(server, "s1", nil, nil)
	defer w.close()

	if !w.enqueueControl(pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK, nil) {
		t.Fatal("enqueueControl returned false unexpectedly")
	}
	f := readFrameTimeout(t, client, time.Second)
	if f.Type != pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK {
		t.Fatalf("expected HEARTBEAT_ACK, got %v", f.Type)
	}
}

func TestWriterWriteErrorTriggersOnWriteError(t *testing.T) {
	server, client := net.Pipe()
	// Close the read side so that writes to server fail immediately.
	client.Close()

	var fired atomic.Bool
	w := newSessionWriter(server, "s1", nil, func() { fired.Store(true) })

	w.enqueue(pb.FrameType_FRAME_TYPE_DELIVER, []byte("x"))

	// close() blocks until the writer goroutine exits. Because onWriteError is
	// called before wg.Done(), fired is guaranteed to be set by the time close() returns.
	w.close()

	if !fired.Load() {
		t.Error("onWriteError was not called after write failure")
	}
}

func TestWriterCloseIsIdempotent(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	w := newSessionWriter(server, "s1", nil, nil)
	w.close()
	w.close() // must not panic or deadlock
}

func TestWriterCloseWaitsForGoroutine(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	var mu sync.Mutex
	var writeCount int
	w := newSessionWriter(&wrappedConn{
		Conn: server,
		// Return success without actually writing to the pipe; writing to server
		// blocks on net.Pipe until someone reads from client, which this test doesn't do.
		writeFunc: func(b []byte) (int, error) {
			mu.Lock()
			writeCount++
			mu.Unlock()
			return len(b), nil
		},
	}, "s1", nil, nil)

	w.enqueue(pb.FrameType_FRAME_TYPE_DELIVER, []byte("a"))
	w.enqueue(pb.FrameType_FRAME_TYPE_DELIVER, []byte("b"))

	// close() must not return until all pending writes have completed.
	w.close()

	mu.Lock()
	got := writeCount
	mu.Unlock()
	if got == 0 {
		t.Error("close() returned before any writes completed")
	}
}

// TestWriterDataChannelOverflow verifies that enqueue returns false instead of
// blocking when the data channel is at capacity.
func TestWriterDataChannelOverflow(t *testing.T) {
	var startOnce sync.Once
	started := make(chan struct{})
	stuck := make(chan struct{})
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	w := newSessionWriter(&wrappedConn{
		Conn: server,
		writeFunc: func(b []byte) (int, error) {
			// Signal the first time we enter a write (goroutine is now stuck here).
			startOnce.Do(func() { close(started) })
			<-stuck
			return 0, io.ErrClosedPipe
		},
	}, "s1", nil, nil)

	// Seed one frame to wake the goroutine; then wait until it is stuck in writeFunc.
	// This guarantees the data channel is empty and the goroutine cannot drain it.
	w.enqueue(pb.FrameType_FRAME_TYPE_DELIVER, []byte("seed"))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("writer goroutine did not start within 2s")
	}

	// Channel is empty and goroutine is blocked. Fill to capacity; one must overflow.
	dropped := 0
	for range writerDataBuf + 1 {
		if !w.enqueue(pb.FrameType_FRAME_TYPE_DELIVER, nil) {
			dropped++
		}
	}

	close(stuck)
	w.close()

	if dropped == 0 {
		t.Errorf("expected at least one drop when data channel is at capacity (%d)", writerDataBuf)
	}
}

// TestWriterCtrlChannelOverflow verifies that enqueueControl returns false
// instead of blocking when the ctrl channel is at capacity.
func TestWriterCtrlChannelOverflow(t *testing.T) {
	var startOnce sync.Once
	started := make(chan struct{})
	stuck := make(chan struct{})
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	w := newSessionWriter(&wrappedConn{
		Conn: server,
		writeFunc: func(b []byte) (int, error) {
			startOnce.Do(func() { close(started) })
			<-stuck
			return 0, io.ErrClosedPipe
		},
	}, "s1", nil, nil)

	w.enqueueControl(pb.FrameType_FRAME_TYPE_ERROR, []byte("seed"))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("writer goroutine did not start within 2s")
	}

	dropped := 0
	for range writerCtrlBuf + 1 {
		if !w.enqueueControl(pb.FrameType_FRAME_TYPE_ERROR, nil) {
			dropped++
		}
	}

	close(stuck)
	w.close()

	if dropped == 0 {
		t.Errorf("expected at least one drop when ctrl channel is at capacity (%d)", writerCtrlBuf)
	}
}
