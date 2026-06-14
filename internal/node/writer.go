package node

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"lattice/internal/wire"
	pb "lattice/proto"
)

const (
	writerCtrlBuf = 64  // HEARTBEAT_ACK, ERROR — small, never dropped under data congestion
	writerDataBuf = 128 // DELIVER, REQUEST, RESPONSE — dropped on overflow (ephemeral policy)
	writeTimeout  = 5 * time.Second
)

type writerMsg struct {
	ft      pb.FrameType
	payload []byte
}

// sessionWriter owns the outbound write path for one connected entity.
// A dedicated goroutine drains two priority-ordered channels onto conn.
//
// Priority: ctrl frames (HEARTBEAT_ACK, ERROR) are always dequeued before data
// frames (DELIVER, REQUEST, RESPONSE). The fast-check at the top of run() ensures
// a pending ctrl frame is never skipped because a data frame also became ready.
// Trade-off: sustained ctrl traffic could in principle starve the data channel,
// but ctrl volume is bounded by the heartbeat interval and per-frame errors,
// so this is not reachable in practice.
//
// Every wire.Write call sets a per-write deadline of writeTimeout. On deadline
// exceeded the conn is closed, onWriteError is called (if non-nil), and the
// goroutine exits.
type sessionWriter struct {
	conn         net.Conn
	ctrl         chan writerMsg
	data         chan writerMsg
	stopOnce     sync.Once
	done         chan struct{}
	wg           sync.WaitGroup
	log          *slog.Logger
	sessionID    string
	onWriteError func() // called after conn.Close() on write failure; may be nil
}

func newSessionWriter(conn net.Conn, sessionID string, log *slog.Logger, onWriteError func()) *sessionWriter {
	w := &sessionWriter{
		conn:         conn,
		ctrl:         make(chan writerMsg, writerCtrlBuf),
		data:         make(chan writerMsg, writerDataBuf),
		done:         make(chan struct{}),
		log:          log,
		sessionID:    sessionID,
		onWriteError: onWriteError,
	}
	w.wg.Add(1)
	go w.run()
	return w
}

// enqueueControl sends a control frame (HEARTBEAT_ACK, ERROR).
// Returns false only if the ctrl buffer is full (writer goroutine is severely stuck).
func (w *sessionWriter) enqueueControl(ft pb.FrameType, payload []byte) bool {
	select {
	case w.ctrl <- writerMsg{ft: ft, payload: payload}:
		return true
	default:
		if w.log != nil {
			w.log.Warn("ctrl channel full, dropping frame",
				"session_id", w.sessionID, "frame_type", ft)
		}
		return false
	}
}

// enqueue sends a data frame (DELIVER, REQUEST, RESPONSE).
// Returns false if the buffer is full; the caller should drop the frame (ephemeral)
// or record the gap (durable — not yet implemented in v0.1.1).
func (w *sessionWriter) enqueue(ft pb.FrameType, payload []byte) bool {
	select {
	case w.data <- writerMsg{ft: ft, payload: payload}:
		return true
	default:
		if w.log != nil {
			w.log.Warn("data channel full, dropping frame",
				"session_id", w.sessionID, "frame_type", ft)
		}
		return false
	}
}

// close signals the writer to stop, drains pending frames from both channels,
// and waits for the goroutine to exit. Safe to call concurrently or multiple times.
func (w *sessionWriter) close() {
	w.stopOnce.Do(func() { close(w.done) })
	w.wg.Wait()
}

func (w *sessionWriter) run() {
	defer w.wg.Done()
	for {
		// Priority pass: always drain ctrl before entering the fair select below.
		select {
		case msg := <-w.ctrl:
			if !w.write(msg) {
				return
			}
			continue
		default:
		}

		select {
		case msg := <-w.ctrl:
			if !w.write(msg) {
				return
			}
		case msg := <-w.data:
			if !w.write(msg) {
				return
			}
		case <-w.done:
			w.drain()
			return
		}
	}
}

// drain flushes remaining frames from both channels after the stop signal.
// A failed write during drain causes early exit (conn is likely already closed).
func (w *sessionWriter) drain() {
	for {
		select {
		case msg := <-w.ctrl:
			if !w.write(msg) {
				return
			}
		case msg := <-w.data:
			if !w.write(msg) {
				return
			}
		default:
			return
		}
	}
}

// write sends one frame with a per-write deadline. Returns false on any error;
// on failure it closes the conn, signals done, and calls onWriteError.
func (w *sessionWriter) write(msg writerMsg) bool {
	w.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	err := wire.Write(w.conn, msg.ft, msg.payload)
	if err == nil {
		w.conn.SetWriteDeadline(time.Time{})
		return true
	}
	if w.log != nil {
		w.log.Warn("write failed, disconnecting",
			"session_id", w.sessionID, "frame_type", msg.ft, "err", err)
	}
	w.conn.Close()
	w.stopOnce.Do(func() { close(w.done) })
	if w.onWriteError != nil {
		w.onWriteError()
	}
	return false
}
