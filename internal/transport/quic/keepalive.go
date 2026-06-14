package quictransport

import (
	"sync"
	"time"

	"lattice/internal/transport"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// Keepalive sends a PING frame on a stream every interval and waits up to
// timeout for a PONG. If no PONG arrives within timeout, onTimeout is called
// once and the goroutine exits.
//
// The caller drives the receive path: call GotPong whenever the protocol
// read loop sees a FRAME_TYPE_PONG frame.
type Keepalive struct {
	stream    transport.Stream
	interval  time.Duration
	timeout   time.Duration
	onTimeout func()

	pongCh chan struct{}
	done   chan struct{}
	once   sync.Once
}

// NewKeepalive starts a keepalive goroutine for stream.
// interval: how often a PING is sent (blueprint: 22 s).
// timeout: how long to wait for a PONG before declaring the peer dead.
func NewKeepalive(stream transport.Stream, interval, timeout time.Duration, onTimeout func()) *Keepalive {
	k := &Keepalive{
		stream:    stream,
		interval:  interval,
		timeout:   timeout,
		onTimeout: onTimeout,
		pongCh:    make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	go k.run()
	return k
}

// GotPong signals that a PONG frame was received. Must be called from the
// protocol read loop; it is safe to call concurrently with all other methods.
func (k *Keepalive) GotPong() {
	select {
	case k.pongCh <- struct{}{}:
	default:
	}
}

// Stop terminates the keepalive goroutine. Idempotent.
func (k *Keepalive) Stop() {
	k.once.Do(func() { close(k.done) })
}

func (k *Keepalive) run() {
	ticker := time.NewTicker(k.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := wire.Write(k.stream, pb.FrameType_FRAME_TYPE_PING, nil); err != nil {
				k.onTimeout()
				return
			}
			select {
			case <-k.pongCh:
				// peer is alive; next tick
			case <-time.After(k.timeout):
				k.onTimeout()
				return
			case <-k.done:
				return
			}
		case <-k.done:
			return
		}
	}
}
