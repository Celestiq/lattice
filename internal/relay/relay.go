// Package relay implements the Lattice relay node. The relay pairs two nodes
// by a rendezvous token and splices their QUIC streams transparently.
//
// Protocol:
//  1. Both nodes connect to the relay via QUIC.
//  2. Each node sends FRAME_TYPE_RELAY_REGISTER{local_pubkey, target_pubkey}.
//  3. The relay XORs both keys to derive a rendezvous token that is identical
//     for both sides (since XOR is commutative and associative).
//  4. When both halves of a rendezvous arrive, the relay sends FRAME_TYPE_RELAY_PAIRED
//     to both and then splices bytes bidirectionally.
//  5. Half-pairs not matched within 30 seconds are silently discarded.
//
// The relay never decrypts application data. QUIC provides end-to-end
// encryption, so a compromised relay can only cause a connectivity failure
// (DoS), not a confidentiality or integrity breach.
package relay

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/transport"
	"lattice/internal/wire"
	pb "lattice/proto"
)

const halfPairTTL = 30 * time.Second

// Relay accepts QUIC streams from pairs of federation nodes and splices them.
type Relay struct {
	listener transport.Listener
	pending  sync.Map // hex(rendezvousToken) → *halfPair
	log      *slog.Logger
	wg       sync.WaitGroup
	done     chan struct{}
	stopOnce sync.Once
}

type halfPair struct {
	stream    transport.Stream
	createdAt time.Time
}

// New creates a Relay that accepts connections on listener.
func New(listener transport.Listener, log *slog.Logger) *Relay {
	return &Relay{
		listener: listener,
		log:      log,
		done:     make(chan struct{}),
	}
}

// Start begins accepting connections and sweeping stale half-pairs.
// It returns immediately; call Stop() to shut down.
func (r *Relay) Start() {
	r.wg.Add(1)
	go r.runAcceptLoop()
	r.wg.Add(1)
	go r.runSweeper()
}

// Stop shuts down the relay: closes the listener, cancels all pending
// goroutines, and waits for them to exit. Safe to call multiple times.
func (r *Relay) Stop() {
	r.stopOnce.Do(func() {
		close(r.done)
		r.listener.Close() //nolint:errcheck
		r.wg.Wait()
	})
}

func (r *Relay) runAcceptLoop() {
	defer r.wg.Done()
	ctx := context.Background()
	for {
		select {
		case <-r.done:
			return
		default:
		}
		stream, err := r.listener.AcceptPeer(ctx)
		if err != nil {
			select {
			case <-r.done:
				return
			default:
				r.log.Error("relay: accept error", "err", err)
				return
			}
		}
		r.wg.Add(1)
		go func(s transport.Stream) {
			defer r.wg.Done()
			r.handleConn(s)
		}(stream)
	}
}

func (r *Relay) handleConn(stream transport.Stream) {
	// Read the relay registration frame with a short deadline.
	stream.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	f, err := wire.Read(stream)
	stream.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		stream.Close() //nolint:errcheck
		return
	}
	if f.Type != pb.FrameType_FRAME_TYPE_RELAY_REGISTER {
		r.log.Warn("relay: unexpected frame type", "type", f.Type)
		stream.Close() //nolint:errcheck
		return
	}
	var reg pb.RelayRegister
	if err := proto.Unmarshal(f.Payload, &reg); err != nil {
		stream.Close() //nolint:errcheck
		return
	}
	if len(reg.LocalPubkey) != 32 || len(reg.TargetPubkey) != 32 {
		r.log.Warn("relay: invalid pubkey length in registration")
		stream.Close() //nolint:errcheck
		return
	}

	token := rendezvousToken(reg.LocalPubkey, reg.TargetPubkey)

	// Try to match with an existing half-pair.
	if v, ok := r.pending.LoadAndDelete(token); ok {
		other := v.(*halfPair)
		r.splicePair(stream, other.stream, token)
		return
	}

	// No match yet — store as a half-pair and wait.
	hp := &halfPair{stream: stream, createdAt: time.Now()}
	if _, loaded := r.pending.LoadOrStore(token, hp); loaded {
		// Another goroutine stored a half-pair between our LoadAndDelete and here.
		// Remove and splice immediately.
		if v, ok := r.pending.LoadAndDelete(token); ok {
			other := v.(*halfPair)
			r.splicePair(stream, other.stream, token)
		} else {
			// Extremely unlikely race; just close this connection.
			stream.Close() //nolint:errcheck
		}
	}
	// Otherwise the half-pair is stored; the sweeper will clean it up if unmatched.
}

// splicePair sends RELAY_PAIRED to both streams, then copies bytes
// bidirectionally until one side closes.
func (r *Relay) splicePair(a, b transport.Stream, tokenHex string) {
	pairedB, _ := proto.Marshal(&pb.RelayPaired{})
	// Notify both sides. Ignore errors — if a side already closed, splice will
	// detect it immediately.
	wire.Write(a, pb.FrameType_FRAME_TYPE_RELAY_PAIRED, pairedB) //nolint:errcheck
	wire.Write(b, pb.FrameType_FRAME_TYPE_RELAY_PAIRED, pairedB) //nolint:errcheck
	r.log.Info("relay: pair connected", "token", tokenHex[:8])

	// Splice bidirectionally. Close both when either side closes.
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		io.Copy(a, b) //nolint:errcheck
		a.Close()     //nolint:errcheck
	}()
	go func() {
		defer r.wg.Done()
		io.Copy(b, a) //nolint:errcheck
		b.Close()     //nolint:errcheck
	}()
}

func (r *Relay) runSweeper() {
	defer r.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			r.pending.Range(func(k, v any) bool {
				hp := v.(*halfPair)
				if now.Sub(hp.createdAt) > halfPairTTL {
					r.pending.Delete(k)
					hp.stream.Close() //nolint:errcheck
					r.log.Info("relay: half-pair timed out", "token", k.(string)[:8])
				}
				return true
			})
		case <-r.done:
			// Close all remaining half-pairs.
			r.pending.Range(func(k, v any) bool {
				v.(*halfPair).stream.Close() //nolint:errcheck
				r.pending.Delete(k)
				return true
			})
			return
		}
	}
}

// rendezvousToken computes hex(XOR(a, b)). XOR is commutative, so
// rendezvousToken(A, B) == rendezvousToken(B, A).
func rendezvousToken(a, b []byte) string {
	xor := make([]byte, 32)
	for i := range xor {
		xor[i] = a[i] ^ b[i]
	}
	return hex.EncodeToString(xor)
}
