package quictransport

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/transport"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// ThreeLayerConnect attempts to connect to a federation peer using up to three
// layers in order of preference, running available layers concurrently:
//
//	Layer 1 (direct):   DialPeer(ctx, storedAddr)
//	Layer 2 (registry): Look up fresh address from registry, then DialPeer
//	Layer 3 (relay):    Connect to relay, register rendezvous, wait for pair
//
// Empty storedAddr skips layer 1. Empty registryAddr skips layer 2.
// Empty relayAddr skips layer 3. The first Stream that connects successfully
// is returned; remaining attempts are cancelled. Returns an error if all
// configured layers fail.
func ThreeLayerConnect(
	ctx context.Context,
	localPub ed25519.PublicKey,
	peerPubkey []byte,
	storedAddr string,
	registryAddr string,
	relayAddr string,
	dialer transport.Dialer,
) (transport.Stream, error) {
	type result struct {
		stream transport.Stream
		err    error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan result, 3)
	launched := 0

	// Layer 1: direct dial using stored address.
	if storedAddr != "" {
		launched++
		go func() {
			s, err := dialer.DialPeer(ctx, storedAddr)
			ch <- result{s, err}
		}()
	}

	// Layer 2: registry-assisted dial (look up fresh address).
	if registryAddr != "" {
		launched++
		go func() {
			lookupCtx, lookupCancel := context.WithTimeout(ctx, 5*time.Second)
			defer lookupCancel()
			stream, err := dialer.DialPeer(lookupCtx, registryAddr)
			if err != nil {
				ch <- result{nil, err}
				return
			}
			// Send lookup request.
			stream.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
			b, _ := proto.Marshal(&pb.RegistryLookup{Pubkey: peerPubkey})
			if err := wire.Write(stream, pb.FrameType_FRAME_TYPE_REGISTRY_LOOKUP, b); err != nil {
				stream.Close() //nolint:errcheck
				ch <- result{nil, err}
				return
			}
			f, err := wire.Read(stream)
			stream.Close() //nolint:errcheck
			if err != nil {
				ch <- result{nil, err}
				return
			}
			if f.Type != pb.FrameType_FRAME_TYPE_REGISTRY_LOOKUP_RESULT {
				ch <- result{nil, nil} // skip silently
				return
			}
			var lResult pb.RegistryLookupResult
			if err := proto.Unmarshal(f.Payload, &lResult); err != nil || lResult.Addr == "" {
				ch <- result{nil, nil}
				return
			}
			// Avoid re-dialing the same address as layer 1.
			if lResult.Addr == storedAddr {
				ch <- result{nil, nil}
				return
			}
			s, err := dialer.DialPeer(ctx, lResult.Addr)
			ch <- result{s, err}
		}()
	}

	// Layer 3: relay rendezvous.
	if relayAddr != "" {
		launched++
		go func() {
			s, err := dialViaRelay(ctx, localPub, peerPubkey, relayAddr, dialer)
			ch <- result{s, err}
		}()
	}

	if launched == 0 {
		return nil, errNoLayersConfigured
	}

	// Collect results; return the first success.
	var lastErr error
	for i := 0; i < launched; i++ {
		r := <-ch
		if r.err == nil && r.stream != nil {
			cancel() // cancel remaining layers
			return r.stream, nil
		}
		if r.err != nil {
			lastErr = r.err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errAllLayersFailed
}

// dialViaRelay connects to the relay, registers the rendezvous, waits for
// RELAY_PAIRED, and returns the stream once paired.
func dialViaRelay(ctx context.Context, localPub ed25519.PublicKey, peerPubkey []byte, relayAddr string, dialer transport.Dialer) (transport.Stream, error) {
	stream, err := dialer.DialPeer(ctx, relayAddr)
	if err != nil {
		return nil, err
	}

	// Register for rendezvous.
	b, err := proto.Marshal(&pb.RelayRegister{
		LocalPubkey:  []byte(localPub),
		TargetPubkey: peerPubkey,
	})
	if err != nil {
		stream.Close() //nolint:errcheck
		return nil, err
	}
	if err := wire.Write(stream, pb.FrameType_FRAME_TYPE_RELAY_REGISTER, b); err != nil {
		stream.Close() //nolint:errcheck
		return nil, err
	}

	// Wait for RELAY_PAIRED. Use context deadline or 60s max.
	deadline := time.Now().Add(60 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	stream.SetDeadline(deadline) //nolint:errcheck

	f, err := wire.Read(stream)
	stream.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		stream.Close() //nolint:errcheck
		return nil, err
	}
	if f.Type != pb.FrameType_FRAME_TYPE_RELAY_PAIRED {
		stream.Close() //nolint:errcheck
		return nil, errRelayUnexpectedFrame
	}
	return stream, nil
}

// rendezvousTokenHex returns the hex encoding of XOR(a, b). Exported for tests.
func rendezvousTokenHex(a, b []byte) string {
	xor := make([]byte, 32)
	for i := range xor {
		xor[i] = a[i] ^ b[i]
	}
	return hex.EncodeToString(xor)
}

type connectError string

func (e connectError) Error() string { return string(e) }

const (
	errNoLayersConfigured  connectError = "ThreeLayerConnect: no layers configured (storedAddr, registryAddr, and relayAddr are all empty)"
	errAllLayersFailed     connectError = "ThreeLayerConnect: all layers returned nil stream without error"
	errRelayUnexpectedFrame connectError = "relay: expected RELAY_PAIRED, got unexpected frame"
)
