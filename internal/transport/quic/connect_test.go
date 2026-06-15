package quictransport_test

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"testing"

	"lattice/internal/address"
	"lattice/internal/relay"
	"lattice/internal/transport"
	quictransport "lattice/internal/transport/quic"
)

func genConnKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func startConnRelay(t *testing.T) string {
	t.Helper()
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal("relay Listen:", err)
	}
	t.Cleanup(func() { l.Close() })
	r := relay.New(l, slog.Default())
	r.Start()
	t.Cleanup(r.Stop)
	return l.Addr().String()
}

func startConnRegistry(t *testing.T) string {
	t.Helper()
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal("registry Listen:", err)
	}
	t.Cleanup(func() { l.Close() })
	d := quictransport.NewDialer()
	srv := address.NewServer(l, d, slog.Default())
	srv.Start()
	t.Cleanup(srv.Stop)
	return l.Addr().String()
}

// startPeerListener starts a plain QUIC listener that accepts and discards one connection.
func startPeerListener(t *testing.T) (string, func()) {
	t.Helper()
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal("peer Listen:", err)
	}
	t.Cleanup(func() { l.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx := context.Background()
		for {
			s, err := l.AcceptPeer(ctx)
			if err != nil {
				return
			}
			go func(st transport.Stream) { defer st.Close() }(s)
		}
	}()
	return l.Addr().String(), func() { <-done }
}

// ─── Topology Verification ────────────────────────────────────────────────────

// TestThreeLayerDirectDialSucceeds verifies that layer 1 (direct) returns a
// connected stream when storedAddr is reachable and registry/relay are absent.
func TestThreeLayerDirectDialSucceeds(t *testing.T) {
	peerAddr, _ := startPeerListener(t)
	ctx := context.Background()
	d := quictransport.NewDialer()

	localPub := genConnKey(t)
	peerPub := genConnKey(t)

	stream, err := quictransport.ThreeLayerConnect(ctx, localPub, peerPub, peerAddr, "", "", d)
	if err != nil {
		t.Fatal("ThreeLayerConnect:", err)
	}
	defer stream.Close()
}

// TestThreeLayerRelayForwarding verifies that layer 3 (relay rendezvous)
// connects two peers when no direct addr or registry is configured.
func TestThreeLayerRelayForwarding(t *testing.T) {
	relayAddr := startConnRelay(t)
	ctx := context.Background()
	d := quictransport.NewDialer()

	localPub := genConnKey(t)
	peerPub := genConnKey(t)

	type res struct {
		stream transport.Stream
		err    error
	}
	peerCh := make(chan res, 1)
	go func() {
		s, err := quictransport.ThreeLayerConnect(ctx, peerPub, localPub, "", "", relayAddr, d)
		peerCh <- res{s, err}
	}()

	localStream, err := quictransport.ThreeLayerConnect(ctx, localPub, peerPub, "", "", relayAddr, d)
	if err != nil {
		t.Fatal("local ThreeLayerConnect:", err)
	}
	defer localStream.Close()

	peerRes := <-peerCh
	if peerRes.err != nil {
		t.Fatal("peer ThreeLayerConnect:", peerRes.err)
	}
	defer peerRes.stream.Close()
}

// TestThreeLayerDirectPathFailsRelaySucceeds verifies that when the direct
// address is unreachable the relay layer succeeds and is returned.
func TestThreeLayerDirectPathFailsRelaySucceeds(t *testing.T) {
	relayAddr := startConnRelay(t)
	ctx := context.Background()
	d := quictransport.NewDialer()

	localPub := genConnKey(t)
	peerPub := genConnKey(t)

	const badDirectAddr = "127.0.0.1:19998" // nothing listening

	peerCh := make(chan error, 1)
	go func() {
		s, err := quictransport.ThreeLayerConnect(ctx, peerPub, localPub, "", "", relayAddr, d)
		if err != nil {
			peerCh <- err
			return
		}
		defer s.Close()
		peerCh <- nil
	}()

	stream, err := quictransport.ThreeLayerConnect(ctx, localPub, peerPub, badDirectAddr, "", relayAddr, d)
	if err != nil {
		t.Fatal("expected relay to succeed:", err)
	}
	defer stream.Close()

	if err := <-peerCh; err != nil {
		t.Fatal("peer relay:", err)
	}
}

// TestThreeLayerNoLayersConfigured verifies that all-empty addrs returns an error.
func TestThreeLayerNoLayersConfigured(t *testing.T) {
	ctx := context.Background()
	d := quictransport.NewDialer()
	localPub := genConnKey(t)
	peerPub := genConnKey(t)

	_, err := quictransport.ThreeLayerConnect(ctx, localPub, peerPub, "", "", "", d)
	if err == nil {
		t.Fatal("expected error for no layers configured, got nil")
	}
}

// TestThreeLayerRegistryLookup verifies that layer 2 (registry-assisted) looks
// up the peer's address from the registry and dials it directly.
func TestThreeLayerRegistryLookup(t *testing.T) {
	registryAddr := startConnRegistry(t)
	peerAddr, _ := startPeerListener(t)
	ctx := context.Background()
	d := quictransport.NewDialer()

	localPub := genConnKey(t)
	peerPub := genConnKey(t)

	// Register the peer's address so the registry layer can find it.
	regClient := address.NewClient(registryAddr, d)
	if err := regClient.Register(ctx, peerPub, peerAddr, nil); err != nil {
		t.Fatal("register peer:", err)
	}

	// Layer 1 is empty; layer 2 (registry) should find the peer addr and dial it.
	stream, err := quictransport.ThreeLayerConnect(ctx, localPub, peerPub, "", registryAddr, "", d)
	if err != nil {
		t.Fatal("ThreeLayerConnect via registry:", err)
	}
	defer stream.Close()
}
