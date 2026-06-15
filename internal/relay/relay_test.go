package relay_test

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/relay"
	"lattice/internal/transport"
	quictransport "lattice/internal/transport/quic"
	"lattice/internal/wire"
	pb "lattice/proto"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// startRelay starts an in-process relay on a random port and returns the address.
func startRelay(t *testing.T) (string, *relay.Relay) {
	t.Helper()
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal("Listen:", err)
	}
	t.Cleanup(func() { l.Close() })
	r := relay.New(l, slog.Default())
	r.Start()
	t.Cleanup(r.Stop)
	return l.Addr().String(), r
}

func sendRelayRegister(t *testing.T, stream transport.Stream, localPub, targetPub []byte) {
	t.Helper()
	b, _ := proto.Marshal(&pb.RelayRegister{LocalPubkey: localPub, TargetPubkey: targetPub})
	if err := wire.Write(stream, pb.FrameType_FRAME_TYPE_RELAY_REGISTER, b); err != nil {
		t.Fatal("write RelayRegister:", err)
	}
}

func waitRelayPaired(t *testing.T, stream transport.Stream, timeout time.Duration) {
	t.Helper()
	stream.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck
	f, err := wire.Read(stream)
	stream.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		t.Fatal("read RelayPaired:", err)
	}
	if f.Type != pb.FrameType_FRAME_TYPE_RELAY_PAIRED {
		t.Fatalf("expected RELAY_PAIRED, got %v", f.Type)
	}
}

// ─── Topology Verification ────────────────────────────────────────────────────

func TestRelayPairAndSplice(t *testing.T) {
	relayAddr, _ := startRelay(t)
	d := quictransport.NewDialer()
	ctx := context.Background()

	pubA, _ := genKey(t)
	pubB, _ := genKey(t)

	// Both nodes connect to relay.
	streamA, err := d.DialPeer(ctx, relayAddr)
	if err != nil {
		t.Fatal("dial A:", err)
	}
	t.Cleanup(func() { streamA.Close() })
	streamB, err := d.DialPeer(ctx, relayAddr)
	if err != nil {
		t.Fatal("dial B:", err)
	}
	t.Cleanup(func() { streamB.Close() })

	// Register for rendezvous concurrently.
	go sendRelayRegister(t, streamA, pubA, pubB)
	go sendRelayRegister(t, streamB, pubB, pubA)

	// Both should receive RELAY_PAIRED.
	doneCh := make(chan struct{}, 2)
	go func() { waitRelayPaired(t, streamA, 3*time.Second); doneCh <- struct{}{} }()
	go func() { waitRelayPaired(t, streamB, 3*time.Second); doneCh <- struct{}{} }()
	<-doneCh
	<-doneCh

	// Now bytes should flow through the relay splice.
	payload := []byte("hello from A")
	if err := wire.Write(streamA, pb.FrameType_FRAME_TYPE_PUBLISH, payload); err != nil {
		t.Fatal("A write:", err)
	}
	f, err := wire.Read(streamB)
	if err != nil {
		t.Fatal("B read:", err)
	}
	if f.Type != pb.FrameType_FRAME_TYPE_PUBLISH {
		t.Fatalf("B got type %v, want PUBLISH", f.Type)
	}
	if string(f.Payload) != string(payload) {
		t.Fatalf("B got payload %q, want %q", f.Payload, payload)
	}

	// Reverse direction.
	payloadB := []byte("reply from B")
	if err := wire.Write(streamB, pb.FrameType_FRAME_TYPE_DELIVER, payloadB); err != nil {
		t.Fatal("B write:", err)
	}
	f2, err := wire.Read(streamA)
	if err != nil {
		t.Fatal("A read:", err)
	}
	if string(f2.Payload) != string(payloadB) {
		t.Fatalf("A got payload %q, want %q", f2.Payload, payloadB)
	}
}

func TestRelayRendezvousTokenSymmetric(t *testing.T) {
	// XOR-based token must be identical from both sides.
	relayAddr, _ := startRelay(t)
	d := quictransport.NewDialer()
	ctx := context.Background()

	pubA, _ := genKey(t)
	pubB, _ := genKey(t)

	streamA, _ := d.DialPeer(ctx, relayAddr)
	streamB, _ := d.DialPeer(ctx, relayAddr)
	t.Cleanup(func() { streamA.Close(); streamB.Close() })

	// A registers A→B, B registers B→A. Relay should match them.
	go sendRelayRegister(t, streamA, pubA, pubB)
	go sendRelayRegister(t, streamB, pubB, pubA)

	doneCh := make(chan struct{}, 2)
	go func() { waitRelayPaired(t, streamA, 3*time.Second); doneCh <- struct{}{} }()
	go func() { waitRelayPaired(t, streamB, 3*time.Second); doneCh <- struct{}{} }()
	<-doneCh
	<-doneCh
}

func TestRelayMultiplePairs(t *testing.T) {
	relayAddr, _ := startRelay(t)
	d := quictransport.NewDialer()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		pubA, _ := genKey(t)
		pubB, _ := genKey(t)

		sA, _ := d.DialPeer(ctx, relayAddr)
		sB, _ := d.DialPeer(ctx, relayAddr)
		t.Cleanup(func() { sA.Close(); sB.Close() })

		go sendRelayRegister(t, sA, pubA, pubB)
		go sendRelayRegister(t, sB, pubB, pubA)

		doneCh := make(chan struct{}, 2)
		go func() { waitRelayPaired(t, sA, 3*time.Second); doneCh <- struct{}{} }()
		go func() { waitRelayPaired(t, sB, 3*time.Second); doneCh <- struct{}{} }()
		<-doneCh
		<-doneCh
	}
}

// ─── Network Fault Injection ─────────────────────────────────────────────────

func TestRelayHalfPairTimeout(t *testing.T) {
	// A half-pair with no match should be cleaned up (we can't easily test the
	// 30s TTL, but we can verify a half-pair with no match eventually gets
	// closed when the relay stops). Stop is idempotent — calling it here and
	// again via t.Cleanup is safe.
	relayAddr, r := startRelay(t)
	d := quictransport.NewDialer()
	ctx := context.Background()

	pubA, _ := genKey(t)
	pubB, _ := genKey(t)

	sA, err := d.DialPeer(ctx, relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sA.Close() })
	// Send register but never send the matching half from B.
	sendRelayRegister(t, sA, pubA, pubB)
	time.Sleep(50 * time.Millisecond)

	// Stop relay — should clean up the half-pair and close the stream.
	r.Stop()

	// Subsequent read on sA should fail (relay closed its side).
	sA.SetDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
	_, err = wire.Read(sA)
	if err == nil {
		t.Error("expected error after relay stopped, got nil")
	}
	_ = pubB
}

func TestRelayInvalidFrameType(t *testing.T) {
	relayAddr, _ := startRelay(t)
	d := quictransport.NewDialer()
	ctx := context.Background()

	stream, err := d.DialPeer(ctx, relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })

	// Send a non-RELAY_REGISTER frame; relay should close the connection.
	if err := wire.Write(stream, pb.FrameType_FRAME_TYPE_PUBLISH, []byte("bad")); err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	_, err = wire.Read(stream)
	if err == nil {
		t.Error("expected connection to be closed by relay, got nil err on read")
	}
}

// ─── State Invalidation & Race Conditions ─────────────────────────────────────

func TestRelayPairRaceConcurrent(t *testing.T) {
	relayAddr, _ := startRelay(t)
	d := quictransport.NewDialer()
	ctx := context.Background()

	pubA, _ := genKey(t)
	pubB, _ := genKey(t)

	const n = 5
	doneCh := make(chan struct{}, n*2)
	for i := 0; i < n; i++ {
		sA, err := d.DialPeer(ctx, relayAddr)
		if err != nil {
			t.Fatal("A dial:", err)
		}
		sB, err := d.DialPeer(ctx, relayAddr)
		if err != nil {
			t.Fatal("B dial:", err)
		}
		t.Cleanup(func() { sA.Close(); sB.Close() })
		go func() {
			sendRelayRegister(t, sA, pubA, pubB)
			waitRelayPaired(t, sA, 3*time.Second)
			doneCh <- struct{}{}
		}()
		go func() {
			sendRelayRegister(t, sB, pubB, pubA)
			waitRelayPaired(t, sB, 3*time.Second)
			doneCh <- struct{}{}
		}()
	}
	for i := 0; i < n*2; i++ {
		<-doneCh
	}
}

