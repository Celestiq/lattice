package address_test

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/address"
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
	_ = priv
	return pub, priv
}

// startRegistry starts an in-process registry server on a random port.
func startRegistry(t *testing.T) (string, *address.Server) {
	t.Helper()
	l, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal("Listen:", err)
	}
	t.Cleanup(func() { l.Close() })
	d := quictransport.NewDialer()
	srv := address.NewServer(l, d, slog.Default())
	srv.Start()
	t.Cleanup(srv.Stop)
	return l.Addr().String(), srv
}

// ─── Topology Verification ────────────────────────────────────────────────────

func TestRegistryRegisterAndLookup(t *testing.T) {
	regAddr, _ := startRegistry(t)
	d := quictransport.NewDialer()
	client := address.NewClient(regAddr, d)
	ctx := context.Background()

	pubA, _ := genKey(t)
	fedAddr := "127.0.0.1:9999"

	// Register.
	if err := client.Register(ctx, []byte(pubA), fedAddr, nil); err != nil {
		t.Fatal("Register:", err)
	}

	// Lookup.
	got, err := client.Lookup(ctx, []byte(pubA))
	if err != nil {
		t.Fatal("Lookup:", err)
	}
	if got != fedAddr {
		t.Fatalf("Lookup returned %q, want %q", got, fedAddr)
	}
}

func TestRegistryLookupUnknown(t *testing.T) {
	regAddr, _ := startRegistry(t)
	d := quictransport.NewDialer()
	client := address.NewClient(regAddr, d)
	ctx := context.Background()

	pubX, _ := genKey(t)
	got, err := client.Lookup(ctx, []byte(pubX))
	if err != nil {
		t.Fatal("Lookup:", err)
	}
	if got != "" {
		t.Fatalf("expected empty addr for unknown pubkey, got %q", got)
	}
}

func TestRegistryAddressUpdate(t *testing.T) {
	regAddr, _ := startRegistry(t)
	d := quictransport.NewDialer()
	client := address.NewClient(regAddr, d)
	ctx := context.Background()

	pubA, _ := genKey(t)
	addrV1 := "127.0.0.1:4001"
	addrV2 := "127.0.0.1:4002"

	if err := client.Register(ctx, []byte(pubA), addrV1, nil); err != nil {
		t.Fatal("Register v1:", err)
	}
	got, _ := client.Lookup(ctx, []byte(pubA))
	if got != addrV1 {
		t.Fatalf("after v1 register, got %q, want %q", got, addrV1)
	}

	// Re-register with updated addr.
	if err := client.Register(ctx, []byte(pubA), addrV2, nil); err != nil {
		t.Fatal("Register v2:", err)
	}
	got, _ = client.Lookup(ctx, []byte(pubA))
	if got != addrV2 {
		t.Fatalf("after v2 register, got %q, want %q", got, addrV2)
	}
}

// ─── Push Notification ────────────────────────────────────────────────────────

func TestRegistryAddressChangeNotification(t *testing.T) {
	// Start a separate "peer" QUIC listener that will receive the push notification.
	peerListener, err := quictransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal("peer Listen:", err)
	}
	t.Cleanup(func() { peerListener.Close() })
	peerAddr := peerListener.Addr().String()

	regAddr, _ := startRegistry(t)
	d := quictransport.NewDialer()
	clientA := address.NewClient(regAddr, d)
	clientB := address.NewClient(regAddr, d)
	ctx := context.Background()

	pubA, _ := genKey(t)
	pubB, _ := genKey(t)

	// B registers its initial addr and lists A as a known peer.
	if err := clientB.Register(ctx, []byte(pubB), "127.0.0.1:5000", [][]byte{[]byte(pubA)}); err != nil {
		t.Fatal("B Register:", err)
	}
	// A registers with its fed addr as peerAddr (the test listener).
	if err := clientA.Register(ctx, []byte(pubA), peerAddr, nil); err != nil {
		t.Fatal("A Register:", err)
	}

	// When B re-registers with a new addr, the registry should push a
	// REGISTRY_NOTIFY to A's registered federation address.
	notifyCh := make(chan string, 1)
	go func() {
		ctx2 := context.Background()
		stream, err := peerListener.AcceptPeer(ctx2)
		if err != nil {
			return
		}
		defer stream.Close() //nolint:errcheck
		stream.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		f, err := wire.Read(stream)
		if err != nil || f.Type != pb.FrameType_FRAME_TYPE_REGISTRY_NOTIFY {
			return
		}
		var notify pb.RegistryNotify
		if err := proto.Unmarshal(f.Payload, &notify); err != nil {
			return
		}
		notifyCh <- notify.Addr
	}()

	newAddrB := "127.0.0.1:5001"
	if err := clientB.Register(ctx, []byte(pubB), newAddrB, [][]byte{[]byte(pubA)}); err != nil {
		t.Fatal("B re-register:", err)
	}

	select {
	case got := <-notifyCh:
		if got != newAddrB {
			t.Fatalf("notification addr = %q, want %q", got, newAddrB)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for registry notification")
	}
}

// ─── Fault Injection ─────────────────────────────────────────────────────────

func TestRegistryUnavailable(t *testing.T) {
	// Use a non-listening address to simulate registry unavailability.
	d := quictransport.NewDialer()
	client := address.NewClient("127.0.0.1:19999", d)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	pubX, _ := genKey(t)
	_, err := client.Lookup(ctx, []byte(pubX))
	if err == nil {
		t.Fatal("expected error for unavailable registry, got nil")
	}
}

// ─── Race Conditions ─────────────────────────────────────────────────────────

func TestRegistryConcurrentRegistrations(t *testing.T) {
	regAddr, _ := startRegistry(t)
	d := quictransport.NewDialer()
	ctx := context.Background()

	const n = 10
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		pub, _ := genKey(t)
		pubBytes := []byte(pub)
		go func() {
			client := address.NewClient(regAddr, d)
			if err := client.Register(ctx, pubBytes, "127.0.0.1:1234", nil); err != nil {
				t.Errorf("concurrent Register: %v", err)
			}
			got, err := client.Lookup(ctx, pubBytes)
			if err != nil || got == "" {
				t.Errorf("concurrent Lookup: err=%v got=%q", err, got)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
}
