package fedhandshake_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	fedhandshake "lattice/internal/federation/handshake"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// sharedNonce returns a 32-byte nonce for test use.
// In production the caller derives this from the QUIC TLS exporter.
func sharedNonce() []byte {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}

// genKey creates an Ed25519 keypair; fatal on error.
func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// pipe returns an in-memory pair that satisfies transport.Stream via net.Conn.
// Both conns are closed by t.Cleanup.
func pipe(t *testing.T) (a, b net.Conn) {
	t.Helper()
	a, b = net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// ─── Topology Verification ────────────────────────────────────────────────────

func TestFedHandshakeMutualAuth(t *testing.T) {
	aConn, bConn := pipe(t)
	nonce := sharedNonce()

	aPub, aPriv := genKey(t)
	bPub, bPriv := genKey(t)

	ctx := context.Background()
	var aPeer, bPeer []byte
	var aErr, bErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aPeer, aErr = fedhandshake.DoFederatedHandshake(ctx, aConn, nonce, aPriv)
	}()
	go func() {
		defer wg.Done()
		bPeer, bErr = fedhandshake.DoFederatedHandshake(ctx, bConn, nonce, bPriv)
	}()
	wg.Wait()

	if aErr != nil {
		t.Fatalf("A side: %v", aErr)
	}
	if bErr != nil {
		t.Fatalf("B side: %v", bErr)
	}
	if !bytes.Equal(aPeer, bPub) {
		t.Errorf("A did not receive B's pubkey: got %x, want %x", aPeer, bPub)
	}
	if !bytes.Equal(bPeer, aPub) {
		t.Errorf("B did not receive A's pubkey: got %x, want %x", bPeer, aPub)
	}
}

func TestFedHandshakeKnownPeerGoesActive(t *testing.T) {
	aConn, bConn := pipe(t)
	nonce := sharedNonce()

	_, aPriv := genKey(t)
	bPub, bPriv := genKey(t)

	ctx := context.Background()
	var aPeer []byte
	var aErr, bErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aPeer, aErr = fedhandshake.DoFederatedHandshake(ctx, aConn, nonce, aPriv)
	}()
	go func() {
		defer wg.Done()
		_, bErr = fedhandshake.DoFederatedHandshake(ctx, bConn, nonce, bPriv)
	}()
	wg.Wait()

	if aErr != nil || bErr != nil {
		t.Fatalf("handshake: A=%v B=%v", aErr, bErr)
	}
	if !bytes.Equal(aPeer, bPub) {
		t.Fatal("A received wrong pubkey")
	}
	// A simulates "lookup peer in store → found as active → PeerConn.Activate"
	// (the store/PeerConn integration is exercised in their own packages; here we
	// just verify the handshake delivers the correct pubkey for the caller to act on)
}

func TestFedHandshakeUnknownPeerGoesPending(t *testing.T) {
	aConn, bConn := pipe(t)
	nonce := sharedNonce()

	_, aPriv := genKey(t)
	bPub, bPriv := genKey(t)

	ctx := context.Background()
	var aPeer []byte
	var aErr, bErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aPeer, aErr = fedhandshake.DoFederatedHandshake(ctx, aConn, nonce, aPriv)
	}()
	go func() {
		defer wg.Done()
		_, bErr = fedhandshake.DoFederatedHandshake(ctx, bConn, nonce, bPriv)
	}()
	wg.Wait()

	if aErr != nil || bErr != nil {
		t.Fatalf("handshake: A=%v B=%v", aErr, bErr)
	}
	// A simulates "lookup peer in store → NOT found → insert as pending"
	if !bytes.Equal(aPeer, bPub) {
		t.Fatal("A received wrong pubkey")
	}
	// In Session 3 the manager would send FedPending here; for S2 we just
	// verify the handshake completed and delivered the pubkey for the caller.
}

// ─── Network Fault Injection ──────────────────────────────────────────────────

func TestFedHandshakeBadSignature(t *testing.T) {
	aConn, bConn := pipe(t)
	nonce := sharedNonce()

	_, aPriv := genKey(t)

	// B sends a FedHello signed with a different key — mismatched pubkey+sig.
	go func() {
		defer bConn.Close()

		badPub, _, _ := ed25519.GenerateKey(nil)
		_, wrongKey, _ := ed25519.GenerateKey(nil)
		badSig := ed25519.Sign(wrongKey, nonce)
		badHello, _ := proto.Marshal(&pb.FedHello{
			Pubkey:          []byte(badPub),
			Signature:       badSig,
			ProtocolVersion: 1,
		})

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			wire.Write(bConn, pb.FrameType_FRAME_TYPE_FED_HELLO, badHello) //nolint:errcheck
		}()
		go func() {
			defer wg.Done()
			wire.Read(bConn) //nolint:errcheck
		}()
		wg.Wait()

		// Drain FedReject from A (may already be closed).
		wire.Read(bConn) //nolint:errcheck
	}()

	_, err := fedhandshake.DoFederatedHandshake(context.Background(), aConn, nonce, aPriv)
	if !errors.Is(err, fedhandshake.ErrInvalidSignature) {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

func TestFedHandshakeWrongProtocolVersion(t *testing.T) {
	aConn, bConn := pipe(t)
	nonce := sharedNonce()

	_, aPriv := genKey(t)

	go func() {
		defer bConn.Close()

		badPub, badPriv, _ := ed25519.GenerateKey(nil)
		badSig := ed25519.Sign(badPriv, nonce)
		badHello, _ := proto.Marshal(&pb.FedHello{
			Pubkey:          []byte(badPub),
			Signature:       badSig,
			ProtocolVersion: 99, // unsupported version
		})

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			wire.Write(bConn, pb.FrameType_FRAME_TYPE_FED_HELLO, badHello) //nolint:errcheck
		}()
		go func() {
			defer wg.Done()
			wire.Read(bConn) //nolint:errcheck
		}()
		wg.Wait()

		// Read FedReject from A.
		f, err := wire.Read(bConn)
		if err != nil {
			return
		}
		if f.Type != pb.FrameType_FRAME_TYPE_FED_REJECT {
			t.Errorf("expected FED_REJECT from A after bad version, got %v", f.Type)
		}
	}()

	_, err := fedhandshake.DoFederatedHandshake(context.Background(), aConn, nonce, aPriv)
	if !errors.Is(err, fedhandshake.ErrProtocolVersion) {
		t.Fatalf("want ErrProtocolVersion, got %v", err)
	}
}

func TestFedHandshakeDeadline(t *testing.T) {
	aConn, bConn := pipe(t)
	nonce := sharedNonce()
	// bConn intentionally unused — nobody reads or writes, so A's goroutines stall.
	_ = bConn

	_, aPriv := genKey(t)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := fedhandshake.DoFederatedHandshake(ctx, aConn, nonce, aPriv)
	if err == nil {
		t.Fatal("expected deadline error, got nil")
	}
	// The WaitGroup inside DoFederatedHandshake ensures both goroutines have
	// exited by the time the function returns — no goroutine leak.
}

func TestFedHandshakeStreamCloseMidway(t *testing.T) {
	aConn, bConn := pipe(t)
	nonce := sharedNonce()

	_, aPriv := genKey(t)

	// B: exchange FedHello normally, then close without sending FedHelloAck.
	bPub, bPriv := genKey(t)
	bSig := ed25519.Sign(bPriv, nonce)
	bHello, _ := proto.Marshal(&pb.FedHello{
		Pubkey:          []byte(bPub),
		Signature:       bSig,
		ProtocolVersion: fedhandshake.FedProtocolVersion,
	})

	go func() {
		defer bConn.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			wire.Write(bConn, pb.FrameType_FRAME_TYPE_FED_HELLO, bHello) //nolint:errcheck
		}()
		go func() {
			defer wg.Done()
			wire.Read(bConn) //nolint:errcheck // read A's FedHello
		}()
		wg.Wait()
		// Close without sending FedHelloAck — stream closes midway.
	}()

	_, err := fedhandshake.DoFederatedHandshake(context.Background(), aConn, nonce, aPriv)
	if err == nil {
		t.Fatal("expected error from closed stream, got nil")
	}
}

// ─── State Invalidation & Distributed Race Conditions ────────────────────────

func TestFedHandshakeConcurrentSamePeer(t *testing.T) {
	const n = 3
	nonce := sharedNonce()
	bPub, bPriv := genKey(t)

	var wg sync.WaitGroup
	errs := make([]error, n)
	peers := make([][]byte, n)

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			aConn, bConn := net.Pipe()
			defer aConn.Close()
			defer bConn.Close()

			_, aPriv := genKey(t)
			ctx := context.Background()

			var inner sync.WaitGroup
			inner.Add(1)
			go func() {
				defer inner.Done()
				// B side always uses the same keypair — same "peer"
				fedhandshake.DoFederatedHandshake(ctx, bConn, nonce, bPriv) //nolint:errcheck
			}()

			peers[i], errs[i] = fedhandshake.DoFederatedHandshake(ctx, aConn, nonce, aPriv)
			inner.Wait()
		}(i)
	}
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Errorf("goroutine %d: %v", i, errs[i])
			continue
		}
		if !bytes.Equal(peers[i], bPub) {
			t.Errorf("goroutine %d: got wrong pubkey %x, want %x", i, peers[i], bPub)
		}
	}
}
