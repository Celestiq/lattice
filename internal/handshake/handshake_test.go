package handshake_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/handshake"
	"lattice/internal/session"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// testServer starts an in-process TLS server. For each accepted connection it
// calls DoServer, then runs handleFrames in the same goroutine.
// Both callbacks receive the *tls.Conn; handleFrames may be nil (connection
// closed after handshake).
func testServer(
	t *testing.T,
	serverPriv ed25519.PrivateKey,
	sessions *session.Table,
	heartbeatInterval uint32,
	handleFrames func(*tls.Conn, *session.Record),
) (addr string, stop func()) {
	t.Helper()

	cert, err := wire.GenerateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}

	tokens := session.NewTokenStore(5 * time.Minute)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tlsConn := c.(*tls.Conn)
				defer tlsConn.Close()
				rec, _, err := handshake.DoServer(tlsConn, serverPriv, sessions, tokens, heartbeatInterval)
				if err != nil {
					return
				}
				if handleFrames != nil {
					handleFrames(tlsConn, rec)
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// heartbeatLoop is a handleFrames callback that responds to HEARTBEAT with
// HEARTBEAT_ACK and exits on any other frame or error.
func heartbeatLoop(conn *tls.Conn, _ *session.Record) {
	for {
		frame, err := wire.Read(conn)
		if err != nil {
			return
		}
		if frame.Type == pb.FrameType_FRAME_TYPE_HEARTBEAT {
			_ = wire.Write(conn, pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK, nil)
		}
	}
}

func newServerKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newClientKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func dialTLS(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// sendHello performs a raw HELLO with the given fields, bypassing DoClient.
// Useful for testing server-side validation without going through the full client path.
func sendHello(t *testing.T, conn *tls.Conn, clientPriv ed25519.PrivateKey, pubkey ed25519.PublicKey, version uint32) {
	t.Helper()
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	cs := conn.ConnectionState()
	nonce, err := cs.ExportKeyingMaterial("lattice-hello-v1", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(clientPriv, nonce)
	hello := &pb.Hello{
		Pubkey:          pubkey,
		Signature:       sig,
		ProtocolVersion: version,
	}
	payload, _ := proto.Marshal(hello)
	if err := wire.Write(conn, pb.FrameType_FRAME_TYPE_HELLO, payload); err != nil {
		t.Fatal(err)
	}
}

// ─── Regression tests (updated for new DoClient signature) ───────────────────

// TestValidHELLO: valid HELLO → HELLO_ACK with non-empty session ID.
func TestValidHELLO(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, nil)
	defer stop()

	_, clientPriv := newClientKey(t)
	conn := dialTLS(t, addr)
	defer conn.Close()

	cs, err := handshake.DoClient(conn, clientPriv, nil, nil)
	if err != nil {
		t.Fatalf("DoClient: %v", err)
	}
	if cs.SessionID == "" {
		t.Fatal("session ID is empty")
	}
	if len(cs.SessionToken) != 32 {
		t.Fatalf("session token length: got %d, want 32", len(cs.SessionToken))
	}
	if len(cs.ServerPubkey) != ed25519.PublicKeySize {
		t.Fatalf("server pubkey length: got %d, want 32", len(cs.ServerPubkey))
	}
}

// TestCorruptedSignature: HELLO with a signature over wrong data → ERROR, connection closed.
func TestCorruptedSignature(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, nil)
	defer stop()

	_, clientPriv := newClientKey(t)
	clientPub := clientPriv.Public().(ed25519.PublicKey)

	conn := dialTLS(t, addr)
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}

	// Sign garbage instead of the real nonce.
	badSig := ed25519.Sign(clientPriv, []byte("not the real nonce"))
	hello := &pb.Hello{
		Pubkey:          clientPub,
		Signature:       badSig,
		ProtocolVersion: handshake.ProtocolVersion,
	}
	payload, _ := proto.Marshal(hello)
	if err := wire.Write(conn, pb.FrameType_FRAME_TYPE_HELLO, payload); err != nil {
		t.Fatal(err)
	}

	frame, err := wire.Read(conn)
	if err != nil {
		t.Fatalf("expected ERROR frame, got read error: %v", err)
	}
	if frame.Type != pb.FrameType_FRAME_TYPE_ERROR {
		t.Fatalf("expected ERROR, got %v", frame.Type)
	}

	// Connection must be closed after ERROR.
	_, err = wire.Read(conn)
	if err == nil {
		t.Fatal("expected connection to be closed after ERROR")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		_ = err // any net error is acceptable — connection is gone
	}
}

// TestMismatchedPubkey: signs with key A but claims key B → ERROR.
func TestMismatchedPubkey(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, nil)
	defer stop()

	_, signerPriv := newClientKey(t) // actual signer
	claimedPub, _ := newClientKey(t) // different key claimed in HELLO

	conn := dialTLS(t, addr)
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}

	cs := conn.ConnectionState()
	nonce, err := cs.ExportKeyingMaterial("lattice-hello-v1", nil, 32)
	if err != nil {
		t.Fatal(err)
	}

	// Sign the real nonce but claim a different pubkey.
	sig := ed25519.Sign(signerPriv, nonce)
	hello := &pb.Hello{
		Pubkey:          claimedPub,
		Signature:       sig,
		ProtocolVersion: handshake.ProtocolVersion,
	}
	payload, _ := proto.Marshal(hello)
	if err := wire.Write(conn, pb.FrameType_FRAME_TYPE_HELLO, payload); err != nil {
		t.Fatal(err)
	}

	frame, err := wire.Read(conn)
	if err != nil {
		t.Fatalf("expected ERROR frame, got: %v", err)
	}
	if frame.Type != pb.FrameType_FRAME_TYPE_ERROR {
		t.Fatalf("expected ERROR, got %v", frame.Type)
	}
}

// TestTwoClientsIndependentSessions: two concurrent clients get different session IDs.
func TestTwoClientsIndependentSessions(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, nil)
	defer stop()

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		sessionIDs []string
	)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, clientPriv := newClientKey(t)
			conn := dialTLS(t, addr)
			defer conn.Close()

			cs, err := handshake.DoClient(conn, clientPriv, nil, nil)
			if err != nil {
				t.Errorf("DoClient: %v", err)
				return
			}
			mu.Lock()
			sessionIDs = append(sessionIDs, cs.SessionID)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(sessionIDs) != 2 {
		t.Fatalf("expected 2 session IDs, got %d", len(sessionIDs))
	}
	if sessionIDs[0] == sessionIDs[1] {
		t.Fatal("both clients got the same session ID")
	}
}

// TestHeartbeatAck: send HEARTBEAT after handshake → HEARTBEAT_ACK within 1 second.
func TestHeartbeatAck(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, heartbeatLoop)
	defer stop()

	_, clientPriv := newClientKey(t)
	conn := dialTLS(t, addr)
	defer conn.Close()

	if _, err := handshake.DoClient(conn, clientPriv, nil, nil); err != nil {
		t.Fatalf("DoClient: %v", err)
	}

	start := time.Now()
	if err := wire.Write(conn, pb.FrameType_FRAME_TYPE_HEARTBEAT, nil); err != nil {
		t.Fatalf("write heartbeat: %v", err)
	}

	frame, err := wire.Read(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	elapsed := time.Since(start)

	if frame.Type != pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK {
		t.Fatalf("expected HEARTBEAT_ACK, got %v", frame.Type)
	}
	if elapsed > time.Second {
		t.Fatalf("HEARTBEAT_ACK took %v, want < 1s", elapsed)
	}
}

// TestClientStoresSessionToken: session token stored by client matches what server issued.
func TestClientStoresSessionToken(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, nil)
	defer stop()

	_, clientPriv := newClientKey(t)
	conn := dialTLS(t, addr)
	defer conn.Close()

	cs, err := handshake.DoClient(conn, clientPriv, nil, nil)
	if err != nil {
		t.Fatalf("DoClient: %v", err)
	}

	rec := sessions.ByID(cs.SessionID)
	if rec == nil {
		t.Fatal("session not found in server table")
	}
	if string(rec.Token) != string(cs.SessionToken) {
		t.Fatal("session token mismatch between client and server")
	}
}

// ─── Session 1 new tests ─────────────────────────────────────────────────────

// TestServerSignatureVerifySuccess: DoClient verifies the server signature when
// the server signs correctly. (Implicitly tested by TestValidHELLO but explicit
// here for clarity.)
func TestServerSignatureVerifySuccess(t *testing.T) {
	serverPub, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, nil)
	defer stop()

	_, clientPriv := newClientKey(t)
	conn := dialTLS(t, addr)
	defer conn.Close()

	// Pass the server's pubkey as the pin — this exercises both signature
	// verification and pin matching on the first connection.
	cs, err := handshake.DoClient(conn, clientPriv, serverPub, nil)
	if err != nil {
		t.Fatalf("DoClient with correct pin: %v", err)
	}
	if len(cs.ServerPubkey) != ed25519.PublicKeySize {
		t.Fatalf("server pubkey length: got %d", len(cs.ServerPubkey))
	}
}

// TestForgedServerSignature: a server that sends zeroed server_signature is rejected.
func TestForgedServerSignature(t *testing.T) {
	_, serverPriv := newServerKey(t)

	// Start a raw server that sends a HELLO_ACK with a zeroed server_signature.
	cert, err := wire.GenerateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverPub := serverPriv.Public().(ed25519.PublicKey)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		frame, err := wire.Read(tlsConn)
		if err != nil || frame.Type != pb.FrameType_FRAME_TYPE_HELLO {
			return
		}
		// Send HELLO_ACK with all-zero server_signature (forged).
		ack := &pb.HelloAck{
			SessionId:         "fake-session",
			SessionToken:      make([]byte, 32),
			ServerPubkey:      serverPub,
			HeartbeatInterval: 30,
			ServerSignature:   make([]byte, 64), // zeros — invalid signature
		}
		payload, _ := proto.Marshal(ack)
		_ = wire.Write(tlsConn, pb.FrameType_FRAME_TYPE_HELLO_ACK, payload)
	}()

	_, clientPriv := newClientKey(t)
	conn := dialTLS(t, ln.Addr().String())
	defer conn.Close()

	_, err = handshake.DoClient(conn, clientPriv, nil, nil)
	if err == nil {
		t.Fatal("expected error for forged server signature, got nil")
	}
	if !strings.Contains(err.Error(), "server signature") {
		t.Fatalf("expected server signature error, got: %v", err)
	}
}

// TestPinMismatch: valid server signature but wrong pinned pubkey → error.
func TestPinMismatch(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, nil)
	defer stop()

	_, clientPriv := newClientKey(t)
	wrongPin, _, _ := ed25519.GenerateKey(rand.Reader) // different key than the server's

	conn := dialTLS(t, addr)
	defer conn.Close()

	_, err := handshake.DoClient(conn, clientPriv, wrongPin, nil)
	if err == nil {
		t.Fatal("expected pin mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("expected pin mismatch error, got: %v", err)
	}
}

// TestUnsupportedProtocolVersion: Hello with wrong protocol_version → ERROR UNSUPPORTED_VERSION.
func TestUnsupportedProtocolVersion(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, nil)
	defer stop()

	_, clientPriv := newClientKey(t)
	clientPub := clientPriv.Public().(ed25519.PublicKey)

	conn := dialTLS(t, addr)
	defer conn.Close()

	// Send Hello with a version the server does not accept.
	sendHello(t, conn, clientPriv, clientPub, 99)

	frame, err := wire.Read(conn)
	if err != nil {
		t.Fatalf("expected ERROR frame: %v", err)
	}
	if frame.Type != pb.FrameType_FRAME_TYPE_ERROR {
		t.Fatalf("expected ERROR, got %v", frame.Type)
	}
	var e pb.Error
	proto.Unmarshal(frame.Payload, &e)
	if e.Code != "UNSUPPORTED_VERSION" {
		t.Fatalf("expected UNSUPPORTED_VERSION, got %q", e.Code)
	}
}

// TestTypedCapabilitiesRoundTrip: Capability fields survive Hello → session.Record.
func TestTypedCapabilitiesRoundTrip(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()

	// Capture the session record from DoServer via handleFrames callback.
	var (
		mu      sync.Mutex
		gotCaps []*pb.Capability
	)
	addr, stop := testServer(t, serverPriv, sessions, 30, func(_ *tls.Conn, rec *session.Record) {
		mu.Lock()
		gotCaps = rec.Capabilities
		mu.Unlock()
	})
	defer stop()

	_, clientPriv := newClientKey(t)
	caps := []*pb.Capability{{Name: "sensor"}, {Name: "actuator"}}

	conn := dialTLS(t, addr)
	defer conn.Close()

	if _, err := handshake.DoClient(conn, clientPriv, nil, caps); err != nil {
		t.Fatalf("DoClient: %v", err)
	}

	// Give the server goroutine time to execute the handleFrames callback.
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(gotCaps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(gotCaps))
	}
	if gotCaps[0].Name != "sensor" || gotCaps[1].Name != "actuator" {
		t.Fatalf("capability names mismatch: got %v", gotCaps)
	}
}
