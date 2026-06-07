package handshake_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
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
// calls doHandshake, then runs handleFrames in the same goroutine.
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

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tlsConn := c.(*tls.Conn)
				defer tlsConn.Close()
				rec, err := handshake.DoServer(tlsConn, serverPriv, sessions, heartbeatInterval)
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

// ─── Tests ────────────────────────────────────────────────────────────────────

// TestValidHELLO: valid HELLO → HELLO_ACK with non-empty session ID.
func TestValidHELLO(t *testing.T) {
	_, serverPriv := newServerKey(t)
	sessions := session.NewTable()
	addr, stop := testServer(t, serverPriv, sessions, 30, nil)
	defer stop()

	_, clientPriv := newClientKey(t)
	conn := dialTLS(t, addr)
	defer conn.Close()

	cs, err := handshake.DoClient(conn, clientPriv)
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
	hello := &pb.Hello{Pubkey: clientPub, Signature: badSig}
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
		// any net error is acceptable — connection is gone
		_ = err
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
	hello := &pb.Hello{Pubkey: claimedPub, Signature: sig}
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
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, clientPriv := newClientKey(t)
			conn := dialTLS(t, addr)
			defer conn.Close()

			cs, err := handshake.DoClient(conn, clientPriv)
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

	if _, err := handshake.DoClient(conn, clientPriv); err != nil {
		t.Fatalf("DoClient: %v", err)
	}

	// Send HEARTBEAT and measure round-trip.
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

	cs, err := handshake.DoClient(conn, clientPriv)
	if err != nil {
		t.Fatalf("DoClient: %v", err)
	}

	// The server's session record for the same ID must have the same token.
	rec := sessions.ByID(cs.SessionID)
	if rec == nil {
		t.Fatal("session not found in server table")
	}
	if string(rec.Token) != string(cs.SessionToken) {
		t.Fatal("session token mismatch between client and server")
	}
}
