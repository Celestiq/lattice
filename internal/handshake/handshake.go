// Package handshake implements the Lattice HELLO exchange.
//
// Both sides derive separate 32-byte nonces from the TLS session via
// ExportKeyingMaterial. The client signs its nonce to prove key possession; the
// server signs its nonce so the client can verify the server's identity
// (Decision #1). The two exporter labels are intentionally distinct so the same
// bytes are never signed in both directions.
package handshake

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/session"
	"lattice/internal/wire"
	pb "lattice/proto"
)

const (
	tlsExporterClientLabel = "lattice-hello-v1"
	tlsExporterServerLabel = "lattice-hello-server-v1"

	// ProtocolVersion is the current wire protocol version sent in Hello.
	// The server rejects any Hello whose protocol_version != ProtocolVersion.
	ProtocolVersion uint32 = 1
)

// ClientSession holds the state received from the server after a successful HELLO.
type ClientSession struct {
	SessionID         string
	SessionToken      []byte
	ServerPubkey      []byte
	HeartbeatInterval time.Duration
}

// DoServer performs the server-side HELLO handshake on an already-accepted TLS
// connection. It forces the TLS handshake, reads one HELLO frame, verifies the
// client's Ed25519 signature, creates a session record, signs the server nonce,
// and sends HELLO_ACK.
//
// On any error it sends an ERROR frame before returning.
func DoServer(
	conn *tls.Conn,
	serverPriv ed25519.PrivateKey,
	sessions *session.Table,
	heartbeatInterval uint32,
) (*session.Record, error) {
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("handshake: TLS: %w", err)
	}

	frame, err := wire.Read(conn)
	if err != nil {
		return nil, fmt.Errorf("handshake: read: %w", err)
	}
	if frame.Type != pb.FrameType_FRAME_TYPE_HELLO {
		sendError(conn, "UNEXPECTED_FRAME", fmt.Sprintf("expected HELLO, got %v", frame.Type))
		return nil, errors.New("handshake: expected HELLO frame")
	}

	var hello pb.Hello
	if err := proto.Unmarshal(frame.Payload, &hello); err != nil {
		sendError(conn, "INVALID_PAYLOAD", "cannot unmarshal HELLO")
		return nil, fmt.Errorf("handshake: unmarshal HELLO: %w", err)
	}

	if hello.ProtocolVersion != ProtocolVersion {
		sendError(conn, "UNSUPPORTED_VERSION",
			fmt.Sprintf("expected protocol_version %d, got %d", ProtocolVersion, hello.ProtocolVersion))
		return nil, fmt.Errorf("handshake: unsupported protocol_version %d", hello.ProtocolVersion)
	}

	if len(hello.Pubkey) != ed25519.PublicKeySize {
		sendError(conn, "INVALID_PUBKEY", "pubkey must be 32 bytes")
		return nil, errors.New("handshake: invalid pubkey length")
	}

	cs := conn.ConnectionState()
	clientNonce, err := cs.ExportKeyingMaterial(tlsExporterClientLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("handshake: export keying material: %w", err)
	}

	if !ed25519.Verify(hello.Pubkey, clientNonce, hello.Signature) {
		sendError(conn, "INVALID_SIGNATURE", "signature verification failed")
		return nil, errors.New("handshake: signature verification failed")
	}

	rec, err := sessions.Create(hello.Pubkey)
	if err != nil {
		sendError(conn, "INTERNAL", "could not create session")
		return nil, fmt.Errorf("handshake: create session: %w", err)
	}
	rec.Capabilities = hello.Capabilities

	// Sign the server-side nonce so the client can verify our identity.
	serverNonce, err := cs.ExportKeyingMaterial(tlsExporterServerLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("handshake: export server keying material: %w", err)
	}
	serverSig := ed25519.Sign(serverPriv, serverNonce)

	serverPub := serverPriv.Public().(ed25519.PublicKey)
	ack := &pb.HelloAck{
		SessionId:         rec.ID,
		SessionToken:      rec.Token,
		ServerPubkey:      serverPub,
		HeartbeatInterval: heartbeatInterval,
		ServerSignature:   serverSig,
	}
	ackPayload, err := proto.Marshal(ack)
	if err != nil {
		return nil, fmt.Errorf("handshake: marshal HELLO_ACK: %w", err)
	}
	if err := wire.Write(conn, pb.FrameType_FRAME_TYPE_HELLO_ACK, ackPayload); err != nil {
		return nil, fmt.Errorf("handshake: write HELLO_ACK: %w", err)
	}

	return rec, nil
}

// DoClient performs the client-side HELLO handshake. It forces the TLS
// handshake, signs the client nonce, sends HELLO, and verifies the server's
// Ed25519 signature in HELLO_ACK.
//
// pinnedServerPubkey: if non-nil, the server's pubkey in HELLO_ACK must match
// exactly (pin mismatch → error). Pass nil on first connection (TOFU).
//
// caps: capabilities to declare in HELLO. May be nil.
func DoClient(conn *tls.Conn, clientPriv ed25519.PrivateKey, pinnedServerPubkey []byte, caps []*pb.Capability) (*ClientSession, error) {
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("handshake: TLS: %w", err)
	}

	cs := conn.ConnectionState()
	clientNonce, err := cs.ExportKeyingMaterial(tlsExporterClientLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("handshake: export keying material: %w", err)
	}

	clientPub := clientPriv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(clientPriv, clientNonce)

	hello := &pb.Hello{
		Pubkey:          clientPub,
		Signature:       sig,
		ProtocolVersion: ProtocolVersion,
		Capabilities:    caps,
	}
	helloPayload, err := proto.Marshal(hello)
	if err != nil {
		return nil, fmt.Errorf("handshake: marshal HELLO: %w", err)
	}
	if err := wire.Write(conn, pb.FrameType_FRAME_TYPE_HELLO, helloPayload); err != nil {
		return nil, fmt.Errorf("handshake: write HELLO: %w", err)
	}

	frame, err := wire.Read(conn)
	if err != nil {
		return nil, fmt.Errorf("handshake: read response: %w", err)
	}

	switch frame.Type {
	case pb.FrameType_FRAME_TYPE_HELLO_ACK:
		var ack pb.HelloAck
		if err := proto.Unmarshal(frame.Payload, &ack); err != nil {
			return nil, fmt.Errorf("handshake: unmarshal HELLO_ACK: %w", err)
		}

		// Verify the server's Ed25519 signature over its own TLS-exporter nonce.
		serverNonce, err := cs.ExportKeyingMaterial(tlsExporterServerLabel, nil, 32)
		if err != nil {
			return nil, fmt.Errorf("handshake: export server keying material: %w", err)
		}
		if !ed25519.Verify(ack.ServerPubkey, serverNonce, ack.ServerSignature) {
			return nil, errors.New("handshake: server signature verification failed")
		}

		// If the caller has pinned a server pubkey, verify it matches.
		if pinnedServerPubkey != nil && !bytes.Equal(ack.ServerPubkey, pinnedServerPubkey) {
			return nil, errors.New("handshake: server pubkey pin mismatch")
		}

		return &ClientSession{
			SessionID:         ack.SessionId,
			SessionToken:      ack.SessionToken,
			ServerPubkey:      ack.ServerPubkey,
			HeartbeatInterval: time.Duration(ack.HeartbeatInterval) * time.Second,
		}, nil

	case pb.FrameType_FRAME_TYPE_ERROR:
		var e pb.Error
		proto.Unmarshal(frame.Payload, &e) //nolint:errcheck — best-effort decode
		return nil, fmt.Errorf("handshake: server error %s: %s", e.Code, e.Message)

	default:
		return nil, fmt.Errorf("handshake: unexpected frame %v", frame.Type)
	}
}

// sendError writes an ERROR frame to conn. Errors are silently ignored because
// the connection is about to be closed.
func sendError(conn *tls.Conn, code, message string) {
	payload, _ := proto.Marshal(&pb.Error{Code: code, Message: message})
	_ = wire.Write(conn, pb.FrameType_FRAME_TYPE_ERROR, payload)
}
