// Package handshake implements the Lattice HELLO exchange (Session 2).
//
// Both sides derive the same 32-byte nonce from the TLS session via
// ExportKeyingMaterial. The client signs the nonce with its Ed25519 private key;
// the server verifies the signature against the claimed public key.
package handshake

import (
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

const tlsExporterLabel = "lattice-hello-v1"

// ClientSession holds the state received from the server after a successful HELLO.
type ClientSession struct {
	SessionID         string
	SessionToken      []byte
	ServerPubkey      []byte
	HeartbeatInterval time.Duration
}

// DoServer performs the server-side HELLO handshake on an already-accepted TLS
// connection. It forces the TLS handshake, reads one HELLO frame, verifies the
// Ed25519 signature, creates a session record, and sends HELLO_ACK.
//
// On any error it sends an ERROR frame before returning, leaving the caller to
// close the connection.
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

	if len(hello.Pubkey) != ed25519.PublicKeySize {
		sendError(conn, "INVALID_PUBKEY", "pubkey must be 32 bytes")
		return nil, errors.New("handshake: invalid pubkey length")
	}

	nonce, err := func() ([]byte, error) { cs := conn.ConnectionState(); return cs.ExportKeyingMaterial(tlsExporterLabel, nil, 32) }()
	if err != nil {
		return nil, fmt.Errorf("handshake: export keying material: %w", err)
	}

	if !ed25519.Verify(hello.Pubkey, nonce, hello.Signature) {
		sendError(conn, "INVALID_SIGNATURE", "signature verification failed")
		return nil, errors.New("handshake: signature verification failed")
	}

	rec, err := sessions.Create(hello.Pubkey)
	if err != nil {
		sendError(conn, "INTERNAL", "could not create session")
		return nil, fmt.Errorf("handshake: create session: %w", err)
	}
	rec.Capabilities = hello.Capabilities

	serverPub := serverPriv.Public().(ed25519.PublicKey)
	ack := &pb.HelloAck{
		SessionId:         rec.ID,
		SessionToken:      rec.Token,
		ServerPubkey:      serverPub,
		HeartbeatInterval: heartbeatInterval,
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
// handshake, derives the nonce, signs it, and sends HELLO. It then reads the
// server's response and returns the session info on HELLO_ACK or an error on
// ERROR / unexpected frame type.
func DoClient(conn *tls.Conn, clientPriv ed25519.PrivateKey) (*ClientSession, error) {
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("handshake: TLS: %w", err)
	}

	nonce, err := func() ([]byte, error) { cs := conn.ConnectionState(); return cs.ExportKeyingMaterial(tlsExporterLabel, nil, 32) }()
	if err != nil {
		return nil, fmt.Errorf("handshake: export keying material: %w", err)
	}

	clientPub := clientPriv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(clientPriv, nonce)

	hello := &pb.Hello{
		Pubkey:    clientPub,
		Signature: sig,
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
