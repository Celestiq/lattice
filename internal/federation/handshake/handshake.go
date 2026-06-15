// Package fedhandshake implements the symmetric federation handshake.
//
// Both nodes send FedHello simultaneously immediately after the QUIC handshake.
// Neither side acts as initiator or responder — the exchange is fully symmetric.
// The TLS-exporter nonce ties each FedHello signature to a specific QUIC session,
// preventing cross-session replay without an extra challenge round-trip.
package fedhandshake

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/transport"
	"lattice/internal/wire"
	pb "lattice/proto"
)

const (
	// FedExporterLabel is the TLS keying material label used by both sides.
	// Distinct from the client-session label "lattice-hello-v1" so cross-context
	// replay is structurally impossible.
	FedExporterLabel = "lattice-fed-hello-v1"

	// FedProtocolVersion is the only accepted protocol_version value in FedHello.
	FedProtocolVersion = uint32(1)

	defaultTimeout = 10 * time.Second
)

var (
	ErrInvalidSignature  = errors.New("federation: invalid peer signature")
	ErrProtocolVersion   = errors.New("federation: unsupported protocol version")
	ErrHandshakeRejected = errors.New("federation: handshake rejected by peer")
)

// DoFederatedHandshake performs the symmetric FedHello exchange on stream.
//
// nonce must be 32 bytes of TLS keying material derived by the caller from the
// underlying QUIC connection before calling this function:
//
//	conn.ConnectionState().TLS.ExportKeyingMaterial(FedExporterLabel, nil, 32)
//
// Both sides of a QUIC connection derive identical material, so nonce is the
// same on both sides without an extra round-trip. In tests, any shared 32-byte
// value is acceptable.
//
// The effective deadline is min(ctx.Deadline(), now+10s).
func DoFederatedHandshake(ctx context.Context, stream transport.Stream, nonce []byte, localPriv ed25519.PrivateKey) (peerPubkey []byte, err error) {
	dl := time.Now().Add(defaultTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	if err := stream.SetDeadline(dl); err != nil {
		return nil, err
	}
	defer stream.SetDeadline(time.Time{}) //nolint:errcheck

	localPub := localPriv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(localPriv, nonce)

	helloBytes, err := proto.Marshal(&pb.FedHello{
		Pubkey:          []byte(localPub),
		Signature:       sig,
		ProtocolVersion: FedProtocolVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("federation: marshal FedHello: %w", err)
	}

	// Phase 1: concurrent FedHello exchange.
	// Both sides send and receive simultaneously. This avoids the deadlock that
	// would occur if one side waited for the other to go first.
	var received pb.FedHello
	var sendErr, recvErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sendErr = wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_HELLO, helloBytes)
	}()
	go func() {
		defer wg.Done()
		f, err := wire.Read(stream)
		if err != nil {
			recvErr = fmt.Errorf("federation: read FedHello: %w", err)
			return
		}
		if f.Type == pb.FrameType_FRAME_TYPE_FED_REJECT {
			var reject pb.FedReject
			proto.Unmarshal(f.Payload, &reject) //nolint:errcheck
			recvErr = fmt.Errorf("%w: %s", ErrHandshakeRejected, reject.Reason)
			return
		}
		if f.Type != pb.FrameType_FRAME_TYPE_FED_HELLO {
			recvErr = fmt.Errorf("federation: expected FED_HELLO, got %v", f.Type)
			return
		}
		if err := proto.Unmarshal(f.Payload, &received); err != nil {
			recvErr = fmt.Errorf("federation: unmarshal FedHello: %w", err)
		}
	}()
	wg.Wait()

	if sendErr != nil {
		return nil, sendErr
	}
	if recvErr != nil {
		return nil, recvErr
	}

	// Validate the peer's identity.
	if received.ProtocolVersion != FedProtocolVersion {
		rejectAndClose(stream, fmt.Sprintf("unsupported protocol version %d", received.ProtocolVersion))
		return nil, fmt.Errorf("%w: %d", ErrProtocolVersion, received.ProtocolVersion)
	}
	if len(received.Pubkey) != ed25519.PublicKeySize {
		rejectAndClose(stream, "invalid pubkey length")
		return nil, errors.New("federation: invalid peer pubkey length")
	}
	if !ed25519.Verify(received.Pubkey, nonce, received.Signature) {
		rejectAndClose(stream, "invalid signature")
		return nil, ErrInvalidSignature
	}

	// Phase 2: concurrent FedHelloAck exchange.
	// Empty frame; signals that both sides have verified each other's identity.
	var ackSendErr, ackRecvErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		ackSendErr = wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_HELLO_ACK, nil)
	}()
	go func() {
		defer wg.Done()
		f, err := wire.Read(stream)
		if err != nil {
			ackRecvErr = fmt.Errorf("federation: read FedHelloAck: %w", err)
			return
		}
		if f.Type == pb.FrameType_FRAME_TYPE_FED_REJECT {
			var reject pb.FedReject
			proto.Unmarshal(f.Payload, &reject) //nolint:errcheck
			ackRecvErr = fmt.Errorf("%w: %s", ErrHandshakeRejected, reject.Reason)
			return
		}
		if f.Type != pb.FrameType_FRAME_TYPE_FED_HELLO_ACK {
			ackRecvErr = fmt.Errorf("federation: expected FED_HELLO_ACK, got %v", f.Type)
		}
	}()
	wg.Wait()

	if ackSendErr != nil {
		return nil, ackSendErr
	}
	if ackRecvErr != nil {
		return nil, ackRecvErr
	}

	return received.Pubkey, nil
}

// DoFederatedHandshakeWithHello completes the handshake when the peer's FedHello
// was already read by the caller (e.g., because the caller peeked at the first
// frame to dispatch between connection types). This variant:
//   - sends our FedHello to the peer (phase 1 send side only)
//   - validates the already-received peerHello
//   - exchanges FedHelloAck frames (phase 2)
//
// Use DoFederatedHandshake for the standard symmetric case where both sides read
// and write simultaneously.
func DoFederatedHandshakeWithHello(ctx context.Context, stream transport.Stream, nonce []byte, localPriv ed25519.PrivateKey, peerHelloFrame *wire.Frame) (peerPubkey []byte, err error) {
	dl := time.Now().Add(defaultTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	if err := stream.SetDeadline(dl); err != nil {
		return nil, err
	}
	defer stream.SetDeadline(time.Time{}) //nolint:errcheck

	// Parse the pre-read frame.
	if peerHelloFrame.Type == pb.FrameType_FRAME_TYPE_FED_REJECT {
		var reject pb.FedReject
		proto.Unmarshal(peerHelloFrame.Payload, &reject) //nolint:errcheck
		return nil, fmt.Errorf("%w: %s", ErrHandshakeRejected, reject.Reason)
	}
	if peerHelloFrame.Type != pb.FrameType_FRAME_TYPE_FED_HELLO {
		return nil, fmt.Errorf("federation: expected FED_HELLO, got %v", peerHelloFrame.Type)
	}
	var received pb.FedHello
	if err := proto.Unmarshal(peerHelloFrame.Payload, &received); err != nil {
		return nil, fmt.Errorf("federation: unmarshal FedHello: %w", err)
	}

	// Phase 1: send our FedHello (peer's FedHello is already received).
	localPub := localPriv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(localPriv, nonce)
	helloBytes, err := proto.Marshal(&pb.FedHello{
		Pubkey:          []byte(localPub),
		Signature:       sig,
		ProtocolVersion: FedProtocolVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("federation: marshal FedHello: %w", err)
	}
	if err := wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_HELLO, helloBytes); err != nil {
		return nil, err
	}

	// Validate the peer's identity.
	if received.ProtocolVersion != FedProtocolVersion {
		rejectAndClose(stream, fmt.Sprintf("unsupported protocol version %d", received.ProtocolVersion))
		return nil, fmt.Errorf("%w: %d", ErrProtocolVersion, received.ProtocolVersion)
	}
	if len(received.Pubkey) != ed25519.PublicKeySize {
		rejectAndClose(stream, "invalid pubkey length")
		return nil, errors.New("federation: invalid peer pubkey length")
	}
	if !ed25519.Verify(received.Pubkey, nonce, received.Signature) {
		rejectAndClose(stream, "invalid signature")
		return nil, ErrInvalidSignature
	}

	// Phase 2: concurrent FedHelloAck exchange.
	var ackSendErr, ackRecvErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ackSendErr = wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_HELLO_ACK, nil)
	}()
	go func() {
		defer wg.Done()
		f, err := wire.Read(stream)
		if err != nil {
			ackRecvErr = fmt.Errorf("federation: read FedHelloAck: %w", err)
			return
		}
		if f.Type == pb.FrameType_FRAME_TYPE_FED_REJECT {
			var reject pb.FedReject
			proto.Unmarshal(f.Payload, &reject) //nolint:errcheck
			ackRecvErr = fmt.Errorf("%w: %s", ErrHandshakeRejected, reject.Reason)
			return
		}
		if f.Type != pb.FrameType_FRAME_TYPE_FED_HELLO_ACK {
			ackRecvErr = fmt.Errorf("federation: expected FED_HELLO_ACK, got %v", f.Type)
		}
	}()
	wg.Wait()

	if ackSendErr != nil {
		return nil, ackSendErr
	}
	if ackRecvErr != nil {
		return nil, ackRecvErr
	}
	return received.Pubkey, nil
}

// rejectAndClose writes FedReject to stream and closes it. Errors are swallowed
// because the caller is about to return a local error regardless.
func rejectAndClose(stream transport.Stream, reason string) {
	b, _ := proto.Marshal(&pb.FedReject{Reason: reason})
	wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_REJECT, b) //nolint:errcheck
	stream.Close()                                              //nolint:errcheck
}
