// Package wire implements the Lattice frame format.
//
// Frame layout:
//   [4 bytes uint32 BE payload length] [1 byte frame type] [N bytes protobuf payload]
//
// Max payload: 256 KiB. Connections that exceed this are closed by the caller.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	pb "lattice/proto"
)

const (
	MaxPayload    = 256 * 1024 // 256 KiB
	headerLen     = 5          // 4 (length) + 1 (type)
	lenFieldBytes = 4
)

var (
	ErrPayloadTooLarge = errors.New("wire: payload exceeds 256 KiB limit")
	ErrUnknownType     = errors.New("wire: unknown frame type")
)

// Frame is a decoded wire frame.
type Frame struct {
	Type    pb.FrameType
	Payload []byte
}

// Read reads exactly one frame from r.
// Returns ErrPayloadTooLarge if the encoded length exceeds MaxPayload.
// The caller must close the connection on any non-nil error.
func Read(r io.Reader) (*Frame, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("wire: read header: %w", err)
	}

	payloadLen := binary.BigEndian.Uint32(hdr[:lenFieldBytes])
	frameType := pb.FrameType(hdr[lenFieldBytes])

	if payloadLen > MaxPayload {
		return nil, ErrPayloadTooLarge
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("wire: read payload: %w", err)
		}
	}

	return &Frame{Type: frameType, Payload: payload}, nil
}

// Write encodes and writes one frame to w.
func Write(w io.Writer, frameType pb.FrameType, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrPayloadTooLarge
	}

	var hdr [headerLen]byte
	binary.BigEndian.PutUint32(hdr[:lenFieldBytes], uint32(len(payload)))
	hdr[lenFieldBytes] = byte(frameType)

	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("wire: write header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("wire: write payload: %w", err)
		}
	}
	return nil
}
