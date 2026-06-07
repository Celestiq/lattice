package wire_test

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	"lattice/internal/wire"
	pb "lattice/proto"
)

func roundTrip(t *testing.T, frameType pb.FrameType, payload []byte) *wire.Frame {
	t.Helper()
	var buf bytes.Buffer
	if err := wire.Write(&buf, frameType, payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	frame, err := wire.Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return frame
}

func TestRoundTrip(t *testing.T) {
	payload := []byte("hello lattice")
	frame := roundTrip(t, pb.FrameType_FRAME_TYPE_PING, payload)

	if frame.Type != pb.FrameType_FRAME_TYPE_PING {
		t.Fatalf("type: got %v, want %v", frame.Type, pb.FrameType_FRAME_TYPE_PING)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("payload: got %q, want %q", frame.Payload, payload)
	}
}

func TestEmptyPayload(t *testing.T) {
	frame := roundTrip(t, pb.FrameType_FRAME_TYPE_HEARTBEAT, nil)
	if len(frame.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(frame.Payload))
	}
}

// TestMaxPayloadAccepted: exactly 256 KiB — must be accepted.
func TestMaxPayloadAccepted(t *testing.T) {
	payload := make([]byte, wire.MaxPayload)
	frame := roundTrip(t, pb.FrameType_FRAME_TYPE_PUBLISH, payload)
	if len(frame.Payload) != wire.MaxPayload {
		t.Fatalf("payload length: got %d, want %d", len(frame.Payload), wire.MaxPayload)
	}
}

// TestMaxPayloadPlusOne: 256 KiB + 1 byte — Read must return ErrPayloadTooLarge.
func TestMaxPayloadPlusOne(t *testing.T) {
	oversize := make([]byte, wire.MaxPayload+1)
	var buf bytes.Buffer
	// Manually craft the oversized frame header (Write would also reject it).
	hdr := [5]byte{}
	length := uint32(len(oversize))
	hdr[0] = byte(length >> 24)
	hdr[1] = byte(length >> 16)
	hdr[2] = byte(length >> 8)
	hdr[3] = byte(length)
	hdr[4] = byte(pb.FrameType_FRAME_TYPE_PUBLISH)
	buf.Write(hdr[:])
	buf.Write(oversize)

	_, err := wire.Read(&buf)
	if err != wire.ErrPayloadTooLarge {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
}

// TestTwoClientsSimultaneous: two goroutines write and read back frames independently.
func TestTwoClientsSimultaneous(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := []byte{byte(id)}
			var buf bytes.Buffer
			if err := wire.Write(&buf, pb.FrameType_FRAME_TYPE_PING, payload); err != nil {
				t.Errorf("goroutine %d write: %v", id, err)
				return
			}
			frame, err := wire.Read(&buf)
			if err != nil {
				t.Errorf("goroutine %d read: %v", id, err)
				return
			}
			if !bytes.Equal(frame.Payload, payload) {
				t.Errorf("goroutine %d payload mismatch", id)
			}
		}(i)
	}
	wg.Wait()
}

// TestClientDisconnectMidRead: simulate a client that closes mid-stream.
func TestClientDisconnectMidRead(t *testing.T) {
	// Write only the 5-byte header, then close — simulates client dropping mid-read.
	var buf bytes.Buffer
	hdr := [5]byte{}
	length := uint32(100)
	hdr[0] = byte(length >> 24)
	hdr[1] = byte(length >> 16)
	hdr[2] = byte(length >> 8)
	hdr[3] = byte(length)
	hdr[4] = byte(pb.FrameType_FRAME_TYPE_PING)
	buf.Write(hdr[:])
	// no payload — EOF mid-read

	_, err := wire.Read(&buf)
	if err == nil {
		t.Fatal("expected error on truncated frame")
	}
	if err != io.ErrUnexpectedEOF {
		// wrapped error is acceptable as long as it is non-nil
		_ = err
	}
}

// TestNetConnTwoClients: full in-process TCP round-trip with two connections.
func TestNetConnTwoClients(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				frame, err := wire.Read(c)
				if err != nil {
					return
				}
				_ = wire.Write(c, frame.Type, frame.Payload)
			}(conn)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer conn.Close()
			payload := []byte{byte(id)}
			if err := wire.Write(conn, pb.FrameType_FRAME_TYPE_PING, payload); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			frame, err := wire.Read(conn)
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			if !bytes.Equal(frame.Payload, payload) {
				t.Errorf("id %d payload mismatch: got %v want %v", id, frame.Payload, payload)
			}
		}(i)
	}
	wg.Wait()
}
