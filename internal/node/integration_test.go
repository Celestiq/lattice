package node_test

// TestIntegrationSequence runs the full 10-step integration scenario described
// in the Session 8 spec. Each step must produce exactly the stated outcome.
//
//  1. Server starts — listening on a random port (replaces port 4222 in tests).
//  2. Client A (admin) connects and subscribes to lattice.system.>
//  3. Client B connects → A receives entity.joined for B.
//  4. Client B subscribes to home.sensor.temperature.
//  5. A publishes a valid temperature reading → B receives DELIVER.
//  6. A publishes an out-of-range temperature → ERROR to A; B receives nothing.
//  7. Client C connects with no allow rules, attempts to publish → PERMISSION_DENIED.
//  8. A sends a Call to B → B receives REQUEST → B responds → A receives RESPONSE.
//  9. B disconnects gracefully → A receives entity.left for B.
// 10. srv.Shutdown() → completes within 5 seconds; no hanging goroutines.

import (
	"crypto/tls"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/acl"
	"lattice/internal/wire"
	pb "lattice/proto"
)

func TestIntegrationSequence(t *testing.T) {
	// ── Step 1: server starts ────────────────────────────────────────────────
	addr, srv, stop := newServer(t, 30)
	defer stop()

	// ── Step 2: Client A connects, subscribes to lattice.system.> ───────────
	a := connect(t, addr)
	defer a.close()

	// A is the "admin" client: can publish temperature readings, subscribe to
	// system events, and call other entities.
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(a.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "lattice.system.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(a.pub),
		Action:          acl.ActionPublish,
		SubjectPattern:  "home.sensor.temperature",
		Effect:          acl.Allow,
		Priority:        10,
	})

	a.subscribe(t, "lattice.system.>")
	// A's own entity.joined fired before the subscription was active; not visible.

	// ── Step 3: Client B connects → A receives entity.joined for B ──────────
	b := connect(t, addr)
	defer b.close()

	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(b.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.sensor.temperature",
		Effect:          acl.Allow,
		Priority:        10,
	})

	joinedPayload := a.expectDeliver(t, "lattice.system.entity.joined")
	var joined pb.EntityJoined
	if err := proto.Unmarshal(joinedPayload, &joined); err != nil {
		t.Fatalf("step 3: unmarshal EntityJoined: %v", err)
	}
	if len(joined.Pubkey) == 0 {
		t.Fatal("step 3: EntityJoined.Pubkey is empty")
	}
	t.Logf("step 3 ✓ entity.joined received for B  session=%s", joined.SessionId)

	// ── Step 4: B subscribes to home.sensor.temperature ─────────────────────
	b.subscribe(t, "home.sensor.temperature")
	t.Log("step 4 ✓ B subscribed to home.sensor.temperature")

	// ── Step 5: A publishes valid temperature → B receives DELIVER ───────────
	a.publish(t, "home.sensor.temperature", tempReading(21.5))
	b.expectDeliver(t, "home.sensor.temperature")
	t.Log("step 5 ✓ valid publish delivered to B")

	// ── Step 6: A publishes out-of-range temperature → ERROR; B silent ───────
	badTemp, _ := proto.Marshal(&pb.TemperatureReading{Value: func() *float32 { v := float32(999); return &v }()})
	a.publish(t, "home.sensor.temperature", badTemp)

	e := a.expectError(t)
	if e.Code != "SCHEMA_ERROR" {
		t.Fatalf("step 6: expected SCHEMA_ERROR, got %q", e.Code)
	}
	b.expectNoFrame(t) // B receives nothing
	t.Log("step 6 ✓ schema error returned to A; B received nothing")

	// ── Step 7: C connects with no rules, attempts to publish → denied ───────
	c := connect(t, addr)

	// A receives entity.joined for C.
	a.expectDeliver(t, "lattice.system.entity.joined")

	c.publish(t, "home.sensor.temperature", tempReading(20.0))
	eC := c.expectError(t)
	if eC.Code != "PERMISSION_DENIED" {
		t.Fatalf("step 7: expected PERMISSION_DENIED, got %q", eC.Code)
	}
	c.close()

	// A receives entity.left for C.
	a.expectDeliver(t, "lattice.system.entity.left")
	t.Log("step 7 ✓ C denied publish; entity.joined and entity.left observed by A")

	// ── Step 8: A calls B → B responds → A receives response ────────────────
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(a.pub),
		Action:          acl.ActionCall,
		SubjectPattern:  acl.EncodeIdentity(b.pub),
		Effect:          acl.Allow,
		Priority:        10,
	})

	corrID := "integration-call-1"
	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: corrID,
		TargetPubkey:  b.pub,
		Payload:       []byte("ping"),
		TimeoutMs:     5000,
	})

	// B receives the forwarded REQUEST.
	reqFrame := b.recv(t, 2*time.Second)
	if reqFrame.Type != pb.FrameType_FRAME_TYPE_REQUEST {
		t.Fatalf("step 8: B expected REQUEST, got %v", reqFrame.Type)
	}
	var req pb.Request
	proto.Unmarshal(reqFrame.Payload, &req)
	if req.CorrelationId != corrID {
		t.Fatalf("step 8: correlation_id: got %q, want %q", req.CorrelationId, corrID)
	}

	// B responds.
	b.send(pb.FrameType_FRAME_TYPE_RESPONSE, &pb.Response{
		CorrelationId: corrID,
		Payload:       []byte("pong"),
	})

	// A receives the response.
	respFrame := a.recv(t, 2*time.Second)
	if respFrame.Type != pb.FrameType_FRAME_TYPE_RESPONSE {
		t.Fatalf("step 8: A expected RESPONSE, got %v", respFrame.Type)
	}
	var resp pb.Response
	proto.Unmarshal(respFrame.Payload, &resp)
	if resp.CorrelationId != corrID {
		t.Fatalf("step 8: response correlation_id: got %q, want %q", resp.CorrelationId, corrID)
	}
	if string(resp.Payload) != "pong" {
		t.Fatalf("step 8: response payload: got %q, want %q", resp.Payload, "pong")
	}
	t.Log("step 8 ✓ A called B; B responded; A received RESPONSE")

	// ── Step 9: B disconnects → A receives entity.left for B ────────────────
	b.close()
	leftPayload := a.expectDeliver(t, "lattice.system.entity.left")
	var left pb.EntityLeft
	if err := proto.Unmarshal(leftPayload, &left); err != nil {
		t.Fatalf("step 9: unmarshal EntityLeft: %v", err)
	}
	if len(left.Pubkey) == 0 {
		t.Fatal("step 9: EntityLeft.Pubkey is empty")
	}
	t.Logf("step 9 ✓ entity.left received for B  session=%s", left.SessionId)

	// ── Step 10: graceful shutdown ───────────────────────────────────────────
	shutdownDone := make(chan struct{})
	go func() {
		srv.Shutdown()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		// OK — no hanging goroutines
	case <-time.After(5 * time.Second):
		t.Fatal("step 10: srv.Shutdown() did not complete within 5 seconds")
	}

	// After shutdown, reads on A must eventually fail (connection closed).
	a.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(time.Second))
	for {
		_, err := wire.Read(a.conn)
		if err != nil {
			break // expected
		}
		// drain any entity.left events emitted during shutdown
	}

	t.Log("step 10 ✓ shutdown completed; connections closed")
}
