package node_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/acl"
	"lattice/internal/handshake"
	"lattice/internal/node"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// ─── Test infrastructure ─────────────────────────────────────────────────────

// newServer starts an in-process TLS server and returns the address, the live
// *node.Server (for adding ACL rules), and a stop function.
func newServer(t *testing.T, heartbeatInterval uint32) (addr string, srv *node.Server, stop func()) {
	t.Helper()
	_, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv = node.New(slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})), serverPriv, heartbeatInterval)

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
			go srv.HandleConn(conn)
		}
	}()
	return ln.Addr().String(), srv, func() { ln.Close() }
}

// testClient wraps a connected+authenticated TLS connection.
type testClient struct {
	conn net.Conn
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	mu   sync.Mutex
}

func connect(t *testing.T, addr string) *testClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshake.DoClient(conn, priv, nil, nil); err != nil {
		conn.Close()
		t.Fatalf("handshake: %v", err)
	}
	return &testClient{conn: conn, pub: pub, priv: priv}
}

func (c *testClient) send(ft pb.FrameType, msg proto.Message) {
	payload, _ := proto.Marshal(msg)
	c.mu.Lock()
	defer c.mu.Unlock()
	wire.Write(c.conn, ft, payload)
}

func (c *testClient) recv(t *testing.T, timeout time.Duration) *wire.Frame {
	t.Helper()
	c.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(timeout))
	frame, err := wire.Read(c.conn)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return frame
}

func (c *testClient) expectFrame(t *testing.T, want pb.FrameType) *wire.Frame {
	t.Helper()
	frame := c.recv(t, 2*time.Second)
	if frame.Type != want {
		t.Fatalf("expected %v, got %v", want, frame.Type)
	}
	return frame
}

// startHeartbeat sends HEARTBEAT every interval so the server does not mark
// this client offline during long-running tests. Call the returned stop func
// when done (or defer it).
func (c *testClient) startHeartbeat(interval time.Duration) func() {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				wire.Write(c.conn, pb.FrameType_FRAME_TYPE_HEARTBEAT, nil)
				c.mu.Unlock()
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(done) }
}

// expectNoFrame asserts no frame of any type arrives within 200 ms.
func (c *testClient) expectNoFrame(t *testing.T) {
	t.Helper()
	c.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	frame, err := wire.Read(c.conn)
	if err == nil {
		t.Fatalf("expected no frame but got %v", frame.Type)
	}
	c.conn.(*tls.Conn).SetReadDeadline(time.Time{})
}

// expectNoDeliver asserts no DELIVER frame arrives within duration, ignoring
// HEARTBEAT_ACK and other protocol frames that may arrive concurrently.
func (c *testClient) expectNoDeliver(t *testing.T, d time.Duration) {
	t.Helper()
	c.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(d))
	for {
		frame, err := wire.Read(c.conn)
		if err != nil {
			break // deadline or EOF — no deliver arrived
		}
		if frame.Type == pb.FrameType_FRAME_TYPE_DELIVER {
			var del pb.Deliver
			proto.Unmarshal(frame.Payload, &del)
			t.Fatalf("unexpected DELIVER on subject %q", del.Subject)
		}
	}
	c.conn.(*tls.Conn).SetReadDeadline(time.Time{})
}

func (c *testClient) subscribe(t *testing.T, pattern string) {
	t.Helper()
	c.send(pb.FrameType_FRAME_TYPE_SUBSCRIBE, &pb.Subscribe{Subject: pattern})
	time.Sleep(20 * time.Millisecond)
}

func (c *testClient) unsubscribe(t *testing.T, pattern string) {
	t.Helper()
	c.send(pb.FrameType_FRAME_TYPE_UNSUBSCRIBE, &pb.Unsubscribe{Subject: pattern})
	time.Sleep(20 * time.Millisecond)
}

func (c *testClient) publish(t *testing.T, subject string, innerPayload []byte) {
	t.Helper()
	c.send(pb.FrameType_FRAME_TYPE_PUBLISH, &pb.Publish{Subject: subject, Payload: innerPayload})
}

func (c *testClient) expectError(t *testing.T) *pb.Error {
	t.Helper()
	frame := c.expectFrame(t, pb.FrameType_FRAME_TYPE_ERROR)
	var e pb.Error
	proto.Unmarshal(frame.Payload, &e)
	return &e
}

func (c *testClient) expectDeliver(t *testing.T, wantSubject string) []byte {
	t.Helper()
	frame := c.recv(t, 2*time.Second)
	if frame.Type != pb.FrameType_FRAME_TYPE_DELIVER {
		t.Fatalf("expected DELIVER, got %v", frame.Type)
	}
	var d pb.Deliver
	if err := proto.Unmarshal(frame.Payload, &d); err != nil {
		t.Fatalf("unmarshal DELIVER: %v", err)
	}
	if d.Subject != wantSubject {
		t.Fatalf("DELIVER subject: got %q, want %q", d.Subject, wantSubject)
	}
	return d.Payload
}

func (c *testClient) close() { c.conn.Close() }

// allowAll adds wildcard allow rules for a specific pubkey on home.> .
func allowAll(t *testing.T, srv *node.Server, pub ed25519.PublicKey) {
	t.Helper()
	id := acl.EncodeIdentity(pub)
	srv.AddRule(acl.Rule{IdentityPattern: id, Action: acl.ActionPublish, SubjectPattern: "home.>", Effect: acl.Allow, Priority: 10})
	srv.AddRule(acl.Rule{IdentityPattern: id, Action: acl.ActionSubscribe, SubjectPattern: "home.>", Effect: acl.Allow, Priority: 10})
	srv.AddRule(acl.Rule{IdentityPattern: id, Action: acl.ActionSubscribe, SubjectPattern: "lattice.system.>", Effect: acl.Allow, Priority: 10})
}

// payload helpers
func tempReading(value float32) []byte {
	b, _ := proto.Marshal(&pb.TemperatureReading{Value: &value})
	return b
}

func lightCmd(a pb.LightAction) []byte {
	b, _ := proto.Marshal(&pb.LightCommand{Action: &a})
	return b
}

// ─── Sessions 3 + 4 regression tests ─────────────────────────────────────────
// These re-run the core pub/sub and schema tests now that ACL is active.
// Each client needs explicit ACL rules.

func TestExactSubjectDelivery(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()
	sub := connect(t, addr)
	defer sub.close()
	pub := connect(t, addr)
	defer pub.close()
	allowAll(t, srv, sub.pub)
	allowAll(t, srv, pub.pub)

	sub.subscribe(t, "home.sensor.temperature")
	pub.publish(t, "home.sensor.temperature", tempReading(22.5))
	sub.expectDeliver(t, "home.sensor.temperature")
}

func TestWildcardGtDelivery(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()
	sub := connect(t, addr)
	defer sub.close()
	pub := connect(t, addr)
	defer pub.close()
	allowAll(t, srv, sub.pub)
	allowAll(t, srv, pub.pub)

	sub.subscribe(t, "home.>")
	pub.publish(t, "home.sensor.temperature", tempReading(22.5))
	sub.expectDeliver(t, "home.sensor.temperature")
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()
	sub := connect(t, addr)
	defer sub.close()
	pub := connect(t, addr)
	defer pub.close()
	allowAll(t, srv, sub.pub)
	allowAll(t, srv, pub.pub)

	sub.subscribe(t, "home.sensor.temperature")
	sub.unsubscribe(t, "home.sensor.temperature")
	pub.publish(t, "home.sensor.temperature", tempReading(22.5))
	sub.expectNoFrame(t)
}

func TestSchemaRejectionAndRecovery(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()
	sub := connect(t, addr)
	defer sub.close()
	pub := connect(t, addr)
	defer pub.close()
	allowAll(t, srv, sub.pub)
	allowAll(t, srv, pub.pub)

	sub.subscribe(t, "home.sensor.temperature")

	// Bad publish
	bad, _ := proto.Marshal(&pb.TemperatureReading{Value: func() *float32 { v := float32(999); return &v }()})
	pub.publish(t, "home.sensor.temperature", bad)
	pub.expectError(t)
	sub.expectNoFrame(t)

	// Recovery
	pub.publish(t, "home.sensor.temperature", tempReading(22.5))
	sub.expectDeliver(t, "home.sensor.temperature")
}

// ─── Session 5: ACL engine ────────────────────────────────────────────────────

// No allow rule → subscribe denied.
func TestNoRuleDeniesSubscribe(t *testing.T) {
	addr, _, stop := newServer(t, 30)
	defer stop()
	c := connect(t, addr)
	defer c.close()

	c.send(pb.FrameType_FRAME_TYPE_SUBSCRIBE, &pb.Subscribe{Subject: "home.sensor.temperature"})
	e := c.expectError(t)
	if e.Code != "PERMISSION_DENIED" {
		t.Fatalf("expected PERMISSION_DENIED, got %q", e.Code)
	}
}

// No allow rule → publish denied.
func TestNoRuleDeniesPublish(t *testing.T) {
	addr, _, stop := newServer(t, 30)
	defer stop()
	c := connect(t, addr)
	defer c.close()

	c.publish(t, "home.sensor.temperature", tempReading(22.5))
	e := c.expectError(t)
	if e.Code != "PERMISSION_DENIED" {
		t.Fatalf("expected PERMISSION_DENIED, got %q", e.Code)
	}
}

// Allow rule for subscribe only — publish still denied.
func TestSubscribeAllowedPublishDenied(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()
	c := connect(t, addr)
	defer c.close()

	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(c.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})

	c.subscribe(t, "home.sensor.temperature") // should succeed silently

	c.publish(t, "home.sensor.temperature", tempReading(22.5))
	e := c.expectError(t)
	if e.Code != "PERMISSION_DENIED" {
		t.Fatalf("expected PERMISSION_DENIED, got %q", e.Code)
	}
}

// Wildcard identity allow lets any client subscribe to home.>.
func TestWildcardIdentityAllowsSubscribe(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	srv.AddRule(acl.Rule{
		IdentityPattern: "*",
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})

	c1 := connect(t, addr)
	defer c1.close()
	c2 := connect(t, addr)
	defer c2.close()

	// Both clients can subscribe without explicit identity rules.
	c1.send(pb.FrameType_FRAME_TYPE_SUBSCRIBE, &pb.Subscribe{Subject: "home.sensor.temperature"})
	c2.send(pb.FrameType_FRAME_TYPE_SUBSCRIBE, &pb.Subscribe{Subject: "home.light.command"})
	time.Sleep(30 * time.Millisecond)
	// No error frames expected.
	c1.expectNoFrame(t)
	c2.expectNoFrame(t)
}

// Specific deny at higher priority overrides wildcard allow.
func TestDenyOverridesWildcardAllow(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()
	c := connect(t, addr)
	defer c.close()

	// Wildcard allow at priority 10
	srv.AddRule(acl.Rule{
		IdentityPattern: "*",
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	// Specific deny for this client at priority 20
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(c.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Deny,
		Priority:        20,
	})

	c.send(pb.FrameType_FRAME_TYPE_SUBSCRIBE, &pb.Subscribe{Subject: "home.sensor.temperature"})
	e := c.expectError(t)
	if e.Code != "PERMISSION_DENIED" {
		t.Fatalf("expected PERMISSION_DENIED, got %q", e.Code)
	}
}

// ACL-denied publish → schema validation is never reached (subscriber gets nothing).
func TestACLDeniedPublishSkipsSchema(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()
	sub := connect(t, addr)
	defer sub.close()
	pub := connect(t, addr)
	defer pub.close()

	// Give subscriber read access but no publish rule for pub.
	allowAll(t, srv, sub.pub)

	sub.subscribe(t, "home.sensor.temperature")

	// pub has no publish rule — ACL blocks before schema is checked.
	pub.publish(t, "home.sensor.temperature", tempReading(22.5))
	pub.expectError(t)
	sub.expectNoFrame(t) // schema and fanout were never reached
}

// ─── Session 6: Entity registry + system events ───────────────────────────────

// Entity join event delivered within 1 second.
func TestEntityJoinedEvent(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(watcher.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "lattice.system.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	watcher.subscribe(t, "lattice.system.>")

	joiner := connect(t, addr)
	defer joiner.close()

	// The joined event must arrive within 1 second.
	watcher.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(time.Second))
	frame, err := wire.Read(watcher.conn)
	if err != nil {
		t.Fatalf("expected entity.joined event: %v", err)
	}
	if frame.Type != pb.FrameType_FRAME_TYPE_DELIVER {
		t.Fatalf("expected DELIVER, got %v", frame.Type)
	}
	var d pb.Deliver
	proto.Unmarshal(frame.Payload, &d)
	if d.Subject != "lattice.system.entity.joined" {
		t.Fatalf("expected entity.joined, got %q", d.Subject)
	}
	var evt pb.EntityJoined
	proto.Unmarshal(d.Payload, &evt)
	if len(evt.Pubkey) == 0 {
		t.Fatal("EntityJoined.Pubkey is empty")
	}
}

// Graceful disconnect fires entity.left.
func TestEntityLeftEvent(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(watcher.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "lattice.system.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	watcher.subscribe(t, "lattice.system.>")

	leaver := connect(t, addr)
	// Drain the joined event for leaver.
	watcher.recv(t, 2*time.Second)

	leaver.close()

	frame := watcher.recv(t, 2*time.Second)
	if frame.Type != pb.FrameType_FRAME_TYPE_DELIVER {
		t.Fatalf("expected DELIVER, got %v", frame.Type)
	}
	var d pb.Deliver
	proto.Unmarshal(frame.Payload, &d)
	if d.Subject != "lattice.system.entity.left" {
		t.Fatalf("expected entity.left, got %q", d.Subject)
	}
}

// Missed heartbeats → offline event after 3 intervals, not before.
// Uses heartbeatInterval=1s so the test completes in ~5 seconds.
func TestEntityOfflineAfterMissedHeartbeats(t *testing.T) {
	addr, srv, stop := newServer(t, 1) // 1-second heartbeat interval
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(watcher.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "lattice.system.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	watcher.subscribe(t, "lattice.system.>")
	stopHB := watcher.startHeartbeat(500 * time.Millisecond)
	defer stopHB()

	// Silent entity: never sends a heartbeat after connecting.
	silent := connect(t, addr)
	// Drain the joined event.
	watcher.recv(t, 2*time.Second)

	// Keep the connection open but send nothing.
	_ = silent

	// After ~2 s (< 3 intervals): no offline event.
	watcher.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := wire.Read(watcher.conn)
	if err == nil {
		// Should be no event, but if we got one check it's not offline
		var d pb.Deliver
		proto.Unmarshal(frame.Payload, &d)
		if d.Subject == "lattice.system.entity.offline" {
			t.Fatal("entity went offline too early (< 3 intervals)")
		}
	}
	watcher.conn.(*tls.Conn).SetReadDeadline(time.Time{})

	// After 3+ intervals: offline event must arrive.
	watcher.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(6 * time.Second))
	for {
		frame, err := wire.Read(watcher.conn)
		if err != nil {
			t.Fatalf("timed out waiting for entity.offline: %v", err)
		}
		var d pb.Deliver
		proto.Unmarshal(frame.Payload, &d)
		if d.Subject == "lattice.system.entity.offline" {
			var evt pb.EntityOffline
			proto.Unmarshal(d.Payload, &evt)
			if len(evt.Pubkey) == 0 {
				t.Fatal("EntityOffline.Pubkey is empty")
			}
			break
		}
	}
	watcher.conn.(*tls.Conn).SetReadDeadline(time.Time{})
}

// After offline detection: publish to a subject the dead entity was subscribed
// to — no panic, no error, no delivery.
func TestNoDeliveryAfterOffline(t *testing.T) {
	addr, srv, stop := newServer(t, 1)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(watcher.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "lattice.system.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	allowAll(t, srv, watcher.pub)
	watcher.subscribe(t, "lattice.system.>")
	stopHB := watcher.startHeartbeat(500 * time.Millisecond)
	defer stopHB()

	silent := connect(t, addr)
	allowAll(t, srv, silent.pub)
	silent.subscribe(t, "home.sensor.temperature")
	// Watcher's own join fired before its subscription was active; only silent's join is visible.
	watcher.recv(t, 2*time.Second) // silent joined

	// Wait for offline event.
	watcher.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(6 * time.Second))
	for {
		frame, err := wire.Read(watcher.conn)
		if err != nil {
			t.Fatalf("timed out waiting for offline: %v", err)
		}
		var d pb.Deliver
		proto.Unmarshal(frame.Payload, &d)
		if d.Subject == "lattice.system.entity.offline" {
			break
		}
	}
	watcher.conn.(*tls.Conn).SetReadDeadline(time.Time{})

	// Now publish — no DELIVER should arrive (offline entity's subscription was removed).
	watcher.publish(t, "home.sensor.temperature", tempReading(20.0))
	watcher.expectNoDeliver(t, 300*time.Millisecond)
}

// ─── Session 7: Call primitive ────────────────────────────────────────────────

// allowCall adds an ACL rule permitting callerPub to call targetPub.
func allowCall(t *testing.T, srv *node.Server, callerPub, targetPub ed25519.PublicKey) {
	t.Helper()
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(callerPub),
		Action:          acl.ActionCall,
		SubjectPattern:  acl.EncodeIdentity(targetPub),
		Effect:          acl.Allow,
		Priority:        10,
	})
}

// Basic round trip: A calls B, B responds, A receives the response.
func TestCallBasicRoundTrip(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()
	b := connect(t, addr)
	defer b.close()

	allowCall(t, srv, a.pub, b.pub)

	corrID := "round-trip-1"
	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: corrID,
		TargetPubkey:  b.pub,
		Payload:       []byte("ping"),
		TimeoutMs:     5000,
	})

	// B receives the forwarded REQUEST with the original correlation ID.
	frame := b.recv(t, 2*time.Second)
	if frame.Type != pb.FrameType_FRAME_TYPE_REQUEST {
		t.Fatalf("B: expected REQUEST, got %v", frame.Type)
	}
	var req pb.Request
	proto.Unmarshal(frame.Payload, &req)
	if req.CorrelationId != corrID {
		t.Fatalf("B: correlation_id: got %q, want %q", req.CorrelationId, corrID)
	}

	// B sends RESPONSE with the same correlation ID.
	b.send(pb.FrameType_FRAME_TYPE_RESPONSE, &pb.Response{
		CorrelationId: corrID,
		Payload:       []byte("pong"),
	})

	// A receives the forwarded RESPONSE.
	frame = a.recv(t, 2*time.Second)
	if frame.Type != pb.FrameType_FRAME_TYPE_RESPONSE {
		t.Fatalf("A: expected RESPONSE, got %v", frame.Type)
	}
	var resp pb.Response
	proto.Unmarshal(frame.Payload, &resp)
	if resp.CorrelationId != corrID {
		t.Fatalf("A: response correlation_id: got %q, want %q", resp.CorrelationId, corrID)
	}
	if string(resp.Payload) != "pong" {
		t.Fatalf("A: response payload: got %q, want %q", resp.Payload, "pong")
	}
}

// Calling an unknown pubkey → immediate NOT_FOUND error.
func TestCallTargetNotFound(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()

	fakePub, _, _ := ed25519.GenerateKey(rand.Reader)

	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(a.pub),
		Action:          acl.ActionCall,
		SubjectPattern:  "*",
		Effect:          acl.Allow,
		Priority:        10,
	})

	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: "corr-not-found",
		TargetPubkey:  fakePub,
		Payload:       []byte("hello"),
		TimeoutMs:     5000,
	})

	e := a.expectError(t)
	if e.Code != "NOT_FOUND" {
		t.Fatalf("expected NOT_FOUND, got %q", e.Code)
	}
}

// Target exists but never responds → ERROR with code TIMEOUT after timeout_ms.
func TestCallTimeout(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()
	b := connect(t, addr)
	defer b.close()

	allowCall(t, srv, a.pub, b.pub)

	// Short deadline: 100ms. The timeout checker runs every 1s, so the error
	// arrives within ~2s of the send.
	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: "corr-timeout",
		TargetPubkey:  b.pub,
		Payload:       []byte("hello"),
		TimeoutMs:     100,
	})

	// B deliberately does not respond.
	a.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(3 * time.Second))
	frame, err := wire.Read(a.conn)
	if err != nil {
		t.Fatalf("waiting for timeout ERROR: %v", err)
	}
	a.conn.(*tls.Conn).SetReadDeadline(time.Time{})

	if frame.Type != pb.FrameType_FRAME_TYPE_ERROR {
		t.Fatalf("expected ERROR, got %v", frame.Type)
	}
	var e pb.Error
	proto.Unmarshal(frame.Payload, &e)
	if e.Code != "TIMEOUT" {
		t.Fatalf("expected TIMEOUT error code, got %q", e.Code)
	}
}

// Two simultaneous calls from A to B with different correlation IDs complete
// independently.
func TestCallTwoSimultaneous(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()
	b := connect(t, addr)
	defer b.close()

	allowCall(t, srv, a.pub, b.pub)

	corrID1, corrID2 := "sim-1", "sim-2"

	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{CorrelationId: corrID1, TargetPubkey: b.pub, Payload: []byte("req1"), TimeoutMs: 5000})
	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{CorrelationId: corrID2, TargetPubkey: b.pub, Payload: []byte("req2"), TimeoutMs: 5000})

	// B receives both forwarded REQUESTs (collect by correlation ID).
	reqs := make(map[string]bool)
	for range 2 {
		frame := b.recv(t, 2*time.Second)
		if frame.Type != pb.FrameType_FRAME_TYPE_REQUEST {
			t.Fatalf("B: expected REQUEST, got %v", frame.Type)
		}
		var req pb.Request
		proto.Unmarshal(frame.Payload, &req)
		reqs[req.CorrelationId] = true
	}
	if !reqs[corrID1] || !reqs[corrID2] {
		t.Fatalf("B: did not receive both requests; got %v", reqs)
	}

	// B responds to both.
	b.send(pb.FrameType_FRAME_TYPE_RESPONSE, &pb.Response{CorrelationId: corrID1, Payload: []byte("resp1")})
	b.send(pb.FrameType_FRAME_TYPE_RESPONSE, &pb.Response{CorrelationId: corrID2, Payload: []byte("resp2")})

	// A receives both responses; check payloads by correlation ID.
	resps := make(map[string]string)
	for range 2 {
		frame := a.recv(t, 2*time.Second)
		if frame.Type != pb.FrameType_FRAME_TYPE_RESPONSE {
			t.Fatalf("A: expected RESPONSE, got %v", frame.Type)
		}
		var resp pb.Response
		proto.Unmarshal(frame.Payload, &resp)
		resps[resp.CorrelationId] = string(resp.Payload)
	}
	if resps[corrID1] != "resp1" {
		t.Fatalf("corrID1: got %q, want %q", resps[corrID1], "resp1")
	}
	if resps[corrID2] != "resp2" {
		t.Fatalf("corrID2: got %q, want %q", resps[corrID2], "resp2")
	}
}

// Requester disconnects before response arrives — no panic; timeout goroutine
// cleans up the pending entry silently.
func TestCallRequesterDisconnects(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	b := connect(t, addr)
	defer b.close()

	allowCall(t, srv, a.pub, b.pub)

	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: "corr-disco",
		TargetPubkey:  b.pub,
		Payload:       []byte("hello"),
		TimeoutMs:     200,
	})
	a.close() // disconnect before B responds

	// Let the timeout goroutine fire and attempt (and silently fail) to write to A.
	time.Sleep(2 * time.Second)

	// Server must still be functional: B can complete a heartbeat round trip.
	b.mu.Lock()
	wire.Write(b.conn, pb.FrameType_FRAME_TYPE_HEARTBEAT, nil)
	b.mu.Unlock()
	b.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		frame, err := wire.Read(b.conn)
		if err != nil {
			t.Fatalf("server unresponsive after requester disconnect: %v", err)
		}
		if frame.Type == pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK {
			break
		}
		// Skip any forwarded REQUEST that B never consumed.
	}
	b.conn.(*tls.Conn).SetReadDeadline(time.Time{})
}

// ACL deny on call → immediate PERMISSION_DENIED error; REQUEST not forwarded.
func TestCallACLDenied(t *testing.T) {
	addr, _, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()
	b := connect(t, addr)
	defer b.close()

	// No call rule added for A.
	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: "corr-acl",
		TargetPubkey:  b.pub,
		Payload:       []byte("hello"),
		TimeoutMs:     5000,
	})

	e := a.expectError(t)
	if e.Code != "PERMISSION_DENIED" {
		t.Fatalf("expected PERMISSION_DENIED, got %q", e.Code)
	}
}

// ─── Session 1 new tests ──────────────────────────────────────────────────────

// TestHandshakeDeadlineReapsStuckClient: a client that completes TLS but never
// sends HELLO is reaped within ~10 seconds (Decision #17).
func TestHandshakeDeadlineReapsStuckClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping deadline test in -short mode (~10s)")
	}
	addr, _, stop := newServer(t, 30)
	defer stop()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Complete TLS handshake but never send HELLO.
	if err := conn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}

	// Server should close the connection (deadline) within ~10s.
	// We allow 12s to absorb scheduling jitter.
	conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	_, err = wire.Read(conn)
	conn.SetReadDeadline(time.Time{})
	if err == nil {
		t.Fatal("expected connection to be closed by server deadline")
	}
}

// TestTypedCapabilitiesNodeRoundTrip: capabilities declared in HELLO survive
// through DoServer → entity registry → EntityJoined system event (Decision #7).
func TestTypedCapabilitiesNodeRoundTrip(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	// watcher subscribes to system events before the capable client joins.
	watcher := connect(t, addr)
	defer watcher.close()
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(watcher.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "lattice.system.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	watcher.subscribe(t, "lattice.system.>")

	// Connect a client that declares typed capabilities.
	_, joinerPriv, _ := ed25519.GenerateKey(rand.Reader)
	tlsConn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tlsConn.Close()

	caps := []*pb.Capability{{Name: "sensor"}, {Name: "actuator"}}
	if _, err := handshake.DoClient(tlsConn, joinerPriv, nil, caps); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Watcher receives EntityJoined with typed capabilities.
	payload := watcher.expectDeliver(t, "lattice.system.entity.joined")
	var evt pb.EntityJoined
	if err := proto.Unmarshal(payload, &evt); err != nil {
		t.Fatalf("unmarshal EntityJoined: %v", err)
	}
	if len(evt.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities in EntityJoined, got %d", len(evt.Capabilities))
	}
	if evt.Capabilities[0].Name != "sensor" || evt.Capabilities[1].Name != "actuator" {
		t.Fatalf("capability names mismatch: %v", evt.Capabilities)
	}
}

// Two entities join simultaneously → two separate joined events.
func TestTwoEntitiesJoinSimultaneously(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	srv.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(watcher.pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "lattice.system.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	watcher.subscribe(t, "lattice.system.>")

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := connect(t, addr)
			defer c.close()
			time.Sleep(100 * time.Millisecond)
		}()
	}
	wg.Wait()

	// Collect joined events (allow up to 2 seconds total).
	joined := 0
	watcher.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(2 * time.Second))
	for joined < 2 {
		frame, err := wire.Read(watcher.conn)
		if err != nil {
			break
		}
		var d pb.Deliver
		proto.Unmarshal(frame.Payload, &d)
		if d.Subject == "lattice.system.entity.joined" {
			joined++
		}
	}
	if joined < 2 {
		t.Fatalf("expected 2 joined events, got %d", joined)
	}
}

// ─── Session 3: delivery-time ACL (Decision #11) ─────────────────────────────

// TestDeliveryTimeACLBlocksWildcardSubscriber is the core Session 3 regression:
// subscribe-time Allow passes for a broad wildcard pattern, but a higher-priority
// deny on the concrete published subject must silently drop the DELIVER frame.
func TestDeliveryTimeACLBlocksWildcardSubscriber(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	publisher := connect(t, addr)
	defer publisher.close()
	subscriber := connect(t, addr)
	defer subscriber.close()

	pubID := acl.EncodeIdentity(publisher.pub)
	subID := acl.EncodeIdentity(subscriber.pub)

	srv.AddRule(acl.Rule{IdentityPattern: pubID, Action: acl.ActionPublish, SubjectPattern: "home.sensor.temperature", Effect: acl.Allow, Priority: 10})
	// Broad subscribe allow at p10 — subscribe-time check for "home.>" passes.
	srv.AddRule(acl.Rule{IdentityPattern: subID, Action: acl.ActionSubscribe, SubjectPattern: "home.>", Effect: acl.Allow, Priority: 10})
	// High-priority deny for the specific concrete subject — fires at delivery time.
	srv.AddRule(acl.Rule{IdentityPattern: subID, Action: acl.ActionSubscribe, SubjectPattern: "home.sensor.temperature", Effect: acl.Deny, Priority: 100})

	subscriber.subscribe(t, "home.>") // subscribe-time check passes — deny does not match "home.>"

	publisher.publish(t, "home.sensor.temperature", tempReading(22.5))

	// Delivery-time deny must silently drop the frame; no DELIVER arrives.
	subscriber.expectNoDeliver(t, 200*time.Millisecond)
}

// TestSystemEventDeliveryDeny verifies that a high-priority deny on a specific
// system-event subject prevents delivery even when the broader subscription to
// "lattice.system.>" was granted at subscribe time.
func TestSystemEventDeliveryDeny(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()

	watcherID := acl.EncodeIdentity(watcher.pub)
	// Broad allow at p10 — subscribe-time check for "lattice.system.>" passes.
	srv.AddRule(acl.Rule{IdentityPattern: watcherID, Action: acl.ActionSubscribe, SubjectPattern: "lattice.system.>", Effect: acl.Allow, Priority: 10})
	// High-priority deny for entity.joined only — fires at delivery time.
	srv.AddRule(acl.Rule{IdentityPattern: watcherID, Action: acl.ActionSubscribe, SubjectPattern: "lattice.system.entity.joined", Effect: acl.Deny, Priority: 100})

	watcher.subscribe(t, "lattice.system.>") // subscribe-time check passes

	// New connection triggers entity.joined — watcher must not receive it.
	joiner := connect(t, addr)
	defer joiner.close()

	watcher.expectNoDeliver(t, 300*time.Millisecond)
}
