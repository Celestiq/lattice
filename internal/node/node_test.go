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
// tokenTTL overrides the default 5-minute resume-token TTL (useful in tests).
func newServer(t *testing.T, heartbeatInterval uint32, tokenTTL ...time.Duration) (addr string, srv *node.Server, stop func()) {
	t.Helper()
	_, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv = node.New(slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})), serverPriv, heartbeatInterval, tokenTTL...)

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

// ─── Session 4: session lifecycle correctness (Decisions #12, #6, #8) ─────────

// connectWithKey connects and authenticates using the supplied keypair instead
// of generating a fresh one. Used to simulate same-identity reconnects.
func connectWithKey(t *testing.T, addr string, pub ed25519.PublicKey, priv ed25519.PrivateKey) *testClient {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshake.DoClient(conn, priv, nil, nil); err != nil {
		conn.Close()
		t.Fatalf("connectWithKey handshake: %v", err)
	}
	return &testClient{conn: conn, pub: pub, priv: priv}
}

// TestReconnectEvictsOldSession verifies that when the same pubkey reconnects,
// the server closes the old connection and the new session remains fully live.
func TestReconnectEvictsOldSession(t *testing.T) {
	addr, _, stop := newServer(t, 30)
	defer stop()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	c1 := connectWithKey(t, addr, pub, priv)

	// c2 connecting with the same key must evict c1.
	c2 := connectWithKey(t, addr, pub, priv)
	defer c2.close()

	// Give the server time to close c1's connection.
	time.Sleep(50 * time.Millisecond)

	// c2 must still be alive.
	c2.send(pb.FrameType_FRAME_TYPE_HEARTBEAT, nil)
	f := c2.recv(t, time.Second)
	if f.Type != pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK {
		t.Fatalf("c2: expected HEARTBEAT_ACK after reconnect, got %v", f.Type)
	}

	// c1's server-side connection must have been closed by the eviction.
	c1.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := wire.Read(c1.conn)
	if err == nil {
		t.Fatal("c1: expected connection closed by server after eviction, but read succeeded")
	}
	c1.conn.Close()
}

// TestAtLeastOnceJoinOnReconnect verifies that reconnecting the same pubkey
// produces two entity.joined events and zero entity.left events — the eviction
// does not publish a spurious left, and the new session announces itself.
func TestAtLeastOnceJoinOnReconnect(t *testing.T) {
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

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c1 := connectWithKey(t, addr, pub, priv)
	c2 := connectWithKey(t, addr, pub, priv)
	defer c2.close()
	c1.conn.Close()

	// Collect all system events delivered within 1 second.
	joined, left := 0, 0
	watcher.conn.(*tls.Conn).SetReadDeadline(time.Now().Add(time.Second))
	for {
		frame, err := wire.Read(watcher.conn)
		if err != nil {
			break
		}
		if frame.Type != pb.FrameType_FRAME_TYPE_DELIVER {
			continue
		}
		var d pb.Deliver
		proto.Unmarshal(frame.Payload, &d)
		switch d.Subject {
		case "lattice.system.entity.joined":
			joined++
		case "lattice.system.entity.left":
			left++
		}
	}

	if joined < 2 {
		t.Fatalf("expected ≥ 2 entity.joined (c1 + c2 reconnect), got %d", joined)
	}
	if left != 0 {
		t.Fatalf("expected 0 entity.left (eviction suppresses it), got %d", left)
	}
}

// TestResponderVerification verifies that a RESPONSE from an entity that is not
// the intended target is rejected with NOT_AUTHORIZED (Decision #6), and that
// the pending call remains valid so the legitimate target can still respond.
func TestResponderVerification(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()
	b := connect(t, addr)
	defer b.close()
	c := connect(t, addr)
	defer c.close()

	allowCall(t, srv, a.pub, b.pub)

	corrID := "responder-verify"
	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: corrID,
		TargetPubkey:  b.pub,
		Payload:       []byte("ping"),
		TimeoutMs:     5000,
	})

	// B receives the forwarded REQUEST.
	b.expectFrame(t, pb.FrameType_FRAME_TYPE_REQUEST)

	// C (imposter) sends RESPONSE with A's correlation ID — must be rejected.
	c.send(pb.FrameType_FRAME_TYPE_RESPONSE, &pb.Response{
		CorrelationId: corrID,
		Payload:       []byte("spoofed"),
	})
	e := c.expectError(t)
	if e.Code != "NOT_AUTHORIZED" {
		t.Fatalf("expected NOT_AUTHORIZED from imposter, got %q", e.Code)
	}

	// The call must still be pending — B responds legitimately.
	b.send(pb.FrameType_FRAME_TYPE_RESPONSE, &pb.Response{
		CorrelationId: corrID,
		Payload:       []byte("real-pong"),
	})
	frame := a.recv(t, 2*time.Second)
	if frame.Type != pb.FrameType_FRAME_TYPE_RESPONSE {
		t.Fatalf("a: expected RESPONSE from B, got %v", frame.Type)
	}
	var resp pb.Response
	proto.Unmarshal(frame.Payload, &resp)
	if string(resp.Payload) != "real-pong" {
		t.Fatalf("a: response payload: got %q, want %q", resp.Payload, "real-pong")
	}
}

// TestEvictionInvalidatesCalls verifies that pending calls targeting an evicted
// session are cancelled with TARGET_DISCONNECTED (Decision #6 ↔ #12 coupling).
func TestEvictionInvalidatesCalls(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()

	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	b1 := connectWithKey(t, addr, bPub, bPriv)

	allowCall(t, srv, a.pub, bPub)

	corrID := "evict-invalidate"
	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: corrID,
		TargetPubkey:  bPub,
		Payload:       []byte("ping"),
		TimeoutMs:     30000, // long — must not expire before eviction fires
	})

	// Drain b1's REQUEST to confirm the call is registered before eviction.
	b1.expectFrame(t, pb.FrameType_FRAME_TYPE_REQUEST)

	// B reconnects with the same key — evicts b1 and invalidates the pending call.
	b2 := connectWithKey(t, addr, bPub, bPriv)
	defer b2.close()
	b1.conn.Close()

	// A must receive TARGET_DISCONNECTED.
	e := a.expectError(t)
	if e.Code != "TARGET_DISCONNECTED" {
		t.Fatalf("expected TARGET_DISCONNECTED, got %q", e.Code)
	}
}

// TestDisconnectTeardown verifies that a DISCONNECT frame triggers an immediate
// entity.left event, rather than waiting up to 3× heartbeat_interval (Decision #8).
func TestDisconnectTeardown(t *testing.T) {
	addr, srv, stop := newServer(t, 30) // 30-second interval — left would take ~90s without fix
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

	c := connect(t, addr)
	defer c.close()

	// Drain entity.joined for c before testing the disconnect path.
	watcher.recv(t, 2*time.Second)

	// c signals graceful shutdown.
	c.send(pb.FrameType_FRAME_TYPE_DISCONNECT, nil)

	// entity.left must arrive well within the 30-second heartbeat interval.
	frame := watcher.recv(t, 2*time.Second)
	if frame.Type != pb.FrameType_FRAME_TYPE_DELIVER {
		t.Fatalf("expected DELIVER after DISCONNECT, got %v", frame.Type)
	}
	var d pb.Deliver
	proto.Unmarshal(frame.Payload, &d)
	if d.Subject != "lattice.system.entity.left" {
		t.Fatalf("expected entity.left after DISCONNECT, got %q", d.Subject)
	}
}

// ─── Session 5: message provenance & correlation (Decisions #4, #18, #5) ──────

// expectFullDeliver receives a DELIVER frame and returns the full decoded Deliver
// message including provenance fields (id, publisher_identity, published_at, schema_version).
func (c *testClient) expectFullDeliver(t *testing.T, wantSubject string) *pb.Deliver {
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
	return &d
}

// TestMonotonicDeliverID verifies that sequential publishes on the same subject
// produce monotonically increasing IDs starting at 1.
func TestMonotonicDeliverID(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	sub := connect(t, addr)
	defer sub.close()
	pub := connect(t, addr)
	defer pub.close()
	allowAll(t, srv, sub.pub)
	allowAll(t, srv, pub.pub)

	sub.subscribe(t, "home.sensor.temperature")

	for i := range 3 {
		pub.publish(t, "home.sensor.temperature", tempReading(float32(20+i)))
		d := sub.expectFullDeliver(t, "home.sensor.temperature")
		want := uint64(i + 1)
		if d.Id != want {
			t.Fatalf("publish %d: DELIVER.id = %d, want %d", i+1, d.Id, want)
		}
	}
}

// TestPerSubjectIsolation verifies that per-subject counters are independent:
// home.sensor.temperature and home.light.command each start at 1.
func TestPerSubjectIsolation(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	sub := connect(t, addr)
	defer sub.close()
	pub := connect(t, addr)
	defer pub.close()
	id := acl.EncodeIdentity(pub.pub)
	subID := acl.EncodeIdentity(sub.pub)
	srv.AddRule(acl.Rule{IdentityPattern: id, Action: acl.ActionPublish, SubjectPattern: "home.>", Effect: acl.Allow, Priority: 10})
	srv.AddRule(acl.Rule{IdentityPattern: subID, Action: acl.ActionSubscribe, SubjectPattern: "home.>", Effect: acl.Allow, Priority: 10})

	sub.subscribe(t, "home.>")

	pub.publish(t, "home.sensor.temperature", tempReading(20))
	d1 := sub.expectFullDeliver(t, "home.sensor.temperature")

	pub.publish(t, "home.light.command", lightCmd(pb.LightAction_LIGHT_ACTION_ON))
	d2 := sub.expectFullDeliver(t, "home.light.command")

	if d1.Id != 1 {
		t.Fatalf("temperature: DELIVER.id = %d, want 1", d1.Id)
	}
	if d2.Id != 1 {
		t.Fatalf("light.command: DELIVER.id = %d, want 1", d2.Id)
	}
}

// TestPublisherIdentityStamped verifies that Deliver.publisher_identity is
// server-stamped with the actual publisher's base32 pubkey.
func TestPublisherIdentityStamped(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	sub := connect(t, addr)
	defer sub.close()
	pub := connect(t, addr)
	defer pub.close()
	allowAll(t, srv, sub.pub)
	allowAll(t, srv, pub.pub)

	sub.subscribe(t, "home.sensor.temperature")
	pub.publish(t, "home.sensor.temperature", tempReading(22))

	d := sub.expectFullDeliver(t, "home.sensor.temperature")
	want := acl.EncodeIdentity(pub.pub)
	if d.PublisherIdentity != want {
		t.Fatalf("publisher_identity: got %q, want %q", d.PublisherIdentity, want)
	}
}

// TestTimestampPopulated verifies that Deliver.published_at is a non-zero Unix
// millisecond timestamp within the observed send window.
func TestTimestampPopulated(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	sub := connect(t, addr)
	defer sub.close()
	pub := connect(t, addr)
	defer pub.close()
	allowAll(t, srv, sub.pub)
	allowAll(t, srv, pub.pub)

	before := time.Now().UnixMilli()
	sub.subscribe(t, "home.sensor.temperature")
	pub.publish(t, "home.sensor.temperature", tempReading(22))
	d := sub.expectFullDeliver(t, "home.sensor.temperature")
	after := time.Now().UnixMilli()

	if d.PublishedAt < before || d.PublishedAt > after {
		t.Fatalf("published_at %d not in range [%d, %d]", d.PublishedAt, before, after)
	}
}

// TestRequestCallerIdentity verifies that the target receives caller_identity
// and received_at server-stamped onto the forwarded REQUEST (Decision #18).
func TestRequestCallerIdentity(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()
	b := connect(t, addr)
	defer b.close()

	allowCall(t, srv, a.pub, b.pub)

	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: "caller-identity-test",
		TargetPubkey:  b.pub,
		Payload:       []byte("ping"),
		TimeoutMs:     5000,
	})

	frame := b.expectFrame(t, pb.FrameType_FRAME_TYPE_REQUEST)
	var req pb.Request
	proto.Unmarshal(frame.Payload, &req)

	want := acl.EncodeIdentity(a.pub)
	if req.CallerIdentity != want {
		t.Fatalf("caller_identity: got %q, want %q", req.CallerIdentity, want)
	}
	if req.ReceivedAt == 0 {
		t.Fatal("received_at is zero")
	}
}

// TestCallerIdentityNotSpoofable verifies that a client-supplied caller_identity
// is overwritten by the server before forwarding (Decision #18).
func TestCallerIdentityNotSpoofable(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()
	b := connect(t, addr)
	defer b.close()

	allowCall(t, srv, a.pub, b.pub)

	// A supplies a fake caller_identity — server must overwrite it.
	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId:  "spoof-caller",
		TargetPubkey:   b.pub,
		Payload:        []byte("ping"),
		TimeoutMs:      5000,
		CallerIdentity: "FAKEFAKEFAKEFAKE",
	})

	frame := b.expectFrame(t, pb.FrameType_FRAME_TYPE_REQUEST)
	var req pb.Request
	proto.Unmarshal(frame.Payload, &req)

	want := acl.EncodeIdentity(a.pub)
	if req.CallerIdentity != want {
		t.Fatalf("caller_identity not overwritten: got %q, want %q", req.CallerIdentity, want)
	}
}

// TestErrorRefID verifies that Error.ref_id echoes the Publish.message_id when
// a publish fails (Decision #5).
func TestErrorRefID(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	pub := connect(t, addr)
	defer pub.close()
	allowAll(t, srv, pub.pub)

	msgID := "my-message-123"
	bad, _ := proto.Marshal(&pb.TemperatureReading{Value: func() *float32 { v := float32(999); return &v }()})
	pub.send(pb.FrameType_FRAME_TYPE_PUBLISH, &pb.Publish{
		Subject:   "home.sensor.temperature",
		Payload:   bad,
		MessageId: msgID,
	})

	e := pub.expectError(t)
	if e.Code != "SCHEMA_ERROR" {
		t.Fatalf("expected SCHEMA_ERROR, got %q", e.Code)
	}
	if e.RefId != msgID {
		t.Fatalf("Error.ref_id: got %q, want %q", e.RefId, msgID)
	}
}

// TestTimeoutErrorRefID verifies that Error.ref_id echoes the correlation_id
// when a call times out (Decision #5).
func TestTimeoutErrorRefID(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	a := connect(t, addr)
	defer a.close()
	b := connect(t, addr)
	defer b.close()

	allowCall(t, srv, a.pub, b.pub)

	corrID := "timeout-ref-test"
	a.send(pb.FrameType_FRAME_TYPE_REQUEST, &pb.Request{
		CorrelationId: corrID,
		TargetPubkey:  b.pub,
		Payload:       []byte("hello"),
		TimeoutMs:     100,
	})

	// B does not respond — wait for timeout ERROR.
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
		t.Fatalf("expected TIMEOUT, got %q", e.Code)
	}
	if e.RefId != corrID {
		t.Fatalf("Error.ref_id: got %q, want %q", e.RefId, corrID)
	}
}

// ─── Session 6: token-based session resume (Decision #2) ─────────────────────

// connectResume dials addr with a specific keypair and optional resume token.
// It returns the testClient and the ClientSession (which carries the new token).
func connectResume(t *testing.T, addr string, pub ed25519.PublicKey, priv ed25519.PrivateKey, token []byte) (*testClient, *handshake.ClientSession) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := handshake.DoClient(conn, priv, nil, nil, token)
	if err != nil {
		conn.Close()
		t.Fatalf("connectResume: %v", err)
	}
	return &testClient{conn: conn, pub: pub, priv: priv}, cs
}

// dialAndSendCraftedHello dials addr, completes TLS, sends hello directly (bypassing
// DoClient), and returns the first frame the server sends back. Used to test
// bad-signature paths without going through the full client handshake.
func dialAndSendCraftedHello(t *testing.T, addr string, hello *pb.Hello) *wire.Frame {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload, _ := proto.Marshal(hello)
	if err := wire.Write(conn, pb.FrameType_FRAME_TYPE_HELLO, payload); err != nil {
		t.Fatalf("dialAndSendCraftedHello write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := wire.Read(conn)
	if err != nil {
		t.Fatalf("dialAndSendCraftedHello read: %v", err)
	}
	return frame
}

// TestResumeRestoresSubscriptions verifies that a token-based resume restores
// subscriptions without firing entity.joined (Decision #2).
func TestResumeRestoresSubscriptions(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	allowAll(t, srv, watcher.pub)
	watcher.subscribe(t, "lattice.system.>")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	allowAll(t, srv, pub)

	// E connects, subscribes, then disconnects cleanly.
	e1, cs1 := connectResume(t, addr, pub, priv, nil)
	watcher.expectDeliver(t, "lattice.system.entity.joined")
	e1.subscribe(t, "home.sensor.temperature")
	token := cs1.SessionToken
	e1.close()
	watcher.expectDeliver(t, "lattice.system.entity.left")
	time.Sleep(50 * time.Millisecond) // ensure teardownSession saved the token

	// E resumes — no entity.joined should fire.
	e2, _ := connectResume(t, addr, pub, priv, token)
	defer e2.close()
	watcher.expectNoDeliver(t, 300*time.Millisecond)

	// Subscription was restored: a publisher's message reaches E2.
	publisher := connect(t, addr)
	defer publisher.close()
	allowAll(t, srv, publisher.pub)
	publisher.publish(t, "home.sensor.temperature", tempReading(21.0))
	e2.expectDeliver(t, "home.sensor.temperature")
}

// TestTokenRotationPreventsReuse verifies that a consumed token cannot be
// used a second time (Decision #2).
func TestTokenRotationPreventsReuse(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	allowAll(t, srv, watcher.pub)
	watcher.subscribe(t, "lattice.system.>")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	allowAll(t, srv, pub)

	// First connect → get T1.
	e1, cs1 := connectResume(t, addr, pub, priv, nil)
	watcher.expectDeliver(t, "lattice.system.entity.joined")
	t1 := cs1.SessionToken
	e1.close()
	watcher.expectDeliver(t, "lattice.system.entity.left")
	time.Sleep(50 * time.Millisecond)

	// Second connect with T1 → resume (T1 consumed, T2 issued).
	e2, _ := connectResume(t, addr, pub, priv, t1)
	watcher.expectNoDeliver(t, 200*time.Millisecond) // resume: no entity.joined
	e2.close()
	watcher.expectDeliver(t, "lattice.system.entity.left")
	time.Sleep(50 * time.Millisecond)

	// Third connect with T1 again (already consumed) → full registration.
	e3, _ := connectResume(t, addr, pub, priv, t1)
	defer e3.close()
	watcher.expectDeliver(t, "lattice.system.entity.joined")
}

// TestResumeRequiresCorrectSignature verifies that a zero/invalid signature is
// rejected before the token is looked up, so the token remains unconsumed
// (Decision #2).
func TestResumeRequiresCorrectSignature(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	allowAll(t, srv, watcher.pub)
	watcher.subscribe(t, "lattice.system.>")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	allowAll(t, srv, pub)

	e1, cs1 := connectResume(t, addr, pub, priv, nil)
	watcher.expectDeliver(t, "lattice.system.entity.joined")
	token := cs1.SessionToken
	e1.close()
	watcher.expectDeliver(t, "lattice.system.entity.left")
	time.Sleep(50 * time.Millisecond)

	// Zero signature + valid token → INVALID_SIGNATURE; token NOT consumed.
	frame := dialAndSendCraftedHello(t, addr, &pb.Hello{
		Pubkey:          pub,
		Signature:       make([]byte, 64), // zeroed — invalid
		ProtocolVersion: handshake.ProtocolVersion,
		ResumeToken:     token,
	})
	if frame.Type != pb.FrameType_FRAME_TYPE_ERROR {
		t.Fatalf("expected ERROR, got %v", frame.Type)
	}
	var sigErr pb.Error
	proto.Unmarshal(frame.Payload, &sigErr)
	if sigErr.Code != "INVALID_SIGNATURE" {
		t.Fatalf("expected INVALID_SIGNATURE, got %q", sigErr.Code)
	}

	// Token is still valid — correct reconnect must succeed as a resume.
	e2, _ := connectResume(t, addr, pub, priv, token)
	defer e2.close()
	watcher.expectNoDeliver(t, 200*time.Millisecond) // resume: no entity.joined
}

// TestResumeTokenPubkeyMismatch verifies that a token issued for key A cannot
// be used to resume as key B (Decision #2).
func TestResumeTokenPubkeyMismatch(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	allowAll(t, srv, watcher.pub)
	watcher.subscribe(t, "lattice.system.>")

	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	allowAll(t, srv, pubA)
	allowAll(t, srv, pubB)

	// A connects, gets T_A, disconnects.
	eA, csA := connectResume(t, addr, pubA, privA, nil)
	watcher.expectDeliver(t, "lattice.system.entity.joined")
	tokenA := csA.SessionToken
	eA.close()
	watcher.expectDeliver(t, "lattice.system.entity.left")
	time.Sleep(50 * time.Millisecond)

	// B presents T_A → pubkey mismatch → full registration as B.
	eB, _ := connectResume(t, addr, pubB, privB, tokenA)
	defer eB.close()
	payload := watcher.expectDeliver(t, "lattice.system.entity.joined")
	var joined pb.EntityJoined
	proto.Unmarshal(payload, &joined)
	if acl.EncodeIdentity(joined.Pubkey) != acl.EncodeIdentity(pubB) {
		t.Fatalf("entity.joined is not for B — pubkey mismatch should have triggered full registration")
	}
}

// TestExpiredTokenFallsBack verifies that a token past its TTL causes a full
// registration rather than a resume (Decision #2).
func TestExpiredTokenFallsBack(t *testing.T) {
	addr, srv, stop := newServer(t, 30, 10*time.Millisecond) // very short TTL
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	allowAll(t, srv, watcher.pub)
	watcher.subscribe(t, "lattice.system.>")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	allowAll(t, srv, pub)

	e1, cs1 := connectResume(t, addr, pub, priv, nil)
	watcher.expectDeliver(t, "lattice.system.entity.joined")
	token := cs1.SessionToken
	e1.close()
	watcher.expectDeliver(t, "lattice.system.entity.left")

	// Wait for the token to expire.
	time.Sleep(50 * time.Millisecond)

	// Expired token → full registration.
	e2, _ := connectResume(t, addr, pub, priv, token)
	defer e2.close()
	watcher.expectDeliver(t, "lattice.system.entity.joined")
}

// TestFreshConnectWithoutTokenUnchanged verifies that the existing full-registration
// path is not affected by the resume feature (regression).
func TestFreshConnectWithoutTokenUnchanged(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	watcher := connect(t, addr)
	defer watcher.close()
	allowAll(t, srv, watcher.pub)
	watcher.subscribe(t, "lattice.system.>")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	allowAll(t, srv, pub)

	// Fresh connect without any token → normal registration.
	e, _ := connectResume(t, addr, pub, priv, nil)
	defer e.close()
	watcher.expectDeliver(t, "lattice.system.entity.joined")

	// Subscribe and receive normally.
	e.subscribe(t, "home.sensor.temperature")
	publisher := connect(t, addr)
	defer publisher.close()
	allowAll(t, srv, publisher.pub)
	watcher.expectDeliver(t, "lattice.system.entity.joined") // publisher joined
	publisher.publish(t, "home.sensor.temperature", tempReading(20.0))
	e.expectDeliver(t, "home.sensor.temperature")
}

// TestDurableReplayHookNoOp verifies that the durable-replay stub is invoked
// during a resume and leaves the connection fully functional (Decision #2,
// v0.1.1 stub).
func TestDurableReplayHookNoOp(t *testing.T) {
	addr, srv, stop := newServer(t, 30)
	defer stop()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	allowAll(t, srv, pub)

	e1, cs1 := connectResume(t, addr, pub, priv, nil)
	e1.subscribe(t, "home.sensor.temperature")
	token := cs1.SessionToken
	e1.close()
	time.Sleep(50 * time.Millisecond)

	// Resume — durableReplayHook runs as a no-op; connection must still work.
	e2, _ := connectResume(t, addr, pub, priv, token)
	defer e2.close()

	publisher := connect(t, addr)
	defer publisher.close()
	allowAll(t, srv, publisher.pub)
	publisher.publish(t, "home.sensor.temperature", tempReading(19.0))
	e2.expectDeliver(t, "home.sensor.temperature")
}
