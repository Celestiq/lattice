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
	if _, err := handshake.DoClient(conn, priv); err != nil {
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
	for i := 0; i < 2; i++ {
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
