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

	"lattice/internal/handshake"
	"lattice/internal/node"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// ─── Test infrastructure ─────────────────────────────────────────────────────

func newServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	_, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := node.New(slog.Default(), serverPriv, 30)

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
	return ln.Addr().String(), func() { ln.Close() }
}

// testClient wraps a connected+authenticated TLS connection.
type testClient struct {
	conn *tls.Conn
	mu   sync.Mutex
}

func connect(t *testing.T, addr string) *testClient {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshake.DoClient(conn, priv); err != nil {
		conn.Close()
		t.Fatalf("handshake: %v", err)
	}
	return &testClient{conn: conn}
}

func (c *testClient) send(ft pb.FrameType, msg proto.Message) error {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return wire.Write(c.conn, ft, payload)
}

func (c *testClient) recv(t *testing.T) *wire.Frame {
	t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := wire.Read(c.conn)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return frame
}

func (c *testClient) close() { c.conn.Close() }

// subscribe sends SUBSCRIBE and waits briefly for the server to register it.
func (c *testClient) subscribe(t *testing.T, pattern string) {
	t.Helper()
	if err := c.send(pb.FrameType_FRAME_TYPE_SUBSCRIBE, &pb.Subscribe{Subject: pattern}); err != nil {
		t.Fatalf("subscribe %q: %v", pattern, err)
	}
	time.Sleep(20 * time.Millisecond) // ensure server processes before publish
}

func (c *testClient) unsubscribe(t *testing.T, pattern string) {
	t.Helper()
	if err := c.send(pb.FrameType_FRAME_TYPE_UNSUBSCRIBE, &pb.Unsubscribe{Subject: pattern}); err != nil {
		t.Fatalf("unsubscribe %q: %v", pattern, err)
	}
	time.Sleep(20 * time.Millisecond)
}

// publish sends a PUBLISH frame with a pre-marshalled inner payload.
func (c *testClient) publish(t *testing.T, subject string, innerPayload []byte) {
	t.Helper()
	if err := c.send(pb.FrameType_FRAME_TYPE_PUBLISH, &pb.Publish{Subject: subject, Payload: innerPayload}); err != nil {
		t.Fatalf("publish to %q: %v", subject, err)
	}
}

// expectError reads the next frame and asserts it is ERROR.
func (c *testClient) expectError(t *testing.T) *pb.Error {
	t.Helper()
	frame := c.recv(t)
	if frame.Type != pb.FrameType_FRAME_TYPE_ERROR {
		t.Fatalf("expected ERROR, got %v", frame.Type)
	}
	var e pb.Error
	proto.Unmarshal(frame.Payload, &e)
	return &e
}

// expectDeliver reads the next frame and asserts it is DELIVER, returning the inner payload.
func (c *testClient) expectDeliver(t *testing.T, wantSubject string) []byte {
	t.Helper()
	frame := c.recv(t)
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

// expectNoFrame asserts no frame arrives within 200 ms.
func (c *testClient) expectNoFrame(t *testing.T) {
	t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	frame, err := wire.Read(c.conn)
	if err == nil {
		t.Fatalf("expected no frame but got %v", frame.Type)
	}
	c.conn.SetReadDeadline(time.Time{}) // clear deadline
}

// ─── payload helpers ─────────────────────────────────────────────────────────

func tempReading(value float32, unit string) []byte {
	b, _ := proto.Marshal(&pb.TemperatureReading{Value: &value, Unit: &unit})
	return b
}

func lightCmd(a pb.LightAction, brightness float32) []byte {
	b, _ := proto.Marshal(&pb.LightCommand{Action: &a, Brightness: &brightness})
	return b
}

func connOf(conn net.Conn) *tls.Conn { return conn.(*tls.Conn) }

// ─── Session 3: Channel primitive ────────────────────────────────────────────

// Exact subject subscription + delivery.
func TestExactSubjectDelivery(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	subscriber := connect(t, addr)
	defer subscriber.close()
	publisher := connect(t, addr)
	defer publisher.close()

	subscriber.subscribe(t, "home.sensor.temperature")
	publisher.publish(t, "home.sensor.temperature", tempReading(22.5, "celsius"))

	subscriber.expectDeliver(t, "home.sensor.temperature")
}

// Wildcard > subscription matches multiple segments.
func TestWildcardGtDelivery(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	subscriber := connect(t, addr)
	defer subscriber.close()
	publisher := connect(t, addr)
	defer publisher.close()

	subscriber.subscribe(t, "home.>")
	publisher.publish(t, "home.sensor.temperature", tempReading(22.5, "celsius"))

	subscriber.expectDeliver(t, "home.sensor.temperature")
}

// Wildcard * subscription matches one segment.
func TestWildcardStarDelivery(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	subscriber := connect(t, addr)
	defer subscriber.close()
	publisher := connect(t, addr)
	defer publisher.close()

	// home.*.temperature should match home.sensor.temperature
	subscriber.subscribe(t, "home.*.temperature")

	// home.light.command has a different last segment, must not be delivered
	// (use it to verify no spurious delivery)
	publisher.publish(t, "home.light.command", lightCmd(pb.LightAction_LIGHT_ACTION_ON, 0.5))
	subscriber.expectNoFrame(t)

	// home.sensor.temperature should match
	publisher.publish(t, "home.sensor.temperature", tempReading(22.5, "celsius"))
	subscriber.expectDeliver(t, "home.sensor.temperature")
}

// Unsubscribe stops delivery.
func TestUnsubscribeStopsDelivery(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	subscriber := connect(t, addr)
	defer subscriber.close()
	publisher := connect(t, addr)
	defer publisher.close()

	subscriber.subscribe(t, "home.sensor.temperature")
	subscriber.unsubscribe(t, "home.sensor.temperature")

	publisher.publish(t, "home.sensor.temperature", tempReading(22.5, "celsius"))
	subscriber.expectNoFrame(t)
}

// Disconnect removes subscriptions — no delivery attempt to dead connection.
func TestDisconnectRemovesSubscriptions(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	subscriber := connect(t, addr)
	publisher := connect(t, addr)
	defer publisher.close()

	subscriber.subscribe(t, "home.sensor.temperature")
	subscriber.close()
	time.Sleep(50 * time.Millisecond) // let server detect the close

	// publish should succeed without error (no delivery attempt to dead conn)
	publisher.publish(t, "home.sensor.temperature", tempReading(22.5, "celsius"))
}

// Invalid pattern in SUBSCRIBE returns ERROR.
func TestSubscribeInvalidPatternReturnsError(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	c := connect(t, addr)
	defer c.close()

	// > in non-terminal position
	c.send(pb.FrameType_FRAME_TYPE_SUBSCRIBE, &pb.Subscribe{Subject: "home.>.temperature"})
	c.expectError(t)
}

// Publish with wildcard in subject returns ERROR.
func TestPublishWildcardSubjectReturnsError(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	c := connect(t, addr)
	defer c.close()

	c.send(pb.FrameType_FRAME_TYPE_PUBLISH, &pb.Publish{Subject: "home.*.temperature", Payload: tempReading(22.5, "celsius")})
	c.expectError(t)
}

// Publish to reserved namespace returns ERROR.
func TestPublishSystemNamespaceReturnsError(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	c := connect(t, addr)
	defer c.close()

	c.send(pb.FrameType_FRAME_TYPE_PUBLISH, &pb.Publish{Subject: "lattice.system.entity.joined", Payload: []byte{}})
	c.expectError(t)
}

// ─── Session 4: Schema validation ────────────────────────────────────────────

// Valid temperature publish is delivered.
func TestValidTemperatureDelivered(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	subscriber := connect(t, addr)
	defer subscriber.close()
	publisher := connect(t, addr)
	defer publisher.close()

	subscriber.subscribe(t, "home.sensor.temperature")
	publisher.publish(t, "home.sensor.temperature", tempReading(22.5, "celsius"))
	subscriber.expectDeliver(t, "home.sensor.temperature")
}

// Out-of-range value returns ERROR to publisher; subscriber receives nothing.
func TestTemperatureOutOfRangeRejected(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	subscriber := connect(t, addr)
	defer subscriber.close()
	publisher := connect(t, addr)
	defer publisher.close()

	subscriber.subscribe(t, "home.sensor.temperature")

	badPayload, _ := proto.Marshal(&pb.TemperatureReading{Value: func() *float32 { v := float32(200.0); return &v }()})
	publisher.publish(t, "home.sensor.temperature", badPayload)

	publisher.expectError(t)        // publisher gets ERROR
	subscriber.expectNoFrame(t)     // subscriber receives nothing
}

// Missing required field returns ERROR.
func TestTemperatureMissingFieldRejected(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	c := connect(t, addr)
	defer c.close()

	emptyPayload, _ := proto.Marshal(&pb.TemperatureReading{})
	c.publish(t, "home.sensor.temperature", emptyPayload)
	c.expectError(t)
}

// Unknown subject (no schema registered) returns ERROR.
func TestPublishUnknownSubjectRejected(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	c := connect(t, addr)
	defer c.close()

	c.publish(t, "home.sensor.humidity", []byte{})
	c.expectError(t)
}

// Two consecutive valid publishes after a rejection — both delivered.
func TestValidPublishAfterRejectionDelivered(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	subscriber := connect(t, addr)
	defer subscriber.close()
	publisher := connect(t, addr)
	defer publisher.close()

	subscriber.subscribe(t, "home.sensor.temperature")

	// Bad publish — not delivered.
	badPayload, _ := proto.Marshal(&pb.TemperatureReading{Value: func() *float32 { v := float32(999.0); return &v }()})
	publisher.publish(t, "home.sensor.temperature", badPayload)
	publisher.expectError(t)

	// Two good publishes — both delivered.
	for i := 0; i < 2; i++ {
		publisher.publish(t, "home.sensor.temperature", tempReading(20.0+float32(i), "c"))
		subscriber.expectDeliver(t, "home.sensor.temperature")
	}
}

// Invalid enum value in LightCommand returns ERROR.
func TestLightCommandInvalidEnumRejected(t *testing.T) {
	addr, stop := newServer(t)
	defer stop()

	c := connect(t, addr)
	defer c.close()

	badPayload, _ := proto.Marshal(&pb.LightCommand{Action: func() *pb.LightAction {
		a := pb.LightAction_LIGHT_ACTION_UNSPECIFIED; return &a
	}()})
	c.publish(t, "home.light.command", badPayload)
	c.expectError(t)
}
