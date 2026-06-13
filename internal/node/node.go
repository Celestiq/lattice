// Package node implements the Lattice server connection handler.
package node

import (
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/acl"
	"lattice/internal/bus"
	"lattice/internal/call"
	"lattice/internal/handshake"
	"lattice/internal/registry"
	"lattice/internal/schema"
	"lattice/internal/session"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// Server handles all Lattice connections. It owns every piece of shared state.
type Server struct {
	log               *slog.Logger
	sessions          *session.Table
	bus               *bus.Bus
	acl               *acl.Engine
	registry          *registry.Registry
	calls             *call.Registry
	serverPriv        ed25519.PrivateKey
	serverPub         ed25519.PublicKey
	heartbeatInterval uint32 // seconds
	conns             sync.Map   // sessionID → *lockedConn
	wg                sync.WaitGroup
	stopOnce          sync.Once
	done              chan struct{}
}

// New creates a Server and starts the background heartbeat checker.
// Default ACL rule: server identity is allowed to do everything.
func New(log *slog.Logger, serverPriv ed25519.PrivateKey, heartbeatInterval uint32) *Server {
	serverPub := serverPriv.Public().(ed25519.PublicKey)
	engine := acl.New()
	// Server identity can always publish and subscribe to any subject.
	engine.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(serverPub),
		Action:          acl.ActionPublish,
		SubjectPattern:  ">",
		Effect:          acl.Allow,
		Priority:        1000,
	})
	engine.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(serverPub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  ">",
		Effect:          acl.Allow,
		Priority:        1000,
	})

	s := &Server{
		log:               log,
		sessions:          session.NewTable(),
		bus:               bus.New(),
		acl:               engine,
		registry:          registry.New(),
		calls:             call.New(),
		serverPriv:        serverPriv,
		serverPub:         serverPub,
		heartbeatInterval: heartbeatInterval,
		done:              make(chan struct{}),
	}
	s.wg.Add(2)
	go s.runHeartbeatChecker()
	go s.runCallTimeoutChecker()
	return s
}

// AddRule inserts an ACL rule. Used by tests and future admin API.
func (s *Server) AddRule(r acl.Rule) {
	s.acl.AddRule(r)
}

// ─── Connection handling ──────────────────────────────────────────────────────

// lockedConn serialises concurrent writes to one connection.
type lockedConn struct {
	mu   sync.Mutex
	conn net.Conn
}

func (lc *lockedConn) writeFrame(ft pb.FrameType, payload []byte) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return wire.Write(lc.conn, ft, payload)
}

// Shutdown gracefully stops the server. It publishes entity.left for every
// connected entity, closes all connections, and waits for all goroutines to
// exit. Safe to call once; subsequent calls are no-ops.
func (s *Server) Shutdown() {
	s.stopOnce.Do(func() { close(s.done) })

	// Publish entity.left for all connected entities while their connections are
	// still open, so observers subscribed to lattice.system.> can receive it.
	for _, ent := range s.registry.All() {
		if s.registry.Remove(ent.Pubkey) == nil {
			continue // concurrent disconnect already handled it
		}
		payload, _ := proto.Marshal(&pb.EntityLeft{
			Pubkey:    ent.Pubkey,
			SessionId: ent.SessionID,
		})
		s.publishSystemEvent("lattice.system.entity.left", payload)
	}

	// Close all connections so HandleConn goroutines see EOF and exit.
	// HandleConn defers get nil from registry.Remove (already removed above)
	// and skip the entity.left publish.
	s.conns.Range(func(_, value any) bool {
		value.(*lockedConn).conn.Close()
		return true
	})

	s.wg.Wait()
}

// HandleConn runs the full lifecycle for one accepted connection.
func (s *Server) HandleConn(conn net.Conn) {
	s.wg.Add(1)
	defer s.wg.Done()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return
	}
	remote := conn.RemoteAddr().String()
	s.log.Info("client connected", "remote", remote)

	// Deadline prevents a client that completes TLS but never sends HELLO from
	// holding a goroutine indefinitely (Decision #17).
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	rec, err := handshake.DoServer(tlsConn, s.serverPriv, s.sessions, s.heartbeatInterval)
	if err != nil {
		s.log.Warn("handshake failed", "remote", remote, "err", err)
		conn.Close()
		return
	}
	tlsConn.SetDeadline(time.Time{})
	s.log.Info("entity authenticated", "remote", remote, "session_id", rec.ID)

	lc := &lockedConn{conn: conn}
	s.conns.Store(rec.ID, lc)

	// Register entity and announce it.
	s.registry.Register(rec.ID, rec.Pubkey, rec.Capabilities)
	s.publishEntityJoined(rec)

	// Cleanup: ordered to prevent fanout to dead connections.
	defer func() {
		// Remove from registry — returns nil if heartbeat checker already removed it.
		if ent := s.registry.Remove(rec.Pubkey); ent != nil {
			// Normal (graceful) disconnect path.
			s.bus.RemoveSession(rec.ID)
			s.conns.Delete(rec.ID)
			s.sessions.Remove(rec.ID)
			s.publishEntityLeft(rec)
		}
		conn.Close()
		s.log.Info("client disconnected", "remote", remote, "session_id", rec.ID)
	}()

	for {
		frame, err := wire.Read(conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return
			}
			if errors.Is(err, wire.ErrPayloadTooLarge) {
				s.log.Warn("payload too large, closing", "remote", remote)
				return
			}
			return
		}

		switch frame.Type {
		case pb.FrameType_FRAME_TYPE_HEARTBEAT:
			s.registry.UpdateHeartbeat(rec.Pubkey)
			if err := lc.writeFrame(pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK, nil); err != nil {
				return
			}

		case pb.FrameType_FRAME_TYPE_SUBSCRIBE:
			s.handleSubscribe(lc, rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_UNSUBSCRIBE:
			s.handleUnsubscribe(rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_PUBLISH:
			s.handlePublish(lc, rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_REQUEST:
			s.handleRequest(lc, rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_RESPONSE:
			s.handleResponse(lc, rec, frame.Payload)

		default:
			s.log.Warn("unhandled frame", "remote", remote, "type", frame.Type)
		}
	}
}

// ─── Frame handlers ───────────────────────────────────────────────────────────

func (s *Server) handleSubscribe(lc *lockedConn, rec *session.Record, payload []byte) {
	var msg pb.Subscribe
	if err := proto.Unmarshal(payload, &msg); err != nil {
		s.sendError(lc, "INVALID_PAYLOAD", "cannot unmarshal SUBSCRIBE")
		return
	}
	// ACL check before touching the registry.
	if !s.acl.Allow(rec.Pubkey, acl.ActionSubscribe, msg.Subject) {
		s.sendError(lc, "PERMISSION_DENIED", "subscribe denied by ACL")
		return
	}
	if err := s.bus.Subscribe(rec.ID, msg.Subject); err != nil {
		s.sendError(lc, "INVALID_SUBJECT", err.Error())
		return
	}
	s.log.Debug("subscribed", "session_id", rec.ID, "pattern", msg.Subject)
}

func (s *Server) handleUnsubscribe(rec *session.Record, payload []byte) {
	var msg pb.Unsubscribe
	if err := proto.Unmarshal(payload, &msg); err != nil {
		return
	}
	s.bus.Unsubscribe(rec.ID, msg.Subject)
	s.log.Debug("unsubscribed", "session_id", rec.ID, "pattern", msg.Subject)
}

func (s *Server) handlePublish(lc *lockedConn, rec *session.Record, payload []byte) {
	var msg pb.Publish
	if err := proto.Unmarshal(payload, &msg); err != nil {
		s.sendError(lc, "INVALID_PAYLOAD", "cannot unmarshal PUBLISH")
		return
	}

	// Reject wildcards and the reserved namespace before touching ACL.
	if err := bus.ValidateSubject(msg.Subject); err != nil {
		s.sendError(lc, "INVALID_SUBJECT", err.Error())
		return
	}

	// ACL check: session exists → ACL → schema → fan-out.
	if !s.acl.Allow(rec.Pubkey, acl.ActionPublish, msg.Subject) {
		s.log.Debug("publish denied by ACL", "session_id", rec.ID, "subject", msg.Subject)
		s.sendError(lc, "PERMISSION_DENIED", "publish denied by ACL")
		return
	}

	// Schema validation.
	if err := schema.Validate(msg.Subject, msg.Payload); err != nil {
		s.sendError(lc, "SCHEMA_ERROR", err.Error())
		return
	}

	// Fan-out.
	s.fanout(msg.Subject, msg.Payload)
}

func (s *Server) handleRequest(lc *lockedConn, rec *session.Record, payload []byte) {
	var req pb.Request
	if err := proto.Unmarshal(payload, &req); err != nil {
		s.sendError(lc, "INVALID_PAYLOAD", "cannot unmarshal REQUEST")
		return
	}
	if len(req.TargetPubkey) != ed25519.PublicKeySize {
		s.sendError(lc, "INVALID_PUBKEY", "target_pubkey must be 32 bytes")
		return
	}

	// ACL check: (caller, "call", base32(target_pubkey)).
	// SubjectPattern in call rules holds the target identity or "*" / ">".
	targetIdentity := acl.EncodeIdentity(req.TargetPubkey)
	if !s.acl.Allow(rec.Pubkey, acl.ActionCall, targetIdentity) {
		s.sendError(lc, "PERMISSION_DENIED", "call denied by ACL")
		return
	}

	// Target must be present in the entity registry.
	targetEnt := s.registry.Get(req.TargetPubkey)
	if targetEnt == nil {
		s.sendError(lc, "NOT_FOUND", "target entity not connected")
		return
	}
	v, ok := s.conns.Load(targetEnt.SessionID)
	if !ok {
		s.sendError(lc, "NOT_FOUND", "target entity not connected")
		return
	}
	targetLc := v.(*lockedConn)

	timeoutMs := req.TimeoutMs
	if timeoutMs == 0 {
		timeoutMs = 5000
	}
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)

	// Register before forwarding to prevent a race where the target responds
	// before the pending entry exists.
	s.calls.Add(req.CorrelationId, rec.ID, deadline)

	if err := targetLc.writeFrame(pb.FrameType_FRAME_TYPE_REQUEST, payload); err != nil {
		s.calls.Remove(req.CorrelationId)
		s.sendError(lc, "DELIVERY_FAILED", "could not forward request to target")
	}
}

func (s *Server) handleResponse(lc *lockedConn, rec *session.Record, payload []byte) {
	var resp pb.Response
	if err := proto.Unmarshal(payload, &resp); err != nil {
		s.sendError(lc, "INVALID_PAYLOAD", "cannot unmarshal RESPONSE")
		return
	}

	pending := s.calls.Remove(resp.CorrelationId)
	if pending == nil {
		s.sendError(lc, "NOT_FOUND", "unknown or expired correlation_id")
		return
	}

	v, ok := s.conns.Load(pending.RequesterSessionID)
	if !ok {
		return // requester disconnected; silently drop
	}
	_ = v.(*lockedConn).writeFrame(pb.FrameType_FRAME_TYPE_RESPONSE, payload)
}

// ─── Call timeout checker ─────────────────────────────────────────────────────

// runCallTimeoutChecker ticks every second and sends ERROR to requesters whose
// calls have exceeded their deadline.
func (s *Server) runCallTimeoutChecker() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			for _, exp := range s.calls.Expired(time.Now()) {
				if v, ok := s.conns.Load(exp.RequesterSessionID); ok {
					payload, _ := proto.Marshal(&pb.Error{Code: "TIMEOUT", Message: "call timed out"})
					_ = v.(*lockedConn).writeFrame(pb.FrameType_FRAME_TYPE_ERROR, payload)
				}
			}
		case <-s.done:
			return
		}
	}
}

// ─── System events ────────────────────────────────────────────────────────────

// publishSystemEvent delivers payload to all subscribers of subject, bypassing
// subject validation, ACL, and schema validation (server-generated, trusted).
func (s *Server) publishSystemEvent(subject string, payload []byte) {
	sids := s.bus.Fanout(subject)
	if len(sids) == 0 {
		return
	}
	deliverPayload, err := proto.Marshal(&pb.Deliver{Subject: subject, Payload: payload})
	if err != nil {
		return
	}
	for _, sid := range sids {
		if v, ok := s.conns.Load(sid); ok {
			_ = v.(*lockedConn).writeFrame(pb.FrameType_FRAME_TYPE_DELIVER, deliverPayload)
		}
	}
}

func (s *Server) publishEntityJoined(rec *session.Record) {
	payload, _ := proto.Marshal(&pb.EntityJoined{
		Pubkey:       rec.Pubkey,
		Capabilities: rec.Capabilities,
		SessionId:    rec.ID,
	})
	s.publishSystemEvent("lattice.system.entity.joined", payload)
}

func (s *Server) publishEntityLeft(rec *session.Record) {
	payload, _ := proto.Marshal(&pb.EntityLeft{
		Pubkey:    rec.Pubkey,
		SessionId: rec.ID,
	})
	s.publishSystemEvent("lattice.system.entity.left", payload)
}

func (s *Server) publishEntityOffline(ent *registry.EntityRecord) {
	payload, _ := proto.Marshal(&pb.EntityOffline{
		Pubkey:    ent.Pubkey,
		SessionId: ent.SessionID,
	})
	s.publishSystemEvent("lattice.system.entity.offline", payload)
}

// ─── Heartbeat checker ────────────────────────────────────────────────────────

// runHeartbeatChecker ticks every heartbeatInterval seconds and marks entities
// offline if their last heartbeat is older than 3 × heartbeatInterval.
func (s *Server) runHeartbeatChecker() {
	defer s.wg.Done()
	interval := time.Duration(s.heartbeatInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			threshold := 3 * interval
			for _, ent := range s.registry.Stale(time.Now(), threshold) {
				s.markOffline(ent)
			}
		case <-s.done:
			return
		}
	}
}

// markOffline handles the offline path for an entity that missed heartbeats.
// It performs cleanup in the correct order and publishes entity.offline.
func (s *Server) markOffline(ent *registry.EntityRecord) {
	// Remove from registry first. If nil, another goroutine already handled it.
	if removed := s.registry.Remove(ent.Pubkey); removed == nil {
		return
	}
	s.log.Info("entity offline (missed heartbeats)",
		"session_id", ent.SessionID,
		"pubkey", acl.EncodeIdentity(ent.Pubkey)[:8]+"...",
	)
	// Remove subscriptions and connection map entry before publishing,
	// so the offline entity cannot receive its own offline event.
	s.bus.RemoveSession(ent.SessionID)
	var lc *lockedConn
	if v, ok := s.conns.LoadAndDelete(ent.SessionID); ok {
		lc = v.(*lockedConn)
	}
	s.sessions.Remove(ent.SessionID)
	// Publish while other subscribers' connections are still in conns.
	s.publishEntityOffline(ent)
	// Close connection so handleConn's read loop exits.
	if lc != nil {
		lc.conn.Close()
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// fanout delivers payload to all subscribers of subject.
func (s *Server) fanout(subject string, innerPayload []byte) {
	sids := s.bus.Fanout(subject)
	if len(sids) == 0 {
		return
	}
	deliverPayload, err := proto.Marshal(&pb.Deliver{Subject: subject, Payload: innerPayload})
	if err != nil {
		return
	}
	for _, sid := range sids {
		if v, ok := s.conns.Load(sid); ok {
			_ = v.(*lockedConn).writeFrame(pb.FrameType_FRAME_TYPE_DELIVER, deliverPayload)
		}
	}
}

func (s *Server) sendError(lc *lockedConn, code, message string) {
	payload, _ := proto.Marshal(&pb.Error{Code: code, Message: message})
	_ = lc.writeFrame(pb.FrameType_FRAME_TYPE_ERROR, payload)
}
