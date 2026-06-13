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
	tokens            *session.TokenStore  // resume tokens keyed by session token (Decision #2)
	schema            *schema.Registry    // dynamic schema registry (Decision #14)
	seq               subjectSequencer    // per-subject monotonic DELIVER IDs (Decision #4)
	serverPriv        ed25519.PrivateKey
	serverPub         ed25519.PublicKey
	heartbeatInterval uint32 // seconds
	conns             sync.Map // sessionID → *sessionWriter
	wg                sync.WaitGroup
	stopOnce          sync.Once
	done              chan struct{}
}

// New creates a Server and starts the background heartbeat checker.
// Default ACL rule: server identity is allowed to do everything.
// tokenTTL controls how long resume tokens are valid; defaults to 5 minutes.
func New(log *slog.Logger, serverPriv ed25519.PrivateKey, heartbeatInterval uint32, tokenTTL ...time.Duration) *Server {
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

	ttl := 5 * time.Minute
	if len(tokenTTL) > 0 && tokenTTL[0] > 0 {
		ttl = tokenTTL[0]
	}

	s := &Server{
		log:               log,
		sessions:          session.NewTable(),
		bus:               bus.New(),
		acl:               engine,
		registry:          registry.New(),
		calls:             call.New(),
		tokens:            session.NewTokenStore(ttl),
		schema:            schema.DefaultRegistry(),
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

// SchemaRegistry returns the server's schema registry (Decision #14).
// Used by the admin server to register schemas at runtime.
func (s *Server) SchemaRegistry() *schema.Registry {
	return s.schema
}

// ─── Connection handling ──────────────────────────────────────────────────────

// Shutdown gracefully stops the server. It publishes entity.left for every
// connected entity, drains pending frames via each session's writer, then
// closes all connections and waits for all goroutines to exit.
// Safe to call once; subsequent calls are no-ops.
func (s *Server) Shutdown() {
	s.stopOnce.Do(func() { close(s.done) })

	// Publish entity.left for all connected entities. Entity.left frames are
	// enqueued into each subscriber's data channel before any conn is closed,
	// so sw.close() below can drain and deliver them.
	for _, ent := range s.registry.All() {
		if s.registry.Remove(ent.Pubkey, ent.SessionID) == nil {
			continue // concurrent disconnect already handled it
		}
		payload, _ := proto.Marshal(&pb.EntityLeft{
			Pubkey:    ent.Pubkey,
			SessionId: ent.SessionID,
		})
		s.publishSystemEvent("lattice.system.entity.left", payload)
	}

	// For each writer: drain queued frames (including entity.left) then close
	// the conn so the HandleConn read loop exits.
	s.conns.Range(func(_, value any) bool {
		sw := value.(*sessionWriter)
		sw.close()      // drain pending frames with write deadline, then wait
		sw.conn.Close() // close conn so HandleConn read loop exits
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
	rec, resume, err := handshake.DoServer(tlsConn, s.serverPriv, s.sessions, s.tokens, s.heartbeatInterval)
	if err != nil {
		s.log.Warn("handshake failed", "remote", remote, "err", err)
		conn.Close()
		return
	}
	tlsConn.SetDeadline(time.Time{})
	s.log.Info("entity authenticated", "remote", remote, "session_id", rec.ID, "resumed", resume.Resumed)

	// onWriteError is called by the writer goroutine when a write deadline fires.
	// It performs the same cleanup as the normal disconnect defer, but publishes
	// entity.offline instead of entity.left.
	onWriteError := func() {
		if s.registry.Remove(rec.Pubkey, rec.ID) == nil {
			return // heartbeat checker, eviction, or Shutdown already cleaned up
		}
		s.log.Info("entity offline (write timeout)",
			"session_id", rec.ID,
			"pubkey", acl.EncodeIdentity(rec.Pubkey)[:8]+"...",
		)
		s.bus.RemoveSession(rec.ID)
		s.conns.Delete(rec.ID)
		s.sessions.Remove(rec.ID)
		s.publishEntityOffline(&registry.EntityRecord{
			Pubkey:    rec.Pubkey,
			SessionID: rec.ID,
		})
	}

	sw := newSessionWriter(conn, rec.ID, s.log, onWriteError)
	s.conns.Store(rec.ID, sw)

	// Evict any existing session for this pubkey before registering the new one
	// (Decision #12: same-identity reconnect). No entity.left is published —
	// the new connection supersedes the old one.
	if oldEnt := s.registry.Get(rec.Pubkey); oldEnt != nil {
		s.evictOldSession(oldEnt)
	}

	// Register entity.
	s.registry.Register(rec.ID, rec.Pubkey, rec.Capabilities)

	// On resume: restore subscriptions silently and call the durable-replay hook.
	// On fresh connect: announce entity.joined so watchers know the entity arrived.
	if resume.Resumed {
		for _, pattern := range resume.Patterns {
			_ = s.bus.Subscribe(rec.ID, pattern)
		}
		s.durableReplayHook(rec)
	} else {
		s.publishEntityJoined(rec)
	}

	// Cleanup: ordered to prevent fanout to dead connections.
	defer func() {
		s.teardownSession(rec)          // no-op if DISCONNECT, eviction, or Shutdown already cleaned up
		conn.Close()                    // interrupt any pending write; idempotent
		sw.close()                      // wait for writer goroutine to finish
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
			sw.enqueueControl(pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK, nil)

		case pb.FrameType_FRAME_TYPE_SUBSCRIBE:
			s.handleSubscribe(sw, rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_UNSUBSCRIBE:
			s.handleUnsubscribe(rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_PUBLISH:
			s.handlePublish(sw, rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_REQUEST:
			s.handleRequest(sw, rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_RESPONSE:
			s.handleResponse(sw, rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_DISCONNECT:
			// Graceful teardown requested by the client (Decision #8).
			// Perform cleanup now so entity.left is published immediately,
			// rather than waiting for the heartbeat checker (up to 3× interval).
			s.teardownSession(rec)
			return

		default:
			s.log.Warn("unhandled frame", "remote", remote, "type", frame.Type)
		}
	}
}

// ─── Frame handlers ───────────────────────────────────────────────────────────

func (s *Server) handleSubscribe(sw *sessionWriter, rec *session.Record, payload []byte) {
	var msg pb.Subscribe
	if err := proto.Unmarshal(payload, &msg); err != nil {
		s.sendError(sw, "INVALID_PAYLOAD", "cannot unmarshal SUBSCRIBE")
		return
	}
	// ACL check before touching the registry.
	if !s.acl.Allow(rec.Pubkey, acl.ActionSubscribe, msg.Subject) {
		s.sendError(sw, "PERMISSION_DENIED", "subscribe denied by ACL")
		return
	}
	if err := s.bus.Subscribe(rec.ID, msg.Subject); err != nil {
		s.sendError(sw, "INVALID_SUBJECT", err.Error())
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

func (s *Server) handlePublish(sw *sessionWriter, rec *session.Record, payload []byte) {
	var msg pb.Publish
	if err := proto.Unmarshal(payload, &msg); err != nil {
		s.sendError(sw, "INVALID_PAYLOAD", "cannot unmarshal PUBLISH")
		return
	}

	// Reject wildcards and the reserved namespace before touching ACL.
	if err := bus.ValidateSubject(msg.Subject); err != nil {
		s.sendError(sw, "INVALID_SUBJECT", err.Error(), msg.MessageId)
		return
	}

	// ACL check: session exists → ACL → schema → fan-out.
	if !s.acl.Allow(rec.Pubkey, acl.ActionPublish, msg.Subject) {
		s.log.Debug("publish denied by ACL", "session_id", rec.ID, "subject", msg.Subject)
		s.sendError(sw, "PERMISSION_DENIED", "publish denied by ACL", msg.MessageId)
		return
	}

	// Schema validation.
	if err := s.schema.Validate(msg.Subject, msg.Payload); err != nil {
		s.sendError(sw, "SCHEMA_ERROR", err.Error(), msg.MessageId)
		return
	}

	// Fan-out — pass publisher pubkey for server-stamped provenance (Decision #4).
	s.fanout(msg.Subject, msg.Payload, rec.Pubkey)
}

func (s *Server) handleRequest(sw *sessionWriter, rec *session.Record, payload []byte) {
	var req pb.Request
	if err := proto.Unmarshal(payload, &req); err != nil {
		s.sendError(sw, "INVALID_PAYLOAD", "cannot unmarshal REQUEST")
		return
	}
	if len(req.TargetPubkey) != ed25519.PublicKeySize {
		s.sendError(sw, "INVALID_PUBKEY", "target_pubkey must be 32 bytes")
		return
	}

	// ACL check: (caller, "call", base32(target_pubkey)).
	// SubjectPattern in call rules holds the target identity or "*" / ">".
	targetIdentity := acl.EncodeIdentity(req.TargetPubkey)
	if !s.acl.Allow(rec.Pubkey, acl.ActionCall, targetIdentity) {
		s.sendError(sw, "PERMISSION_DENIED", "call denied by ACL")
		return
	}

	// Target must be present in the entity registry.
	targetEnt := s.registry.Get(req.TargetPubkey)
	if targetEnt == nil {
		s.sendError(sw, "NOT_FOUND", "target entity not connected")
		return
	}
	v, ok := s.conns.Load(targetEnt.SessionID)
	if !ok {
		s.sendError(sw, "NOT_FOUND", "target entity not connected")
		return
	}
	targetSw := v.(*sessionWriter)

	timeoutMs := req.TimeoutMs
	if timeoutMs == 0 {
		timeoutMs = 5000
	}
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)

	// Register before forwarding to prevent a race where the target responds
	// before the pending entry exists.
	s.calls.Add(req.CorrelationId, rec.ID, targetEnt.SessionID, deadline)

	// Stamp caller_identity and received_at server-side before forwarding so the
	// target can trust these fields (Decision #18). Client-supplied values are overwritten.
	req.CallerIdentity = acl.EncodeIdentity(rec.Pubkey)
	req.ReceivedAt = time.Now().UnixMilli()
	stampedPayload, _ := proto.Marshal(&req)

	if !targetSw.enqueue(pb.FrameType_FRAME_TYPE_REQUEST, stampedPayload) {
		s.calls.Remove(req.CorrelationId)
		s.sendError(sw, "DELIVERY_FAILED", "target data channel full")
	}
}

func (s *Server) handleResponse(sw *sessionWriter, rec *session.Record, payload []byte) {
	var resp pb.Response
	if err := proto.Unmarshal(payload, &resp); err != nil {
		s.sendError(sw, "INVALID_PAYLOAD", "cannot unmarshal RESPONSE")
		return
	}

	// Verify the responder is the intended target before removing the call (Decision #6).
	// Peek leaves the call intact so the legitimate target can still respond if this
	// is a spoofed RESPONSE from a third party.
	pending := s.calls.Peek(resp.CorrelationId)
	if pending == nil {
		s.sendError(sw, "NOT_FOUND", "unknown or expired correlation_id")
		return
	}
	if pending.TargetSessionID != rec.ID {
		s.sendError(sw, "NOT_AUTHORIZED", "response from unexpected entity")
		return
	}

	// Target verified — remove and forward.
	pending = s.calls.Remove(resp.CorrelationId)
	if pending == nil {
		return // expired between Peek and Remove; silently drop
	}

	v, ok := s.conns.Load(pending.RequesterSessionID)
	if !ok {
		return // requester disconnected; silently drop
	}
	_ = v.(*sessionWriter).enqueue(pb.FrameType_FRAME_TYPE_RESPONSE, payload)
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
					// Echo correlation_id as ref_id so the requester can match the error
					// to the originating call (Decision #5).
					payload, _ := proto.Marshal(&pb.Error{
						Code:    "TIMEOUT",
						Message: "call timed out",
						RefId:   exp.CorrelationID,
					})
					_ = v.(*sessionWriter).enqueueControl(pb.FrameType_FRAME_TYPE_ERROR, payload)
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
	deliverPayload, err := proto.Marshal(&pb.Deliver{
		Id:                s.seq.Next(subject),
		Subject:           subject,
		Payload:           payload,
		PublisherIdentity: acl.EncodeIdentity(s.serverPub),
		PublishedAt:       time.Now().UnixMilli(),
		SchemaVersion:     s.schema.Version(subject), // 0 for system subjects
	})
	if err != nil {
		return
	}
	for _, sid := range sids {
		rec := s.sessions.ByID(sid)
		if rec == nil {
			continue // session already cleaned up
		}
		if !s.acl.AllowConcrete(rec.Pubkey, acl.ActionSubscribe, subject) {
			continue // delivery-time ACL check: subscriber is denied this concrete subject
		}
		if v, ok := s.conns.Load(sid); ok {
			_ = v.(*sessionWriter).enqueue(pb.FrameType_FRAME_TYPE_DELIVER, deliverPayload)
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
	// Remove from registry first (CAS). If nil, another goroutine already handled it.
	if removed := s.registry.Remove(ent.Pubkey, ent.SessionID); removed == nil {
		return
	}
	s.log.Info("entity offline (missed heartbeats)",
		"session_id", ent.SessionID,
		"pubkey", acl.EncodeIdentity(ent.Pubkey)[:8]+"...",
	)
	// Remove subscriptions and connection map entry before publishing,
	// so the offline entity cannot receive its own offline event.
	s.bus.RemoveSession(ent.SessionID)
	var sw *sessionWriter
	if v, ok := s.conns.LoadAndDelete(ent.SessionID); ok {
		sw = v.(*sessionWriter)
	}
	s.sessions.Remove(ent.SessionID)
	// Publish while other subscribers' connections are still in conns.
	s.publishEntityOffline(ent)
	// Close connection so HandleConn's read loop exits. The writer goroutine
	// will detect the closed conn on the next write and exit via onWriteError
	// (which will be a no-op since the entity is already removed).
	if sw != nil {
		sw.conn.Close()
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// fanout delivers payload to all subscribers of subject with a full provenance envelope.
func (s *Server) fanout(subject string, innerPayload []byte, publisherPubkey []byte) {
	sids := s.bus.Fanout(subject)
	if len(sids) == 0 {
		return
	}
	deliverPayload, err := proto.Marshal(&pb.Deliver{
		Id:                s.seq.Next(subject),
		Subject:           subject,
		Payload:           innerPayload,
		PublisherIdentity: acl.EncodeIdentity(publisherPubkey),
		PublishedAt:       time.Now().UnixMilli(),
		SchemaVersion:     s.schema.Version(subject),
	})
	if err != nil {
		return
	}
	for _, sid := range sids {
		rec := s.sessions.ByID(sid)
		if rec == nil {
			continue // session already cleaned up
		}
		if !s.acl.AllowConcrete(rec.Pubkey, acl.ActionSubscribe, subject) {
			continue // delivery-time ACL check: subscriber is denied this concrete subject
		}
		if v, ok := s.conns.Load(sid); ok {
			_ = v.(*sessionWriter).enqueue(pb.FrameType_FRAME_TYPE_DELIVER, deliverPayload)
		}
	}
}

// sendError sends an ERROR frame. An optional refID (e.g. Publish.message_id) is
// echoed in Error.ref_id for client-side correlation (Decision #5).
func (s *Server) sendError(sw *sessionWriter, code, message string, refID ...string) {
	e := &pb.Error{Code: code, Message: message}
	if len(refID) > 0 && refID[0] != "" {
		e.RefId = refID[0]
	}
	payload, _ := proto.Marshal(e)
	_ = sw.enqueueControl(pb.FrameType_FRAME_TYPE_ERROR, payload)
}

// teardownSession performs the cleanup for a graceful disconnect (DISCONNECT frame or
// connection EOF). The CAS Remove ensures only the first caller does real work.
// Subscription patterns are saved to the token store so the entity can resume later
// (Decision #2).
func (s *Server) teardownSession(rec *session.Record) {
	if s.registry.Remove(rec.Pubkey, rec.ID) == nil {
		return // eviction, heartbeat checker, or Shutdown already cleaned up
	}
	// Snapshot subscriptions and save under rec.Token BEFORE RemoveSession wipes them.
	patterns := s.bus.GetPatterns(rec.ID)
	s.tokens.Save(rec.Token, rec.Pubkey, patterns)
	s.bus.RemoveSession(rec.ID)
	s.conns.Delete(rec.ID)
	s.sessions.Remove(rec.ID)
	s.publishEntityLeft(rec)
}

// durableReplayHook is called after a successful token-based session resume.
// In v0.1.1 this is a no-op stub; durable message replay is not yet implemented.
func (s *Server) durableReplayHook(_ *session.Record) {}

// evictOldSession forcibly removes an existing session when the same pubkey
// reconnects (Decision #12). No entity.left is published — the reconnection
// supersedes the old session. Pending calls targeting the old session are
// cancelled with TARGET_DISCONNECTED (Decision #6 amendment).
func (s *Server) evictOldSession(old *registry.EntityRecord) {
	if s.registry.Remove(old.Pubkey, old.SessionID) == nil {
		return // already gone (concurrent cleanup beat us here)
	}
	for _, exp := range s.calls.InvalidateTarget(old.SessionID) {
		if v, ok := s.conns.Load(exp.RequesterSessionID); ok {
			payload, _ := proto.Marshal(&pb.Error{
				Code:    "TARGET_DISCONNECTED",
				Message: "target entity reconnected with a new session",
			})
			_ = v.(*sessionWriter).enqueueControl(pb.FrameType_FRAME_TYPE_ERROR, payload)
		}
	}
	s.bus.RemoveSession(old.SessionID)
	if v, ok := s.conns.LoadAndDelete(old.SessionID); ok {
		v.(*sessionWriter).conn.Close() // unblocks the old HandleConn read loop
	}
	s.sessions.Remove(old.SessionID)
	// No entity.left: the reconnect supersedes the old session.
}
