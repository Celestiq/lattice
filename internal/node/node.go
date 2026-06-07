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

	"google.golang.org/protobuf/proto"

	"lattice/internal/bus"
	"lattice/internal/handshake"
	"lattice/internal/schema"
	"lattice/internal/session"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// Server handles Lattice connections. It owns the session table, subscription
// bus, and the per-connection write locks.
type Server struct {
	log               *slog.Logger
	sessions          *session.Table
	bus               *bus.Bus
	serverPriv        ed25519.PrivateKey
	heartbeatInterval uint32
	conns             sync.Map // sessionID → *lockedConn
}

func New(log *slog.Logger, serverPriv ed25519.PrivateKey, heartbeatInterval uint32) *Server {
	return &Server{
		log:               log,
		sessions:          session.NewTable(),
		bus:               bus.New(),
		serverPriv:        serverPriv,
		heartbeatInterval: heartbeatInterval,
	}
}

// lockedConn serialises concurrent writes to a single connection.
type lockedConn struct {
	mu   sync.Mutex
	conn net.Conn
}

func (lc *lockedConn) writeFrame(ft pb.FrameType, payload []byte) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return wire.Write(lc.conn, ft, payload)
}

// HandleConn runs the full lifecycle for one accepted connection:
// TLS handshake → HELLO → frame dispatch loop → cleanup.
func (s *Server) HandleConn(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return
	}
	remote := conn.RemoteAddr().String()
	s.log.Info("client connected", "remote", remote)

	rec, err := handshake.DoServer(tlsConn, s.serverPriv, s.sessions, s.heartbeatInterval)
	if err != nil {
		s.log.Warn("handshake failed", "remote", remote, "err", err)
		conn.Close()
		return
	}
	s.log.Info("entity authenticated", "remote", remote, "session_id", rec.ID)

	lc := &lockedConn{conn: conn}
	s.conns.Store(rec.ID, lc)

	// Cleanup in the right order: logical state before network close.
	defer func() {
		s.sessions.Remove(rec.ID)
		s.bus.RemoveSession(rec.ID)
		s.conns.Delete(rec.ID)
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
			// net.OpError after connection close — not worth logging at error level
			return
		}

		switch frame.Type {
		case pb.FrameType_FRAME_TYPE_HEARTBEAT:
			if err := lc.writeFrame(pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK, nil); err != nil {
				return
			}

		case pb.FrameType_FRAME_TYPE_SUBSCRIBE:
			s.handleSubscribe(lc, rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_UNSUBSCRIBE:
			s.handleUnsubscribe(rec, frame.Payload)

		case pb.FrameType_FRAME_TYPE_PUBLISH:
			s.handlePublish(lc, rec, frame.Payload)

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

	// Subject validation — no wildcards, no reserved namespace.
	if err := bus.ValidateSubject(msg.Subject); err != nil {
		s.sendError(lc, "INVALID_SUBJECT", err.Error())
		return
	}

	// Schema validation (Session 4): every subject must have a registered schema.
	if err := schema.Validate(msg.Subject, msg.Payload); err != nil {
		s.sendError(lc, "SCHEMA_ERROR", err.Error())
		return
	}

	// Fan-out to subscribers.
	sids := s.bus.Fanout(msg.Subject)
	if len(sids) == 0 {
		return
	}
	deliverPayload, err := proto.Marshal(&pb.Deliver{Subject: msg.Subject, Payload: msg.Payload})
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
