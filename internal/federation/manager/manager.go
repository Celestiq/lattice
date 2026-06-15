// Package manager implements the federation peer lifecycle manager.
//
// Manager orchestrates all peer connections: dials active and paused peers on
// startup, accepts incoming connections from the QUIC listener, drives the
// bilateral consent state machine, and dispatches inbound control frames.
// Cross-peer message forwarding (FED_DELIVER, FED_REQUEST, FED_RESPONSE) is
// wired in S4/S5; the read loop skeleton is here to handle FED_STATUS frames.
package manager

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	fedhandshake "lattice/internal/federation/handshake"
	"lattice/internal/federation/peer"
	fedstore "lattice/internal/federation/store"
	"lattice/internal/schema"
	"lattice/internal/transport"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// NodeHooks is the interface back to node.Server. Defined here, implemented
// there. The nil-check pattern: if s.fedManager == nil, each node.Server
// method is a no-op, keeping the 192 pre-S3 tests unaffected.
type NodeHooks interface {
	FederatedPublish(subject string, payload []byte, publisherPubkey []byte)
	SchemaRegistry() *schema.Registry
	RouteLocalRequest(corrID string, targetPubkey []byte, payload []byte,
		callerIdentity string, receivedAt int64, sourcePeerPubkey []byte)
	RouteLocalResponse(corrID string, payload []byte, sourcePeerPubkey []byte)
}

// ConnectionInfo is the per-peer summary returned by GetConnections.
type ConnectionInfo struct {
	PubkeyHex     string `json:"pubkey_hex"`
	Name          string `json:"name"`
	Addr          string `json:"addr"`
	State         string `json:"state"`
	OutboundRules int    `json:"outbound_rules"`
	InboundRules  int    `json:"inbound_rules"`
}

// Manager manages all federation peer connections and their consent lifecycle.
// All exported methods are safe to call from multiple goroutines.
type Manager struct {
	localPriv ed25519.PrivateKey
	localPub  ed25519.PublicKey
	store     *fedstore.Store
	dialer    transport.Dialer
	listener  transport.Listener
	peers     sync.Map // hex(peerPubkey) → *peer.PeerConn
	nodeHooks NodeHooks
	log       *slog.Logger
	wg        sync.WaitGroup
	done      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	consentMu sync.Mutex // serializes all consent state transitions
}

// New creates a Manager. Call Start() to begin accepting and dialing.
// nodeHooks may be nil (stubs are used); wiring happens in S4/S5.
func New(localPriv ed25519.PrivateKey, store *fedstore.Store, dialer transport.Dialer, listener transport.Listener, nodeHooks NodeHooks, log *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		localPriv: localPriv,
		localPub:  localPriv.Public().(ed25519.PublicKey),
		store:     store,
		dialer:    dialer,
		listener:  listener,
		nodeHooks: nodeHooks,
		log:       log,
		done:      make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins the accept loop and dials all persisted active/paused peers.
func (m *Manager) Start() error {
	active, err := m.store.AllActivePeers()
	if err != nil {
		return fmt.Errorf("manager: read active peers: %w", err)
	}
	all, err := m.store.AllPeers()
	if err != nil {
		return fmt.Errorf("manager: read all peers: %w", err)
	}

	m.wg.Add(1)
	go m.runAcceptLoop()

	for _, rec := range active {
		r := rec
		m.wg.Add(1)
		go m.connectPeerWithRetry(r, true)
	}
	for _, rec := range all {
		if rec.State != "paused" {
			continue
		}
		r := rec
		m.wg.Add(1)
		go m.connectPeerWithRetry(r, false)
	}
	return nil
}

// Stop shuts down the manager: revokes all peer streams, closes the listener,
// waits for all goroutines to exit, then closes the store.
func (m *Manager) Stop() {
	m.cancel()
	close(m.done)
	m.peers.Range(func(_, v any) bool {
		v.(*peer.PeerConn).Revoke() //nolint:errcheck
		return true
	})
	if m.listener != nil {
		m.listener.Close() //nolint:errcheck
	}
	m.wg.Wait()
	m.store.Close() //nolint:errcheck
}

// HandleIncoming handles a new inbound federation connection. It runs the
// FedHello handshake and dispatches based on the stored peer state.
func (m *Manager) HandleIncoming(stream transport.Stream) {
	nonce := deriveNonce(stream)
	peerPubkey, err := fedhandshake.DoFederatedHandshake(m.ctx, stream, nonce, m.localPriv)
	if err != nil {
		m.log.Warn("fed: incoming handshake failed", "err", err)
		stream.Close() //nolint:errcheck
		return
	}
	peerHex := hex.EncodeToString(peerPubkey)

	stored, err := m.store.GetPeer(peerHex)
	if err != nil {
		m.log.Error("fed: GetPeer failed", "peer", peerHex, "err", err)
		stream.Close() //nolint:errcheck
		return
	}

	state := ""
	if stored != nil {
		state = stored.State
	}

	switch state {
	case "active":
		pc := m.getOrCreatePeer(peerPubkey, stored.Name, stored.Addr)
		if err := pc.Activate(stream); err != nil {
			// Another goroutine activated first (concurrent incoming from same peer).
			rejectB, _ := proto.Marshal(&pb.FedReject{Reason: "concurrent_connection"})
			wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_REJECT, rejectB) //nolint:errcheck
			stream.Close()                                                    //nolint:errcheck
			return
		}
		if err := m.sendFedPolicy(stream, peerHex); err != nil {
			m.log.Warn("fed: sendFedPolicy failed", "peer", peerHex, "err", err)
		}
		m.wg.Add(1)
		go m.runPeerReadLoop(pc, peerHex, true)

	case "paused":
		pc := m.getOrCreatePeer(peerPubkey, stored.Name, stored.Addr)
		if err := pc.Activate(stream); err != nil {
			rejectB, _ := proto.Marshal(&pb.FedReject{Reason: "concurrent_connection"})
			wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_REJECT, rejectB) //nolint:errcheck
			stream.Close()                                                    //nolint:errcheck
			return
		}
		// No FedPolicy on paused — connection maintained but no message flow.
		m.wg.Add(1)
		go m.runPeerReadLoop(pc, peerHex, true)

	case "revoked":
		rejectB, _ := proto.Marshal(&pb.FedReject{Reason: "revoked"})
		wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_REJECT, rejectB) //nolint:errcheck
		stream.Close()                                                    //nolint:errcheck
		m.log.Info("fed: rejected revoked peer", "peer", peerHex)

	default: // nil (unknown) or "pending"
		name, addr := "", ""
		if stored != nil {
			name, addr = stored.Name, stored.Addr
		}
		m.store.UpsertPeer(peerHex, name, addr, "incoming", "pending") //nolint:errcheck
		introID := peerHex[:8]
		pendingB, _ := proto.Marshal(&pb.FedPending{IntroductionId: introID})
		wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_PENDING, pendingB) //nolint:errcheck
		stream.Close()                                                      //nolint:errcheck
		m.log.Info("fed: queued unknown peer as pending", "peer", peerHex)
	}
}

// ─── Consent operations ────────────────────────────────────────────────────

// PairPeer queues a peer for pairing. Returns an error if the peer is already
// known. The operator must call AcceptPeer to allow connection.
func (m *Manager) PairPeer(peerHex, name, addr string) error {
	m.consentMu.Lock()
	defer m.consentMu.Unlock()

	stored, err := m.store.GetPeer(peerHex)
	if err != nil {
		return err
	}
	if stored != nil {
		return fmt.Errorf("peer already known (state: %s)", stored.State)
	}
	return m.store.UpsertPeer(peerHex, name, addr, "manual", "pending")
}

// AcceptPeer transitions a pending peer to active and starts dialing it.
func (m *Manager) AcceptPeer(peerHex string) error {
	m.consentMu.Lock()
	defer m.consentMu.Unlock()

	stored, err := m.store.GetPeer(peerHex)
	if err != nil {
		return err
	}
	if stored == nil {
		return fmt.Errorf("peer not found")
	}
	if stored.State != "pending" {
		return fmt.Errorf("peer state is %q, want pending", stored.State)
	}
	if err := m.store.UpdatePeerState(peerHex, "active"); err != nil {
		return err
	}
	rec := *stored
	rec.State = "active"
	m.wg.Add(1)
	go m.connectPeerWithRetry(&rec, true)
	return nil
}

// RejectPeer deletes a pending peer from the store.
func (m *Manager) RejectPeer(peerHex string) error {
	m.consentMu.Lock()
	defer m.consentMu.Unlock()

	stored, err := m.store.GetPeer(peerHex)
	if err != nil {
		return err
	}
	if stored == nil {
		return fmt.Errorf("peer not found")
	}
	if stored.State != "pending" {
		return fmt.Errorf("peer state is %q, want pending", stored.State)
	}
	return m.store.DeletePeer(peerHex)
}

// PausePeer transitions an active peer to paused and sends FedStatus{paused}.
func (m *Manager) PausePeer(peerHex string) error {
	m.consentMu.Lock()
	defer m.consentMu.Unlock()

	v, ok := m.peers.Load(peerHex)
	if !ok {
		return fmt.Errorf("peer not connected")
	}
	pc := v.(*peer.PeerConn)
	stream := pc.Stream()
	if err := pc.Pause(); err != nil {
		return err
	}
	m.store.UpdatePeerState(peerHex, "paused") //nolint:errcheck
	if stream != nil {
		statusB, _ := proto.Marshal(&pb.FedStatus{State: "paused"})
		wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_STATUS, statusB) //nolint:errcheck
	}
	return nil
}

// ResumePeer transitions a paused peer back to active and sends FedPolicy.
func (m *Manager) ResumePeer(peerHex string) error {
	m.consentMu.Lock()
	defer m.consentMu.Unlock()

	v, ok := m.peers.Load(peerHex)
	if !ok {
		return fmt.Errorf("peer not connected")
	}
	pc := v.(*peer.PeerConn)
	stream := pc.Stream()
	if err := pc.Resume(stream); err != nil {
		return err
	}
	m.store.UpdatePeerState(peerHex, "active") //nolint:errcheck
	if stream != nil {
		m.sendFedPolicy(stream, peerHex) //nolint:errcheck
	}
	return nil
}

// RevokePeer sends FedStatus{revoked}, closes the peer stream, and persists
// the revoked state. Idempotent if the peer is not currently connected.
func (m *Manager) RevokePeer(peerHex string) error {
	m.consentMu.Lock()
	defer m.consentMu.Unlock()

	if v, ok := m.peers.Load(peerHex); ok {
		pc := v.(*peer.PeerConn)
		if stream := pc.Stream(); stream != nil {
			statusB, _ := proto.Marshal(&pb.FedStatus{State: "revoked"})
			wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_STATUS, statusB) //nolint:errcheck
		}
		pc.Revoke() //nolint:errcheck
		m.peers.Delete(peerHex)
	}
	return m.store.UpdatePeerState(peerHex, "revoked")
}

// UpdatePolicy replaces the outbound and inbound policy rules for peerHex
// and sends an updated FedPolicy if the peer is currently active.
func (m *Manager) UpdatePolicy(peerHex string, outbound, inbound []fedstore.PolicyRule) error {
	m.consentMu.Lock()
	defer m.consentMu.Unlock()

	if err := m.store.SetOutboundPolicy(peerHex, outbound); err != nil {
		return err
	}
	if err := m.store.SetInboundPolicy(peerHex, inbound); err != nil {
		return err
	}
	if v, ok := m.peers.Load(peerHex); ok {
		pc := v.(*peer.PeerConn)
		if pc.State() == peer.StateActive {
			if stream := pc.Stream(); stream != nil {
				m.sendFedPolicy(stream, peerHex) //nolint:errcheck
			}
		}
	}
	return nil
}

// UpdateExportList replaces the exported entity pubkeys for peerHex and
// sends an updated FedPolicy if the peer is currently active.
func (m *Manager) UpdateExportList(peerHex string, entityHexes []string) error {
	m.consentMu.Lock()
	defer m.consentMu.Unlock()

	if err := m.store.SetExportList(peerHex, entityHexes); err != nil {
		return err
	}
	if v, ok := m.peers.Load(peerHex); ok {
		pc := v.(*peer.PeerConn)
		if pc.State() == peer.StateActive {
			if stream := pc.Stream(); stream != nil {
				m.sendFedPolicy(stream, peerHex) //nolint:errcheck
			}
		}
	}
	return nil
}

// GetConnections returns a summary of all known peers from the store,
// including their current state and policy rule counts.
func (m *Manager) GetConnections() ([]*ConnectionInfo, error) {
	all, err := m.store.AllPeers()
	if err != nil {
		return nil, err
	}
	result := make([]*ConnectionInfo, 0, len(all))
	for _, rec := range all {
		out, err := m.store.GetOutboundPolicy(rec.PubkeyHex)
		if err != nil {
			return nil, err
		}
		in, err := m.store.GetInboundPolicy(rec.PubkeyHex)
		if err != nil {
			return nil, err
		}
		result = append(result, &ConnectionInfo{
			PubkeyHex:     rec.PubkeyHex,
			Name:          rec.Name,
			Addr:          rec.Addr,
			State:         rec.State,
			OutboundRules: len(out),
			InboundRules:  len(in),
		})
	}
	return result, nil
}

// ─── Internal goroutines ───────────────────────────────────────────────────

func (m *Manager) runAcceptLoop() {
	defer m.wg.Done()
	for {
		stream, err := m.listener.AcceptPeer(m.ctx)
		if err != nil {
			select {
			case <-m.done:
				return
			default:
				m.log.Error("fed: accept error", "err", err)
				return
			}
		}
		m.wg.Add(1)
		go func(s transport.Stream) {
			defer m.wg.Done()
			m.HandleIncoming(s)
		}(stream)
	}
}

// connectPeerWithRetry dials rec.Addr with exponential backoff (cap 60 s)
// until the connection is established or the manager is stopped.
// sendPolicy controls whether FedPolicy is sent after activation (true for
// active peers, false for paused ones). The state in rec is used at dial time
// only; the actual DB state governs HandleIncoming on the listener side.
func (m *Manager) connectPeerWithRetry(rec *fedstore.PeerRecord, sendPolicy bool) {
	defer m.wg.Done()

	backoff := time.Second
	for {
		select {
		case <-m.done:
			return
		default:
		}

		stream, err := m.dialer.DialPeer(m.ctx, rec.Addr)
		if err != nil {
			m.log.Warn("fed: dial failed", "peer", rec.PubkeyHex, "addr", rec.Addr,
				"err", err, "retry_in", backoff)
			select {
			case <-m.done:
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			continue
		}

		nonce := deriveNonce(stream)
		peerPubkey, err := fedhandshake.DoFederatedHandshake(m.ctx, stream, nonce, m.localPriv)
		if err != nil {
			stream.Close() //nolint:errcheck
			m.log.Warn("fed: outgoing handshake failed", "peer", rec.PubkeyHex, "err", err)
			select {
			case <-m.done:
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			continue
		}

		peerHex := hex.EncodeToString(peerPubkey)
		if peerHex != rec.PubkeyHex {
			m.log.Warn("fed: connected to unexpected peer", "want", rec.PubkeyHex, "got", peerHex)
			stream.Close() //nolint:errcheck
			return
		}

		pc := m.getOrCreatePeer(peerPubkey, rec.Name, rec.Addr)
		if err := pc.Activate(stream); err != nil {
			// Peer already active from a concurrent incoming connection — skip.
			stream.Close() //nolint:errcheck
			return
		}

		if sendPolicy {
			m.sendFedPolicy(stream, peerHex) //nolint:errcheck
		}
		m.wg.Add(1)
		go m.runPeerReadLoop(pc, peerHex, false)
		return
	}
}

// runPeerReadLoop reads federation frames from pc's stream until error or stop.
// If resetOnDrop is true (HandleIncoming path), the peer's store state is
// updated to "pending" on stream error so the peer can reconnect.
// If resetOnDrop is false (outgoing dial path), the store state is left as-is
// so that a subsequent HandleIncoming from the peer will be accepted normally.
func (m *Manager) runPeerReadLoop(pc *peer.PeerConn, peerHex string, resetOnDrop bool) {
	defer m.wg.Done()
	for {
		select {
		case <-m.done:
			return
		default:
		}
		stream := pc.Stream()
		if stream == nil {
			return
		}
		f, err := wire.Read(stream)
		if err != nil {
			m.log.Info("fed: peer disconnected", "peer", peerHex, "err", err)
			m.peers.Delete(peerHex)
			if resetOnDrop {
				m.store.UpdatePeerState(peerHex, "pending") //nolint:errcheck
			}
			return
		}
		m.handleInboundFrame(pc, peerHex, f)
	}
}

func (m *Manager) handleInboundFrame(pc *peer.PeerConn, peerHex string, f *wire.Frame) {
	switch f.Type {
	case pb.FrameType_FRAME_TYPE_FED_STATUS:
		var status pb.FedStatus
		if err := proto.Unmarshal(f.Payload, &status); err != nil {
			return
		}
		switch status.State {
		case "paused":
			pc.Pause() //nolint:errcheck
			m.store.UpdatePeerState(peerHex, "paused") //nolint:errcheck
		case "revoked":
			pc.Revoke() //nolint:errcheck
			m.store.UpdatePeerState(peerHex, "revoked") //nolint:errcheck
			m.peers.Delete(peerHex)
		}
	// FED_DELIVER, FED_REQUEST, FED_RESPONSE are handled in S4/S5.
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────

// getOrCreatePeer returns the existing PeerConn for pubkey or creates a new
// Pending one. Stale Revoked entries are replaced atomically.
func (m *Manager) getOrCreatePeer(pubkey []byte, name, addr string) *peer.PeerConn {
	peerHex := hex.EncodeToString(pubkey)
	newPC := peer.New(pubkey, name, addr)
	actual, _ := m.peers.LoadOrStore(peerHex, newPC)
	existing := actual.(*peer.PeerConn)
	if existing.State() == peer.StateRevoked {
		m.peers.CompareAndDelete(peerHex, existing)
		actual, _ = m.peers.LoadOrStore(peerHex, newPC)
		return actual.(*peer.PeerConn)
	}
	return existing
}

// sendFedPolicy loads rules from the store and writes a FED_POLICY frame.
func (m *Manager) sendFedPolicy(stream transport.Stream, peerHex string) error {
	out, err := m.store.GetOutboundPolicy(peerHex)
	if err != nil {
		return err
	}
	in, err := m.store.GetInboundPolicy(peerHex)
	if err != nil {
		return err
	}
	policy := &pb.FedPolicy{}
	for _, r := range out {
		policy.Outbound = append(policy.Outbound, &pb.FedPolicyRule{
			SubjectPattern: r.SubjectPattern,
			Effect:         r.Effect,
		})
	}
	for _, r := range in {
		policy.Inbound = append(policy.Inbound, &pb.FedPolicyRule{
			SubjectPattern: r.SubjectPattern,
			Effect:         r.Effect,
		})
	}
	b, err := proto.Marshal(policy)
	if err != nil {
		return err
	}
	return wire.Write(stream, pb.FrameType_FRAME_TYPE_FED_POLICY, b)
}

// deriveNonce returns TLS keying material when the stream implements
// transport.TLSExporter (QUIC streams do). Falls back to a zero slice for
// test streams — test nonceStream shims must implement TLSExporter.
func deriveNonce(stream transport.Stream) []byte {
	if exporter, ok := stream.(transport.TLSExporter); ok {
		if nonce, err := exporter.ExportKeyingMaterial(fedhandshake.FedExporterLabel, nil, 32); err == nil {
			return nonce
		}
	}
	return make([]byte, 32)
}
