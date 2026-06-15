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
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	fedcalls "lattice/internal/federation/calls"
	fedhandshake "lattice/internal/federation/handshake"
	"lattice/internal/federation/peer"
	fedpolicy "lattice/internal/federation/policy"
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
	// RouteLocalRequest forwards an inbound cross-federation REQUEST to the
	// local target entity (S5). timeoutMs is forwarded from FedRequest so the
	// local call deadline matches the original caller's timeout.
	RouteLocalRequest(corrID string, targetPubkey []byte, payload []byte,
		callerIdentity string, receivedAt int64, timeoutMs uint32, sourcePeerPubkey []byte)
	// RouteLocalResponse delivers a cross-federation RESPONSE to the local
	// session identified by requesterSessionID (S5).
	RouteLocalResponse(corrID string, payload []byte, requesterSessionID string)
	// SendLocalError delivers an ERROR frame to the local session (S5). Used
	// to send TIMEOUT errors for expired cross-federation outbound calls.
	SendLocalError(sessionID, code, message, refID string)
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

	// S4: per-peer policy engines loaded from SQLite on activation.
	outPolicies sync.Map // peerHex → *fedpolicy.Engine (outbound forwarding rules)
	inPolicies  sync.Map // peerHex → *fedpolicy.Engine (inbound acceptance rules)
	// S4: schema propagation tracker. Key: peerHex+":"+subject; value: struct{}.
	// LoadOrStore ensures SchemaDescriptor is sent at most once per peer per subject.
	schemaTracker sync.Map

	// S5: in-memory routing table. key: entityHex → peerHex.
	// Populated from SQLite at Start() and updated on inbound FedPolicy frames.
	remoteEntities sync.Map
	// S5: outbound cross-federation call registry.
	fedCalls *fedcalls.Registry

	stopOnce sync.Once
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
		fedCalls:  fedcalls.New(),
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

	// S5: hydrate the in-memory routing table from SQLite so cross-federation
	// call routing survives node restarts.
	entMap, err := m.store.GetRemoteEntityMap()
	if err != nil {
		return fmt.Errorf("manager: read remote entity map: %w", err)
	}
	for entityHex, peerHex := range entMap {
		m.remoteEntities.Store(entityHex, peerHex)
	}

	m.wg.Add(1)
	go m.runAcceptLoop()
	m.wg.Add(1)
	go m.runFedCallTimeoutChecker()

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
// waits for all goroutines to exit, then closes the store. Safe to call multiple times.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
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
	})
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
		m.loadPolicies(peerHex)
		if err := m.sendFedPolicy(pc, peerHex); err != nil {
			m.log.Warn("fed: sendFedPolicy failed", "peer", peerHex, "err", err)
		}
		m.wg.Add(1)
		go m.runPeerWriteLoop(pc, peerHex, true)
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
		m.loadPolicies(peerHex)
		// No FedPolicy on paused — connection maintained but no message flow.
		m.wg.Add(1)
		go m.runPeerWriteLoop(pc, peerHex, true)
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
	m.sendFedPolicy(pc, peerHex) //nolint:errcheck
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
	m.loadPolicies(peerHex)
	if v, ok := m.peers.Load(peerHex); ok {
		pc := v.(*peer.PeerConn)
		if pc.State() == peer.StateActive {
			m.sendFedPolicy(pc, peerHex) //nolint:errcheck
		}
	}
	return nil
}

// UpdateExportList replaces the exported entity pubkeys for peerHex, refreshes
// the in-memory routing table, and sends an updated FedPolicy to the peer.
func (m *Manager) UpdateExportList(peerHex string, entityHexes []string) error {
	m.consentMu.Lock()
	defer m.consentMu.Unlock()

	if err := m.store.SetExportList(peerHex, entityHexes); err != nil {
		return err
	}
	// Refresh in-memory routing table: remove old entries for this peer, add new ones.
	m.remoteEntities.Range(func(k, v any) bool {
		if v.(string) == peerHex {
			m.remoteEntities.Delete(k)
		}
		return true
	})
	for _, entityHex := range entityHexes {
		m.remoteEntities.Store(entityHex, peerHex)
	}

	m.loadPolicies(peerHex)
	if v, ok := m.peers.Load(peerHex); ok {
		pc := v.(*peer.PeerConn)
		if pc.State() == peer.StateActive {
			m.sendFedPolicy(pc, peerHex) //nolint:errcheck
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

		m.loadPolicies(peerHex)
		if sendPolicy {
			m.sendFedPolicy(pc, peerHex) //nolint:errcheck
		}
		m.wg.Add(1)
		go m.runPeerWriteLoop(pc, peerHex, false)
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
			m.dropPeer(peerHex, resetOnDrop)
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
	case pb.FrameType_FRAME_TYPE_FED_POLICY:
		var pol pb.FedPolicy
		if err := proto.Unmarshal(f.Payload, &pol); err != nil {
			return
		}
		m.handleInboundPolicy(pc, peerHex, &pol)
	case pb.FrameType_FRAME_TYPE_FED_DELIVER:
		var deliver pb.FedDeliver
		if err := proto.Unmarshal(f.Payload, &deliver); err != nil {
			return
		}
		m.handleInboundDeliver(pc, peerHex, &deliver)
	case pb.FrameType_FRAME_TYPE_FED_REQUEST:
		var req pb.FedRequest
		if err := proto.Unmarshal(f.Payload, &req); err != nil {
			return
		}
		m.handleInboundRequest(pc, peerHex, &req)
	case pb.FrameType_FRAME_TYPE_FED_RESPONSE:
		var resp pb.FedResponse
		if err := proto.Unmarshal(f.Payload, &resp); err != nil {
			return
		}
		m.handleInboundResponse(peerHex, &resp)
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

// sendFedPolicy loads rules and export list from the store and enqueues a
// FED_POLICY frame on the peer's ctrl channel. Non-blocking: returns an error
// only on store failure or full ctrl channel (extremely rare).
func (m *Manager) sendFedPolicy(pc *peer.PeerConn, peerHex string) error {
	out, err := m.store.GetOutboundPolicy(peerHex)
	if err != nil {
		return err
	}
	in, err := m.store.GetInboundPolicy(peerHex)
	if err != nil {
		return err
	}
	exported, err := m.store.GetExportList(peerHex)
	if err != nil {
		return err
	}
	pol := &pb.FedPolicy{}
	for _, r := range out {
		pol.Outbound = append(pol.Outbound, &pb.FedPolicyRule{
			SubjectPattern: r.SubjectPattern,
			Effect:         r.Effect,
		})
	}
	for _, r := range in {
		pol.Inbound = append(pol.Inbound, &pb.FedPolicyRule{
			SubjectPattern: r.SubjectPattern,
			Effect:         r.Effect,
		})
	}
	for _, entityHex := range exported {
		entityBytes, err := hex.DecodeString(entityHex)
		if err != nil {
			continue
		}
		pol.ExportedPubkeys = append(pol.ExportedPubkeys, entityBytes)
	}
	b, err := proto.Marshal(pol)
	if err != nil {
		return err
	}
	if !pc.SendCtrl(pb.FrameType_FRAME_TYPE_FED_POLICY, b) {
		return fmt.Errorf("sendFedPolicy: ctrl channel full for peer %s", peerHex)
	}
	return nil
}

// runPeerWriteLoop wraps pc.RunWriteLoop in a manager-tracked goroutine.
// onWriteError calls dropPeer so the peer is cleaned up if the stream dies.
func (m *Manager) runPeerWriteLoop(pc *peer.PeerConn, peerHex string, resetOnDrop bool) {
	defer m.wg.Done()
	pc.RunWriteLoop(m.done, m.log, func() {
		m.dropPeer(peerHex, resetOnDrop)
	})
}

// dropPeer removes the peer from the active peers map and optionally resets its
// store state to "pending". Safe to call concurrently from read and write loops.
func (m *Manager) dropPeer(peerHex string, resetOnDrop bool) {
	m.peers.Delete(peerHex)
	if resetOnDrop {
		m.store.UpdatePeerState(peerHex, "pending") //nolint:errcheck
	}
}

// loadPolicies reads outbound and inbound policy rules from SQLite and refreshes
// the in-memory policy engines for peerHex. Called on activation and after any
// policy update so ForwardIfNeeded doesn't need to hit SQLite on the hot path.
func (m *Manager) loadPolicies(peerHex string) {
	outRules, err := m.store.GetOutboundPolicy(peerHex)
	if err != nil {
		m.log.Warn("fed: loadPolicies: GetOutboundPolicy failed", "peer", peerHex, "err", err)
		return
	}
	inRules, err := m.store.GetInboundPolicy(peerHex)
	if err != nil {
		m.log.Warn("fed: loadPolicies: GetInboundPolicy failed", "peer", peerHex, "err", err)
		return
	}
	outEngRules := make([]fedpolicy.Rule, 0, len(outRules))
	for _, r := range outRules {
		eff := fedpolicy.EffectDeny
		if r.Effect == "forward" {
			eff = fedpolicy.EffectForward
		}
		outEngRules = append(outEngRules, fedpolicy.Rule{SubjectPattern: r.SubjectPattern, Effect: eff})
	}
	inEngRules := make([]fedpolicy.Rule, 0, len(inRules))
	for _, r := range inRules {
		eff := fedpolicy.EffectDeny
		if r.Effect == "accept" {
			eff = fedpolicy.EffectAccept
		}
		inEngRules = append(inEngRules, fedpolicy.Rule{SubjectPattern: r.SubjectPattern, Effect: eff})
	}
	m.outPolicies.Store(peerHex, fedpolicy.NewEngine(outEngRules))
	m.inPolicies.Store(peerHex, fedpolicy.NewEngine(inEngRules))
}

// ForwardIfNeeded is called by the node after every successful local fanout.
// It iterates all active peers, evaluates the outbound forwarding policy for
// each, and enqueues a FedDeliver frame on the peer's data channel.
// SchemaDescriptor is piggybacked on the first forward of any subject to a
// given peer (LoadOrStore atomically guards against duplicate sends).
func (m *Manager) ForwardIfNeeded(subject string, payload []byte, publisherPubkey []byte) {
	pubIdentity := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(publisherPubkey)
	m.peers.Range(func(key, val any) bool {
		peerHex := key.(string)
		pc := val.(*peer.PeerConn)
		if pc.State() != peer.StateActive {
			return true
		}
		v, ok := m.outPolicies.Load(peerHex)
		if !ok {
			return true // no engine = deny
		}
		eng := v.(*fedpolicy.Engine)
		if eng.Evaluate(subject) != fedpolicy.EffectForward {
			return true
		}

		deliver := &pb.FedDeliver{
			Subject:          subject,
			Payload:          payload,
			PublisherIdentity: pubIdentity,
			PublishedAt:      time.Now().UnixMilli(),
		}

		// Piggyback SchemaDescriptor on first forward of this subject to this peer.
		if m.nodeHooks != nil {
			fdBytes := m.nodeHooks.SchemaRegistry().Descriptor(subject)
			if fdBytes != nil {
				trackerKey := peerHex + ":" + subject
				if _, loaded := m.schemaTracker.LoadOrStore(trackerKey, struct{}{}); !loaded {
					deliver.SchemaDescriptor = fdBytes
				}
			}
		}

		b, err := proto.Marshal(deliver)
		if err != nil {
			return true
		}
		if !pc.SendData(pb.FrameType_FRAME_TYPE_FED_DELIVER, b) {
			m.log.Warn("fed: FedDeliver dropped (data channel full)", "peer", peerHex, "subject", subject)
		}
		return true
	})
}

// handleInboundDeliver processes a FedDeliver frame received from a peer.
// Checks inbound policy; if accepted, optionally registers the schema and
// delivers the payload to local subscribers via nodeHooks.FederatedPublish.
func (m *Manager) handleInboundDeliver(pc *peer.PeerConn, peerHex string, msg *pb.FedDeliver) {
	v, ok := m.inPolicies.Load(peerHex)
	if !ok {
		return // no inbound engine = deny
	}
	if v.(*fedpolicy.Engine).Evaluate(msg.Subject) != fedpolicy.EffectAccept {
		return
	}
	if len(msg.SchemaDescriptor) > 0 && m.nodeHooks != nil {
		reg := m.nodeHooks.SchemaRegistry()
		if reg.Version(msg.Subject) == 0 {
			msgName := extractMsgName(msg.SchemaDescriptor)
			if msgName != "" {
				reg.Register(msg.Subject, msgName, msg.SchemaDescriptor) //nolint:errcheck
			}
		}
	}
	if m.nodeHooks != nil {
		m.nodeHooks.FederatedPublish(msg.Subject, msg.Payload, pc.PeerPubkey())
	}
}

// ─── S5: Cross-federation call routing ────────────────────────────────────────

// TryRouteRequest attempts to route a REQUEST to a remote peer via federation.
// Returns true if the request was handed off to a peer (caller should not send
// NOT_FOUND). Returns false if the target is not in the remote entity routing
// table or the peer is not active.
func (m *Manager) TryRouteRequest(req *pb.Request, requesterSID string) bool {
	targetHex := hex.EncodeToString(req.TargetPubkey)
	peerHexVal, ok := m.remoteEntities.Load(targetHex)
	if !ok {
		return false
	}
	peerHex := peerHexVal.(string)

	v, ok := m.peers.Load(peerHex)
	if !ok {
		return false
	}
	pc := v.(*peer.PeerConn)
	if pc.State() != peer.StateActive {
		return false
	}

	timeoutMs := req.TimeoutMs
	if timeoutMs == 0 {
		timeoutMs = 5000
	}
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	m.fedCalls.AddOutbound(req.CorrelationId, requesterSID, pc.PeerPubkey(), deadline)

	fedReq := &pb.FedRequest{
		CorrelationId:    req.CorrelationId,
		TargetPubkey:     req.TargetPubkey,
		Payload:          req.Payload,
		TimeoutMs:        req.TimeoutMs,
		CallerIdentity:   req.CallerIdentity, // already stamped by handleRequest
		ReceivedAt:       req.ReceivedAt,
		RequesterNodePub: m.localPub,
	}
	b, err := proto.Marshal(fedReq)
	if err != nil {
		m.fedCalls.RemoveOutbound(req.CorrelationId)
		return false
	}
	if !pc.SendData(pb.FrameType_FRAME_TYPE_FED_REQUEST, b) {
		m.fedCalls.RemoveOutbound(req.CorrelationId)
		m.log.Warn("fed: FedRequest dropped (data channel full)", "peer", peerHex,
			"corrID", req.CorrelationId)
		return false
	}
	return true
}

// handleInboundRequest processes a FED_REQUEST from a peer and routes it to
// the local target entity via nodeHooks.RouteLocalRequest.
func (m *Manager) handleInboundRequest(pc *peer.PeerConn, peerHex string, req *pb.FedRequest) {
	if m.nodeHooks == nil {
		return
	}
	m.nodeHooks.RouteLocalRequest(
		req.CorrelationId,
		req.TargetPubkey,
		req.Payload,
		req.CallerIdentity,
		req.ReceivedAt,
		req.TimeoutMs,
		pc.PeerPubkey(),
	)
}

// handleInboundResponse processes a FED_RESPONSE from a peer. Looks up the
// outbound call by correlation ID and routes the response to the local
// requester via nodeHooks.RouteLocalResponse.
func (m *Manager) handleInboundResponse(peerHex string, resp *pb.FedResponse) {
	oc := m.fedCalls.RemoveOutbound(resp.CorrelationId)
	if oc == nil {
		return // already expired or unknown
	}
	if m.nodeHooks != nil {
		m.nodeHooks.RouteLocalResponse(resp.CorrelationId, resp.Payload, oc.RequesterLocalSID)
	}
}

// ForwardResponse sends a FED_RESPONSE back to the peer node identified by
// peerPubkey. Called from node.Server.handleResponse when the RESPONSE is for
// a cross-federation inbound call (FedSourcePeerPubkey is set).
func (m *Manager) ForwardResponse(corrID string, payload []byte, peerPubkey []byte) {
	peerHex := hex.EncodeToString(peerPubkey)
	v, ok := m.peers.Load(peerHex)
	if !ok {
		m.log.Warn("fed: ForwardResponse: peer not found", "peer", peerHex[:8], "corrID", corrID)
		return
	}
	pc := v.(*peer.PeerConn)
	if pc.State() != peer.StateActive {
		m.log.Warn("fed: ForwardResponse: peer not active", "peer", peerHex[:8], "corrID", corrID)
		return
	}
	resp := &pb.FedResponse{
		CorrelationId: corrID,
		Payload:       payload,
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		return
	}
	if !pc.SendData(pb.FrameType_FRAME_TYPE_FED_RESPONSE, b) {
		m.log.Warn("fed: FedResponse dropped (data channel full)", "peer", peerHex[:8], "corrID", corrID)
	}
}

// handleInboundPolicy processes a FED_POLICY frame from a peer. Updates the
// in-memory remote entity routing table with the peer's exported pubkeys and
// persists them to SQLite for restart recovery.
func (m *Manager) handleInboundPolicy(pc *peer.PeerConn, peerHex string, pol *pb.FedPolicy) {
	// Remove old routing entries for this peer.
	m.remoteEntities.Range(func(k, v any) bool {
		if v.(string) == peerHex {
			m.remoteEntities.Delete(k)
		}
		return true
	})
	// Insert new entries and collect for SQLite persistence.
	entityHexes := make([]string, 0, len(pol.ExportedPubkeys))
	for _, pk := range pol.ExportedPubkeys {
		entityHex := hex.EncodeToString(pk)
		m.remoteEntities.Store(entityHex, peerHex)
		entityHexes = append(entityHexes, entityHex)
	}
	m.store.SetExportList(peerHex, entityHexes) //nolint:errcheck
}

// runFedCallTimeoutChecker ticks every second and sends errors to local
// requesters whose cross-federation outbound calls have exceeded their deadline.
func (m *Manager) runFedCallTimeoutChecker() {
	defer m.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			for _, exp := range m.fedCalls.ExpiredOutbound(time.Now()) {
				if m.nodeHooks != nil {
					m.nodeHooks.SendLocalError(
						exp.RequesterLocalSID,
						"TIMEOUT",
						"cross-federation call timed out",
						exp.CorrelationID,
					)
				}
			}
		case <-m.done:
			return
		}
	}
}

// extractMsgName parses a raw FileDescriptorProto and returns the name of the
// first top-level message, or "" on any parse error.
func extractMsgName(fdBytes []byte) string {
	var fdProto descriptorpb.FileDescriptorProto
	if err := proto.Unmarshal(fdBytes, &fdProto); err != nil {
		return ""
	}
	if len(fdProto.MessageType) == 0 || fdProto.MessageType[0].Name == nil {
		return ""
	}
	return *fdProto.MessageType[0].Name
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
