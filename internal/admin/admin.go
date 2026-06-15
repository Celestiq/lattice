// Package admin implements the localhost-only HTTP admin API (Decision #15).
package admin

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"lattice/internal/federation/manager"
	fedstore "lattice/internal/federation/store"
	"lattice/internal/schema"
)

// Server is the HTTP admin API server.
type Server struct {
	registry   *schema.Registry
	fedManager *manager.Manager // nil when federation is disabled
	mux        *http.ServeMux
}

// New creates a new admin Server backed by registry.
func New(registry *schema.Registry) *Server {
	s := &Server{registry: registry, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /schema", s.handleRegisterSchema)
	s.mux.HandleFunc("GET /schema", s.handleListSchemas)
	return s
}

// SetFederationManager attaches a federation Manager and registers the 9
// /federation/* endpoints. Idempotent within a single process lifetime.
func (s *Server) SetFederationManager(mgr *manager.Manager) {
	s.fedManager = mgr
	s.mux.HandleFunc("POST /federation/pair", s.handleFedPair)
	s.mux.HandleFunc("POST /federation/accept", s.handleFedAccept)
	s.mux.HandleFunc("POST /federation/reject", s.handleFedReject)
	s.mux.HandleFunc("POST /federation/pause", s.handleFedPause)
	s.mux.HandleFunc("POST /federation/resume", s.handleFedResume)
	s.mux.HandleFunc("POST /federation/revoke", s.handleFedRevoke)
	s.mux.HandleFunc("GET /federation/connections", s.handleFedConnections)
	s.mux.HandleFunc("POST /federation/policy", s.handleFedPolicy)
	s.mux.HandleFunc("POST /federation/export", s.handleFedExport)
}

// ListenAndServe binds to addr and serves. addr must resolve to a loopback interface.
// The server uses explicit timeouts to prevent local Slowloris and idle-connection exhaustion.
func (s *Server) ListenAndServe(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("admin: invalid addr %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("admin: addr %q must bind to a loopback address", addr)
	}
	srv := &http.Server{
		Addr:           addr,
		Handler:        s.mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64 KiB
	}
	return srv.ListenAndServe()
}

// Handler returns the underlying http.Handler for use with httptest.NewServer.
// Production code must use ListenAndServe to enforce the loopback-only constraint.
func (s *Server) Handler() http.Handler { return s.mux }

// Serve runs the admin API on the provided listener WITHOUT the loopback-address
// restriction enforced by ListenAndServe. It exists only so tests can bind a
// random-port listener. Production code MUST use ListenAndServe; serving this mux
// on a non-loopback listener exposes unauthenticated schema registration.
func (s *Server) Serve(ln net.Listener) error {
	return http.Serve(ln, s.mux)
}

// registerSchemaRequest is the JSON body for POST /schema.
type registerSchemaRequest struct {
	Subject     string `json:"subject"`
	MessageName string `json:"message_name"`
	Descriptor  string `json:"descriptor"` // base64-encoded FileDescriptorProto
}

func (s *Server) handleRegisterSchema(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<10) // 512 KiB cap
	var req registerSchemaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Subject == "" || req.MessageName == "" || req.Descriptor == "" {
		http.Error(w, "subject, message_name, and descriptor are required", http.StatusBadRequest)
		return
	}
	fdBytes, err := base64.StdEncoding.DecodeString(req.Descriptor)
	if err != nil {
		http.Error(w, "descriptor must be base64-encoded", http.StatusBadRequest)
		return
	}
	if err := s.registry.Register(req.Subject, req.MessageName, fdBytes); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSchemas(w http.ResponseWriter, r *http.Request) {
	list := s.registry.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// ─── Federation endpoint helpers ─────────────────────────────────────────────

func (s *Server) requireFedManager(w http.ResponseWriter) bool {
	if s.fedManager == nil {
		http.Error(w, "federation not enabled", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// fedPubkeyRequest is the common JSON body for endpoints that take just a pubkey.
type fedPubkeyRequest struct {
	Pubkey string `json:"pubkey"`
}

func decodeFedBody[T any](w http.ResponseWriter, r *http.Request, v *T) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
		}
		return false
	}
	return true
}

// validatePubkeyHex returns an error if s is not a valid 32-byte hex pubkey.
func validatePubkeyHex(s string) error {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("pubkey must be 64 hex characters (32 bytes)")
	}
	return nil
}

// ─── Federation endpoint handlers ────────────────────────────────────────────

// POST /federation/pair — queue a peer for pairing.
func (s *Server) handleFedPair(w http.ResponseWriter, r *http.Request) {
	if !s.requireFedManager(w) {
		return
	}
	var req struct {
		Pubkey string `json:"pubkey"`
		Name   string `json:"name"`
		Addr   string `json:"addr"`
	}
	if !decodeFedBody(w, r, &req) {
		return
	}
	if err := validatePubkeyHex(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.fedManager.PairPeer(req.Pubkey, req.Name, req.Addr); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// POST /federation/accept — accept a pending peer.
func (s *Server) handleFedAccept(w http.ResponseWriter, r *http.Request) {
	if !s.requireFedManager(w) {
		return
	}
	var req fedPubkeyRequest
	if !decodeFedBody(w, r, &req) {
		return
	}
	if err := validatePubkeyHex(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.fedManager.AcceptPeer(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /federation/reject — reject a pending peer.
func (s *Server) handleFedReject(w http.ResponseWriter, r *http.Request) {
	if !s.requireFedManager(w) {
		return
	}
	var req fedPubkeyRequest
	if !decodeFedBody(w, r, &req) {
		return
	}
	if err := validatePubkeyHex(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.fedManager.RejectPeer(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /federation/pause — pause an active peer connection.
func (s *Server) handleFedPause(w http.ResponseWriter, r *http.Request) {
	if !s.requireFedManager(w) {
		return
	}
	var req fedPubkeyRequest
	if !decodeFedBody(w, r, &req) {
		return
	}
	if err := validatePubkeyHex(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.fedManager.PausePeer(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /federation/resume — resume a paused peer connection.
func (s *Server) handleFedResume(w http.ResponseWriter, r *http.Request) {
	if !s.requireFedManager(w) {
		return
	}
	var req fedPubkeyRequest
	if !decodeFedBody(w, r, &req) {
		return
	}
	if err := validatePubkeyHex(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.fedManager.ResumePeer(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /federation/revoke — revoke a peer connection.
func (s *Server) handleFedRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.requireFedManager(w) {
		return
	}
	var req fedPubkeyRequest
	if !decodeFedBody(w, r, &req) {
		return
	}
	if err := validatePubkeyHex(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.fedManager.RevokePeer(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /federation/connections — list all peers with state and policy counts.
func (s *Server) handleFedConnections(w http.ResponseWriter, r *http.Request) {
	if !s.requireFedManager(w) {
		return
	}
	conns, err := s.fedManager.GetConnections()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if conns == nil {
		conns = []*manager.ConnectionInfo{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conns) //nolint:errcheck
}

// POST /federation/policy — update outbound and inbound policy for a peer.
func (s *Server) handleFedPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireFedManager(w) {
		return
	}
	var req struct {
		Pubkey   string                `json:"pubkey"`
		Outbound []fedstore.PolicyRule `json:"outbound"`
		Inbound  []fedstore.PolicyRule `json:"inbound"`
	}
	if !decodeFedBody(w, r, &req) {
		return
	}
	if err := validatePubkeyHex(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.fedManager.UpdatePolicy(req.Pubkey, req.Outbound, req.Inbound); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /federation/export — update the exported entity pubkeys for a peer.
func (s *Server) handleFedExport(w http.ResponseWriter, r *http.Request) {
	if !s.requireFedManager(w) {
		return
	}
	var req struct {
		Pubkey       string   `json:"pubkey"`
		EntityPubkeys []string `json:"entity_pubkeys"`
	}
	if !decodeFedBody(w, r, &req) {
		return
	}
	if err := validatePubkeyHex(req.Pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.fedManager.UpdateExportList(req.Pubkey, req.EntityPubkeys); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
