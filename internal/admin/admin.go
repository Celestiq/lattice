// Package admin implements the localhost-only HTTP admin API (Decision #15).
package admin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"lattice/internal/schema"
)

// Server is the HTTP admin API server.
type Server struct {
	registry *schema.Registry
	mux      *http.ServeMux
}

// New creates a new admin Server backed by registry.
func New(registry *schema.Registry) *Server {
	s := &Server{registry: registry, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /schema", s.handleRegisterSchema)
	s.mux.HandleFunc("GET /schema", s.handleListSchemas)
	return s
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
