// Package fedcalls tracks outbound cross-federation REQUEST/RESPONSE pairs.
//
// Node A sends a FED_REQUEST to node B and registers an OutboundCall here.
// When FED_RESPONSE arrives from B, RemoveOutbound returns the call so
// handleInboundResponse can route the response back to the local requester.
package fedcalls

import (
	"sync"
	"time"
)

// OutboundCall tracks a cross-federation REQUEST sent from this node to a peer.
type OutboundCall struct {
	RequesterLocalSID string // session on this node that sent the REQUEST
	TargetPeerPubkey  []byte // peer node the REQUEST was routed to
	Deadline          time.Time
}

// ExpiredOutbound is returned by ExpiredOutbound for each call past its deadline.
type ExpiredOutbound struct {
	CorrelationID     string
	RequesterLocalSID string
}

// Registry tracks outbound cross-federation calls indexed by correlation ID.
type Registry struct {
	mu       sync.Mutex
	outbound map[string]*OutboundCall
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{outbound: make(map[string]*OutboundCall)}
}

// AddOutbound registers an outbound cross-federation call. peerPubkey is copied.
func (r *Registry) AddOutbound(corrID, requesterSID string, peerPubkey []byte, deadline time.Time) {
	pk := make([]byte, len(peerPubkey))
	copy(pk, peerPubkey)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outbound[corrID] = &OutboundCall{
		RequesterLocalSID: requesterSID,
		TargetPeerPubkey:  pk,
		Deadline:          deadline,
	}
}

// RemoveOutbound deletes and returns the outbound call for corrID.
// Returns nil if not found.
func (r *Registry) RemoveOutbound(corrID string) *OutboundCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	oc, ok := r.outbound[corrID]
	if !ok {
		return nil
	}
	delete(r.outbound, corrID)
	return oc
}

// ExpiredOutbound removes and returns all outbound calls whose deadline is before now.
func (r *Registry) ExpiredOutbound(now time.Time) []ExpiredOutbound {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ExpiredOutbound
	for id, oc := range r.outbound {
		if now.After(oc.Deadline) {
			out = append(out, ExpiredOutbound{
				CorrelationID:     id,
				RequesterLocalSID: oc.RequesterLocalSID,
			})
			delete(r.outbound, id)
		}
	}
	return out
}
