// Package call manages in-flight REQUEST/RESPONSE pairs.
package call

import (
	"sync"
	"time"
)

// PendingCall tracks a forwarded REQUEST waiting for its RESPONSE.
type PendingCall struct {
	RequesterSessionID string
	TargetSessionID    string // session that must send the RESPONSE (Decision #6)
	Deadline           time.Time
}

// ExpiredCall is returned by Expired for each call that has passed its deadline.
type ExpiredCall struct {
	CorrelationID      string
	RequesterSessionID string
}

// Registry is a thread-safe store of pending calls indexed by correlation ID.
type Registry struct {
	mu      sync.Mutex
	pending map[string]*PendingCall
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{pending: make(map[string]*PendingCall)}
}

// Add registers a pending call. An existing entry with the same correlation ID
// is overwritten.
func (r *Registry) Add(correlationID, requesterSessionID, targetSessionID string, deadline time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending[correlationID] = &PendingCall{
		RequesterSessionID: requesterSessionID,
		TargetSessionID:    targetSessionID,
		Deadline:           deadline,
	}
}

// Peek returns the pending call without removing it. Returns nil if not found.
// The returned pointer is valid until the next mutation of the Registry.
func (r *Registry) Peek(correlationID string) *PendingCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending[correlationID]
}

// InvalidateTarget removes and returns all pending calls whose target session
// matches targetSessionID. Used when a target entity is evicted (Decision #12).
func (r *Registry) InvalidateTarget(targetSessionID string) []ExpiredCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ExpiredCall
	for id, pc := range r.pending {
		if pc.TargetSessionID == targetSessionID {
			out = append(out, ExpiredCall{
				CorrelationID:      id,
				RequesterSessionID: pc.RequesterSessionID,
			})
			delete(r.pending, id)
		}
	}
	return out
}

// Remove deletes and returns the pending call for correlationID.
// Returns nil if not found.
func (r *Registry) Remove(correlationID string) *PendingCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	pc, ok := r.pending[correlationID]
	if !ok {
		return nil
	}
	delete(r.pending, correlationID)
	return pc
}

// Expired removes and returns all pending calls whose deadline is before now.
func (r *Registry) Expired(now time.Time) []ExpiredCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ExpiredCall
	for id, pc := range r.pending {
		if now.After(pc.Deadline) {
			out = append(out, ExpiredCall{
				CorrelationID:      id,
				RequesterSessionID: pc.RequesterSessionID,
			})
			delete(r.pending, id)
		}
	}
	return out
}
