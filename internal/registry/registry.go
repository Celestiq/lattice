// Package registry tracks connected entities and their liveness state.
package registry

import (
	"encoding/hex"
	"sync"
	"time"
)

// EntityRecord holds runtime state for a connected entity.
type EntityRecord struct {
	Pubkey          []byte
	Capabilities    []string
	SessionID       string
	ConnectedAt     time.Time
	LastHeartbeatAt time.Time
}

// Registry is a thread-safe store of EntityRecords keyed by hex-encoded pubkey.
type Registry struct {
	mu       sync.RWMutex
	entities map[string]*EntityRecord
}

func New() *Registry {
	return &Registry{entities: make(map[string]*EntityRecord)}
}

// Register adds a new entity. If an entity with the same pubkey already exists
// it is overwritten.
func (r *Registry) Register(sessionID string, pubkey []byte, capabilities []string) *EntityRecord {
	now := time.Now()
	rec := &EntityRecord{
		Pubkey:          append([]byte(nil), pubkey...),
		Capabilities:    capabilities,
		SessionID:       sessionID,
		ConnectedAt:     now,
		LastHeartbeatAt: now,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entities[hex.EncodeToString(pubkey)] = rec
	return rec
}

// UpdateHeartbeat refreshes the liveness timestamp for pubkey. No-op if not found.
func (r *Registry) UpdateHeartbeat(pubkey []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.entities[hex.EncodeToString(pubkey)]; ok {
		rec.LastHeartbeatAt = time.Now()
	}
}

// Remove deletes the entity for pubkey and returns the record.
// Returns nil if not found.
func (r *Registry) Remove(pubkey []byte) *EntityRecord {
	key := hex.EncodeToString(pubkey)
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.entities[key]
	if !ok {
		return nil
	}
	delete(r.entities, key)
	return rec
}

// Stale returns all entities whose last heartbeat is older than threshold.
// Records are not removed — call Remove separately.
func (r *Registry) Stale(now time.Time, threshold time.Duration) []*EntityRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*EntityRecord
	for _, rec := range r.entities {
		if now.Sub(rec.LastHeartbeatAt) > threshold {
			out = append(out, rec)
		}
	}
	return out
}

// Get returns the EntityRecord for pubkey, or nil if not found.
func (r *Registry) Get(pubkey []byte) *EntityRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entities[hex.EncodeToString(pubkey)]
}

// All returns a snapshot of all registered entity records.
func (r *Registry) All() []*EntityRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*EntityRecord, 0, len(r.entities))
	for _, rec := range r.entities {
		out = append(out, rec)
	}
	return out
}
