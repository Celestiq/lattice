// Package session manages authenticated connection state.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	pb "lattice/proto"
)

// Record holds state for a single authenticated connection.
type Record struct {
	ID           string           // UUID v4
	Pubkey       []byte           // Ed25519 public key (32 bytes)
	Token        []byte           // 32-byte random session token
	CreatedAt    time.Time
	Capabilities []*pb.Capability // declared at HELLO time; informational only
}

// Table is a thread-safe session store indexed by session ID and by pubkey.
// If the same pubkey reconnects, the new session overwrites the old one.
type Table struct {
	mu       sync.RWMutex
	byID     map[string]*Record
	byPubkey map[string]*Record // hex(pubkey) → record
}

func NewTable() *Table {
	return &Table{
		byID:     make(map[string]*Record),
		byPubkey: make(map[string]*Record),
	}
}

// Create registers a new session for pubkey and returns it.
func (t *Table) Create(pubkey []byte) (*Record, error) {
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	rec := &Record{
		ID:        id,
		Pubkey:    append([]byte(nil), pubkey...),
		Token:     token[:],
		CreatedAt: time.Now(),
	}
	key := hex.EncodeToString(pubkey)

	t.mu.Lock()
	defer t.mu.Unlock()
	t.byID[rec.ID] = rec
	t.byPubkey[key] = rec
	return rec, nil
}

// ByID returns the session with the given ID, or nil.
func (t *Table) ByID(id string) *Record {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byID[id]
}

// ByPubkey returns the active session for pubkey, or nil.
func (t *Table) ByPubkey(pubkey []byte) *Record {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byPubkey[hex.EncodeToString(pubkey)]
}

// Remove deletes a session by ID. No-op if not found.
func (t *Table) Remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.byID[id]
	if !ok {
		return
	}
	delete(t.byID, id)
	delete(t.byPubkey, hex.EncodeToString(rec.Pubkey))
}

// Len returns the number of active sessions.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byID)
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
