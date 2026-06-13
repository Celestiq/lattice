package session

import (
	"bytes"
	"encoding/hex"
	"sync"
	"time"
)

// ResumeState is the session state saved under a token for future resume.
type ResumeState struct {
	Pubkey    []byte
	Patterns  []string
	CreatedAt time.Time
}

// TokenStore maps session tokens to saved session state with a TTL.
// Consume atomically removes the entry, preventing token replay.
type TokenStore struct {
	mu     sync.Mutex
	states map[string]*ResumeState
	ttl    time.Duration
}

func NewTokenStore(ttl time.Duration) *TokenStore {
	return &TokenStore{
		states: make(map[string]*ResumeState),
		ttl:    ttl,
	}
}

// Save stores session state keyed by token. Any prior entry for the same token is replaced.
func (s *TokenStore) Save(token, pubkey []byte, patterns []string) {
	key := hex.EncodeToString(token)
	patsCopy := append([]string(nil), patterns...)
	state := &ResumeState{
		Pubkey:    append([]byte(nil), pubkey...),
		Patterns:  patsCopy,
		CreatedAt: time.Now(),
	}
	s.mu.Lock()
	s.states[key] = state
	s.mu.Unlock()
}

// Consume atomically removes and returns the patterns for token if the entry exists,
// has not expired, and pubkey matches. Returns (nil, false) on any mismatch.
func (s *TokenStore) Consume(token, pubkey []byte) ([]string, bool) {
	key := hex.EncodeToString(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.states[key]
	if !ok {
		return nil, false
	}
	if time.Since(state.CreatedAt) > s.ttl {
		delete(s.states, key)
		return nil, false
	}
	if !bytes.Equal(state.Pubkey, pubkey) {
		return nil, false
	}
	delete(s.states, key)
	return state.Patterns, true
}

// Delete removes a token without returning its state.
func (s *TokenStore) Delete(token []byte) {
	s.mu.Lock()
	delete(s.states, hex.EncodeToString(token))
	s.mu.Unlock()
}

// ExpireTokens removes all entries whose TTL has elapsed.
func (s *TokenStore) ExpireTokens() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, state := range s.states {
		if now.Sub(state.CreatedAt) > s.ttl {
			delete(s.states, key)
		}
	}
}
