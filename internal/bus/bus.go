// Package bus implements the Lattice pub/sub subscription registry.
package bus

import "sync"

// Bus maps subject patterns to sets of session IDs.
type Bus struct {
	mu   sync.RWMutex
	subs map[string]map[string]struct{} // pattern → {sessionID}
}

func New() *Bus {
	return &Bus{subs: make(map[string]map[string]struct{})}
}

// Subscribe registers sessionID under pattern.
// Returns an error if pattern fails validation.
func (b *Bus) Subscribe(sessionID, pattern string) error {
	if err := ValidatePattern(pattern); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subs[pattern] == nil {
		b.subs[pattern] = make(map[string]struct{})
	}
	b.subs[pattern][sessionID] = struct{}{}
	return nil
}

// Unsubscribe removes sessionID from pattern. No-op if not registered.
func (b *Bus) Unsubscribe(sessionID, pattern string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if set, ok := b.subs[pattern]; ok {
		delete(set, sessionID)
		if len(set) == 0 {
			delete(b.subs, pattern)
		}
	}
}

// RemoveSession removes all subscriptions for sessionID.
func (b *Bus) RemoveSession(sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for pattern, set := range b.subs {
		delete(set, sessionID)
		if len(set) == 0 {
			delete(b.subs, pattern)
		}
	}
}

// Fanout returns the deduplicated list of session IDs whose patterns match subject.
func (b *Bus) Fanout(subject string) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	seen := make(map[string]struct{})
	for pattern, set := range b.subs {
		if Match(pattern, subject) {
			for sid := range set {
				seen[sid] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for sid := range seen {
		result = append(result, sid)
	}
	return result
}
