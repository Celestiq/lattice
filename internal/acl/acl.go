// Package acl implements the Lattice access-control engine.
//
// Rules are evaluated in descending priority order. The first rule whose
// identity pattern, action, and subject pattern all match decides the outcome.
// If no rule matches, the request is denied (deny-by-default).
package acl

import (
	"encoding/base32"
	"sort"
	"sync"

	"lattice/internal/bus"
)

// Effect is the outcome of a matching rule.
type Effect int

const (
	Deny  Effect = iota
	Allow Effect = iota
)

// Action identifies what the entity is trying to do.
type Action string

const (
	ActionPublish   Action = "publish"
	ActionSubscribe Action = "subscribe"
	ActionCall      Action = "call"
)

// Rule is a single access-control entry.
type Rule struct {
	// IdentityPattern is either "*" (any identity) or a base32-encoded Ed25519 public key.
	IdentityPattern string
	Action          Action
	// SubjectPattern follows the same wildcard syntax as subscription patterns.
	// Use ">" to match all subjects.
	SubjectPattern string
	Effect         Effect
	Priority       int // higher number = evaluated first
}

// cacheKey indexes the per-identity-per-action filtered rule list.
type cacheKey struct {
	identity string
	action   Action
}

// Engine evaluates ACL rules for incoming requests.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule            // kept in descending Priority order
	cache map[cacheKey][]Rule // protected by mu; rebuilt lazily after AddRule
}

func New() *Engine {
	return &Engine{cache: make(map[cacheKey][]Rule)}
}

// AddRule inserts a rule and re-sorts the list by descending priority.
// The identity-indexed cache is invalidated so stale entries are not served.
func (e *Engine) AddRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
	sort.Slice(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})
	e.cache = make(map[cacheKey][]Rule) // drop all cached rule sets
}

// rulesFor returns the cached filtered rule list for the given identity and action.
// It uses a double-checked locking pattern: a quick read-lock check avoids the
// write-lock on the hot path once the entry is cached.
func (e *Engine) rulesFor(key cacheKey) []Rule {
	e.mu.RLock()
	cached, ok := e.cache[key]
	e.mu.RUnlock()
	if ok {
		return cached
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if cached, ok = e.cache[key]; ok {
		return cached // built by a concurrent goroutine while we waited
	}
	var filtered []Rule
	for _, r := range e.rules {
		if r.Action == key.action && matchIdentity(r.IdentityPattern, key.identity) {
			filtered = append(filtered, r)
		}
	}
	e.cache[key] = filtered
	return filtered
}

// Allow returns true if the entity identified by pubkey is permitted to
// perform action on subject. Returns false (deny) if no rule matches.
func (e *Engine) Allow(pubkey []byte, action Action, subject string) bool {
	identity := EncodeIdentity(pubkey)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, r := range e.rules {
		if r.Action != action {
			continue
		}
		if !matchIdentity(r.IdentityPattern, identity) {
			continue
		}
		if !bus.Match(r.SubjectPattern, subject) {
			continue
		}
		return r.Effect == Allow
	}
	return false // deny by default
}

// AllowPattern returns true if the subscription pattern is not wholly-denied —
// i.e., at least one concrete subject matching pattern would be permitted.
// Used at subscribe time when the entity provides a wildcard subscription pattern.
// Uses the identity-indexed rule cache for efficiency.
//
// A pattern is wholly-denied when every Allow rule that intersects it is fully
// subsumed by a higher-priority Deny rule (meaning no concrete subject under the
// pattern is actually reachable via an Allow).
func (e *Engine) AllowPattern(pubkey []byte, action Action, pattern string) bool {
	key := cacheKey{identity: EncodeIdentity(pubkey), action: action}
	rules := e.rulesFor(key)
	// Rules are sorted by descending priority. For each Allow rule that intersects
	// the subscription pattern, check whether any higher-priority (earlier-index)
	// Deny rule fully subsumes the Allow rule's pattern. If a subsumption exists,
	// every subject covered by the Allow is blocked by the Deny. If not, at least
	// one subject under the pattern is permitted, so the subscription is not
	// wholly-denied.
	for i, r := range rules {
		if r.Effect != Allow {
			continue
		}
		if !bus.PatternsIntersect(r.SubjectPattern, pattern) {
			continue
		}
		// r covers some subjects within the subscription pattern.
		// Check whether any higher-priority Deny subsumes the entire subscription
		// pattern — if so, every subject in the pattern is denied by that rule,
		// making this Allow unreachable regardless of what it covers.
		// rules[:i] are all strictly higher priority than r.
		fullyBlocked := false
		for _, deny := range rules[:i] {
			if deny.Effect != Deny {
				continue
			}
			if bus.PatternSubsumedBy(pattern, deny.SubjectPattern) {
				fullyBlocked = true
				break
			}
		}
		if !fullyBlocked {
			return true // found at least one reachable Allow
		}
	}
	return false // deny by default — no reachable Allow found
}

// AllowConcrete is the delivery-time variant of Allow. It checks whether pubkey
// can perform action on a concrete (non-wildcard) subject using the identity-indexed
// rule cache to avoid scanning the full rule list on every fanout delivery.
func (e *Engine) AllowConcrete(pubkey []byte, action Action, subject string) bool {
	key := cacheKey{identity: EncodeIdentity(pubkey), action: action}
	for _, r := range e.rulesFor(key) {
		if bus.Match(r.SubjectPattern, subject) {
			return r.Effect == Allow
		}
	}
	return false // deny by default
}

// EncodeIdentity returns the base32 (no-padding) representation of a raw
// Ed25519 public key, used as the canonical identity string in ACL rules.
func EncodeIdentity(pubkey []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(pubkey)
}

func matchIdentity(pattern, identity string) bool {
	return pattern == "*" || pattern == identity
}
