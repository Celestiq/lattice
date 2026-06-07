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

// Engine evaluates ACL rules for incoming requests.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule // kept in descending Priority order
}

func New() *Engine {
	return &Engine{}
}

// AddRule inserts a rule and re-sorts the list by descending priority.
func (e *Engine) AddRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
	sort.Slice(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})
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

// EncodeIdentity returns the base32 (no-padding) representation of a raw
// Ed25519 public key, used as the canonical identity string in ACL rules.
func EncodeIdentity(pubkey []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(pubkey)
}

func matchIdentity(pattern, identity string) bool {
	return pattern == "*" || pattern == identity
}
