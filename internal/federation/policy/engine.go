// Package policy implements the first-match forwarding/acceptance policy engine
// used by the federation manager to decide whether a message should cross a
// peer boundary (outbound) or be accepted for local delivery (inbound).
package policy

import (
	"sync"

	"lattice/internal/bus"
)

// Effect is the evaluation result for a subject against a rule set.
type Effect int

const (
	EffectDeny    Effect = iota // no matching rule → deny (default)
	EffectForward               // outbound: message should cross to this peer
	EffectAccept                // inbound: message should be delivered locally
)

// Rule maps a subject wildcard pattern to an effect.
type Rule struct {
	SubjectPattern string
	Effect         Effect
}

// Engine evaluates a first-match forwarding policy. The zero value is an
// engine with no rules (default deny for all subjects).
// All methods are goroutine-safe.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewEngine creates an Engine with the given rules applied in first-match order.
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: append([]Rule(nil), rules...)}
}

// Empty returns an Engine with no rules (deny all).
func Empty() *Engine { return &Engine{} }

// Evaluate returns the effect of the first rule whose SubjectPattern matches
// subject using the same wildcard semantics as the local bus (`*` and `>`).
// Returns EffectDeny if no rule matches.
func (e *Engine) Evaluate(subject string) Effect {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()
	for _, r := range rules {
		if bus.Match(r.SubjectPattern, subject) {
			return r.Effect
		}
	}
	return EffectDeny
}

// SetRules atomically replaces all rules.
func (e *Engine) SetRules(rules []Rule) {
	e.mu.Lock()
	e.rules = append([]Rule(nil), rules...)
	e.mu.Unlock()
}

// Rules returns a snapshot of the current rule set.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule(nil), e.rules...)
}
