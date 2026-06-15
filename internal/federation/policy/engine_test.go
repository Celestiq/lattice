package policy_test

import (
	"testing"

	"lattice/internal/federation/policy"
)

func TestPolicyEngineDenyByDefault(t *testing.T) {
	e := policy.Empty()
	if e.Evaluate("home.sensor.temperature") != policy.EffectDeny {
		t.Error("empty engine: want EffectDeny for any subject")
	}
}

func TestPolicyEngineFirstMatchForward(t *testing.T) {
	e := policy.NewEngine([]policy.Rule{
		{SubjectPattern: "home.sensor.>", Effect: policy.EffectForward},
		{SubjectPattern: ">", Effect: policy.EffectDeny},
	})
	if e.Evaluate("home.sensor.temperature") != policy.EffectForward {
		t.Error("want EffectForward for home.sensor.temperature")
	}
	if e.Evaluate("home.light.command") != policy.EffectDeny {
		t.Error("want EffectDeny for home.light.command (second rule is deny)")
	}
}

func TestPolicyEngineFirstMatchAccept(t *testing.T) {
	e := policy.NewEngine([]policy.Rule{
		{SubjectPattern: "sensors.*", Effect: policy.EffectAccept},
	})
	if e.Evaluate("sensors.temp") != policy.EffectAccept {
		t.Error("want EffectAccept for sensors.temp")
	}
	if e.Evaluate("metrics.cpu") != policy.EffectDeny {
		t.Error("want EffectDeny for unmatched metrics.cpu")
	}
}

func TestPolicyEngineExactMatch(t *testing.T) {
	e := policy.NewEngine([]policy.Rule{
		{SubjectPattern: "home.sensor.temperature", Effect: policy.EffectForward},
	})
	if e.Evaluate("home.sensor.temperature") != policy.EffectForward {
		t.Error("want EffectForward for exact match")
	}
	if e.Evaluate("home.sensor.humidity") != policy.EffectDeny {
		t.Error("want EffectDeny for non-matching subject")
	}
}

func TestPolicyEngineGtWildcard(t *testing.T) {
	e := policy.NewEngine([]policy.Rule{
		{SubjectPattern: ">", Effect: policy.EffectForward},
	})
	for _, subj := range []string{
		"a", "a.b", "a.b.c", "home.sensor.temperature",
	} {
		if e.Evaluate(subj) != policy.EffectForward {
			t.Errorf("want EffectForward for %q with > rule", subj)
		}
	}
}

func TestPolicyEngineSetRules(t *testing.T) {
	e := policy.NewEngine([]policy.Rule{
		{SubjectPattern: "old.subject", Effect: policy.EffectForward},
	})
	if e.Evaluate("old.subject") != policy.EffectForward {
		t.Error("initial rule not working")
	}

	e.SetRules([]policy.Rule{
		{SubjectPattern: "new.subject", Effect: policy.EffectAccept},
	})
	if e.Evaluate("old.subject") != policy.EffectDeny {
		t.Error("old rule still active after SetRules")
	}
	if e.Evaluate("new.subject") != policy.EffectAccept {
		t.Error("new rule not active after SetRules")
	}
}

func TestPolicyEngineRulesSnapshot(t *testing.T) {
	rules := []policy.Rule{
		{SubjectPattern: "a.>", Effect: policy.EffectForward},
		{SubjectPattern: "b.>", Effect: policy.EffectDeny},
	}
	e := policy.NewEngine(rules)
	snapshot := e.Rules()
	if len(snapshot) != 2 {
		t.Fatalf("want 2 rules, got %d", len(snapshot))
	}
	// Mutating the snapshot must not affect the engine.
	snapshot[0].SubjectPattern = "mutated"
	if e.Evaluate("a.test") != policy.EffectForward {
		t.Error("engine affected by snapshot mutation")
	}
}
