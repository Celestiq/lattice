package acl_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"lattice/internal/acl"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// noRules: empty engine always denies.
func TestEmptyEngineDeniesAll(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)
	if e.Allow(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("empty engine should deny all")
	}
	if e.Allow(pub, acl.ActionPublish, "home.sensor.temperature") {
		t.Fatal("empty engine should deny all")
	}
}

// Exact pubkey allow rule: only that pubkey is allowed.
func TestExactPubkeyAllowRule(t *testing.T) {
	e := acl.New()
	pubA, _ := genKey(t)
	pubB, _ := genKey(t)

	e.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(pubA),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})

	if !e.Allow(pubA, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("pubA should be allowed")
	}
	if e.Allow(pubB, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("pubB should be denied (no rule)")
	}
}

// Wildcard identity allow: any pubkey is allowed on matching subject.
func TestWildcardIdentityAllow(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)

	e.AddRule(acl.Rule{
		IdentityPattern: "*",
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})

	if !e.Allow(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("wildcard rule should allow any pubkey on home.>")
	}
	// Subject outside the pattern is still denied.
	if e.Allow(pub, acl.ActionSubscribe, "work.sensor.temperature") {
		t.Fatal("subject outside pattern should be denied")
	}
}

// Deny rule at higher priority overrides allow.
func TestDenyBeatsAllow(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)
	identity := acl.EncodeIdentity(pub)

	// Lower priority allow
	e.AddRule(acl.Rule{
		IdentityPattern: "*",
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	// Higher priority deny for this specific pubkey
	e.AddRule(acl.Rule{
		IdentityPattern: identity,
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Deny,
		Priority:        20,
	})

	if e.Allow(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("deny at higher priority should block the allow")
	}
}

// Allow rule at higher priority overrides deny.
func TestAllowBeatesDeny(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)
	identity := acl.EncodeIdentity(pub)

	// Lower priority deny-all
	e.AddRule(acl.Rule{
		IdentityPattern: "*",
		Action:          acl.ActionSubscribe,
		SubjectPattern:  ">",
		Effect:          acl.Deny,
		Priority:        5,
	})
	// Higher priority allow for this pubkey
	e.AddRule(acl.Rule{
		IdentityPattern: identity,
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        15,
	})

	if !e.Allow(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("allow at higher priority should override deny")
	}
}

// Action mismatch: subscribe rule does not cover publish.
func TestActionIsolation(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)

	e.AddRule(acl.Rule{
		IdentityPattern: "*",
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})

	if !e.Allow(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("subscribe should be allowed")
	}
	if e.Allow(pub, acl.ActionPublish, "home.sensor.temperature") {
		t.Fatal("publish should be denied — no publish rule")
	}
}

// ─── AllowConcrete (delivery-time ACL) ───────────────────────────────────────

func TestAllowConcreteEmptyDenies(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)
	if e.AllowConcrete(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("empty engine must deny")
	}
}

func TestAllowConcreteAllow(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)
	e.AddRule(acl.Rule{
		IdentityPattern: "*",
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	if !e.AllowConcrete(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("should be allowed via home.>")
	}
}

// DeliveryTimeDenyFixesWildcardBypass is the core bug that Session 3 fixes:
// a subscriber on "home.>" gets allow at subscribe-time (Allow passes),
// but a higher-priority deny for the concrete subject fires at delivery time.
func TestAllowConcreteDeliveryTimeDeny(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)
	e.AddRule(acl.Rule{
		IdentityPattern: "*",
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	e.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.private.temperature",
		Effect:          acl.Deny,
		Priority:        100,
	})

	// Subscribe-time check for the broad pattern must still succeed.
	if !e.Allow(pub, acl.ActionSubscribe, "home.>") {
		t.Fatal("subscribe-time Allow must accept home.> (deny does not match that pattern)")
	}
	// Delivery-time check for the denied concrete subject must fail.
	if e.AllowConcrete(pub, acl.ActionSubscribe, "home.private.temperature") {
		t.Fatal("AllowConcrete must deny home.private.temperature")
	}
	// Other concrete subjects not covered by the deny remain allowed.
	if !e.AllowConcrete(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("AllowConcrete must allow home.sensor.temperature")
	}
}

// TestACLCacheInvalidation verifies that AddRule clears the identity-indexed
// cache so subsequent calls see the updated rule set.
func TestACLCacheInvalidation(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)
	e.AddRule(acl.Rule{
		IdentityPattern: "*",
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        10,
	})
	// Prime the cache — should allow.
	if !e.AllowConcrete(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("should be allowed before deny is added")
	}
	// Add a high-priority deny — must invalidate the cache.
	e.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.sensor.temperature",
		Effect:          acl.Deny,
		Priority:        100,
	})
	// New deny must be visible on the very next call.
	if e.AllowConcrete(pub, acl.ActionSubscribe, "home.sensor.temperature") {
		t.Fatal("should be denied after high-priority deny rule is added")
	}
}

// ─── AllowPattern (subscribe-time wholly-denied check) ───────────────────────

// TestAllowPatternWhollyDeniedRejected: a subscription pattern for which no
// concrete subject is permitted must be rejected. The only rule is a Deny, so
// there is no Allow intersecting the pattern — wholly-denied by default.
func TestAllowPatternWhollyDeniedRejected(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)
	e.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.private.>",
		Effect:          acl.Deny,
		Priority:        100,
	})
	if e.AllowPattern(pub, acl.ActionSubscribe, "home.private.>") {
		t.Fatal("AllowPattern must reject a wholly-denied subscription pattern")
	}
	// Corollary: empty engine is also wholly-denied.
	e2 := acl.New()
	if e2.AllowPattern(pub, acl.ActionSubscribe, "home.>") {
		t.Fatal("AllowPattern on empty engine must deny by default")
	}
}

// TestAllowPatternBroadAcceptedDespiteNarrowDeny: subscribing to a broad pattern
// that includes both permitted and denied subjects must be accepted because some
// concrete subjects remain reachable via the Allow rule.
//
// Rule set: deny home.private.> p100, allow home.> p50
// - home.> is NOT wholly-denied: home.sensor.temperature is allowed.
// - home.private.> IS wholly-denied: every subject under it hits the p100 deny.
func TestAllowPatternBroadAcceptedDespiteNarrowDeny(t *testing.T) {
	e := acl.New()
	pub, _ := genKey(t)
	e.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.private.>",
		Effect:          acl.Deny,
		Priority:        100,
	})
	e.AddRule(acl.Rule{
		IdentityPattern: acl.EncodeIdentity(pub),
		Action:          acl.ActionSubscribe,
		SubjectPattern:  "home.>",
		Effect:          acl.Allow,
		Priority:        50,
	})
	// Broad subscription must be accepted — subjects outside home.private.> are allowed.
	if !e.AllowPattern(pub, acl.ActionSubscribe, "home.>") {
		t.Fatal("AllowPattern must accept broad pattern when some subjects are permitted")
	}
	// Narrow subscription fully covered by the deny must be rejected.
	if e.AllowPattern(pub, acl.ActionSubscribe, "home.private.>") {
		t.Fatal("AllowPattern must reject home.private.> which is fully subsumed by the deny rule")
	}
}

// EncodeIdentity is deterministic and round-trips through base32.
func TestEncodeIdentityDeterministic(t *testing.T) {
	pub, _ := genKey(t)
	a := acl.EncodeIdentity(pub)
	b := acl.EncodeIdentity(pub)
	if a != b {
		t.Fatalf("EncodeIdentity not deterministic: %q != %q", a, b)
	}
	if len(a) == 0 {
		t.Fatal("EncodeIdentity returned empty string")
	}
}
