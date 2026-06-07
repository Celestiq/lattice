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
