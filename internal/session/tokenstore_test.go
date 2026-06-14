package session_test

import (
	"testing"
	"time"

	"lattice/internal/session"
)

func newKey(b byte) []byte {
	k := make([]byte, 32)
	k[0] = b
	return k
}

func TestConsumeHappyPath(t *testing.T) {
	ts := session.NewTokenStore(5 * time.Minute)
	pub := newKey(1)
	token := newKey(2)
	patterns := []string{"home.>", "work.>"}

	ts.Save(token, pub, patterns)
	got, ok := ts.Consume(token, pub)
	if !ok {
		t.Fatal("Consume should succeed on first use")
	}
	if len(got) != 2 || got[0] != "home.>" {
		t.Fatalf("unexpected patterns: %v", got)
	}
}

func TestConsumeSingleUse(t *testing.T) {
	ts := session.NewTokenStore(5 * time.Minute)
	pub := newKey(1)
	token := newKey(2)
	ts.Save(token, pub, nil)
	ts.Consume(token, pub)

	_, ok := ts.Consume(token, pub)
	if ok {
		t.Fatal("second Consume must fail — token is single-use")
	}
}

func TestConsumeWrongPubkey(t *testing.T) {
	ts := session.NewTokenStore(5 * time.Minute)
	pub := newKey(1)
	other := newKey(9)
	token := newKey(2)
	ts.Save(token, pub, nil)

	_, ok := ts.Consume(token, other)
	if ok {
		t.Fatal("Consume with wrong pubkey must fail")
	}
	// Token must still be present (not consumed).
	_, ok = ts.Consume(token, pub)
	if !ok {
		t.Fatal("token should still be consumable after pubkey mismatch")
	}
}

func TestConsumeExpired(t *testing.T) {
	ts := session.NewTokenStore(10 * time.Millisecond)
	pub := newKey(1)
	token := newKey(2)
	ts.Save(token, pub, nil)
	time.Sleep(20 * time.Millisecond)

	_, ok := ts.Consume(token, pub)
	if ok {
		t.Fatal("Consume on expired token must fail")
	}
}

func TestExpireTokensSweepsExpired(t *testing.T) {
	ts := session.NewTokenStore(20 * time.Millisecond)
	pub := newKey(1)
	expiredToken := newKey(2)
	liveToken := newKey(3)

	ts.Save(expiredToken, pub, nil)
	time.Sleep(30 * time.Millisecond)
	ts.Save(liveToken, pub, nil)

	ts.ExpireTokens()

	// Expired token should be gone.
	_, ok := ts.Consume(expiredToken, pub)
	if ok {
		t.Fatal("expired token should have been swept by ExpireTokens")
	}
	// Live token should still work.
	_, ok = ts.Consume(liveToken, pub)
	if !ok {
		t.Fatal("live token should still be consumable after ExpireTokens")
	}
}

func TestDeleteRemovesToken(t *testing.T) {
	ts := session.NewTokenStore(5 * time.Minute)
	pub := newKey(1)
	token := newKey(2)
	ts.Save(token, pub, nil)
	ts.Delete(token)

	_, ok := ts.Consume(token, pub)
	if ok {
		t.Fatal("Consume after Delete must fail")
	}
}
