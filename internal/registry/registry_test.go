package registry_test

import (
	"testing"
	"time"

	"lattice/internal/registry"
)

func newPub(b byte) []byte {
	key := make([]byte, 32)
	key[0] = b
	return key
}

func TestRegisterAndGet(t *testing.T) {
	r := registry.New()
	pub := newPub(1)
	rec := r.Register("s1", pub, nil)
	if rec == nil {
		t.Fatal("Register returned nil")
	}
	got := r.Get(pub)
	if got == nil || got.SessionID != "s1" {
		t.Fatalf("Get after Register: got %v", got)
	}
}

func TestRegisterAndEvictNoExisting(t *testing.T) {
	r := registry.New()
	pub := newPub(2)
	old := r.RegisterAndEvict("s1", pub, nil)
	if old != nil {
		t.Fatalf("expected nil old record, got %+v", old)
	}
	got := r.Get(pub)
	if got == nil || got.SessionID != "s1" {
		t.Fatalf("Get after RegisterAndEvict: got %v", got)
	}
}

func TestRegisterAndEvictReturnsOld(t *testing.T) {
	r := registry.New()
	pub := newPub(3)

	r.Register("s1", pub, nil)
	old := r.RegisterAndEvict("s2", pub, nil)

	if old == nil {
		t.Fatal("expected old record, got nil")
	}
	if old.SessionID != "s1" {
		t.Fatalf("expected old session s1, got %q", old.SessionID)
	}
	// New session must be live.
	got := r.Get(pub)
	if got == nil || got.SessionID != "s2" {
		t.Fatalf("expected s2 to be registered, got %v", got)
	}
}

func TestRemoveCASMatchingSession(t *testing.T) {
	r := registry.New()
	pub := newPub(4)
	r.Register("s1", pub, nil)

	removed := r.Remove(pub, "s1")
	if removed == nil {
		t.Fatal("Remove should return the record when session matches")
	}
	if r.Get(pub) != nil {
		t.Fatal("entry should be gone after Remove")
	}
}

func TestRemoveCASStaleSession(t *testing.T) {
	r := registry.New()
	pub := newPub(5)
	r.Register("s1", pub, nil)
	r.RegisterAndEvict("s2", pub, nil) // s2 is now the live session

	// Removing with old session ID must be a no-op.
	removed := r.Remove(pub, "s1")
	if removed != nil {
		t.Fatalf("Remove with stale session ID must return nil, got %+v", removed)
	}
	// s2 must still be alive.
	got := r.Get(pub)
	if got == nil || got.SessionID != "s2" {
		t.Fatalf("s2 should still be registered, got %v", got)
	}
}

func TestStale(t *testing.T) {
	r := registry.New()
	pub1 := newPub(6)
	pub2 := newPub(7)

	r.Register("s1", pub1, nil)
	time.Sleep(50 * time.Millisecond)
	r.Register("s2", pub2, nil)

	// Only s1 should be stale at 25 ms threshold from now.
	stale := r.Stale(time.Now(), 25*time.Millisecond)
	if len(stale) != 1 || stale[0].SessionID != "s1" {
		t.Fatalf("expected only s1 to be stale, got %v", stale)
	}
}

func TestUpdateHeartbeat(t *testing.T) {
	r := registry.New()
	pub := newPub(8)
	r.Register("s1", pub, nil)

	time.Sleep(30 * time.Millisecond)
	r.UpdateHeartbeat(pub)

	// 25 ms threshold: entity just heartbeat'd, should not be stale.
	stale := r.Stale(time.Now(), 25*time.Millisecond)
	for _, rec := range stale {
		if rec.SessionID == "s1" {
			t.Fatal("s1 should not be stale after heartbeat update")
		}
	}
}

func TestUpdateHeartbeatUnknownNoop(t *testing.T) {
	r := registry.New()
	// Must not panic for an unknown pubkey.
	r.UpdateHeartbeat(newPub(9))
}

func TestAll(t *testing.T) {
	r := registry.New()
	r.Register("s1", newPub(10), nil)
	r.Register("s2", newPub(11), nil)
	all := r.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 records, got %d", len(all))
	}
}
