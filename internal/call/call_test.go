package call_test

import (
	"testing"
	"time"

	"lattice/internal/call"
)

func TestAddPeekRemove(t *testing.T) {
	r := call.New()
	deadline := time.Now().Add(5 * time.Second)
	r.Add("corr1", "req-sess", "tgt-sess", deadline)

	// Peek is non-destructive.
	pc := r.Peek("corr1")
	if pc == nil {
		t.Fatal("Peek should return the pending call")
	}
	if pc.RequesterSessionID != "req-sess" || pc.TargetSessionID != "tgt-sess" {
		t.Fatalf("unexpected PendingCall: %+v", pc)
	}
	// Peek again — still there.
	if r.Peek("corr1") == nil {
		t.Fatal("Peek should be non-destructive")
	}

	// Remove returns it and deletes.
	removed := r.Remove("corr1")
	if removed == nil {
		t.Fatal("Remove should return the pending call")
	}
	if r.Peek("corr1") != nil {
		t.Fatal("call should be gone after Remove")
	}
}

func TestPeekRemoveUnknown(t *testing.T) {
	r := call.New()
	if r.Peek("unknown") != nil {
		t.Fatal("Peek on unknown corrID must return nil")
	}
	if r.Remove("unknown") != nil {
		t.Fatal("Remove on unknown corrID must return nil")
	}
}

func TestExpiredRemovesOnlyPastDeadline(t *testing.T) {
	r := call.New()
	past := time.Now().Add(-time.Second)
	future := time.Now().Add(time.Hour)

	r.Add("expired", "r1", "t1", past)
	r.Add("live", "r2", "t2", future)

	exp := r.Expired(time.Now())
	if len(exp) != 1 || exp[0].CorrelationID != "expired" {
		t.Fatalf("expected only 'expired' call, got %v", exp)
	}
	// Live call must still be present.
	if r.Peek("live") == nil {
		t.Fatal("live call must not be removed by Expired")
	}
}

func TestInvalidateTarget(t *testing.T) {
	r := call.New()
	future := time.Now().Add(time.Hour)
	r.Add("c1", "r1", "target", future)
	r.Add("c2", "r2", "target", future)
	r.Add("c3", "r3", "other", future)

	invalidated := r.InvalidateTarget("target")
	if len(invalidated) != 2 {
		t.Fatalf("expected 2 invalidated calls, got %d", len(invalidated))
	}
	// Calls targeting "target" must be gone.
	if r.Peek("c1") != nil || r.Peek("c2") != nil {
		t.Fatal("target's calls should be removed after InvalidateTarget")
	}
	// Unrelated call must survive.
	if r.Peek("c3") == nil {
		t.Fatal("unrelated call must not be removed by InvalidateTarget")
	}
}

func TestInvalidateTargetNoMatch(t *testing.T) {
	r := call.New()
	r.Add("c1", "r1", "target", time.Now().Add(time.Hour))
	result := r.InvalidateTarget("nobody")
	if len(result) != 0 {
		t.Fatalf("expected empty result for non-matching target, got %v", result)
	}
}
