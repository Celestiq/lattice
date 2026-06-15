package fedcalls_test

import (
	"testing"
	"time"

	fedcalls "lattice/internal/federation/calls"
)

func TestAddOutboundRemoveRoundTrip(t *testing.T) {
	r := fedcalls.New()
	peerPub := make([]byte, 32)
	for i := range peerPub {
		peerPub[i] = byte(i)
	}
	deadline := time.Now().Add(5 * time.Second)

	r.AddOutbound("corr-1", "sess-abc", peerPub, deadline)

	oc := r.RemoveOutbound("corr-1")
	if oc == nil {
		t.Fatal("expected non-nil OutboundCall")
	}
	if oc.RequesterLocalSID != "sess-abc" {
		t.Errorf("RequesterLocalSID = %q, want %q", oc.RequesterLocalSID, "sess-abc")
	}
	if len(oc.TargetPeerPubkey) != 32 || oc.TargetPeerPubkey[1] != 1 {
		t.Error("TargetPeerPubkey not copied correctly")
	}
}

func TestRemoveOutboundNonDestructivePeek(t *testing.T) {
	r := fedcalls.New()
	r.AddOutbound("corr-1", "sess-1", nil, time.Now().Add(time.Hour))

	// First remove succeeds.
	if oc := r.RemoveOutbound("corr-1"); oc == nil {
		t.Fatal("first remove: expected non-nil")
	}
	// Second remove returns nil (already removed).
	if oc := r.RemoveOutbound("corr-1"); oc != nil {
		t.Error("second remove: expected nil, got non-nil")
	}
}

func TestRemoveOutboundUnknown(t *testing.T) {
	r := fedcalls.New()
	if r.RemoveOutbound("nonexistent") != nil {
		t.Fatal("expected nil for unknown corrID")
	}
}

func TestExpiredOutboundRemovesExpired(t *testing.T) {
	r := fedcalls.New()
	past := time.Now().Add(-time.Second)
	future := time.Now().Add(time.Hour)

	r.AddOutbound("expired-1", "sess-1", nil, past)
	r.AddOutbound("expired-2", "sess-2", nil, past)
	r.AddOutbound("live", "sess-3", nil, future)

	expired := r.ExpiredOutbound(time.Now())
	if len(expired) != 2 {
		t.Fatalf("expected 2 expired calls, got %d", len(expired))
	}
	// The live call must still be retrievable.
	if r.RemoveOutbound("live") == nil {
		t.Error("live call was incorrectly removed by ExpiredOutbound")
	}
}

func TestExpiredOutboundCleansUpBeforeRemove(t *testing.T) {
	r := fedcalls.New()
	r.AddOutbound("corr-1", "sess-1", nil, time.Now().Add(-time.Second))
	r.ExpiredOutbound(time.Now())
	// Entry should be gone after expiry sweep.
	if r.RemoveOutbound("corr-1") != nil {
		t.Error("expected call to be gone after ExpiredOutbound")
	}
}

func TestAddOutboundPubkeyCopied(t *testing.T) {
	r := fedcalls.New()
	peerPub := []byte{1, 2, 3}
	r.AddOutbound("corr-1", "sess-1", peerPub, time.Now().Add(time.Hour))

	// Mutate original slice — stored copy must be unaffected.
	peerPub[0] = 99
	oc := r.RemoveOutbound("corr-1")
	if oc == nil {
		t.Fatal("expected non-nil")
	}
	if oc.TargetPeerPubkey[0] != 1 {
		t.Errorf("pubkey was not copied: got %d, want 1", oc.TargetPeerPubkey[0])
	}
}
