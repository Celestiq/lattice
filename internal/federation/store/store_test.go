package fedstore_test

import (
	"path/filepath"
	"sync"
	"testing"

	fedstore "lattice/internal/federation/store"
)

// openTemp creates a file-backed Store in t.TempDir() for round-trip tests.
func openTemp(t *testing.T) (*fedstore.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fed.db")
	s, err := fedstore.Open(path)
	if err != nil {
		t.Fatal("Open:", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

// openMem creates an in-memory Store for tests that don't need persistence.
func openMem(t *testing.T) *fedstore.Store {
	t.Helper()
	s, err := fedstore.Open(":memory:")
	if err != nil {
		t.Fatal("Open :memory:", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ─── Topology Verification ────────────────────────────────────────────────────

func TestSQLiteRoundTrip(t *testing.T) {
	s, path := openTemp(t)

	const peerHex = "aabbccdd00112233445566778899aabbccdd001122334455667788990011aabb"

	// Insert peer.
	if err := s.UpsertPeer(peerHex, "Alice", "10.0.0.1:4224", "manual", "active"); err != nil {
		t.Fatal("UpsertPeer:", err)
	}

	// Outbound policy: 3 rules.
	outRules := []fedstore.PolicyRule{
		{SubjectPattern: "sensors.>", Effect: "forward"},
		{SubjectPattern: "home.command.*", Effect: "deny"},
		{SubjectPattern: ">", Effect: "deny"},
	}
	if err := s.SetOutboundPolicy(peerHex, outRules); err != nil {
		t.Fatal("SetOutboundPolicy:", err)
	}

	// Inbound policy: 2 rules.
	inRules := []fedstore.PolicyRule{
		{SubjectPattern: "sensors.>", Effect: "accept"},
		{SubjectPattern: ">", Effect: "deny"},
	}
	if err := s.SetInboundPolicy(peerHex, inRules); err != nil {
		t.Fatal("SetInboundPolicy:", err)
	}

	// Export list: 5 entity pubkeys.
	entities := []string{"e1", "e2", "e3", "e4", "e5"}
	if err := s.SetExportList(peerHex, entities); err != nil {
		t.Fatal("SetExportList:", err)
	}

	// Close and reopen from the same path.
	s.Close()
	s2, err := fedstore.Open(path)
	if err != nil {
		t.Fatal("reopen:", err)
	}
	defer s2.Close()

	// Verify peer record.
	p, err := s2.GetPeer(peerHex)
	if err != nil {
		t.Fatal("GetPeer:", err)
	}
	if p == nil {
		t.Fatal("GetPeer: nil result")
	}
	if p.Name != "Alice" || p.Addr != "10.0.0.1:4224" || p.State != "active" {
		t.Errorf("peer record mismatch: %+v", p)
	}

	// Verify outbound policy (order preserved).
	gotOut, err := s2.GetOutboundPolicy(peerHex)
	if err != nil {
		t.Fatal("GetOutboundPolicy:", err)
	}
	if len(gotOut) != len(outRules) {
		t.Fatalf("outbound rules: got %d, want %d", len(gotOut), len(outRules))
	}
	for i, want := range outRules {
		if gotOut[i] != want {
			t.Errorf("outbound[%d]: got %+v, want %+v", i, gotOut[i], want)
		}
	}

	// Verify inbound policy (order preserved).
	gotIn, err := s2.GetInboundPolicy(peerHex)
	if err != nil {
		t.Fatal("GetInboundPolicy:", err)
	}
	if len(gotIn) != len(inRules) {
		t.Fatalf("inbound rules: got %d, want %d", len(gotIn), len(inRules))
	}
	for i, want := range inRules {
		if gotIn[i] != want {
			t.Errorf("inbound[%d]: got %+v, want %+v", i, gotIn[i], want)
		}
	}

	// Verify entity map: all 5 entities point to peerHex.
	entityMap, err := s2.GetRemoteEntityMap()
	if err != nil {
		t.Fatal("GetRemoteEntityMap:", err)
	}
	if len(entityMap) != len(entities) {
		t.Fatalf("entity map: got %d entries, want %d", len(entityMap), len(entities))
	}
	for _, e := range entities {
		if entityMap[e] != peerHex {
			t.Errorf("entity %s: got peer %s, want %s", e, entityMap[e], peerHex)
		}
	}
}

// ─── Network Fault Injection & Boundary Edge Cases ───────────────────────────

func TestSQLiteOpenBadPath(t *testing.T) {
	_, err := fedstore.Open("/nonexistent/directory/fed.db")
	if err == nil {
		t.Fatal("expected error opening bad path, got nil")
	}
}

// ─── State Invalidation & Distributed Race Conditions ────────────────────────

func TestSQLiteConcurrentWrites(t *testing.T) {
	s, _ := openTemp(t)

	const n = 10
	hexes := [n]string{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"0000000000000000000000000000000000000000000000000000000000000003",
		"0000000000000000000000000000000000000000000000000000000000000004",
		"0000000000000000000000000000000000000000000000000000000000000005",
		"0000000000000000000000000000000000000000000000000000000000000006",
		"0000000000000000000000000000000000000000000000000000000000000007",
		"0000000000000000000000000000000000000000000000000000000000000008",
		"0000000000000000000000000000000000000000000000000000000000000009",
		"000000000000000000000000000000000000000000000000000000000000000a",
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.UpsertPeer(hexes[i], "peer", "addr", "manual", "active")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	all, err := s.AllPeers()
	if err != nil {
		t.Fatal("AllPeers:", err)
	}
	if len(all) != n {
		t.Errorf("AllPeers: got %d rows, want %d", len(all), n)
	}
}

// ─── E2E Distributed Workflows ────────────────────────────────────────────────

func TestFedPersistRestart(t *testing.T) {
	s, path := openTemp(t)

	const (
		peerA = "aaaa000000000000000000000000000000000000000000000000000000000001"
		peerB = "bbbb000000000000000000000000000000000000000000000000000000000002"
	)

	s.UpsertPeer(peerA, "Alpha", "10.0.0.1:4224", "manual", "active") //nolint:errcheck
	s.UpsertPeer(peerB, "Beta", "10.0.0.2:4224", "manual", "active")  //nolint:errcheck
	s.SetExportList(peerA, []string{"entity-x", "entity-y"})          //nolint:errcheck
	s.SetExportList(peerB, []string{"entity-z"})                       //nolint:errcheck
	s.Close()

	// Reopen — simulates process restart.
	s2, err := fedstore.Open(path)
	if err != nil {
		t.Fatal("reopen:", err)
	}
	defer s2.Close()

	active, err := s2.AllActivePeers()
	if err != nil {
		t.Fatal("AllActivePeers:", err)
	}
	if len(active) != 2 {
		t.Fatalf("AllActivePeers: got %d, want 2", len(active))
	}

	em, err := s2.GetRemoteEntityMap()
	if err != nil {
		t.Fatal("GetRemoteEntityMap:", err)
	}
	if em["entity-x"] != peerA || em["entity-y"] != peerA {
		t.Errorf("entity-x/y → peerA: %v", em)
	}
	if em["entity-z"] != peerB {
		t.Errorf("entity-z → peerB: %v", em)
	}
}

func TestFedRevokedPeerRejected(t *testing.T) {
	s := openMem(t)

	const peerHex = "cccc000000000000000000000000000000000000000000000000000000000003"

	s.UpsertPeer(peerHex, "Charlie", "10.0.0.3:4224", "manual", "active") //nolint:errcheck
	s.UpdatePeerState(peerHex, "revoked")                                  //nolint:errcheck

	p, err := s.GetPeer(peerHex)
	if err != nil {
		t.Fatal("GetPeer:", err)
	}
	if p == nil {
		t.Fatal("GetPeer: nil — peer disappeared after revoke")
	}
	if p.State != "revoked" {
		t.Errorf("state: got %s, want revoked", p.State)
	}

	// Revoked peer must not appear in AllActivePeers.
	active, err := s.AllActivePeers()
	if err != nil {
		t.Fatal("AllActivePeers:", err)
	}
	for _, ap := range active {
		if ap.PubkeyHex == peerHex {
			t.Error("revoked peer appeared in AllActivePeers")
		}
	}
}
