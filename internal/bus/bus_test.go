package bus_test

import (
	"strings"
	"testing"

	"lattice/internal/bus"
)

// ─── Subject matching ─────────────────────────────────────────────────────────

func TestMatchExact(t *testing.T) {
	if !bus.Match("home.sensor.temperature", "home.sensor.temperature") {
		t.Fatal("exact match should return true")
	}
}

func TestMatchStarOneSegment(t *testing.T) {
	if !bus.Match("home.*.temperature", "home.sensor.temperature") {
		t.Fatal("* should match one segment")
	}
}

func TestMatchStarNotTwoSegments(t *testing.T) {
	// * must not match two segments
	if bus.Match("home.*.temperature", "home.deep.sensor.temperature") {
		t.Fatal("* must not match more than one segment")
	}
}

func TestMatchGtOneOrMore(t *testing.T) {
	if !bus.Match("home.>", "home.sensor.humidity") {
		t.Fatal("> should match one or more segments")
	}
	if !bus.Match("home.>", "home.sensor") {
		t.Fatal("> should match a single remaining segment")
	}
	// > does not match zero remaining segments
	if bus.Match("home.>", "home") {
		t.Fatal("> requires at least one segment after prefix")
	}
}

func TestMatchGtDifferentSubject(t *testing.T) {
	if bus.Match("home.*.temperature", "home.sensor.humidity") {
		t.Fatal("home.*.temperature must not match home.sensor.humidity")
	}
}

func TestMatchNoWildcard(t *testing.T) {
	if bus.Match("home.sensor.temperature", "home.sensor.humidity") {
		t.Fatal("exact pattern must not match different subject")
	}
}

// ─── Pattern validation ───────────────────────────────────────────────────────

func TestValidatePatternGtNonTerminal(t *testing.T) {
	if err := bus.ValidatePattern("home.>.temperature"); err == nil {
		t.Fatal("expected error for > in non-terminal position")
	}
}

func TestValidatePatternInvalidChars(t *testing.T) {
	if err := bus.ValidatePattern("home.UPPER.temp"); err == nil {
		t.Fatal("expected error for uppercase segment")
	}
}

func TestValidatePatternTooManySegments(t *testing.T) {
	// 17 segments — one over the limit
	segs := strings.Repeat("a.", 17)
	if err := bus.ValidatePattern(strings.TrimSuffix(segs, ".")); err == nil {
		t.Fatal("expected error for too many segments")
	}
}

func TestValidatePatternTooLong(t *testing.T) {
	long := strings.Repeat("a", 257)
	if err := bus.ValidatePattern(long); err == nil {
		t.Fatal("expected error for pattern exceeding 256 chars")
	}
}

// ─── Subject validation ───────────────────────────────────────────────────────

func TestValidateSubjectWildcardRejected(t *testing.T) {
	if err := bus.ValidateSubject("home.*.temperature"); err == nil {
		t.Fatal("expected error for wildcard in PUBLISH subject")
	}
}

func TestValidateSubjectSystemNamespaceRejected(t *testing.T) {
	if err := bus.ValidateSubject("lattice.system.entity.joined"); err == nil {
		t.Fatal("expected error for reserved namespace")
	}
}

// ─── Subscription registry ────────────────────────────────────────────────────

func TestSubscribeThenFanout(t *testing.T) {
	b := bus.New()
	if err := b.Subscribe("session-a", "home.sensor.temperature"); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	sids := b.Fanout("home.sensor.temperature")
	if len(sids) != 1 || sids[0] != "session-a" {
		t.Fatalf("expected [session-a], got %v", sids)
	}
}

func TestUnsubscribeStopsFanout(t *testing.T) {
	b := bus.New()
	b.Subscribe("session-a", "home.sensor.temperature")
	b.Unsubscribe("session-a", "home.sensor.temperature")
	if sids := b.Fanout("home.sensor.temperature"); len(sids) != 0 {
		t.Fatalf("expected empty fanout after unsubscribe, got %v", sids)
	}
}

func TestRemoveSessionClearsAllSubs(t *testing.T) {
	b := bus.New()
	b.Subscribe("session-a", "home.sensor.temperature")
	b.Subscribe("session-a", "home.>")
	b.RemoveSession("session-a")
	if sids := b.Fanout("home.sensor.temperature"); len(sids) != 0 {
		t.Fatalf("expected empty fanout after session removal, got %v", sids)
	}
}

func TestFanoutDeduplicatesMultipleMatchingPatterns(t *testing.T) {
	b := bus.New()
	b.Subscribe("session-a", "home.sensor.temperature") // exact match
	b.Subscribe("session-a", "home.>")                  // also matches
	sids := b.Fanout("home.sensor.temperature")
	if len(sids) != 1 {
		t.Fatalf("expected deduplicated fanout [session-a], got %v", sids)
	}
}

func TestWildcardFanoutMultipleSubscribers(t *testing.T) {
	b := bus.New()
	b.Subscribe("session-a", "home.>")
	b.Subscribe("session-b", "home.sensor.temperature")
	sids := b.Fanout("home.sensor.temperature")
	if len(sids) != 2 {
		t.Fatalf("expected 2 subscribers, got %v", sids)
	}
}
