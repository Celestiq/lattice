package node

import (
	"sync"
	"sync/atomic"
)

// subjectSequencer assigns per-subject monotonic uint64 IDs for DELIVER frames.
// IDs start at 1 and increment independently per concrete subject (Decision #4).
type subjectSequencer struct {
	m sync.Map // subject (string) → *atomic.Uint64
}

func (s *subjectSequencer) Next(subject string) uint64 {
	v, _ := s.m.LoadOrStore(subject, new(atomic.Uint64))
	return v.(*atomic.Uint64).Add(1)
}
