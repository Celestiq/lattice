package bus

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxSegments = 16
	maxLength   = 256
)

var segmentRe = regexp.MustCompile(`^[a-z0-9\-_]+$`)

// ValidatePattern validates a subject pattern used in SUBSCRIBE.
// Wildcards * and > are permitted; > must be the terminal segment.
func ValidatePattern(pattern string) error {
	if len(pattern) > maxLength {
		return fmt.Errorf("subject: exceeds %d chars", maxLength)
	}
	segs := strings.Split(pattern, ".")
	if len(segs) > maxSegments {
		return fmt.Errorf("subject: exceeds %d segments", maxSegments)
	}
	for i, seg := range segs {
		if seg == "*" {
			continue
		}
		if seg == ">" {
			if i != len(segs)-1 {
				return errors.New("subject: '>' must be the last segment")
			}
			continue
		}
		if !segmentRe.MatchString(seg) {
			return fmt.Errorf("subject: segment %q contains invalid characters (allowed: [a-z0-9-_])", seg)
		}
	}
	return nil
}

// ValidateSubject validates a concrete subject used in PUBLISH.
// Wildcards are not allowed. The lattice.system namespace is reserved.
func ValidateSubject(subject string) error {
	if len(subject) > maxLength {
		return fmt.Errorf("subject: exceeds %d chars", maxLength)
	}
	segs := strings.Split(subject, ".")
	if len(segs) > maxSegments {
		return fmt.Errorf("subject: exceeds %d segments", maxSegments)
	}
	for _, seg := range segs {
		if seg == "*" || seg == ">" {
			return errors.New("subject: wildcards not allowed in PUBLISH subject")
		}
		if !segmentRe.MatchString(seg) {
			return fmt.Errorf("subject: segment %q contains invalid characters (allowed: [a-z0-9-_])", seg)
		}
	}
	if subject == "lattice.system" || strings.HasPrefix(subject, "lattice.system.") {
		return errors.New("subject: lattice.system.* is a server-reserved namespace")
	}
	return nil
}

// PatternsIntersect reports whether there is any concrete subject that matches
// both pattern a and pattern b. Both must be valid Lattice patterns.
// Used by the ACL engine to check subscribe-time subsumption and delivery-time rules.
func PatternsIntersect(a, b string) bool {
	return intersectSegs(strings.Split(a, "."), strings.Split(b, "."), 0, 0)
}

func intersectSegs(a, b []string, i, j int) bool {
	ia, ib := i >= len(a), j >= len(b)
	if ia && ib {
		return true // both fully consumed — an empty suffix matches
	}
	if ia || ib {
		return false // one pattern still requires segments the other cannot provide
	}
	sa, sb := a[i], b[j]
	if sa == ">" || sb == ">" {
		// ">" matches any suffix of length ≥ 1; the other side still has a segment
		// at this position (checked above), so a common subject always exists.
		return true
	}
	if sa == "*" || sb == "*" || sa == sb {
		return intersectSegs(a, b, i+1, j+1)
	}
	return false // literal mismatch — no common subject possible
}

// Match reports whether concrete subject matches pattern.
// * matches exactly one segment. > matches one or more segments and must be terminal.
func Match(pattern, subject string) bool {
	pp := strings.Split(pattern, ".")
	sp := strings.Split(subject, ".")

	for i, seg := range pp {
		if seg == ">" {
			// subject must have at least one segment at position i
			return i <= len(sp)-1
		}
		if i >= len(sp) {
			return false
		}
		if seg != "*" && seg != sp[i] {
			return false
		}
	}
	return len(pp) == len(sp)
}
