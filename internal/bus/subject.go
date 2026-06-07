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
