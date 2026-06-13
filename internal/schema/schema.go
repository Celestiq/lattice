// Package schema validates PUBLISH payloads against registered schemas.
package schema

// defaultRegistry backs the package-level Validate and Version functions,
// pre-populated with the built-in message types.
var defaultRegistry = DefaultRegistry()

// Validate checks payload against the schema registered for subject.
// Returns a descriptive error if validation fails or the subject is unknown.
func Validate(subject string, payload []byte) error {
	return defaultRegistry.Validate(subject, payload)
}

// Version returns the current schema version for subject, or 0 if none is registered.
func Version(subject string) uint32 {
	return defaultRegistry.Version(subject)
}
