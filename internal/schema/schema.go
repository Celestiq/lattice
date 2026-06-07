// Package schema validates PUBLISH payloads against registered schemas.
package schema

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	pb "lattice/proto"
)

// registry maps subject → validator function.
var registry = map[string]func([]byte) error{
	"home.sensor.temperature": validateTemperature,
	"home.light.command":      validateLightCommand,
}

// Validate checks payload against the schema registered for subject.
// Returns a descriptive error if validation fails or the subject is unknown.
func Validate(subject string, payload []byte) error {
	v, ok := registry[subject]
	if !ok {
		return fmt.Errorf("unknown subject: no schema registered for %q", subject)
	}
	return v(payload)
}

// ─── home.sensor.temperature ─────────────────────────────────────────────────

func validateTemperature(payload []byte) error {
	var msg pb.TemperatureReading
	if err := proto.Unmarshal(payload, &msg); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	if msg.Value == nil {
		return errors.New("field 'value' is required")
	}
	v := *msg.Value
	if v < -50.0 || v > 150.0 {
		return fmt.Errorf("field 'value' out of range: %g is not in [-50, 150]", v)
	}
	if msg.Unit != nil && len(*msg.Unit) > 10 {
		return fmt.Errorf("field 'unit' exceeds max length: %d > 10", len(*msg.Unit))
	}
	return nil
}

// ─── home.light.command ──────────────────────────────────────────────────────

func validateLightCommand(payload []byte) error {
	var msg pb.LightCommand
	if err := proto.Unmarshal(payload, &msg); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	if msg.Action == nil {
		return errors.New("field 'action' is required")
	}
	switch *msg.Action {
	case pb.LightAction_LIGHT_ACTION_ON,
		pb.LightAction_LIGHT_ACTION_OFF,
		pb.LightAction_LIGHT_ACTION_TOGGLE:
		// valid
	default:
		return fmt.Errorf("field 'action' has invalid value: %v", *msg.Action)
	}
	if msg.Brightness != nil {
		b := *msg.Brightness
		if b < 0.0 || b > 1.0 {
			return fmt.Errorf("field 'brightness' out of range: %g is not in [0.0, 1.0]", b)
		}
	}
	return nil
}
