package schema_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"lattice/internal/schema"
	pb "lattice/proto"
)

// helpers

func tempPayload(value *float32, unit *string) []byte {
	b, _ := proto.Marshal(&pb.TemperatureReading{Value: value, Unit: unit})
	return b
}

func f32(v float32) *float32 { return &v }
func str(s string) *string   { return &s }

func lightPayload(action *pb.LightAction, brightness *float32) []byte {
	b, _ := proto.Marshal(&pb.LightCommand{Action: action, Brightness: brightness})
	return b
}

func action(a pb.LightAction) *pb.LightAction { return &a }

// ─── home.sensor.temperature ─────────────────────────────────────────────────

func TestTemperatureValid(t *testing.T) {
	if err := schema.Validate("home.sensor.temperature", tempPayload(f32(25.0), str("celsius"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTemperatureValidBoundaries(t *testing.T) {
	if err := schema.Validate("home.sensor.temperature", tempPayload(f32(-50.0), nil)); err != nil {
		t.Fatalf("lower boundary -50 should be valid: %v", err)
	}
	if err := schema.Validate("home.sensor.temperature", tempPayload(f32(150.0), nil)); err != nil {
		t.Fatalf("upper boundary 150 should be valid: %v", err)
	}
}

func TestTemperatureOutOfRange(t *testing.T) {
	err := schema.Validate("home.sensor.temperature", tempPayload(f32(200.0), nil))
	if err == nil {
		t.Fatal("expected error for value 200.0 (exceeds max 150)")
	}
}

func TestTemperatureMissingRequired(t *testing.T) {
	err := schema.Validate("home.sensor.temperature", tempPayload(nil, nil))
	if err == nil {
		t.Fatal("expected error for missing required field 'value'")
	}
}

func TestTemperatureUnitAtMaxLength(t *testing.T) {
	if err := schema.Validate("home.sensor.temperature", tempPayload(f32(20.0), str("1234567890"))); err != nil {
		t.Fatalf("10-char unit should be valid: %v", err)
	}
}

func TestTemperatureUnitExceedsMaxLength(t *testing.T) {
	err := schema.Validate("home.sensor.temperature", tempPayload(f32(20.0), str("12345678901")))
	if err == nil {
		t.Fatal("expected error for unit exceeding 10 chars")
	}
}

// ─── home.light.command ──────────────────────────────────────────────────────

func TestLightCommandValidOn(t *testing.T) {
	if err := schema.Validate("home.light.command", lightPayload(action(pb.LightAction_LIGHT_ACTION_ON), f32(0.8))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLightCommandValidAllActions(t *testing.T) {
	for _, a := range []pb.LightAction{
		pb.LightAction_LIGHT_ACTION_ON,
		pb.LightAction_LIGHT_ACTION_OFF,
		pb.LightAction_LIGHT_ACTION_TOGGLE,
	} {
		if err := schema.Validate("home.light.command", lightPayload(action(a), nil)); err != nil {
			t.Fatalf("action %v should be valid: %v", a, err)
		}
	}
}

func TestLightCommandMissingAction(t *testing.T) {
	err := schema.Validate("home.light.command", lightPayload(nil, nil))
	if err == nil {
		t.Fatal("expected error for missing required field 'action'")
	}
}

func TestLightCommandInvalidEnumUnspecified(t *testing.T) {
	err := schema.Validate("home.light.command", lightPayload(action(pb.LightAction_LIGHT_ACTION_UNSPECIFIED), nil))
	if err == nil {
		t.Fatal("expected error for UNSPECIFIED action")
	}
}

func TestLightCommandBrightnessOutOfRange(t *testing.T) {
	err := schema.Validate("home.light.command", lightPayload(action(pb.LightAction_LIGHT_ACTION_ON), f32(1.5)))
	if err == nil {
		t.Fatal("expected error for brightness 1.5 (exceeds max 1.0)")
	}
}

func TestLightCommandBrightnessValid(t *testing.T) {
	if err := schema.Validate("home.light.command", lightPayload(action(pb.LightAction_LIGHT_ACTION_ON), f32(1.0))); err != nil {
		t.Fatalf("brightness 1.0 should be valid: %v", err)
	}
}

// ─── Unknown subject ─────────────────────────────────────────────────────────

func TestUnknownSubjectRejected(t *testing.T) {
	err := schema.Validate("home.sensor.humidity", []byte{})
	if err == nil {
		t.Fatal("expected error for subject with no registered schema")
	}
}
