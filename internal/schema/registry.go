package schema

import (
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	pb "lattice/proto"
)

// fieldConstraint holds validation rules for a single field.
type fieldConstraint struct {
	required  bool
	hasRange  bool
	rangeMin  float64
	rangeMax  float64
	maxLength int // 0 = unconstrained
}

// registryEntry is one registered schema.
type registryEntry struct {
	msgDesc     protoreflect.MessageDescriptor
	version     uint32
	constraints map[protoreflect.FieldNumber]fieldConstraint
}

// SubjectInfo is returned by List.
type SubjectInfo struct {
	Subject string `json:"subject"`
	Version uint32 `json:"schema_version"`
}

// Registry is a dynamic, thread-safe schema registry.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*registryEntry
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]*registryEntry)}
}

// DefaultRegistry returns a Registry pre-populated with the built-in schemas.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.registerBuiltin("home.sensor.temperature", &pb.TemperatureReading{})
	r.registerBuiltin("home.light.command", &pb.LightCommand{})
	return r
}

// registerBuiltin adds a compiled proto message to the registry at version 1.
// Panics on error (only called at package init with known-good types).
func (r *Registry) registerBuiltin(subject string, m proto.Message) {
	desc := m.ProtoReflect().Descriptor()
	r.entries[subject] = &registryEntry{
		msgDesc:     desc,
		version:     1,
		constraints: extractConstraints(desc),
	}
}

// Register dynamically adds or upgrades a schema for subject.
// fdBytes is a marshalled FileDescriptorProto; messageName selects which message
// in that file to use as the schema.
// Upgrades are additive-only (Decision #16): field removal, type changes, cardinality
// changes, and new fields marked lattice.required are rejected.
// Note: any field carrying lattice.required MUST be declared `optional` in proto3
// so that presence tracking (Has) works correctly for zero values.
func (r *Registry) Register(subject, messageName string, fdBytes []byte) error {
	var fdProto descriptorpb.FileDescriptorProto
	if err := proto.Unmarshal(fdBytes, &fdProto); err != nil {
		return fmt.Errorf("schema: unmarshal FileDescriptorProto: %w", err)
	}

	// protoregistry.GlobalFiles resolves imports (e.g. lattice_options.proto is
	// registered by its generated init() function).
	fd, err := protodesc.NewFile(&fdProto, protoregistry.GlobalFiles)
	if err != nil {
		return fmt.Errorf("schema: build FileDescriptor: %w", err)
	}

	msgDesc, err := findMessage(fd, messageName)
	if err != nil {
		return err
	}

	constraints := extractConstraints(msgDesc)

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.entries[subject]
	if exists {
		if err := checkAdditive(existing.msgDesc, msgDesc); err != nil {
			return fmt.Errorf("schema: breaking change rejected: %w", err)
		}
	}

	version := uint32(1)
	if exists {
		version = existing.version + 1
	}

	r.entries[subject] = &registryEntry{
		msgDesc:     msgDesc,
		version:     version,
		constraints: constraints,
	}
	return nil
}

// Validate checks payload against the schema registered for subject.
func (r *Registry) Validate(subject string, payload []byte) error {
	r.mu.RLock()
	entry, ok := r.entries[subject]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown subject: no schema registered for %q", subject)
	}
	return validateDynamic(entry, payload)
}

// Version returns the schema version for subject, or 0 if not registered.
func (r *Registry) Version(subject string) uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[subject]; ok {
		return e.version
	}
	return 0
}

// List returns all registered subjects and their current versions.
func (r *Registry) List() []SubjectInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SubjectInfo, 0, len(r.entries))
	for subject, e := range r.entries {
		out = append(out, SubjectInfo{Subject: subject, Version: e.version})
	}
	return out
}

// ─── Validation ───────────────────────────────────────────────────────────────

func validateDynamic(entry *registryEntry, payload []byte) error {
	dynMsg := dynamicpb.NewMessage(entry.msgDesc)
	if err := proto.Unmarshal(payload, dynMsg); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	fields := entry.msgDesc.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		fc, ok := entry.constraints[fd.Number()]
		if !ok {
			continue
		}
		present := dynMsg.Has(fd)

		if fc.required && !present {
			return fmt.Errorf("field %s is required", fd.Name())
		}
		if !present {
			continue
		}

		val := dynMsg.Get(fd)

		if fc.hasRange {
			var v float64
			switch fd.Kind() {
			case protoreflect.FloatKind, protoreflect.DoubleKind:
				v = val.Float()
			case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
				protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
				v = float64(val.Int())
			case protoreflect.Uint32Kind, protoreflect.Fixed32Kind,
				protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
				v = float64(val.Uint())
			case protoreflect.EnumKind:
				v = float64(val.Enum())
			default:
				continue
			}
			if v < fc.rangeMin {
				return fmt.Errorf("field %s value %g below minimum %g", fd.Name(), v, fc.rangeMin)
			}
			if v > fc.rangeMax {
				return fmt.Errorf("field %s value %g above maximum %g", fd.Name(), v, fc.rangeMax)
			}
		}

		if fc.maxLength > 0 {
			switch fd.Kind() {
			case protoreflect.StringKind:
				if len(val.String()) > fc.maxLength {
					return fmt.Errorf("field %s exceeds max length: %d > %d", fd.Name(), len(val.String()), fc.maxLength)
				}
			case protoreflect.BytesKind:
				if len(val.Bytes()) > fc.maxLength {
					return fmt.Errorf("field %s exceeds max length: %d > %d", fd.Name(), len(val.Bytes()), fc.maxLength)
				}
			}
		}
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// extractConstraints reads lattice.* extensions from a message descriptor's fields.
func extractConstraints(msgDesc protoreflect.MessageDescriptor) map[protoreflect.FieldNumber]fieldConstraint {
	out := make(map[protoreflect.FieldNumber]fieldConstraint)
	fields := msgDesc.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		opts := fd.Options()
		if opts == nil {
			continue
		}
		fopts, ok := opts.(*descriptorpb.FieldOptions)
		if !ok {
			continue
		}

		var fc fieldConstraint
		changed := false

		if proto.HasExtension(fopts, pb.E_Range) {
			r := proto.GetExtension(fopts, pb.E_Range).(*pb.RangeOptions)
			fc.hasRange = true
			fc.rangeMin = float64(r.Min)
			fc.rangeMax = float64(r.Max)
			changed = true
		}
		if proto.HasExtension(fopts, pb.E_MaxLength) {
			fc.maxLength = int(proto.GetExtension(fopts, pb.E_MaxLength).(uint32))
			changed = true
		}
		if proto.HasExtension(fopts, pb.E_Required) {
			fc.required = proto.GetExtension(fopts, pb.E_Required).(bool)
			changed = true
		}
		if changed {
			out[fd.Number()] = fc
		}
	}
	return out
}

// checkAdditive verifies that newDesc is additive-only relative to oldDesc.
// Rejects: field removal, type (Kind) changes, cardinality changes (e.g.
// optional→repeated), and new fields marked lattice.required (which would
// break existing publishers that don't supply the new field).
func checkAdditive(oldDesc, newDesc protoreflect.MessageDescriptor) error {
	// Verify every existing field is still present and unchanged.
	oldFields := oldDesc.Fields()
	for i := 0; i < oldFields.Len(); i++ {
		oldFd := oldFields.Get(i)
		newFd := newDesc.Fields().ByNumber(oldFd.Number())
		if newFd == nil {
			return fmt.Errorf("field %s (number %d) removed", oldFd.Name(), oldFd.Number())
		}
		if oldFd.Kind() != newFd.Kind() {
			return fmt.Errorf("field %s type changed from %v to %v", oldFd.Name(), oldFd.Kind(), newFd.Kind())
		}
		if oldFd.Cardinality() != newFd.Cardinality() {
			return fmt.Errorf("field %s cardinality changed from %v to %v", oldFd.Name(), oldFd.Cardinality(), newFd.Cardinality())
		}
	}
	// New fields are allowed only if they are not required; a new required field
	// causes existing publishers (who don't know about it) to fail validation.
	newFields := newDesc.Fields()
	for i := 0; i < newFields.Len(); i++ {
		newFd := newFields.Get(i)
		if oldDesc.Fields().ByNumber(newFd.Number()) != nil {
			continue // existing field — already verified above
		}
		if fieldIsRequired(newFd) {
			return fmt.Errorf("new required field %s (number %d) breaks existing publishers", newFd.Name(), newFd.Number())
		}
	}
	return nil
}

// fieldIsRequired reports whether the lattice.required extension is true for fd.
func fieldIsRequired(fd protoreflect.FieldDescriptor) bool {
	opts := fd.Options()
	if opts == nil {
		return false
	}
	fopts, ok := opts.(*descriptorpb.FieldOptions)
	if !ok {
		return false
	}
	return proto.HasExtension(fopts, pb.E_Required) && proto.GetExtension(fopts, pb.E_Required).(bool)
}

// findMessage searches the top-level messages in fd for messageName.
func findMessage(fd protoreflect.FileDescriptor, messageName string) (protoreflect.MessageDescriptor, error) {
	msgs := fd.Messages()
	for i := 0; i < msgs.Len(); i++ {
		m := msgs.Get(i)
		if string(m.Name()) == messageName || string(m.FullName()) == messageName {
			return m, nil
		}
	}
	return nil, fmt.Errorf("schema: message %q not found in %s", messageName, fd.Path())
}
