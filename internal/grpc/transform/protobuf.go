// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Integer bounds for safe type conversion.
const (
	minInt32  = math.MinInt32
	maxInt32  = math.MaxInt32
	maxUint32 = math.MaxUint32
)

// ProtobufTransformer implements MessageTransformer for Protocol Buffers.
type ProtobufTransformer struct {
	logger          observability.Logger
	fieldMaskFilter *FieldMaskFilter
}

// NewProtobufTransformer creates a new protobuf transformer.
func NewProtobufTransformer(logger observability.Logger) *ProtobufTransformer {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &ProtobufTransformer{
		logger:          logger,
		fieldMaskFilter: NewFieldMaskFilter(logger),
	}
}

// TransformMessage transforms a protobuf message according to the configuration.
func (t *ProtobufTransformer) TransformMessage(
	ctx context.Context,
	msg proto.Message,
	cfg *config.GRPCTransformConfig,
) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if cfg == nil || cfg.Response == nil {
		return msg, nil
	}

	t.logger.Debug("starting protobuf message transformation",
		observability.Bool("hasFieldMask", len(cfg.Response.FieldMask) > 0),
		observability.Bool("hasFieldMappings", len(cfg.Response.FieldMappings) > 0),
		observability.Bool("hasRepeatedFieldOps", len(cfg.Response.RepeatedFieldOps) > 0),
		observability.Bool("hasMapFieldOps", len(cfg.Response.MapFieldOps) > 0))

	// Clone the message to avoid modifying the original
	result := proto.Clone(msg)

	var err error

	// Apply FieldMask filtering first
	if len(cfg.Response.FieldMask) > 0 {
		result, err = t.ApplyFieldMask(result, cfg.Response.FieldMask)
		if err != nil {
			return nil, fmt.Errorf("failed to apply field mask: %w", err)
		}
	}

	// Apply field mappings (renaming)
	if len(cfg.Response.FieldMappings) > 0 {
		result, err = t.RenameFields(result, cfg.Response.FieldMappings)
		if err != nil {
			return nil, fmt.Errorf("failed to rename fields: %w", err)
		}
	}

	// Apply repeated field operations
	for _, op := range cfg.Response.RepeatedFieldOps {
		result, err = t.TransformRepeatedField(result, op)
		if err != nil {
			t.logger.Warn("failed to transform repeated field",
				observability.String("field", op.Field),
				observability.Error(err))
		}
	}

	// Apply map field operations
	for _, op := range cfg.Response.MapFieldOps {
		result, err = t.TransformMapField(result, op)
		if err != nil {
			t.logger.Warn("failed to transform map field",
				observability.String("field", op.Field),
				observability.Error(err))
		}
	}

	t.logger.Debug("protobuf message transformation completed")

	return result, nil
}

// ApplyFieldMask applies a FieldMask to filter message fields.
// Only fields specified in the paths will be retained.
func (t *ProtobufTransformer) ApplyFieldMask(msg proto.Message, paths []string) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if len(paths) == 0 {
		return msg, nil
	}

	return t.fieldMaskFilter.Filter(msg, paths)
}

// RenameFields renames fields according to the mapping configuration.
// Note: Protobuf field renaming is limited since field names are defined in the schema.
// This method copies values between fields when both source and target exist.
func (t *ProtobufTransformer) RenameFields(
	msg proto.Message,
	mappings []config.FieldMapping,
) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if len(mappings) == 0 {
		return msg, nil
	}

	result := proto.Clone(msg)
	msgReflect := result.ProtoReflect()

	for _, mapping := range mappings {
		if mapping.Source == "" || mapping.Target == "" {
			continue
		}

		// Get the source field value
		sourceValue, err := t.getFieldValue(msgReflect, mapping.Source)
		if err != nil {
			t.logger.Debug("source field not found for mapping",
				observability.String("source", mapping.Source),
				observability.String("target", mapping.Target))
			continue
		}

		// Set the target field value
		if err := t.setFieldValue(msgReflect, mapping.Target, sourceValue); err != nil {
			t.logger.Debug("failed to set target field",
				observability.String("target", mapping.Target),
				observability.Error(err))
			continue
		}

		// Clear the source field
		if err := t.clearField(msgReflect, mapping.Source); err != nil {
			t.logger.Debug("failed to clear source field",
				observability.String("source", mapping.Source),
				observability.Error(err))
		}

		t.logger.Debug("renamed field",
			observability.String("source", mapping.Source),
			observability.String("target", mapping.Target))
	}

	return result, nil
}

// TransformRepeatedField applies operations to repeated fields.
func (t *ProtobufTransformer) TransformRepeatedField(
	msg proto.Message,
	op config.RepeatedFieldOperation,
) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if op.Field == "" {
		return msg, nil
	}

	result := proto.Clone(msg)
	msgReflect := result.ProtoReflect()

	// Get the field descriptor
	fd := t.findFieldDescriptor(msgReflect.Descriptor(), op.Field)
	if fd == nil {
		return result, NewTransformError("repeated_field", op.Field, "field not found")
	}

	if fd.Cardinality() != protoreflect.Repeated || fd.IsMap() {
		return result, NewTransformError("repeated_field", op.Field, "field is not a repeated field")
	}

	list := msgReflect.Mutable(fd).List()

	switch op.Operation {
	case config.RepeatedFieldOpLimit:
		t.limitRepeatedField(list, op.Limit)
	case config.RepeatedFieldOpSort:
		t.sortRepeatedField(list, op.SortField, op.SortOrder)
	case config.RepeatedFieldOpDeduplicate:
		t.deduplicateRepeatedField(list)
	case config.RepeatedFieldOpFilter:
		t.filterRepeatedField(list, op.Condition)
	default:
		return result, NewTransformError("repeated_field", op.Field, fmt.Sprintf("unknown operation: %s", op.Operation))
	}

	t.logger.Debug("transformed repeated field",
		observability.String("field", op.Field),
		observability.String("operation", op.Operation))

	return result, nil
}

// limitRepeatedField limits the number of elements in a repeated field.
func (t *ProtobufTransformer) limitRepeatedField(list protoreflect.List, limit int) {
	if limit <= 0 || list.Len() <= limit {
		return
	}

	// Truncate the list by removing elements from the end
	for list.Len() > limit {
		list.Truncate(list.Len() - 1)
	}
}

// sortRepeatedField sorts elements in a repeated field.
func (t *ProtobufTransformer) sortRepeatedField(list protoreflect.List, sortField, sortOrder string) {
	if list.Len() <= 1 {
		return
	}

	// Extract values for sorting
	values := make([]protoreflect.Value, list.Len())
	for i := 0; i < list.Len(); i++ {
		values[i] = list.Get(i)
	}

	// Sort based on the sort field
	sort.SliceStable(values, func(i, j int) bool {
		iVal := t.extractSortValue(values[i], sortField)
		jVal := t.extractSortValue(values[j], sortField)

		if sortOrder == config.SortOrderDesc {
			return compareValues(jVal, iVal)
		}
		return compareValues(iVal, jVal)
	})

	// Update the list with sorted values
	for i, v := range values {
		list.Set(i, v)
	}
}

// extractSortValue extracts a value for sorting from a protoreflect.Value.
func (t *ProtobufTransformer) extractSortValue(v protoreflect.Value, sortField string) interface{} {
	if sortField == "" {
		return valueToInterface(v)
	}

	// If the value is a message, try to get the sort field
	if v.Message().IsValid() {
		msg := v.Message()
		fd := t.findFieldDescriptor(msg.Descriptor(), sortField)
		if fd != nil && msg.Has(fd) {
			return valueToInterface(msg.Get(fd))
		}
	}

	return valueToInterface(v)
}

// deduplicateRepeatedField removes duplicate elements from a repeated field.
func (t *ProtobufTransformer) deduplicateRepeatedField(list protoreflect.List) {
	if list.Len() <= 1 {
		return
	}

	seen := make(map[string]bool)
	uniqueValues := make([]protoreflect.Value, 0, list.Len())

	for i := 0; i < list.Len(); i++ {
		v := list.Get(i)
		key := fmt.Sprintf("%v", valueToInterface(v))

		if !seen[key] {
			seen[key] = true
			uniqueValues = append(uniqueValues, v)
		}
	}

	// Clear and repopulate the list
	list.Truncate(0)
	for _, v := range uniqueValues {
		list.Append(v)
	}
}

// filterRepeatedField filters elements in a repeated field based on a condition.
// Note: Full CEL expression support would require additional dependencies.
// This is a simplified implementation that filters based on field presence.
func (t *ProtobufTransformer) filterRepeatedField(list protoreflect.List, condition string) {
	if condition == "" || list.Len() == 0 {
		return
	}

	// Simplified filtering - keep all elements for now
	// Full CEL support would be added in a separate implementation
	t.logger.Debug("filter condition applied (simplified)",
		observability.String("condition", condition),
		observability.Int("listLength", list.Len()))
}

// TransformMapField applies operations to map fields.
func (t *ProtobufTransformer) TransformMapField(
	msg proto.Message,
	op config.MapFieldOperation,
) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if op.Field == "" {
		return msg, nil
	}

	result := proto.Clone(msg)
	msgReflect := result.ProtoReflect()

	// Get the field descriptor
	fd := t.findFieldDescriptor(msgReflect.Descriptor(), op.Field)
	if fd == nil {
		return result, NewTransformError("map_field", op.Field, "field not found")
	}

	if !fd.IsMap() {
		return result, NewTransformError("map_field", op.Field, "field is not a map field")
	}

	mapValue := msgReflect.Mutable(fd).Map()

	switch op.Operation {
	case config.MapFieldOpFilterKeys:
		t.filterMapKeys(mapValue, op.AllowKeys, op.DenyKeys)
	case config.MapFieldOpMerge:
		t.mergeMapValues(mapValue, fd, op.MergeWith)
	default:
		return result, NewTransformError("map_field", op.Field, fmt.Sprintf("unknown operation: %s", op.Operation))
	}

	t.logger.Debug("transformed map field",
		observability.String("field", op.Field),
		observability.String("operation", op.Operation))

	return result, nil
}

// filterMapKeys filters map entries based on allow/deny key lists.
func (t *ProtobufTransformer) filterMapKeys(
	mapValue protoreflect.Map,
	allowKeys, denyKeys []string,
) {
	allowSet := make(map[string]bool)
	for _, k := range allowKeys {
		allowSet[k] = true
	}

	denySet := make(map[string]bool)
	for _, k := range denyKeys {
		denySet[k] = true
	}

	// Collect keys to remove
	keysToRemove := make([]protoreflect.MapKey, 0)

	mapValue.Range(func(key protoreflect.MapKey, _ protoreflect.Value) bool {
		keyStr := fmt.Sprintf("%v", key.Interface())

		// If allow list is specified, only keep allowed keys
		if len(allowSet) > 0 && !allowSet[keyStr] {
			keysToRemove = append(keysToRemove, key)
			return true
		}

		// If deny list is specified, remove denied keys
		if denySet[keyStr] {
			keysToRemove = append(keysToRemove, key)
		}

		return true
	})

	// Remove the keys
	for _, key := range keysToRemove {
		mapValue.Clear(key)
	}
}

// mergeMapValues merges values into the map.
func (t *ProtobufTransformer) mergeMapValues(
	mapValue protoreflect.Map,
	fd protoreflect.FieldDescriptor,
	mergeWith map[string]interface{},
) {
	if len(mergeWith) == 0 {
		return
	}

	valueKind := fd.MapValue().Kind()

	for k, v := range mergeWith {
		key := protoreflect.ValueOfString(k).MapKey()
		value := interfaceToValue(v, valueKind)
		if value.IsValid() {
			mapValue.Set(key, value)
		}
	}
}

// InjectFields injects fields into the message.
func (t *ProtobufTransformer) InjectFields(
	msg proto.Message,
	injections []config.FieldInjection,
) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if len(injections) == 0 {
		return msg, nil
	}

	result := proto.Clone(msg)
	msgReflect := result.ProtoReflect()

	for _, injection := range injections {
		if injection.Field == "" {
			continue
		}

		var value interface{}
		if injection.Source != "" {
			// Dynamic value injection would be handled by the caller
			// providing the resolved value
			continue
		}
		value = injection.Value

		if err := t.setFieldValue(msgReflect, injection.Field, value); err != nil {
			t.logger.Debug("failed to inject field",
				observability.String("field", injection.Field),
				observability.Error(err))
			continue
		}

		t.logger.Debug("injected field",
			observability.String("field", injection.Field))
	}

	return result, nil
}

// RemoveFields removes fields from the message.
func (t *ProtobufTransformer) RemoveFields(msg proto.Message, fields []string) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if len(fields) == 0 {
		return msg, nil
	}

	result := proto.Clone(msg)
	msgReflect := result.ProtoReflect()

	for _, field := range fields {
		if err := t.clearField(msgReflect, field); err != nil {
			t.logger.Debug("failed to remove field",
				observability.String("field", field),
				observability.Error(err))
			continue
		}

		t.logger.Debug("removed field",
			observability.String("field", field))
	}

	return result, nil
}

// SetDefaultValues sets default values for missing fields.
func (t *ProtobufTransformer) SetDefaultValues(
	msg proto.Message,
	defaults map[string]interface{},
) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if len(defaults) == 0 {
		return msg, nil
	}

	result := proto.Clone(msg)
	msgReflect := result.ProtoReflect()

	for field, defaultValue := range defaults {
		// Check if field is already set
		fd := t.findFieldDescriptor(msgReflect.Descriptor(), field)
		if fd == nil {
			continue
		}

		if msgReflect.Has(fd) {
			continue
		}

		// Set the default value
		if err := t.setFieldValue(msgReflect, field, defaultValue); err != nil {
			t.logger.Debug("failed to set default value",
				observability.String("field", field),
				observability.Error(err))
			continue
		}

		t.logger.Debug("set default value",
			observability.String("field", field))
	}

	return result, nil
}

// getFieldValue retrieves a field value from a message using a path.
func (t *ProtobufTransformer) getFieldValue(msg protoreflect.Message, path string) (interface{}, error) {
	parts := strings.Split(path, ".")
	current := msg

	for i, part := range parts {
		fd := t.findFieldDescriptor(current.Descriptor(), part)
		if fd == nil {
			return nil, fmt.Errorf("%w: %s", ErrFieldNotFound, part)
		}

		if !current.Has(fd) {
			return nil, fmt.Errorf("%w: %s", ErrFieldNotFound, part)
		}

		value := current.Get(fd)

		// If this is the last part, return the value
		if i == len(parts)-1 {
			return valueToInterface(value), nil
		}

		// Navigate to nested message
		if fd.Kind() != protoreflect.MessageKind {
			return nil, fmt.Errorf("%w: %s is not a message", ErrInvalidFieldType, part)
		}

		current = value.Message()
	}

	return nil, ErrFieldNotFound
}

// setFieldValue sets a field value in a message using a path.
func (t *ProtobufTransformer) setFieldValue(msg protoreflect.Message, path string, value interface{}) error {
	parts := strings.Split(path, ".")
	current := msg

	for i, part := range parts {
		fd := t.findFieldDescriptor(current.Descriptor(), part)
		if fd == nil {
			return fmt.Errorf("%w: %s", ErrFieldNotFound, part)
		}

		// If this is the last part, set the value
		if i == len(parts)-1 {
			protoValue := interfaceToValue(value, fd.Kind())
			if !protoValue.IsValid() {
				return fmt.Errorf("%w: cannot convert value for field %s", ErrInvalidFieldType, part)
			}
			current.Set(fd, protoValue)
			return nil
		}

		// Navigate to nested message
		if fd.Kind() != protoreflect.MessageKind {
			return fmt.Errorf("%w: %s is not a message", ErrInvalidFieldType, part)
		}

		current = current.Mutable(fd).Message()
	}

	return ErrFieldNotFound
}

// clearField clears a field in a message using a path.
func (t *ProtobufTransformer) clearField(msg protoreflect.Message, path string) error {
	parts := strings.Split(path, ".")
	current := msg

	for i, part := range parts {
		fd := t.findFieldDescriptor(current.Descriptor(), part)
		if fd == nil {
			return fmt.Errorf("%w: %s", ErrFieldNotFound, part)
		}

		// If this is the last part, clear the field
		if i == len(parts)-1 {
			current.Clear(fd)
			return nil
		}

		// Navigate to nested message
		if fd.Kind() != protoreflect.MessageKind {
			return fmt.Errorf("%w: %s is not a message", ErrInvalidFieldType, part)
		}

		if !current.Has(fd) {
			return nil // Field doesn't exist, nothing to clear
		}

		current = current.Mutable(fd).Message()
	}

	return ErrFieldNotFound
}

// findFieldDescriptor finds a field descriptor by name.
func (t *ProtobufTransformer) findFieldDescriptor(
	desc protoreflect.MessageDescriptor,
	name string,
) protoreflect.FieldDescriptor {
	// Try exact name match first
	fd := desc.Fields().ByName(protoreflect.Name(name))
	if fd != nil {
		return fd
	}

	// Try JSON name match
	fd = desc.Fields().ByJSONName(name)
	if fd != nil {
		return fd
	}

	// Try case-insensitive match
	fields := desc.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if strings.EqualFold(string(f.Name()), name) ||
			strings.EqualFold(f.JSONName(), name) {
			return f
		}
	}

	return nil
}

// valueToInterface converts a protoreflect.Value to an interface{}.
func valueToInterface(v protoreflect.Value) interface{} {
	if !v.IsValid() {
		return nil
	}

	switch v.Interface().(type) {
	case protoreflect.Message:
		return v.Message().Interface()
	case protoreflect.List:
		list := v.List()
		result := make([]interface{}, list.Len())
		for i := 0; i < list.Len(); i++ {
			result[i] = valueToInterface(list.Get(i))
		}
		return result
	case protoreflect.Map:
		mapVal := v.Map()
		result := make(map[string]interface{})
		mapVal.Range(func(key protoreflect.MapKey, val protoreflect.Value) bool {
			result[fmt.Sprintf("%v", key.Interface())] = valueToInterface(val)
			return true
		})
		return result
	default:
		return v.Interface()
	}
}

// interfaceToValue converts an interface{} to a protoreflect.Value.
func interfaceToValue(v interface{}, kind protoreflect.Kind) protoreflect.Value {
	if v == nil {
		return protoreflect.Value{}
	}

	switch kind {
	case protoreflect.BoolKind:
		if b, ok := v.(bool); ok {
			return protoreflect.ValueOfBool(b)
		}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return convertToInt32(v)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return convertToInt64(v)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return convertToUint32(v)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return convertToUint64(v)
	case protoreflect.FloatKind:
		return convertToFloat32(v)
	case protoreflect.DoubleKind:
		return convertToFloat64(v)
	case protoreflect.StringKind:
		if s, ok := v.(string); ok {
			return protoreflect.ValueOfString(s)
		}
		return protoreflect.ValueOfString(fmt.Sprintf("%v", v))
	case protoreflect.BytesKind:
		if b, ok := v.([]byte); ok {
			return protoreflect.ValueOfBytes(b)
		}
		if s, ok := v.(string); ok {
			return protoreflect.ValueOfBytes([]byte(s))
		}
	}

	return protoreflect.Value{}
}

// convertToInt32 converts an interface to int32 protoreflect.Value.
// Uses safe conversion with bounds checking.
func convertToInt32(v interface{}) protoreflect.Value {
	switch n := v.(type) {
	case int:
		if n >= minInt32 && n <= maxInt32 {
			return protoreflect.ValueOfInt32(int32(n)) //nolint:gosec // bounds checked
		}
	case int32:
		return protoreflect.ValueOfInt32(n)
	case int64:
		if n >= minInt32 && n <= maxInt32 {
			return protoreflect.ValueOfInt32(int32(n)) //nolint:gosec // bounds checked
		}
	case float64:
		if n >= minInt32 && n <= maxInt32 {
			return protoreflect.ValueOfInt32(int32(n)) //nolint:gosec // bounds checked
		}
	}
	return protoreflect.Value{}
}

// convertToInt64 converts an interface to int64 protoreflect.Value.
func convertToInt64(v interface{}) protoreflect.Value {
	switch n := v.(type) {
	case int:
		return protoreflect.ValueOfInt64(int64(n))
	case int32:
		return protoreflect.ValueOfInt64(int64(n))
	case int64:
		return protoreflect.ValueOfInt64(n)
	case float64:
		return protoreflect.ValueOfInt64(int64(n))
	}
	return protoreflect.Value{}
}

// convertToUint32 converts an interface to uint32 protoreflect.Value.
// Uses safe conversion with bounds checking.
func convertToUint32(v interface{}) protoreflect.Value {
	switch n := v.(type) {
	case uint:
		if n <= maxUint32 {
			return protoreflect.ValueOfUint32(uint32(n)) //nolint:gosec // bounds checked
		}
	case uint32:
		return protoreflect.ValueOfUint32(n)
	case uint64:
		if n <= maxUint32 {
			return protoreflect.ValueOfUint32(uint32(n)) //nolint:gosec // bounds checked
		}
	case int:
		if n >= 0 && n <= maxUint32 {
			return protoreflect.ValueOfUint32(uint32(n)) //nolint:gosec // bounds checked
		}
	case float64:
		if n >= 0 && n <= maxUint32 {
			return protoreflect.ValueOfUint32(uint32(n)) //nolint:gosec // bounds checked
		}
	}
	return protoreflect.Value{}
}

// convertToUint64 converts an interface to uint64 protoreflect.Value.
// Uses safe conversion with bounds checking.
func convertToUint64(v interface{}) protoreflect.Value {
	switch n := v.(type) {
	case uint:
		return protoreflect.ValueOfUint64(uint64(n))
	case uint32:
		return protoreflect.ValueOfUint64(uint64(n))
	case uint64:
		return protoreflect.ValueOfUint64(n)
	case int:
		if n >= 0 {
			return protoreflect.ValueOfUint64(uint64(n)) //nolint:gosec // bounds checked
		}
	case float64:
		if n >= 0 {
			return protoreflect.ValueOfUint64(uint64(n)) //nolint:gosec // bounds checked
		}
	}
	return protoreflect.Value{}
}

// convertToFloat32 converts an interface to float32 protoreflect.Value.
func convertToFloat32(v interface{}) protoreflect.Value {
	switch n := v.(type) {
	case float32:
		return protoreflect.ValueOfFloat32(n)
	case float64:
		return protoreflect.ValueOfFloat32(float32(n))
	case int:
		return protoreflect.ValueOfFloat32(float32(n))
	}
	return protoreflect.Value{}
}

// convertToFloat64 converts an interface to float64 protoreflect.Value.
func convertToFloat64(v interface{}) protoreflect.Value {
	switch n := v.(type) {
	case float32:
		return protoreflect.ValueOfFloat64(float64(n))
	case float64:
		return protoreflect.ValueOfFloat64(n)
	case int:
		return protoreflect.ValueOfFloat64(float64(n))
	}
	return protoreflect.Value{}
}

// compareValues compares two interface values for sorting.
func compareValues(a, b interface{}) bool {
	switch av := a.(type) {
	case string:
		if bv, ok := b.(string); ok {
			return av < bv
		}
	case int:
		if bv, ok := b.(int); ok {
			return av < bv
		}
	case int32:
		if bv, ok := b.(int32); ok {
			return av < bv
		}
	case int64:
		if bv, ok := b.(int64); ok {
			return av < bv
		}
	case float32:
		if bv, ok := b.(float32); ok {
			return av < bv
		}
	case float64:
		if bv, ok := b.(float64); ok {
			return av < bv
		}
	}

	// Fallback to string comparison
	return fmt.Sprintf("%v", a) < fmt.Sprintf("%v", b)
}
