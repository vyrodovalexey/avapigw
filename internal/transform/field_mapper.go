// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// fieldMapper implements the FieldMapper interface.
type fieldMapper struct {
	logger observability.Logger
}

// NewFieldMapper creates a new FieldMapper instance.
func NewFieldMapper(logger observability.Logger) FieldMapper {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &fieldMapper{
		logger: logger,
	}
}

// MapFields applies field mappings to the data.
// Each mapping renames a field from source path to target path.
func (m *fieldMapper) MapFields(
	data map[string]interface{},
	mappings []config.FieldMapping,
) (map[string]interface{}, error) {
	if len(mappings) == 0 {
		return data, nil
	}

	result := deepCopyMap(data)

	for _, mapping := range mappings {
		if err := m.applyMapping(result, mapping); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// applyMapping applies a single field mapping.
func (m *fieldMapper) applyMapping(result map[string]interface{}, mapping config.FieldMapping) error {
	if mapping.Source == "" || mapping.Target == "" {
		return nil
	}

	// Get the value at the source path
	value, err := getValueAtPath(result, mapping.Source)
	if err != nil {
		m.logger.Debug("source field not found for mapping",
			observability.String("source", mapping.Source),
			observability.String("target", mapping.Target),
			observability.Error(err))
		return nil
	}

	// Remove the source field
	if err := deleteValueAtPath(result, mapping.Source); err != nil {
		m.logger.Debug("failed to delete source field",
			observability.String("source", mapping.Source),
			observability.Error(err))
	}

	// Set the value at the target path
	if err := setValueAtPath(result, mapping.Target, value); err != nil {
		return fmt.Errorf("failed to set value at target path %s: %w", mapping.Target, err)
	}

	m.logger.Debug("mapped field",
		observability.String("source", mapping.Source),
		observability.String("target", mapping.Target))

	return nil
}

// getValueAtPath retrieves a value at the given path.
// Supports dot notation (e.g., "user.name") and array indexing (e.g., "items[0].id").
func getValueAtPath(data map[string]interface{}, path string) (interface{}, error) {
	parts := parseFieldPath(path)
	if len(parts) == 0 {
		return nil, ErrInvalidFieldPath
	}

	var current interface{} = data

	for _, part := range parts {
		var err error
		current, err = traversePath(current, part)
		if err != nil {
			return nil, err
		}
	}

	return current, nil
}

// traversePath traverses one level of the path.
func traversePath(current interface{}, part pathPart) (interface{}, error) {
	switch v := current.(type) {
	case map[string]interface{}:
		return traverseMap(v, part)
	case []interface{}:
		return traverseArray(v, part)
	default:
		return nil, fmt.Errorf("%w: cannot traverse into %T", ErrInvalidDataType, current)
	}
}

// traverseMap traverses a map with the given path part.
func traverseMap(m map[string]interface{}, part pathPart) (interface{}, error) {
	val, exists := m[part.Name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrFieldNotFound, part.Name)
	}

	if part.IsArray && part.Index >= 0 {
		return getArrayElement(val, part)
	}

	return val, nil
}

// getArrayElement gets an element from an array value.
func getArrayElement(val interface{}, part pathPart) (interface{}, error) {
	arr, ok := val.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s is not an array", ErrInvalidDataType, part.Name)
	}
	if part.Index >= len(arr) {
		return nil, fmt.Errorf("%w: index %d out of bounds", ErrFieldNotFound, part.Index)
	}
	return arr[part.Index], nil
}

// traverseArray traverses an array with the given path part.
func traverseArray(arr []interface{}, part pathPart) (interface{}, error) {
	if !part.IsArray || part.Index < 0 {
		return nil, fmt.Errorf("%w: expected array index", ErrInvalidFieldPath)
	}
	if part.Index >= len(arr) {
		return nil, fmt.Errorf("%w: index %d out of bounds", ErrFieldNotFound, part.Index)
	}
	return arr[part.Index], nil
}

// setValueAtPath sets a value at the given path, creating intermediate objects as needed.
func setValueAtPath(data map[string]interface{}, path string, value interface{}) error {
	parts := parseFieldPath(path)
	if len(parts) == 0 {
		return ErrInvalidFieldPath
	}

	current := data

	// Navigate to the parent of the target field
	for i := 0; i < len(parts)-1; i++ {
		var err error
		current, err = navigateOrCreate(current, parts[i], parts[i+1])
		if err != nil {
			return err
		}
	}

	// Set the final value
	return setFinalValue(current, parts[len(parts)-1], value)
}

// navigateOrCreate navigates to the next level, creating it if needed.
func navigateOrCreate(
	current map[string]interface{},
	part pathPart,
	nextPart pathPart,
) (map[string]interface{}, error) {
	val, exists := current[part.Name]
	if !exists {
		val = createIntermediateValue(nextPart)
		current[part.Name] = val
	}

	return navigateValue(current, part, val)
}

// createIntermediateValue creates an intermediate value based on the next part.
func createIntermediateValue(nextPart pathPart) interface{} {
	if nextPart.IsArray && nextPart.Index >= 0 {
		return make([]interface{}, nextPart.Index+1)
	}
	return make(map[string]interface{})
}

// navigateValue navigates into a value.
func navigateValue(
	current map[string]interface{},
	part pathPart,
	val interface{},
) (map[string]interface{}, error) {
	switch v := val.(type) {
	case map[string]interface{}:
		return v, nil
	case []interface{}:
		return navigateArrayValue(current, part, v)
	default:
		newMap := make(map[string]interface{})
		current[part.Name] = newMap
		return newMap, nil
	}
}

// navigateArrayValue navigates into an array value.
func navigateArrayValue(
	current map[string]interface{},
	part pathPart,
	arr []interface{},
) (map[string]interface{}, error) {
	if !part.IsArray || part.Index < 0 {
		return nil, fmt.Errorf("%w: expected map, got array", ErrInvalidDataType)
	}

	// Extend array if needed
	for len(arr) <= part.Index {
		arr = append(arr, make(map[string]interface{}))
	}
	current[part.Name] = arr

	if m, ok := arr[part.Index].(map[string]interface{}); ok {
		return m, nil
	}

	newMap := make(map[string]interface{})
	arr[part.Index] = newMap
	return newMap, nil
}

// setFinalValue sets the final value at the path.
func setFinalValue(current map[string]interface{}, part pathPart, value interface{}) error {
	if part.IsArray && part.Index >= 0 {
		return setArrayValue(current, part, value)
	}
	current[part.Name] = value
	return nil
}

// setArrayValue sets a value in an array.
func setArrayValue(current map[string]interface{}, part pathPart, value interface{}) error {
	arr, ok := current[part.Name].([]interface{})
	if !ok {
		arr = make([]interface{}, 0, part.Index+1)
	}
	for len(arr) <= part.Index {
		arr = append(arr, nil)
	}
	arr[part.Index] = value
	current[part.Name] = arr
	return nil
}

// deleteValueAtPath removes a value at the given path.
func deleteValueAtPath(data map[string]interface{}, path string) error {
	parts := parseFieldPath(path)
	if len(parts) == 0 {
		return ErrInvalidFieldPath
	}

	if len(parts) == 1 {
		delete(data, parts[0].Name)
		return nil
	}

	// Navigate to the parent
	current := data
	for i := 0; i < len(parts)-1; i++ {
		next, ok := navigateForDelete(current, parts[i])
		if !ok {
			return nil // Already doesn't exist
		}
		current = next
	}

	// Delete the final field
	delete(current, parts[len(parts)-1].Name)
	return nil
}

// navigateForDelete navigates to the next level for deletion.
func navigateForDelete(current map[string]interface{}, part pathPart) (map[string]interface{}, bool) {
	val, exists := current[part.Name]
	if !exists {
		return nil, false
	}

	switch v := val.(type) {
	case map[string]interface{}:
		return v, true
	case []interface{}:
		if part.IsArray && part.Index >= 0 && part.Index < len(v) {
			if m, ok := v[part.Index].(map[string]interface{}); ok {
				return m, true
			}
		}
		return nil, false
	default:
		return nil, false
	}
}

// pathPart represents a part of a field path.
type pathPart struct {
	Name    string
	IsArray bool
	Index   int
}

// parseFieldPath parses a field path into parts.
// Supports dot notation and array indexing.
// Examples:
//   - "name" -> [{Name: "name"}]
//   - "user.name" -> [{Name: "user"}, {Name: "name"}]
//   - "items[0].id" -> [{Name: "items", IsArray: true, Index: 0}, {Name: "id"}]
func parseFieldPath(path string) []pathPart {
	parser := &pathParser{path: path}
	return parser.parse()
}

// pathParser parses field paths.
type pathParser struct {
	path           string
	parts          []pathPart
	current        strings.Builder
	bracketContent strings.Builder
	inBracket      bool
}

// parse parses the path into parts.
func (p *pathParser) parse() []pathPart {
	for i := 0; i < len(p.path); i++ {
		p.processChar(p.path[i])
	}

	if p.current.Len() > 0 {
		p.parts = append(p.parts, pathPart{Name: p.current.String()})
	}

	return p.parts
}

// processChar processes a single character.
func (p *pathParser) processChar(ch byte) {
	switch {
	case ch == '.':
		p.handleDot()
	case ch == '[':
		p.handleOpenBracket()
	case ch == ']':
		p.handleCloseBracket()
	case p.inBracket:
		p.bracketContent.WriteByte(ch)
	default:
		p.current.WriteByte(ch)
	}
}

// handleDot handles a dot character.
func (p *pathParser) handleDot() {
	if p.current.Len() > 0 {
		p.parts = append(p.parts, pathPart{Name: p.current.String()})
		p.current.Reset()
	}
}

// handleOpenBracket handles an open bracket.
func (p *pathParser) handleOpenBracket() {
	if p.current.Len() > 0 {
		p.inBracket = true
		p.bracketContent.Reset()
	}
}

// handleCloseBracket handles a close bracket.
func (p *pathParser) handleCloseBracket() {
	if !p.inBracket {
		return
	}

	p.inBracket = false
	indexStr := p.bracketContent.String()

	if indexStr == "" {
		p.parts = append(p.parts, pathPart{
			Name:    p.current.String(),
			IsArray: true,
			Index:   -1,
		})
	} else {
		p.addIndexedPart(indexStr)
	}
	p.current.Reset()
}

// addIndexedPart adds an indexed array part.
func (p *pathParser) addIndexedPart(indexStr string) {
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		p.parts = append(p.parts, pathPart{Name: p.current.String() + "[" + indexStr + "]"})
	} else {
		p.parts = append(p.parts, pathPart{
			Name:    p.current.String(),
			IsArray: true,
			Index:   index,
		})
	}
}

// deepCopyMap creates a deep copy of a map.
func deepCopyMap(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}

	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = deepCopyValue(v)
	}
	return dst
}

// deepCopyValue creates a deep copy of a value.
func deepCopyValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return deepCopyMap(val)
	case []interface{}:
		return deepCopySlice(val)
	default:
		return v
	}
}

// deepCopySlice creates a deep copy of a slice.
func deepCopySlice(src []interface{}) []interface{} {
	if src == nil {
		return nil
	}

	dst := make([]interface{}, len(src))
	for i, v := range src {
		dst[i] = deepCopyValue(v)
	}
	return dst
}

// GroupFields groups multiple fields into a nested object.
func GroupFields(data map[string]interface{}, groups []config.FieldGroup) map[string]interface{} {
	if len(groups) == 0 {
		return data
	}

	result := deepCopyMap(data)

	for _, group := range groups {
		if group.Name == "" || len(group.Fields) == 0 {
			continue
		}

		groupData := make(map[string]interface{})
		for _, field := range group.Fields {
			if value, exists := result[field]; exists {
				groupData[field] = value
				delete(result, field)
			}
		}

		if len(groupData) > 0 {
			result[group.Name] = groupData
		}
	}

	return result
}

// FlattenFields flattens nested objects into the parent.
func FlattenFields(data map[string]interface{}, fields []string) map[string]interface{} {
	if len(fields) == 0 {
		return data
	}

	result := deepCopyMap(data)

	for _, field := range fields {
		if nested, ok := result[field].(map[string]interface{}); ok {
			for k, v := range nested {
				result[k] = v
			}
			delete(result, field)
		}
	}

	return result
}
