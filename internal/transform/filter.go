// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// fieldFilter implements the FieldFilter interface.
type fieldFilter struct {
	logger observability.Logger
}

// NewFieldFilter creates a new FieldFilter instance.
func NewFieldFilter(logger observability.Logger) FieldFilter {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &fieldFilter{
		logger: logger,
	}
}

// FilterAllow filters data to include only allowed fields.
// Supports dot notation for nested fields (e.g., "user.name").
// Supports array notation for array fields (e.g., "items[].id").
func (f *fieldFilter) FilterAllow(
	data map[string]interface{},
	allowFields []string,
) map[string]interface{} {
	if len(allowFields) == 0 {
		return data
	}

	// Build a tree of allowed paths for efficient lookup
	allowTree := buildPathTree(allowFields)

	return f.filterAllowRecursive(data, allowTree, "")
}

// FilterDeny filters data to exclude denied fields.
// Supports dot notation for nested fields (e.g., "user.password").
// Supports array notation for array fields (e.g., "items[].secret").
func (f *fieldFilter) FilterDeny(
	data map[string]interface{},
	denyFields []string,
) map[string]interface{} {
	if len(denyFields) == 0 {
		return data
	}

	// Build a set of denied paths for efficient lookup
	denySet := buildPathSet(denyFields)

	return f.filterDenyRecursive(data, denySet, "")
}

// filterAllowRecursive recursively filters data based on allowed paths.
func (f *fieldFilter) filterAllowRecursive(
	data map[string]interface{},
	allowTree map[string]interface{},
	prefix string,
) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range data {
		currentPath := buildCurrentPath(prefix, key)
		filtered := f.filterAllowField(key, value, allowTree, currentPath)
		if filtered != nil {
			result[key] = filtered
		}
	}

	return result
}

// filterAllowField filters a single field based on allowed paths.
func (f *fieldFilter) filterAllowField(
	key string,
	value interface{},
	allowTree map[string]interface{},
	currentPath string,
) interface{} {
	subtree, keyAllowed := allowTree[key]
	_, wildcardAllowed := allowTree["*"]

	if !keyAllowed && !wildcardAllowed {
		return nil
	}

	subtreeMap, isMap := subtree.(map[string]interface{})
	if !isMap || len(subtreeMap) == 0 {
		return value
	}

	return f.filterAllowValue(value, subtreeMap, currentPath)
}

// filterAllowValue filters a value based on its type.
func (f *fieldFilter) filterAllowValue(
	value interface{},
	subtreeMap map[string]interface{},
	currentPath string,
) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		filtered := f.filterAllowRecursive(v, subtreeMap, currentPath)
		if len(filtered) > 0 {
			return filtered
		}
		return nil
	case []interface{}:
		return f.filterAllowArrayValue(v, subtreeMap, currentPath)
	default:
		return value
	}
}

// filterAllowArrayValue filters an array value.
func (f *fieldFilter) filterAllowArrayValue(
	arr []interface{},
	subtreeMap map[string]interface{},
	currentPath string,
) interface{} {
	arraySubtree, hasArrayNotation := subtreeMap["[]"]
	if !hasArrayNotation {
		return arr
	}

	arraySubtreeMap, ok := arraySubtree.(map[string]interface{})
	if !ok {
		arraySubtreeMap = make(map[string]interface{})
	}

	filtered := f.filterAllowArray(arr, arraySubtreeMap, currentPath)
	if len(filtered) > 0 {
		return filtered
	}
	return nil
}

// filterAllowArray filters array elements based on allowed paths.
func (f *fieldFilter) filterAllowArray(
	arr []interface{},
	allowTree map[string]interface{},
	prefix string,
) []interface{} {
	result := make([]interface{}, 0, len(arr))

	for _, item := range arr {
		switch v := item.(type) {
		case map[string]interface{}:
			if len(allowTree) == 0 {
				result = append(result, v)
			} else {
				filtered := f.filterAllowRecursive(v, allowTree, prefix+"[]")
				if len(filtered) > 0 {
					result = append(result, filtered)
				}
			}
		default:
			result = append(result, item)
		}
	}

	return result
}

// filterDenyRecursive recursively filters data based on denied paths.
func (f *fieldFilter) filterDenyRecursive(
	data map[string]interface{},
	denySet map[string]bool,
	prefix string,
) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range data {
		currentPath := buildCurrentPath(prefix, key)

		if denySet[currentPath] {
			f.logger.Debug("filtering denied field",
				observability.String("path", currentPath))
			continue
		}

		result[key] = f.filterDenyValue(value, denySet, currentPath)
	}

	return result
}

// filterDenyValue filters a value based on denied paths.
func (f *fieldFilter) filterDenyValue(
	value interface{},
	denySet map[string]bool,
	currentPath string,
) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		return f.filterDenyRecursive(v, denySet, currentPath)
	case []interface{}:
		return f.filterDenyArray(v, denySet, currentPath)
	default:
		return value
	}
}

// filterDenyArray filters array elements based on denied paths.
func (f *fieldFilter) filterDenyArray(
	arr []interface{},
	denySet map[string]bool,
	prefix string,
) []interface{} {
	result := make([]interface{}, 0, len(arr))
	arrayPrefix := prefix + "[]"

	for _, item := range arr {
		switch v := item.(type) {
		case map[string]interface{}:
			filtered := f.filterDenyRecursive(v, denySet, arrayPrefix)
			result = append(result, filtered)
		default:
			result = append(result, item)
		}
	}

	return result
}

// buildCurrentPath builds the current path from prefix and key.
func buildCurrentPath(prefix, key string) string {
	if prefix != "" {
		return prefix + "." + key
	}
	return key
}

// buildPathTree builds a tree structure from a list of paths.
// Example: ["user.name", "user.email", "items[].id"] becomes:
//
//	{
//	  "user": {"name": {}, "email": {}},
//	  "items": {"[]": {"id": {}}}
//	}
func buildPathTree(paths []string) map[string]interface{} {
	tree := make(map[string]interface{})

	for _, path := range paths {
		parts := splitPath(path)
		current := tree

		for i, part := range parts {
			if _, exists := current[part]; !exists {
				current[part] = make(map[string]interface{})
			}

			if i < len(parts)-1 {
				current = current[part].(map[string]interface{})
			}
		}
	}

	return tree
}

// buildPathSet builds a set of paths for efficient lookup.
func buildPathSet(paths []string) map[string]bool {
	set := make(map[string]bool, len(paths))
	for _, path := range paths {
		set[path] = true
	}
	return set
}

// splitPath splits a field path into parts.
// Handles both dot notation and array notation.
// Example: "items[].name" -> ["items", "[]", "name"]
func splitPath(path string) []string {
	var parts []string
	var current strings.Builder

	for i := 0; i < len(path); i++ {
		i = processPathChar(path, i, &current, &parts)
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// processPathChar processes a single character in the path.
func processPathChar(path string, i int, current *strings.Builder, parts *[]string) int {
	switch path[i] {
	case '.':
		if current.Len() > 0 {
			*parts = append(*parts, current.String())
			current.Reset()
		}
	case '[':
		if current.Len() > 0 {
			*parts = append(*parts, current.String())
			current.Reset()
		}
		if i+1 < len(path) && path[i+1] == ']' {
			*parts = append(*parts, "[]")
			return i + 1 // Skip the ]
		}
	case ']':
		// Already handled with [
	default:
		current.WriteByte(path[i])
	}
	return i
}
