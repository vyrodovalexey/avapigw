package security

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Schema validation sentinel errors (HUB-403/404).
var (
	// ErrSchemaNetworkRef indicates a schema contained an external $ref with a
	// network/file scheme, which the hub rejects by default (HUB-403).
	ErrSchemaNetworkRef = errors.New("security: schema contains external $ref")
	// ErrSchemaTooDeep indicates the schema exceeded the max nesting depth
	// (HUB-404).
	ErrSchemaTooDeep = errors.New("security: schema nesting too deep")
	// ErrSchemaTooManyNodes indicates the schema exceeded the max subschema
	// count (HUB-404).
	ErrSchemaTooManyNodes = errors.New("security: schema has too many subschemas")
	// ErrSchemaBudgetExceeded indicates schema validation exceeded its
	// wall-clock budget (HUB-404).
	ErrSchemaBudgetExceeded = errors.New("security: schema validation budget exceeded")
)

// SchemaLimits bounds the cost of validating a single tool schema (HUB-404).
type SchemaLimits struct {
	// MaxDepth bounds nesting depth. Zero disables the depth check.
	MaxDepth int
	// MaxNodes bounds the number of subschema nodes. Zero disables the count
	// check.
	MaxNodes int
	// Budget bounds the wall-clock validation time. Zero disables the budget.
	Budget time.Duration
}

// schemaWalker carries the mutable state for a single bounded schema walk.
type schemaWalker struct {
	limits   SchemaLimits
	nodes    int
	deadline time.Time
	now      func() time.Time
}

// ValidateSchema walks a JSON schema enforcing the external-$ref rejection
// (HUB-403) and the cost bounds (HUB-404). It returns nil when the schema is
// safe to accept, or a sentinel error describing the first breach. An empty
// schema is trivially valid.
func ValidateSchema(schema json.RawMessage, limits SchemaLimits) error {
	if len(schema) == 0 {
		return nil
	}
	var root any
	if err := json.Unmarshal(schema, &root); err != nil {
		// A schema that is not valid JSON cannot be safely validated; reject.
		return ErrSchemaNetworkRef
	}
	w := &schemaWalker{limits: limits, now: time.Now}
	if limits.Budget > 0 {
		w.deadline = w.now().Add(limits.Budget)
	}
	return w.walk(root, 0)
}

// walk recursively validates a decoded schema node.
func (w *schemaWalker) walk(node any, depth int) error {
	if err := w.checkBounds(depth); err != nil {
		return err
	}
	switch v := node.(type) {
	case map[string]any:
		return w.walkObject(v, depth)
	case []any:
		return w.walkArray(v, depth)
	default:
		return nil
	}
}

// checkBounds enforces the depth, node-count and time-budget limits.
func (w *schemaWalker) checkBounds(depth int) error {
	if w.limits.MaxDepth > 0 && depth > w.limits.MaxDepth {
		return ErrSchemaTooDeep
	}
	w.nodes++
	if w.limits.MaxNodes > 0 && w.nodes > w.limits.MaxNodes {
		return ErrSchemaTooManyNodes
	}
	if !w.deadline.IsZero() && w.now().After(w.deadline) {
		return ErrSchemaBudgetExceeded
	}
	return nil
}

// walkObject validates a schema object, rejecting network $ref and recursing
// into every value.
func (w *schemaWalker) walkObject(obj map[string]any, depth int) error {
	if ref, ok := obj["$ref"].(string); ok && isNetworkRef(ref) {
		return ErrSchemaNetworkRef
	}
	for _, val := range obj {
		if err := w.walk(val, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// walkArray validates each element of a schema array (e.g. anyOf/allOf/oneOf).
func (w *schemaWalker) walkArray(arr []any, depth int) error {
	for _, val := range arr {
		if err := w.walk(val, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// networkRefSchemes are the $ref schemes rejected by default (HUB-403). A local
// fragment ref (#/...) or a bare relative pointer is allowed.
var networkRefSchemes = []string{"http://", "https://", "file://", "ftp://"}

// isNetworkRef reports whether a $ref target points at a network/file resource
// the hub must not dereference (HUB-403).
func isNetworkRef(ref string) bool {
	lower := strings.ToLower(strings.TrimSpace(ref))
	for _, scheme := range networkRefSchemes {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	// An absolute network-style ref like "//host/path" is also rejected.
	return strings.HasPrefix(lower, "//")
}
