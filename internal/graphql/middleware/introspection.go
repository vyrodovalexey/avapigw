// Package middleware provides GraphQL-specific middleware for query analysis and protection.
package middleware

import (
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// IntrospectionGuard controls whether GraphQL introspection queries are allowed.
type IntrospectionGuard struct {
	enabled bool
	logger  observability.Logger
}

// NewIntrospectionGuard creates a new introspection guard.
// When enabled is true, introspection queries are allowed.
// When enabled is false, introspection queries are rejected.
func NewIntrospectionGuard(enabled bool, logger observability.Logger) *IntrospectionGuard {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &IntrospectionGuard{
		enabled: enabled,
		logger:  logger,
	}
}

// Check validates that the query does not contain introspection fields when disabled.
// Returns nil if introspection is allowed or the query does not contain introspection fields.
func (g *IntrospectionGuard) Check(query string) error {
	if g.enabled {
		// Introspection is allowed
		return nil
	}

	doc, parseErr := parser.ParseQuery(&ast.Source{Input: query})
	if parseErr != nil {
		return fmt.Errorf("failed to parse GraphQL query: %w", parseErr)
	}

	for _, op := range doc.Operations {
		if containsIntrospection(op.SelectionSet) {
			g.logger.Warn("GraphQL introspection query blocked",
				observability.String("operation", string(op.Operation)),
			)
			return fmt.Errorf("introspection queries are not allowed")
		}
	}

	return nil
}

// containsIntrospection checks if a selection set contains introspection fields.
func containsIntrospection(selectionSet ast.SelectionSet) bool {
	for _, selection := range selectionSet {
		switch sel := selection.(type) {
		case *ast.Field:
			if isIntrospectionField(sel.Name) {
				return true
			}
			if containsIntrospection(sel.SelectionSet) {
				return true
			}
		case *ast.InlineFragment:
			if containsIntrospection(sel.SelectionSet) {
				return true
			}
		}
	}
	return false
}

// isIntrospectionField returns true if the field name is a GraphQL introspection field.
func isIntrospectionField(name string) bool {
	return strings.HasPrefix(name, "__")
}

// IsEnabled returns whether introspection is enabled.
func (g *IntrospectionGuard) IsEnabled() bool {
	return g.enabled
}
