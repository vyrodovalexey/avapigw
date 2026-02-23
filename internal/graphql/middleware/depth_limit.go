// Package middleware provides GraphQL-specific middleware for query analysis and protection.
package middleware

import (
	"fmt"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// DepthLimiter enforces a maximum query depth for GraphQL operations.
type DepthLimiter struct {
	maxDepth int
	logger   observability.Logger
}

// NewDepthLimiter creates a new depth limiter with the specified maximum depth.
// A maxDepth of 0 disables depth limiting.
func NewDepthLimiter(maxDepth int, logger observability.Logger) *DepthLimiter {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &DepthLimiter{
		maxDepth: maxDepth,
		logger:   logger,
	}
}

// Check validates that the query depth does not exceed the configured maximum.
// Returns nil if the query is within limits, or an error describing the violation.
func (d *DepthLimiter) Check(query string) error {
	if d.maxDepth <= 0 {
		// Depth limiting is disabled
		return nil
	}

	doc, parseErr := parser.ParseQuery(&ast.Source{Input: query})
	if parseErr != nil {
		return fmt.Errorf("failed to parse GraphQL query: %w", parseErr)
	}

	for _, op := range doc.Operations {
		depth := calculateSelectionSetDepth(op.SelectionSet)
		if depth > d.maxDepth {
			d.logger.Warn("GraphQL query depth limit exceeded",
				observability.Int("depth", depth),
				observability.Int("max_depth", d.maxDepth),
				observability.String("operation", string(op.Operation)),
			)
			return fmt.Errorf("query depth %d exceeds maximum allowed depth of %d", depth, d.maxDepth)
		}
	}

	for _, frag := range doc.Fragments {
		depth := calculateSelectionSetDepth(frag.SelectionSet)
		if depth > d.maxDepth {
			d.logger.Warn("GraphQL fragment depth limit exceeded",
				observability.Int("depth", depth),
				observability.Int("max_depth", d.maxDepth),
				observability.String("fragment", frag.Name),
			)
			return fmt.Errorf("fragment %q depth %d exceeds maximum allowed depth of %d", frag.Name, depth, d.maxDepth)
		}
	}

	return nil
}

// calculateSelectionSetDepth calculates the maximum depth of a selection set.
func calculateSelectionSetDepth(selectionSet ast.SelectionSet) int {
	if len(selectionSet) == 0 {
		return 0
	}

	maxDepth := 0
	for _, selection := range selectionSet {
		var childDepth int
		switch sel := selection.(type) {
		case *ast.Field:
			childDepth = calculateSelectionSetDepth(sel.SelectionSet)
		case *ast.InlineFragment:
			childDepth = calculateSelectionSetDepth(sel.SelectionSet)
		case *ast.FragmentSpread:
			// Fragment spreads reference named fragments; their depth is counted
			// when the fragment definition itself is analyzed. Here we count 0
			// to avoid double-counting.
			childDepth = 0
		}
		if childDepth > maxDepth {
			maxDepth = childDepth
		}
	}

	return maxDepth + 1
}

// MaxDepth returns the configured maximum depth.
func (d *DepthLimiter) MaxDepth() int {
	return d.maxDepth
}
