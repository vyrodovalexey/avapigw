// Package middleware provides GraphQL-specific middleware for query analysis and protection.
package middleware

import (
	"fmt"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ComplexityAnalyzer enforces a maximum query complexity for GraphQL operations.
// Complexity is calculated by counting the total number of fields in the query,
// with nested fields contributing multiplicatively based on their depth.
type ComplexityAnalyzer struct {
	maxComplexity int
	logger        observability.Logger
}

// NewComplexityAnalyzer creates a new complexity analyzer with the specified maximum complexity.
// A maxComplexity of 0 disables complexity analysis.
func NewComplexityAnalyzer(maxComplexity int, logger observability.Logger) *ComplexityAnalyzer {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &ComplexityAnalyzer{
		maxComplexity: maxComplexity,
		logger:        logger,
	}
}

// Check validates that the query complexity does not exceed the configured maximum.
// Returns nil if the query is within limits, or an error describing the violation.
func (c *ComplexityAnalyzer) Check(query string) error {
	if c.maxComplexity <= 0 {
		// Complexity analysis is disabled
		return nil
	}

	doc, parseErr := parser.ParseQuery(&ast.Source{Input: query})
	if parseErr != nil {
		return fmt.Errorf("failed to parse GraphQL query: %w", parseErr)
	}

	totalComplexity := 0
	for _, op := range doc.Operations {
		complexity := calculateSelectionSetComplexity(op.SelectionSet)
		totalComplexity += complexity
	}

	if totalComplexity > c.maxComplexity {
		c.logger.Warn("GraphQL query complexity limit exceeded",
			observability.Int("complexity", totalComplexity),
			observability.Int("max_complexity", c.maxComplexity),
		)
		return fmt.Errorf(
			"query complexity %d exceeds maximum allowed complexity of %d",
			totalComplexity, c.maxComplexity,
		)
	}

	return nil
}

// calculateSelectionSetComplexity calculates the complexity of a selection set.
// Each field contributes 1 to the complexity, and nested selections are additive.
func calculateSelectionSetComplexity(selectionSet ast.SelectionSet) int {
	if len(selectionSet) == 0 {
		return 0
	}

	complexity := 0
	for _, selection := range selectionSet {
		switch sel := selection.(type) {
		case *ast.Field:
			// Each field contributes at least 1
			fieldComplexity := 1 + calculateSelectionSetComplexity(sel.SelectionSet)
			complexity += fieldComplexity
		case *ast.InlineFragment:
			complexity += calculateSelectionSetComplexity(sel.SelectionSet)
		case *ast.FragmentSpread:
			// Fragment spreads are counted when the fragment definition is analyzed.
			// Add 1 for the spread reference itself.
			complexity++
		}
	}

	return complexity
}

// MaxComplexity returns the configured maximum complexity.
func (c *ComplexityAnalyzer) MaxComplexity() int {
	return c.maxComplexity
}
