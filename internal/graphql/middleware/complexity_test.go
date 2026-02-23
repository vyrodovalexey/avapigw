package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewComplexityAnalyzer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		maxComplexity int
		logger        observability.Logger
	}{
		{
			name:          "with positive complexity and logger",
			maxComplexity: 100,
			logger:        observability.NopLogger(),
		},
		{
			name:          "with zero complexity",
			maxComplexity: 0,
			logger:        observability.NopLogger(),
		},
		{
			name:          "with negative complexity",
			maxComplexity: -1,
			logger:        observability.NopLogger(),
		},
		{
			name:          "with nil logger",
			maxComplexity: 50,
			logger:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ca := NewComplexityAnalyzer(tt.maxComplexity, tt.logger)
			require.NotNil(t, ca)
			assert.Equal(t, tt.maxComplexity, ca.MaxComplexity())
		})
	}
}

func TestComplexityAnalyzer_MaxComplexity(t *testing.T) {
	t.Parallel()

	ca := NewComplexityAnalyzer(200, nil)
	assert.Equal(t, 200, ca.MaxComplexity())
}

func TestComplexityAnalyzer_Check(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		maxComplexity int
		query         string
		wantErr       bool
		errSubstr     string
	}{
		{
			name:          "disabled (zero complexity) allows any query",
			maxComplexity: 0,
			query:         `{ user { name email posts { title body comments { text author { name } } } } }`,
			wantErr:       false,
		},
		{
			name:          "disabled (negative complexity) allows any query",
			maxComplexity: -1,
			query:         `{ user { name email posts { title body } } }`,
			wantErr:       false,
		},
		{
			name:          "simple query within limit",
			maxComplexity: 10,
			query:         `{ user { name email } }`,
			wantErr:       false,
		},
		{
			name:          "query at exact limit - 3 fields (user, name, email)",
			maxComplexity: 3,
			query:         `{ user { name email } }`,
			wantErr:       false,
		},
		{
			name:          "query exceeds limit",
			maxComplexity: 2,
			query:         `{ user { name email } }`,
			wantErr:       true,
			errSubstr:     "exceeds maximum allowed complexity",
		},
		{
			name:          "nested query within limit",
			maxComplexity: 20,
			query:         `{ user { name posts { title author { name } } } }`,
			wantErr:       false,
		},
		{
			name:          "complex query exceeds limit",
			maxComplexity: 3,
			query:         `{ user { name email posts { title body } } }`,
			wantErr:       true,
			errSubstr:     "exceeds maximum allowed complexity",
		},
		{
			name:          "mutation within limit",
			maxComplexity: 10,
			query:         `mutation { createUser(input: {name: "test"}) { id name } }`,
			wantErr:       false,
		},
		{
			name:          "single field query",
			maxComplexity: 1,
			query:         `{ users }`,
			wantErr:       false,
		},
		{
			name:          "invalid query",
			maxComplexity: 100,
			query:         `this is not valid graphql`,
			wantErr:       true,
			errSubstr:     "failed to parse",
		},
		{
			name:          "query with inline fragment",
			maxComplexity: 10,
			query: `{
				user {
					... on Admin {
						permissions
						role
					}
				}
			}`,
			wantErr: false,
		},
		{
			name:          "query with fragment spread",
			maxComplexity: 10,
			query: `{
				user {
					...UserFields
				}
			}`,
			wantErr: false,
		},
		{
			name:          "multiple operations",
			maxComplexity: 10,
			query: `query A { user { name } }
			         query B { posts { title } }`,
			wantErr: false,
		},
		{
			name:          "multiple operations combined exceed limit",
			maxComplexity: 3,
			query: `query A { user { name } }
			         query B { posts { title } }`,
			wantErr:   true,
			errSubstr: "exceeds maximum allowed complexity",
		},
		{
			name:          "empty query body",
			maxComplexity: 5,
			query:         `{ }`,
			wantErr:       true,
			errSubstr:     "failed to parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ca := NewComplexityAnalyzer(tt.maxComplexity, observability.NopLogger())
			err := ca.Check(tt.query)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
