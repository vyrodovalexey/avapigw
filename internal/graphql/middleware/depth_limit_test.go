package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewDepthLimiter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		maxDepth int
		logger   observability.Logger
	}{
		{
			name:     "with positive depth and logger",
			maxDepth: 10,
			logger:   observability.NopLogger(),
		},
		{
			name:     "with zero depth",
			maxDepth: 0,
			logger:   observability.NopLogger(),
		},
		{
			name:     "with negative depth",
			maxDepth: -1,
			logger:   observability.NopLogger(),
		},
		{
			name:     "with nil logger",
			maxDepth: 5,
			logger:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dl := NewDepthLimiter(tt.maxDepth, tt.logger)
			require.NotNil(t, dl)
			assert.Equal(t, tt.maxDepth, dl.MaxDepth())
		})
	}
}

func TestDepthLimiter_MaxDepth(t *testing.T) {
	t.Parallel()

	dl := NewDepthLimiter(15, nil)
	assert.Equal(t, 15, dl.MaxDepth())
}

func TestDepthLimiter_Check(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		maxDepth  int
		query     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "disabled (zero depth) allows any query",
			maxDepth: 0,
			query:    `{ user { posts { comments { author { name } } } } }`,
			wantErr:  false,
		},
		{
			name:     "disabled (negative depth) allows any query",
			maxDepth: -1,
			query:    `{ user { posts { comments { author { name } } } } }`,
			wantErr:  false,
		},
		{
			name:     "simple query within limit",
			maxDepth: 5,
			query:    `{ user { name } }`,
			wantErr:  false,
		},
		{
			name:     "query at exact limit",
			maxDepth: 3,
			query:    `{ user { posts { title } } }`,
			wantErr:  false,
		},
		{
			name:      "query exceeds limit",
			maxDepth:  2,
			query:     `{ user { posts { title } } }`,
			wantErr:   true,
			errSubstr: "exceeds maximum allowed depth",
		},
		{
			name:     "deeply nested query within limit",
			maxDepth: 10,
			query:    `{ user { posts { comments { author { name } } } } }`,
			wantErr:  false,
		},
		{
			name:      "deeply nested query exceeds limit",
			maxDepth:  3,
			query:     `{ user { posts { comments { author { name } } } } }`,
			wantErr:   true,
			errSubstr: "exceeds maximum allowed depth",
		},
		{
			name:     "mutation within limit",
			maxDepth: 5,
			query:    `mutation { createUser(input: {name: "test"}) { id name } }`,
			wantErr:  false,
		},
		{
			name:     "subscription within limit",
			maxDepth: 5,
			query:    `subscription { onUserCreated { id name } }`,
			wantErr:  false,
		},
		{
			name:     "query with single field",
			maxDepth: 1,
			query:    `{ users }`,
			wantErr:  false,
		},
		{
			name:      "invalid query",
			maxDepth:  5,
			query:     `this is not valid graphql`,
			wantErr:   true,
			errSubstr: "failed to parse",
		},
		{
			name:      "empty query body",
			maxDepth:  5,
			query:     `{ }`,
			wantErr:   true,
			errSubstr: "failed to parse",
		},
		{
			name:     "query with inline fragment within limit",
			maxDepth: 5,
			query: `{
				user {
					... on Admin {
						permissions
					}
				}
			}`,
			wantErr: false,
		},
		{
			name:     "query with inline fragment exceeds limit",
			maxDepth: 2,
			query: `{
				user {
					... on Admin {
						permissions { name }
					}
				}
			}`,
			wantErr:   true,
			errSubstr: "exceeds maximum allowed depth",
		},
		{
			name:     "named query within limit",
			maxDepth: 5,
			query:    `query GetUser { user { name email } }`,
			wantErr:  false,
		},
		{
			name:     "multiple operations within limit",
			maxDepth: 3,
			query: `query GetUser { user { name } }
			         query GetPosts { posts { title } }`,
			wantErr: false,
		},
		{
			name:     "one of multiple operations exceeds limit",
			maxDepth: 2,
			query: `query GetUser { user { name } }
			         query GetPosts { posts { comments { text } } }`,
			wantErr:   true,
			errSubstr: "exceeds maximum allowed depth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dl := NewDepthLimiter(tt.maxDepth, observability.NopLogger())
			err := dl.Check(tt.query)
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

func TestDepthLimiter_Check_Fragments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		maxDepth  int
		query     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "fragment definition within limit",
			maxDepth: 5,
			query: `
				fragment UserFields on User {
					name
					email
				}
				query GetUser {
					user {
						...UserFields
					}
				}
			`,
			wantErr: false,
		},
		{
			name:     "fragment definition exceeds limit",
			maxDepth: 2,
			query: `
				fragment UserFields on User {
					name
					posts {
						title
						comments {
							text
						}
					}
				}
				query GetUser {
					user {
						...UserFields
					}
				}
			`,
			wantErr:   true,
			errSubstr: "fragment",
		},
		{
			name:     "nested fragment within limit",
			maxDepth: 4,
			query: `
				fragment PostFields on Post {
					title
					author {
						name
					}
				}
				query GetPosts {
					posts {
						...PostFields
					}
				}
			`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dl := NewDepthLimiter(tt.maxDepth, observability.NopLogger())
			err := dl.Check(tt.query)
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
