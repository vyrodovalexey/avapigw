package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewIntrospectionGuard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled bool
		logger  observability.Logger
	}{
		{
			name:    "enabled with logger",
			enabled: true,
			logger:  observability.NopLogger(),
		},
		{
			name:    "disabled with logger",
			enabled: false,
			logger:  observability.NopLogger(),
		},
		{
			name:    "enabled with nil logger",
			enabled: true,
			logger:  nil,
		},
		{
			name:    "disabled with nil logger",
			enabled: false,
			logger:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := NewIntrospectionGuard(tt.enabled, tt.logger)
			require.NotNil(t, g)
			assert.Equal(t, tt.enabled, g.IsEnabled())
		})
	}
}

func TestIntrospectionGuard_IsEnabled(t *testing.T) {
	t.Parallel()

	g1 := NewIntrospectionGuard(true, nil)
	assert.True(t, g1.IsEnabled())

	g2 := NewIntrospectionGuard(false, nil)
	assert.False(t, g2.IsEnabled())
}

func TestIntrospectionGuard_Check(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		enabled   bool
		query     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "enabled allows __schema query",
			enabled: true,
			query:   `{ __schema { types { name } } }`,
			wantErr: false,
		},
		{
			name:    "enabled allows __type query",
			enabled: true,
			query:   `{ __type(name: "User") { name fields { name } } }`,
			wantErr: false,
		},
		{
			name:    "enabled allows normal query",
			enabled: true,
			query:   `{ user { name email } }`,
			wantErr: false,
		},
		{
			name:      "disabled blocks __schema query",
			enabled:   false,
			query:     `{ __schema { types { name } } }`,
			wantErr:   true,
			errSubstr: "introspection queries are not allowed",
		},
		{
			name:      "disabled blocks __type query",
			enabled:   false,
			query:     `{ __type(name: "User") { name fields { name } } }`,
			wantErr:   true,
			errSubstr: "introspection queries are not allowed",
		},
		{
			name:    "disabled allows normal query",
			enabled: false,
			query:   `{ user { name email } }`,
			wantErr: false,
		},
		{
			name:      "disabled blocks nested __schema",
			enabled:   false,
			query:     `{ user { name __schema { types { name } } } }`,
			wantErr:   true,
			errSubstr: "introspection queries are not allowed",
		},
		{
			name:      "disabled blocks __typename in nested field",
			enabled:   false,
			query:     `{ user { __typename name } }`,
			wantErr:   true,
			errSubstr: "introspection queries are not allowed",
		},
		{
			name:    "disabled allows query without introspection",
			enabled: false,
			query:   `mutation { createUser(input: {name: "test"}) { id } }`,
			wantErr: false,
		},
		{
			name:      "disabled blocks introspection in mutation",
			enabled:   false,
			query:     `mutation { createUser(input: {name: "test"}) { __typename id } }`,
			wantErr:   true,
			errSubstr: "introspection queries are not allowed",
		},
		{
			name:      "invalid query returns parse error",
			enabled:   false,
			query:     `this is not valid graphql`,
			wantErr:   true,
			errSubstr: "failed to parse",
		},
		{
			name:      "disabled rejects empty query body",
			enabled:   false,
			query:     `{ }`,
			wantErr:   true,
			errSubstr: "failed to parse",
		},
		{
			name:    "disabled blocks introspection in inline fragment",
			enabled: false,
			query: `{
				user {
					... on Admin {
						__schema { types { name } }
					}
				}
			}`,
			wantErr:   true,
			errSubstr: "introspection queries are not allowed",
		},
		{
			name:    "disabled allows inline fragment without introspection",
			enabled: false,
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
			name:      "disabled blocks __schema in subscription",
			enabled:   false,
			query:     `subscription { __schema { types { name } } }`,
			wantErr:   true,
			errSubstr: "introspection queries are not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := NewIntrospectionGuard(tt.enabled, observability.NopLogger())
			err := g.Check(tt.query)
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
