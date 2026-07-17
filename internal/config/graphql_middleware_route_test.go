package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestGraphQLRoute_ToMiddlewareRoute verifies the middleware-relevant fields
// are projected onto the Route view and routing-only fields are not.
func TestGraphQLRoute_ToMiddlewareRoute(t *testing.T) {
	t.Parallel()

	auth := &AuthenticationConfig{Enabled: true}
	authz := &AuthorizationConfig{Enabled: true}
	rl := &RateLimitConfig{Enabled: true, RequestsPerSecond: 10}
	cors := &CORSConfig{AllowOrigins: []string{"*"}}
	sec := &SecurityConfig{Enabled: true}
	cache := &CacheConfig{Enabled: true}
	headers := &HeaderManipulation{Request: &HeaderOperation{Set: map[string]string{"a": "b"}}}
	retries := &RetryPolicy{Attempts: 2}

	gqlRoute := &GraphQLRoute{
		Name:           "gql-route",
		Timeout:        Duration(5 * time.Second),
		Retries:        retries,
		Headers:        headers,
		RateLimit:      rl,
		Cache:          cache,
		CORS:           cors,
		Security:       sec,
		Authentication: auth,
		Authorization:  authz,
		// Routing-only fields that must NOT be projected:
		Match:     []GraphQLRouteMatch{{OperationType: "query"}},
		Route:     []RouteDestination{{Destination: Destination{Host: "b"}}},
		Aggregate: &AggregateConfig{Enabled: true},
	}

	view := gqlRoute.ToMiddlewareRoute()

	assert.Equal(t, "gql-route", view.Name)
	assert.Equal(t, Duration(5*time.Second), view.Timeout)
	assert.Same(t, retries, view.Retries)
	assert.Same(t, headers, view.Headers)
	assert.Same(t, rl, view.RateLimit)
	assert.Same(t, cache, view.Cache)
	assert.Same(t, cors, view.CORS)
	assert.Same(t, sec, view.Security)
	assert.Same(t, auth, view.Authentication)
	assert.Same(t, authz, view.Authorization)

	// Routing concerns stay out of the middleware view.
	assert.Nil(t, view.Match)
	assert.Nil(t, view.Route)
	assert.Nil(t, view.Aggregate)
	assert.Nil(t, view.Transform)
	assert.Nil(t, view.Encoding)
}

// TestGraphQLRoute_ToMiddlewareRoute_Empty verifies an empty route projects
// an empty view without panics.
func TestGraphQLRoute_ToMiddlewareRoute_Empty(t *testing.T) {
	t.Parallel()

	view := (&GraphQLRoute{Name: "bare"}).ToMiddlewareRoute()
	assert.Equal(t, "bare", view.Name)
	assert.Nil(t, view.Authentication)
	assert.Nil(t, view.RateLimit)
	assert.Nil(t, view.CORS)
}
