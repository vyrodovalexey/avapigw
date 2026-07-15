package gateway

import (
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// GraphQLPathDispatcher routes GraphQL endpoint requests (GET/POST/OPTIONS
// on the configured GraphQL path, including WebSocket upgrades) to the
// GraphQL pipeline and everything else to the next handler (the HTTP reverse
// proxy). Composing the dispatcher INSIDE the gateway's global middleware
// chain guarantees GraphQL traffic passes the same global middleware
// (recovery, request ID, logging, tracing, audit, metrics, CORS, max
// sessions, circuit breaker, rate limit, auth, body limit) as proxied HTTP
// routes — previously /graphql was registered directly on the gin engine and
// bypassed the entire chain.
type GraphQLPathDispatcher struct {
	path    string
	graphql http.Handler
	next    http.Handler
}

// NewGraphQLPathDispatcher creates a dispatcher for the given GraphQL
// endpoint path. An empty path falls back to the default GraphQL path. A nil
// graphql handler disables dispatching (every request goes to next).
func NewGraphQLPathDispatcher(path string, graphql, next http.Handler) *GraphQLPathDispatcher {
	if path == "" {
		path = defaultGraphQLPath
	}
	return &GraphQLPathDispatcher{
		path:    path,
		graphql: graphql,
		next:    next,
	}
}

// GraphQLPathFromConfig resolves the configured GraphQL endpoint path,
// falling back to the default ("/graphql").
func GraphQLPathFromConfig(cfg *config.GatewayConfig) string {
	if cfg != nil && cfg.Spec.GraphQL != nil && cfg.Spec.GraphQL.Path != "" {
		return cfg.Spec.GraphQL.Path
	}
	return defaultGraphQLPath
}

// ServeHTTP implements http.Handler.
func (d *GraphQLPathDispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d.graphql != nil && r.URL.Path == d.path && graphqlMethodAllowed(r.Method) {
		d.graphql.ServeHTTP(w, r)
		return
	}
	d.next.ServeHTTP(w, r)
}

// graphqlMethodAllowed reports whether the method is served by the GraphQL
// pipeline: POST/GET for operations (GET also carries WebSocket upgrades)
// and OPTIONS for CORS preflight. Other methods fall through to the HTTP
// pipeline, mirroring the previous gin registration behavior.
func graphqlMethodAllowed(method string) bool {
	switch method {
	case http.MethodPost, http.MethodGet, http.MethodOptions:
		return true
	default:
		return false
	}
}
