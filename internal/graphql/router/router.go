// Package router provides GraphQL request routing based on operation type and name.
package router

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// routerTracerName is the OpenTelemetry tracer name for router operations.
const routerTracerName = "avapigw/graphql-router"

// GraphQLRequest represents a parsed GraphQL request body.
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// MatchResult contains the result of a route match.
type MatchResult struct {
	// Route is the matched route configuration.
	Route *config.GraphQLRoute

	// BackendName is the name of the backend to forward to.
	BackendName string

	// OperationType is the detected operation type (query, mutation, subscription).
	OperationType string

	// OperationName is the detected operation name.
	OperationName string
}

// Router matches GraphQL requests to configured routes.
type Router struct {
	mu     sync.RWMutex
	routes []compiledRoute
	logger observability.Logger
}

// compiledRoute is a route with pre-compiled regex patterns.
type compiledRoute struct {
	config        config.GraphQLRoute
	pathRegex     *regexp.Regexp
	opNameRegex   *regexp.Regexp
	headerRegexes map[string]*regexp.Regexp
}

// Option is a functional option for configuring the router.
type Option func(*Router)

// WithRouterLogger sets the logger for the router.
func WithRouterLogger(logger observability.Logger) Option {
	return func(r *Router) {
		r.logger = logger
	}
}

// New creates a new GraphQL router.
func New(opts ...Option) *Router {
	r := &Router{
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// LoadRoutes loads and compiles route configurations.
func (r *Router) LoadRoutes(routes []config.GraphQLRoute) error {
	compiled := make([]compiledRoute, 0, len(routes))

	for i := range routes {
		cr, err := compileRoute(&routes[i])
		if err != nil {
			return fmt.Errorf("failed to compile route %q: %w", routes[i].Name, err)
		}
		compiled = append(compiled, *cr)
	}

	r.mu.Lock()
	r.routes = compiled
	r.mu.Unlock()

	r.logger.Info("GraphQL routes loaded",
		observability.Int("count", len(compiled)),
	)

	return nil
}

// Match finds the best matching route for the given HTTP request and parsed GraphQL request.
func (r *Router) Match(req *http.Request, gqlReq *GraphQLRequest) *MatchResult {
	tracer := otel.Tracer(routerTracerName)
	_, span := tracer.Start(req.Context(), "graphql.router.match",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	r.mu.RLock()
	defer r.mu.RUnlock()

	opType := detectOperationType(gqlReq.Query)

	for i := range r.routes {
		cr := &r.routes[i]
		if r.matchRoute(cr, req, gqlReq, opType) {
			backendName := ""
			if len(cr.config.Route) > 0 {
				backendName = cr.config.Route[0].Destination.Host
			}

			span.SetAttributes(
				attribute.String("graphql.route", cr.config.Name),
				attribute.String("graphql.backend", backendName),
				attribute.String("graphql.operation_type", opType),
				attribute.String("graphql.operation_name", gqlReq.OperationName),
			)

			return &MatchResult{
				Route:         &cr.config,
				BackendName:   backendName,
				OperationType: opType,
				OperationName: gqlReq.OperationName,
			}
		}
	}

	span.SetAttributes(attribute.Bool("graphql.route_matched", false))
	return nil
}

// matchRoute checks if a compiled route matches the request.
//
//nolint:gocognit // Route matching requires checking multiple conditions
func (r *Router) matchRoute(
	cr *compiledRoute,
	req *http.Request,
	gqlReq *GraphQLRequest,
	opType string,
) bool {
	// If no match conditions, the route matches everything
	if len(cr.config.Match) == 0 {
		return true
	}

	for i := range cr.config.Match {
		match := &cr.config.Match[i]
		if r.matchCondition(cr, match, req, gqlReq, opType) {
			return true
		}
	}

	return false
}

// matchCondition checks if a single match condition is satisfied.
//
//nolint:gocognit // Match condition checking requires multiple nested checks
func (r *Router) matchCondition(
	cr *compiledRoute,
	match *config.GraphQLRouteMatch,
	req *http.Request,
	gqlReq *GraphQLRequest,
	opType string,
) bool {
	// Check path match
	if match.Path != nil {
		if !matchStringMatch(match.Path, req.URL.Path, cr.pathRegex) {
			return false
		}
	}

	// Check operation type
	if match.OperationType != "" {
		if !strings.EqualFold(match.OperationType, opType) {
			return false
		}
	}

	// Check operation name
	if match.OperationName != nil {
		if !matchStringMatch(match.OperationName, gqlReq.OperationName, cr.opNameRegex) {
			return false
		}
	}

	// Check headers
	for _, headerMatch := range match.Headers {
		headerValue := req.Header.Get(headerMatch.Name)
		if !matchHeaderConfig(&headerMatch, headerValue, cr.headerRegexes) {
			return false
		}
	}

	return true
}

// matchStringMatch checks if a value matches a StringMatch configuration.
func matchStringMatch(sm *config.StringMatch, value string, compiledRegex *regexp.Regexp) bool {
	if sm == nil {
		return true
	}

	if sm.Exact != "" {
		return sm.Exact == value
	}
	if sm.Prefix != "" {
		return strings.HasPrefix(value, sm.Prefix)
	}
	if sm.Regex != "" && compiledRegex != nil {
		return compiledRegex.MatchString(value)
	}

	return true
}

// matchHeaderConfig checks if a header value matches a HeaderMatchConfig.
func matchHeaderConfig(
	hm *config.HeaderMatchConfig,
	value string,
	regexes map[string]*regexp.Regexp,
) bool {
	if hm.Exact != "" {
		return hm.Exact == value
	}
	if hm.Prefix != "" {
		return strings.HasPrefix(value, hm.Prefix)
	}
	if hm.Regex != "" {
		if re, ok := regexes[hm.Name]; ok {
			return re.MatchString(value)
		}
	}
	return true
}

// compileRoute compiles a route configuration with pre-compiled regex patterns.
func compileRoute(route *config.GraphQLRoute) (*compiledRoute, error) {
	cr := &compiledRoute{
		config:        *route,
		headerRegexes: make(map[string]*regexp.Regexp),
	}

	for _, match := range route.Match {
		if err := compileMatchRegexes(cr, &match); err != nil {
			return nil, err
		}
	}

	return cr, nil
}

// compileMatchRegexes compiles regex patterns from a single match condition.
func compileMatchRegexes(cr *compiledRoute, match *config.GraphQLRouteMatch) error {
	if match.Path != nil && match.Path.Regex != "" {
		re, err := regexp.Compile(match.Path.Regex)
		if err != nil {
			return fmt.Errorf("invalid path regex: %w", err)
		}
		cr.pathRegex = re
	}

	if match.OperationName != nil && match.OperationName.Regex != "" {
		re, err := regexp.Compile(match.OperationName.Regex)
		if err != nil {
			return fmt.Errorf("invalid operation name regex: %w", err)
		}
		cr.opNameRegex = re
	}

	for _, hm := range match.Headers {
		if hm.Regex != "" {
			re, err := regexp.Compile(hm.Regex)
			if err != nil {
				return fmt.Errorf("invalid header regex for %q: %w", hm.Name, err)
			}
			cr.headerRegexes[hm.Name] = re
		}
	}

	return nil
}

// detectOperationType detects the GraphQL operation type from the query string.
func detectOperationType(query string) string {
	trimmed := strings.TrimSpace(query)

	if strings.HasPrefix(trimmed, "mutation") {
		return "mutation"
	}
	if strings.HasPrefix(trimmed, "subscription") {
		return "subscription"
	}
	// Default to query (including shorthand queries without the "query" keyword)
	return "query"
}

// ParseGraphQLRequest parses a GraphQL request from an HTTP request body.
func ParseGraphQLRequest(r *http.Request) (*GraphQLRequest, error) {
	if r.Body == nil {
		return nil, fmt.Errorf("request body is empty")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	var gqlReq GraphQLRequest
	if err := json.Unmarshal(body, &gqlReq); err != nil {
		return nil, fmt.Errorf("failed to parse GraphQL request: %w", err)
	}

	if gqlReq.Query == "" {
		return nil, fmt.Errorf("GraphQL query is empty")
	}

	return &gqlReq, nil
}

// RouteCount returns the number of loaded routes.
func (r *Router) RouteCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.routes)
}
