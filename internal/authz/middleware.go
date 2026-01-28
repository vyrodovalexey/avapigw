package authz

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// HTTPAuthorizer handles authorization for HTTP requests.
type HTTPAuthorizer interface {
	// Authorize authorizes an HTTP request.
	Authorize(r *http.Request) (*Decision, error)

	// HTTPMiddleware returns an HTTP middleware for authorization.
	HTTPMiddleware() func(http.Handler) http.Handler
}

// httpAuthorizer implements the HTTPAuthorizer interface.
type httpAuthorizer struct {
	authorizer Authorizer
	config     *Config
	logger     observability.Logger
	metrics    *Metrics
}

// HTTPAuthorizerOption is a functional option for the HTTP authorizer.
type HTTPAuthorizerOption func(*httpAuthorizer)

// WithHTTPAuthorizerLogger sets the logger.
func WithHTTPAuthorizerLogger(logger observability.Logger) HTTPAuthorizerOption {
	return func(a *httpAuthorizer) {
		a.logger = logger
	}
}

// WithHTTPAuthorizerMetrics sets the metrics.
func WithHTTPAuthorizerMetrics(metrics *Metrics) HTTPAuthorizerOption {
	return func(a *httpAuthorizer) {
		a.metrics = metrics
	}
}

// NewHTTPAuthorizer creates a new HTTP authorizer.
func NewHTTPAuthorizer(authorizer Authorizer, config *Config, opts ...HTTPAuthorizerOption) HTTPAuthorizer {
	a := &httpAuthorizer{
		authorizer: authorizer,
		config:     config,
		logger:     observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.metrics == nil {
		a.metrics = NewMetrics("gateway")
	}

	return a
}

// Authorize authorizes an HTTP request.
func (a *httpAuthorizer) Authorize(r *http.Request) (*Decision, error) {
	ctx := r.Context()

	// Get identity from context
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return nil, ErrNoIdentity
	}

	// Build authorization request
	req := &Request{
		Identity: identity,
		Resource: r.URL.Path,
		Action:   r.Method,
		Context:  a.buildRequestContext(r),
	}

	return a.authorizer.Authorize(ctx, req)
}

// buildRequestContext builds the request context for authorization.
func (a *httpAuthorizer) buildRequestContext(r *http.Request) map[string]interface{} {
	ctx := make(map[string]interface{})

	// Add request information
	ctx["method"] = r.Method
	ctx["path"] = r.URL.Path
	ctx["query"] = r.URL.RawQuery
	ctx["host"] = r.Host
	ctx["remote_addr"] = r.RemoteAddr
	ctx["user_agent"] = r.UserAgent()

	// Add headers (excluding sensitive ones)
	headers := make(map[string]string)
	for key, values := range r.Header {
		if !isSensitiveHeader(key) && len(values) > 0 {
			headers[key] = values[0]
		}
	}
	ctx["headers"] = headers

	// Extract client IP
	ctx["client_ip"] = extractClientIP(r)

	return ctx
}

// HTTPMiddleware returns an HTTP middleware for authorization.
func (a *httpAuthorizer) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			decision, err := a.Authorize(r)
			if err != nil {
				a.handleAuthzError(w, r, err)
				return
			}

			if !decision.Allowed {
				a.handleAccessDenied(w, r, decision)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// handleAuthzError handles authorization errors.
func (a *httpAuthorizer) handleAuthzError(w http.ResponseWriter, r *http.Request, err error) {
	a.logger.Warn("authorization error",
		observability.String("path", r.URL.Path),
		observability.String("method", r.Method),
		observability.Error(err),
	)

	w.Header().Set(HeaderContentType, ContentTypeJSON)

	var statusCode int
	var message string

	switch {
	case errors.Is(err, ErrNoIdentity):
		statusCode = http.StatusUnauthorized
		message = "authentication required"
	case errors.Is(err, ErrExternalAuthzTimeout):
		statusCode = http.StatusGatewayTimeout
		message = "authorization timeout"
	case errors.Is(err, ErrExternalAuthzUnavailable):
		statusCode = http.StatusServiceUnavailable
		message = "authorization service unavailable"
	default:
		statusCode = http.StatusInternalServerError
		message = "authorization error"
	}

	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// handleAccessDenied handles access denied responses.
func (a *httpAuthorizer) handleAccessDenied(w http.ResponseWriter, r *http.Request, decision *Decision) {
	a.logger.Warn("access denied",
		observability.String("path", r.URL.Path),
		observability.String("method", r.Method),
		observability.String("reason", decision.Reason),
		observability.String("policy", decision.Policy),
	)

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "access denied",
		"reason": decision.Reason,
	})
}

// isSensitiveHeader checks if a header is sensitive and should not be included in context.
func isSensitiveHeader(name string) bool {
	sensitiveHeaders := map[string]bool{
		HeaderAuthorization:      true,
		HeaderCookie:             true,
		HeaderSetCookie:          true,
		HeaderXAPIKey:            true,
		HeaderXAuthToken:         true,
		HeaderProxyAuthorization: true,
	}
	return sensitiveHeaders[name]
}

// extractClientIP extracts the client IP from the request using the
// secure global ClientIPExtractor which validates trusted proxies
// before trusting X-Forwarded-For headers.
func extractClientIP(r *http.Request) string {
	return middleware.GetClientIP(r)
}

// Ensure httpAuthorizer implements HTTPAuthorizer.
var _ HTTPAuthorizer = (*httpAuthorizer)(nil)
