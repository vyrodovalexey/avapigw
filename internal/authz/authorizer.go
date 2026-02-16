package authz

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// authzTracer is the OTEL tracer used for authorization operations.
var authzTracer = otel.Tracer("avapigw/authz")

// Decision represents an authorization decision.
type Decision struct {
	// Allowed indicates if the request is allowed.
	Allowed bool

	// Reason is the reason for the decision.
	Reason string

	// Policy is the policy that made the decision.
	Policy string

	// Engine is the engine that made the decision.
	Engine string

	// Cached indicates if the decision was from cache.
	Cached bool
}

// Request represents an authorization request.
type Request struct {
	// Identity is the authenticated identity.
	Identity *auth.Identity

	// Resource is the resource being accessed.
	Resource string

	// Action is the action being performed.
	Action string

	// Context contains additional context for the request.
	Context map[string]interface{}
}

// Authorizer handles authorization.
type Authorizer interface {
	// Authorize authorizes a request.
	Authorize(ctx context.Context, req *Request) (*Decision, error)

	// Close closes the authorizer.
	Close() error
}

// authorizer implements the Authorizer interface.
type authorizer struct {
	config     *Config
	rbacEngine rbac.Engine
	abacEngine abac.Engine
	opaClient  external.OPAClient
	cache      DecisionCache
	logger     observability.Logger
	metrics    *Metrics
}

// AuthorizerOption is a functional option for the authorizer.
type AuthorizerOption func(*authorizer)

// WithAuthorizerLogger sets the logger.
func WithAuthorizerLogger(logger observability.Logger) AuthorizerOption {
	return func(a *authorizer) {
		a.logger = logger
	}
}

// WithAuthorizerMetrics sets the metrics.
func WithAuthorizerMetrics(metrics *Metrics) AuthorizerOption {
	return func(a *authorizer) {
		a.metrics = metrics
	}
}

// WithRBACEngine sets the RBAC engine.
func WithRBACEngine(engine rbac.Engine) AuthorizerOption {
	return func(a *authorizer) {
		a.rbacEngine = engine
	}
}

// WithABACEngine sets the ABAC engine.
func WithABACEngine(engine abac.Engine) AuthorizerOption {
	return func(a *authorizer) {
		a.abacEngine = engine
	}
}

// WithOPAClient sets the OPA client.
func WithOPAClient(client external.OPAClient) AuthorizerOption {
	return func(a *authorizer) {
		a.opaClient = client
	}
}

// WithDecisionCache sets the decision cache.
func WithDecisionCache(cache DecisionCache) AuthorizerOption {
	return func(a *authorizer) {
		a.cache = cache
	}
}

// New creates a new authorizer.
func New(config *Config, opts ...AuthorizerOption) (Authorizer, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}

	a := &authorizer{
		config: config,
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(a)
	}

	// Initialize metrics if not provided
	if a.metrics == nil {
		a.metrics = NewMetrics("gateway")
	}

	// Initialize engines
	if err := a.initializeEngines(config); err != nil {
		return nil, err
	}

	// Initialize cache
	a.initializeCache(config)

	return a, nil
}

// initializeEngines initializes the authorization engines.
func (a *authorizer) initializeEngines(config *Config) error {
	if err := a.initializeRBAC(config); err != nil {
		return err
	}
	if err := a.initializeABAC(config); err != nil {
		return err
	}
	return a.initializeOPA(config)
}

// initializeRBAC initializes the RBAC engine if enabled.
func (a *authorizer) initializeRBAC(config *Config) error {
	if !config.IsRBACEnabled() || a.rbacEngine != nil {
		return nil
	}
	engine, err := rbac.NewEngine(config.RBAC, rbac.WithEngineLogger(a.logger))
	if err != nil {
		return err
	}
	a.rbacEngine = engine
	a.metrics.SetPolicyCount("rbac", len(config.RBAC.Policies))
	return nil
}

// initializeABAC initializes the ABAC engine if enabled.
func (a *authorizer) initializeABAC(config *Config) error {
	if !config.IsABACEnabled() || a.abacEngine != nil {
		return nil
	}
	engine, err := abac.NewEngine(config.ABAC, abac.WithEngineLogger(a.logger))
	if err != nil {
		return err
	}
	a.abacEngine = engine
	a.metrics.SetPolicyCount("abac", len(config.ABAC.Policies))
	return nil
}

// initializeOPA initializes the OPA client if enabled.
func (a *authorizer) initializeOPA(config *Config) error {
	if !config.IsExternalEnabled() || config.External.OPA == nil || a.opaClient != nil {
		return nil
	}
	timeout := 10 * time.Second
	if config.External.Timeout > 0 {
		timeout = config.External.Timeout
	}
	client, err := external.NewOPAClient(config.External.OPA, timeout, external.WithOPALogger(a.logger))
	if err != nil {
		return err
	}
	a.opaClient = client
	return nil
}

// initializeCache initializes the decision cache.
func (a *authorizer) initializeCache(config *Config) {
	if a.cache != nil {
		return
	}
	if config.Cache == nil || !config.Cache.Enabled {
		a.cache = NewNoopDecisionCache()
		return
	}
	ttl := 5 * time.Minute
	if config.Cache.TTL > 0 {
		ttl = config.Cache.TTL
	}
	maxSize := 10000
	if config.Cache.MaxSize > 0 {
		maxSize = config.Cache.MaxSize
	}
	a.cache = NewMemoryDecisionCache(ttl, maxSize,
		WithMemoryCacheLogger(a.logger),
		WithMemoryCacheMetrics(a.metrics),
	)
}

// Authorize authorizes a request.
func (a *authorizer) Authorize(ctx context.Context, req *Request) (*Decision, error) {
	start := time.Now()

	ctx, span := authzTracer.Start(ctx, "authz.authorize",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("authz.resource", req.Resource),
			attribute.String("authz.action", req.Action),
		),
	)
	defer span.End()

	// Check if authorization is enabled
	if !a.config.Enabled {
		span.SetAttributes(attribute.String("authz.result", "disabled"))
		return &Decision{
			Allowed: true,
			Reason:  "authorization disabled",
		}, nil
	}

	// Check if path should be skipped
	if a.config.ShouldSkipPath(req.Resource) {
		span.SetAttributes(attribute.String("authz.result", "skipped"))
		return &Decision{
			Allowed: true,
			Reason:  "path skipped",
		}, nil
	}

	// Check if identity is present
	if req.Identity == nil {
		span.SetAttributes(attribute.String("authz.result", "no_identity"))
		return nil, ErrNoIdentity
	}

	span.SetAttributes(attribute.String("authz.subject", req.Identity.Subject))

	// Check cache
	cacheKey := a.buildCacheKey(req)
	if cached, ok := a.cache.Get(ctx, cacheKey); ok {
		span.SetAttributes(
			attribute.Bool("authz.cached", true),
			attribute.Bool("authz.allowed", cached.Allowed),
			attribute.String("authz.policy", cached.Policy),
		)
		a.logger.Debug("authorization decision from cache",
			observability.String("subject", req.Identity.Subject),
			observability.String("resource", req.Resource),
			observability.String("action", req.Action),
			observability.Bool("allowed", cached.Allowed),
		)
		return &Decision{
			Allowed: cached.Allowed,
			Reason:  cached.Reason,
			Policy:  cached.Policy,
			Cached:  true,
		}, nil
	}

	// Evaluate authorization
	decision, err := a.evaluate(ctx, req)
	if err != nil {
		span.SetAttributes(
			attribute.String("authz.result", "error"),
			attribute.String("authz.error", err.Error()),
		)
		a.metrics.RecordEvaluation("combined", "error", time.Since(start))
		return nil, err
	}

	// Cache the decision
	a.cache.Set(ctx, cacheKey, &CachedDecision{
		Allowed: decision.Allowed,
		Reason:  decision.Reason,
		Policy:  decision.Policy,
	})

	// Record metrics
	result := "denied"
	if decision.Allowed {
		result = "allowed"
	}
	a.metrics.RecordEvaluation("combined", result, time.Since(start))
	a.metrics.RecordDecision(result, decision.Policy)

	span.SetAttributes(
		attribute.Bool("authz.cached", false),
		attribute.Bool("authz.allowed", decision.Allowed),
		attribute.String("authz.engine", decision.Engine),
		attribute.String("authz.policy", decision.Policy),
		attribute.String("authz.reason", decision.Reason),
	)

	a.logger.Debug("authorization decision",
		observability.String("subject", req.Identity.Subject),
		observability.String("resource", req.Resource),
		observability.String("action", req.Action),
		observability.Bool("allowed", decision.Allowed),
		observability.String("engine", decision.Engine),
		observability.String("policy", decision.Policy),
	)

	return decision, nil
}

// evaluate evaluates authorization using configured engines.
func (a *authorizer) evaluate(ctx context.Context, req *Request) (*Decision, error) {
	// Try RBAC first
	if a.config.IsRBACEnabled() && a.rbacEngine != nil {
		decision, err := a.evaluateRBAC(ctx, req)
		if err != nil {
			a.logger.Warn("RBAC evaluation failed", observability.Error(err))
		} else if decision.Policy != "" {
			// RBAC made a decision
			return decision, nil
		}
	}

	// Try ABAC
	if a.config.IsABACEnabled() && a.abacEngine != nil {
		decision, err := a.evaluateABAC(ctx, req)
		if err != nil {
			a.logger.Warn("ABAC evaluation failed", observability.Error(err))
		} else if decision.Policy != "" {
			// ABAC made a decision
			return decision, nil
		}
	}

	// Try external authorization
	if a.config.IsExternalEnabled() && a.opaClient != nil {
		decision, err := a.evaluateExternal(ctx, req)
		if err != nil {
			a.logger.Warn("external authorization failed", observability.Error(err))
			// Don't fail on external authz errors if fail-open is configured
			if a.config.External.FailOpen {
				return &Decision{
					Allowed: true,
					Reason:  "external authorization failed, fail-open enabled",
					Engine:  "external",
				}, nil
			}
			return nil, err
		}
		return decision, nil
	}

	// No engine made a decision, use default policy
	defaultAllowed := a.config.GetEffectiveDefaultPolicy() == PolicyAllow
	return &Decision{
		Allowed: defaultAllowed,
		Reason:  "default policy",
		Engine:  "default",
	}, nil
}

// evaluateRBAC evaluates authorization using RBAC.
func (a *authorizer) evaluateRBAC(ctx context.Context, req *Request) (*Decision, error) {
	rbacReq := &rbac.Request{
		Subject:     req.Identity.Subject,
		Roles:       req.Identity.Roles,
		Permissions: req.Identity.Permissions,
		Groups:      req.Identity.Groups,
		Resource:    req.Resource,
		Action:      req.Action,
		Context:     req.Context,
	}

	rbacDecision, err := a.rbacEngine.Authorize(ctx, rbacReq)
	if err != nil {
		return nil, err
	}

	return &Decision{
		Allowed: rbacDecision.Allowed,
		Reason:  rbacDecision.Reason,
		Policy:  rbacDecision.Policy,
		Engine:  "rbac",
	}, nil
}

// evaluateABAC evaluates authorization using ABAC.
func (a *authorizer) evaluateABAC(ctx context.Context, req *Request) (*Decision, error) {
	// Build subject attributes
	subjectAttrs := map[string]interface{}{
		"id":          req.Identity.Subject,
		"roles":       req.Identity.Roles,
		"permissions": req.Identity.Permissions,
		"groups":      req.Identity.Groups,
		"scopes":      req.Identity.Scopes,
		"email":       req.Identity.Email,
		"tenant_id":   req.Identity.TenantID,
	}

	// Add claims to subject attributes
	for k, v := range req.Identity.Claims {
		subjectAttrs[k] = v
	}

	abacReq := &abac.Request{
		Subject:      subjectAttrs,
		Resource:     req.Resource,
		Action:       req.Action,
		RequestAttrs: req.Context,
		Environment: map[string]interface{}{
			"time": time.Now(),
		},
	}

	abacDecision, err := a.abacEngine.Authorize(ctx, abacReq)
	if err != nil {
		return nil, err
	}

	return &Decision{
		Allowed: abacDecision.Allowed,
		Reason:  abacDecision.Reason,
		Policy:  abacDecision.Policy,
		Engine:  "abac",
	}, nil
}

// evaluateExternal evaluates authorization using external authorization.
func (a *authorizer) evaluateExternal(ctx context.Context, req *Request) (*Decision, error) {
	start := time.Now()

	input := &external.OPAInput{
		Subject: map[string]interface{}{
			"id":          req.Identity.Subject,
			"roles":       req.Identity.Roles,
			"permissions": req.Identity.Permissions,
			"groups":      req.Identity.Groups,
			"scopes":      req.Identity.Scopes,
			"email":       req.Identity.Email,
			"tenant_id":   req.Identity.TenantID,
			"claims":      req.Identity.Claims,
		},
		Resource: req.Resource,
		Action:   req.Action,
		Request:  req.Context,
		Context:  req.Context,
	}

	result, err := a.opaClient.Authorize(ctx, input)
	if err != nil {
		a.metrics.RecordExternalRequest("opa", "error", time.Since(start))
		return nil, err
	}

	status := "denied"
	if result.Allow {
		status = "allowed"
	}
	a.metrics.RecordExternalRequest("opa", status, time.Since(start))

	return &Decision{
		Allowed: result.Allow,
		Reason:  result.Reason,
		Engine:  "external",
	}, nil
}

// buildCacheKey builds a cache key for the request.
func (a *authorizer) buildCacheKey(req *Request) *CacheKey {
	return &CacheKey{
		Subject:  req.Identity.Subject,
		Resource: req.Resource,
		Action:   req.Action,
		Roles:    req.Identity.Roles,
		Groups:   req.Identity.Groups,
	}
}

// Close closes the authorizer.
func (a *authorizer) Close() error {
	var errs []error

	if a.cache != nil {
		if err := a.cache.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if a.opaClient != nil {
		if err := a.opaClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// Ensure authorizer implements Authorizer.
var _ Authorizer = (*authorizer)(nil)
