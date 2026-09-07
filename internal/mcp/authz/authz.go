package authz

import (
	"context"
	"errors"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Sentinel errors returned by token validation and authorization.
var (
	// ErrNoToken indicates no bearer token was presented.
	ErrNoToken = errors.New("mcp authz: no bearer token")
	// ErrInvalidToken indicates the token failed signature/issuer validation.
	ErrInvalidToken = errors.New("mcp authz: invalid token")
	// ErrAudienceMismatch indicates the token audience is not the hub's
	// canonical URI (HUB-302).
	ErrAudienceMismatch = errors.New("mcp authz: token audience is not the hub resource")
	// ErrInsufficientScope indicates the principal lacks a required scope.
	ErrInsufficientScope = errors.New("mcp authz: insufficient scope")
	// ErrPolicyDenied indicates the policy engine denied the request.
	ErrPolicyDenied = errors.New("mcp authz: denied by policy")
)

// Principal is the authenticated caller derived from a validated bearer token.
type Principal struct {
	// Subject is the token subject (the principal identity).
	Subject string
	// Scopes is the set of scopes granted to the token.
	Scopes []string
	// Issuer is the token issuer.
	Issuer string
}

// TokenValidator validates a bearer token and returns its claims. It is
// satisfied by an adapter over internal/auth/oidc.Provider so signature and
// issuer validation are reused; the audience check is layered on top here.
type TokenValidator interface {
	// Validate validates the token and returns its info, or an error.
	Validate(ctx context.Context, token string) (*oidc.TokenInfo, error)
}

// oidcValidator adapts an oidc.Provider to the TokenValidator interface.
type oidcValidator struct {
	provider oidc.Provider
}

// NewOIDCValidator wraps an oidc.Provider as a TokenValidator.
func NewOIDCValidator(provider oidc.Provider) TokenValidator {
	return &oidcValidator{provider: provider}
}

// Validate delegates to the OIDC provider for signature/issuer validation.
func (v *oidcValidator) Validate(ctx context.Context, token string) (*oidc.TokenInfo, error) {
	info, err := v.provider.ValidateToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// Config configures the Authorizer.
type Config struct {
	// CanonicalURI is the hub's canonical resource identifier; presented
	// token audiences MUST contain it (HUB-302).
	CanonicalURI string
	// ResourceMetadataURL is the absolute URL of the RFC 9728 metadata
	// document, embedded in WWW-Authenticate challenges.
	ResourceMetadataURL string
	// PolicyMode enables the deny-by-default policy engine (HUB-310).
	PolicyMode bool
}

// Authorizer validates tokens (audience-aware) and enforces scope + policy for
// MCP requests. It is additive: when Validator is nil, ValidateToken returns
// ErrNoToken and callers treat authorization as not configured.
type Authorizer struct {
	validator TokenValidator
	scopes    ScopeResolver
	policy    PolicyEngine
	cfg       Config
	logger    observability.Logger
}

// Option is a functional option for the Authorizer.
type Option func(*Authorizer)

// WithLogger sets the authorizer logger.
func WithLogger(logger observability.Logger) Option {
	return func(a *Authorizer) {
		if logger != nil {
			a.logger = logger
		}
	}
}

// WithScopeResolver sets the scope resolver.
func WithScopeResolver(r ScopeResolver) Option {
	return func(a *Authorizer) {
		if r != nil {
			a.scopes = r
		}
	}
}

// WithPolicyEngine sets the policy engine.
func WithPolicyEngine(p PolicyEngine) Option {
	return func(a *Authorizer) {
		if p != nil {
			a.policy = p
		}
	}
}

// NewAuthorizer constructs an Authorizer. The validator may be nil for routes
// that do not require authentication (additive/opt-in). A nil scope resolver
// defaults to the map-based resolver with no mappings (everything allowed by
// scope), and a nil policy engine defaults to allow-all unless PolicyMode is
// set, in which case a deny-by-default engine is used.
func NewAuthorizer(validator TokenValidator, cfg Config, opts ...Option) *Authorizer {
	a := &Authorizer{
		validator: validator,
		scopes:    NewMapScopeResolver(nil, nil),
		policy:    AllowAllPolicy{},
		cfg:       cfg,
		logger:    observability.NopLogger(),
	}
	if cfg.PolicyMode {
		a.policy = NewDenyByDefaultPolicy(nil)
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Enabled reports whether token validation is configured for this authorizer.
func (a *Authorizer) Enabled() bool { return a.validator != nil }

// ResourceMetadataURL returns the configured metadata URL for challenges.
func (a *Authorizer) ResourceMetadataURL() string { return a.cfg.ResourceMetadataURL }

// ValidateToken validates the bearer token, enforcing the audience check
// (HUB-302) on top of the provider's signature/issuer validation, and returns
// the resulting principal.
func (a *Authorizer) ValidateToken(ctx context.Context, token string) (*Principal, error) {
	if a.validator == nil {
		return nil, ErrNoToken
	}
	if token == "" {
		return nil, ErrNoToken
	}
	info, err := a.validator.Validate(ctx, token)
	if err != nil {
		return nil, errors.Join(ErrInvalidToken, err)
	}
	if !audienceMatches(info.Audience, a.cfg.CanonicalURI) {
		return nil, ErrAudienceMismatch
	}
	return &Principal{
		Subject: info.Subject,
		Scopes:  info.Scopes,
		Issuer:  info.Issuer,
	}, nil
}

// RequiredScopes returns the scopes required for (method, primitive), combined
// with any route ScopeMap the caller has installed on the resolver.
func (a *Authorizer) RequiredScopes(method, primitive string) []string {
	return a.scopes.Required(method, primitive)
}

// EnforceScopes checks whether the principal's granted scopes are sufficient
// for the required scopes using the authorizer's default resolver, returning
// ErrInsufficientScope when not (HUB-305/306).
func (a *Authorizer) EnforceScopes(granted, required []string) error {
	return a.EnforceScopesWith(a.scopes, granted, required)
}

// EnforceScopesWith checks sufficiency using an explicit resolver so a
// per-route ScopeResolver (built from the route ScopeMap) can drive the
// hierarchy-aware decision (HUB-305/306).
func (a *Authorizer) EnforceScopesWith(resolver ScopeResolver, granted, required []string) error {
	if len(required) == 0 {
		return nil
	}
	if resolver == nil {
		resolver = a.scopes
	}
	if resolver.Sufficient(granted, required) {
		return nil
	}
	return ErrInsufficientScope
}

// EnforcePolicy consults the deny-by-default policy engine (HUB-310).
func (a *Authorizer) EnforcePolicy(
	ctx context.Context, principal, upstream, primitive, method string,
) error {
	allow, reason := a.policy.Decide(ctx, principal, upstream, primitive, method)
	if allow {
		return nil
	}
	a.logger.Debug("mcp authz: policy denied",
		observability.String("principal", principal),
		observability.String("upstream", upstream),
		observability.String("primitive", primitive),
		observability.String("method", method),
		observability.String("reason", reason))
	return ErrPolicyDenied
}

// PermitsPrimitive reports whether the principal's granted scopes (evaluated
// against the supplied per-route resolver) and the policy engine permit the
// (method, primitive). It is used to filter list results to the primitives the
// caller may see (HUB-306). A nil resolver falls back to the authorizer's
// default resolver.
func (a *Authorizer) PermitsPrimitive(
	ctx context.Context, resolver ScopeResolver, p *Principal, upstream, primitive, method string,
) bool {
	if p == nil {
		return false
	}
	if resolver == nil {
		resolver = a.scopes
	}
	if err := a.EnforceScopesWith(resolver, p.Scopes, resolver.Required(method, primitive)); err != nil {
		return false
	}
	return a.EnforcePolicy(ctx, p.Subject, upstream, primitive, method) == nil
}

// audienceMatches reports whether the token audience contains the hub's
// canonical URI (RFC 8707, HUB-302). An empty canonical URI disables the check
// (audience validation is opt-in via configuration).
func audienceMatches(audience []string, canonical string) bool {
	if canonical == "" {
		return true
	}
	for _, aud := range audience {
		if strings.EqualFold(strings.TrimRight(aud, "/"), strings.TrimRight(canonical, "/")) {
			return true
		}
	}
	return false
}
