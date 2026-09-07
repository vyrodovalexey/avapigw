package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
)

// fakeValidator is a test TokenValidator returning a canned info/error.
type fakeValidator struct {
	info *oidc.TokenInfo
	err  error
}

func (f *fakeValidator) Validate(_ context.Context, _ string) (*oidc.TokenInfo, error) {
	return f.info, f.err
}

// ── resource_metadata / RFC 9728 ────────────────────────────────────────

func TestResourceMetadataHandlerServeHTTP(t *testing.T) {
	t.Parallel()
	h, err := NewResourceMetadataHandler(
		"https://hub.example/mcp",
		[]string{"https://issuer.example"},
		[]string{"mcp:tools:read", "mcp:tools"},
	)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, WellKnownPath, nil)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var md ResourceMetadata
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &md))
	assert.Equal(t, "https://hub.example/mcp", md.Resource)
	assert.Equal(t, []string{"https://issuer.example"}, md.AuthorizationServers)
	assert.Equal(t, []string{bearerMethodHeader}, md.BearerMethodsSupported)
	assert.Equal(t, h.Metadata().Resource, md.Resource)
}

func TestResourceMetadataHandlerHEAD(t *testing.T) {
	t.Parallel()
	h, err := NewResourceMetadataHandler("https://hub.example/mcp", nil, nil)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, WellKnownPath, nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.Bytes(), "HEAD returns no body")
}

func TestResourceMetadataHandlerMethodNotAllowed(t *testing.T) {
	t.Parallel()
	h, err := NewResourceMetadataHandler("https://hub.example/mcp", nil, nil)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, WellKnownPath, nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, http.MethodGet, rec.Header().Get("Allow"))
}

func TestExtractBearer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"valid", "Bearer abc.def", "abc.def"},
		{"case insensitive scheme", "bearer abc", "abc"},
		{"trims whitespace", "Bearer   spaced  ", "spaced"},
		{"missing", "", ""},
		{"wrong scheme", "Basic xyz", ""},
		{"scheme only", "Bearer", ""},
		{"scheme only with space", "Bearer ", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			assert.Equal(t, tc.want, ExtractBearer(req))
		})
	}
}

func TestWriteUnauthorized(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteUnauthorized(rec, "https://hub.example/.well-known/oauth-protected-resource", "mcp:tools:read", "expired")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	challenge := rec.Header().Get("WWW-Authenticate")
	assert.True(t, strings.HasPrefix(challenge, "Bearer "))
	assert.Contains(t, challenge, `resource_metadata="https://hub.example/.well-known/oauth-protected-resource"`)
	assert.Contains(t, challenge, `scope="mcp:tools:read"`)
	assert.Contains(t, challenge, `error="invalid_token"`)
	assert.Contains(t, challenge, `error_description="expired"`)
}

func TestWriteUnauthorizedEmptyParams(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteUnauthorized(rec, "", "", "")
	// Empty resource_metadata/scope/description are omitted, but the
	// constant error code remains.
	assert.Equal(t, `Bearer error="invalid_token"`, rec.Header().Get("WWW-Authenticate"))
}

func TestWriteInsufficientScope(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteInsufficientScope(rec, "https://hub.example/meta", []string{"mcp:tools:read", "mcp:tools:write"})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	challenge := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, challenge, `error="insufficient_scope"`)
	// ALL scopes named in a single challenge (HUB-305).
	assert.Contains(t, challenge, `scope="mcp:tools:read mcp:tools:write"`)
	assert.Contains(t, challenge, `resource_metadata="https://hub.example/meta"`)
}

// ── scope resolver ──────────────────────────────────────────────────────

func TestSatisfiedByHierarchy(t *testing.T) {
	t.Parallel()
	r := NewMapScopeResolver(nil, nil)
	cases := []struct {
		name     string
		granted  []string
		required []string
		want     bool
	}{
		{"exact match", []string{"mcp:tools:read"}, []string{"mcp:tools:read"}, true},
		{"broad grant satisfies child", []string{"mcp:tools"}, []string{"mcp:tools:read"}, true},
		{"narrow grant does not satisfy broad", []string{"mcp:tools:read"}, []string{"mcp:tools"}, false},
		{"unrelated", []string{"mcp:prompts"}, []string{"mcp:tools:read"}, false},
		{"prefix without separator not sufficient", []string{"mcp:tool"}, []string{"mcp:tools"}, false},
		{"empty required always sufficient", []string{}, []string{}, true},
		{"multiple required all satisfied", []string{"mcp:tools"}, []string{"mcp:tools:read", "mcp:tools:write"}, true},
		{"multiple required one missing", []string{"mcp:tools:read"}, []string{"mcp:tools:read", "mcp:tools:write"}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, r.Sufficient(tc.granted, tc.required))
		})
	}
}

func TestMapScopeResolverRequiredUnion(t *testing.T) {
	t.Parallel()
	r := NewMapScopeResolver(map[string][]string{
		"tools/call|echo": {"mcp:tools:echo"},
		"tools/call":      {"mcp:tools:call"},
		"echo":            {"mcp:primitive:echo"},
	}, []string{"mcp:base"})

	got := r.Required("tools/call", "echo")
	// Union of method|primitive, method, primitive and "*".
	assert.ElementsMatch(t, []string{"mcp:tools:echo", "mcp:tools:call", "mcp:primitive:echo", "mcp:base"}, got)
	// Stable ordering (sorted).
	sorted := append([]string(nil), got...)
	assert.Equal(t, sorted, got)
}

func TestMapScopeResolverRequiredNoPrimitive(t *testing.T) {
	t.Parallel()
	r := NewMapScopeResolver(map[string][]string{"tools/list": {"mcp:tools:read"}}, nil)
	got := r.Required("tools/list", "")
	assert.Equal(t, []string{"mcp:tools:read"}, got)
}

func TestMapScopeResolverRequiredEmpty(t *testing.T) {
	t.Parallel()
	r := NewMapScopeResolver(nil, nil)
	assert.Empty(t, r.Required("tools/call", "echo"))
}

// ── policy engine ───────────────────────────────────────────────────────

func TestAllowAllPolicy(t *testing.T) {
	t.Parallel()
	allow, reason := AllowAllPolicy{}.Decide(context.Background(), "p", "u", "prim", "m")
	assert.True(t, allow)
	assert.Equal(t, "policy disabled", reason)
}

func TestDenyByDefaultPolicy(t *testing.T) {
	t.Parallel()
	p := NewDenyByDefaultPolicy([]PolicyRule{
		{Principal: "alice", Upstream: "up1"},
		{Method: "tools/list"},
	})
	cases := []struct {
		name                                   string
		principal, upstream, primitive, method string
		want                                   bool
	}{
		{"matches principal+upstream rule", "alice", "up1", "echo", "tools/call", true},
		{"matches wildcard method rule", "bob", "up2", "echo", "tools/list", true},
		{"no rule matches -> deny", "bob", "up2", "echo", "tools/call", false},
		{"principal mismatch", "bob", "up1", "echo", "tools/call", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, reason := p.Decide(context.Background(), tc.principal, tc.upstream, tc.primitive, tc.method)
			assert.Equal(t, tc.want, got)
			assert.NotEmpty(t, reason)
		})
	}
}

func TestDenyByDefaultPolicyNoRules(t *testing.T) {
	t.Parallel()
	p := NewDenyByDefaultPolicy(nil)
	allow, _ := p.Decide(context.Background(), "a", "u", "p", "m")
	assert.False(t, allow)
}

// ── Authorizer / token audience validation ─────────────────────────────

func TestNewAuthorizerDefaults(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer(nil, Config{})
	assert.False(t, a.Enabled())
	assert.IsType(t, AllowAllPolicy{}, a.policy)

	a2 := NewAuthorizer(&fakeValidator{}, Config{PolicyMode: true})
	assert.True(t, a2.Enabled())
	assert.IsType(t, &DenyByDefaultPolicy{}, a2.policy)
}

func TestValidateTokenNoValidator(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer(nil, Config{})
	_, err := a.ValidateToken(context.Background(), "tok")
	assert.ErrorIs(t, err, ErrNoToken)
}

func TestValidateTokenEmptyToken(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer(&fakeValidator{}, Config{})
	_, err := a.ValidateToken(context.Background(), "")
	assert.ErrorIs(t, err, ErrNoToken)
}

func TestValidateTokenValidatorError(t *testing.T) {
	t.Parallel()
	underlying := errors.New("bad signature")
	a := NewAuthorizer(&fakeValidator{err: underlying}, Config{})
	_, err := a.ValidateToken(context.Background(), "tok")
	assert.ErrorIs(t, err, ErrInvalidToken)
	assert.ErrorIs(t, err, underlying)
}

func TestValidateTokenAudienceMismatch(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer(
		&fakeValidator{info: &oidc.TokenInfo{Subject: "s", Audience: []string{"https://other"}}},
		Config{CanonicalURI: "https://hub.example/mcp"},
	)
	_, err := a.ValidateToken(context.Background(), "tok")
	assert.ErrorIs(t, err, ErrAudienceMismatch)
}

func TestValidateTokenAudienceMatch(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer(
		&fakeValidator{info: &oidc.TokenInfo{
			Subject:  "sub-1",
			Issuer:   "https://issuer",
			Scopes:   []string{"mcp:tools:read"},
			Audience: []string{"https://hub.example/mcp/"}, // trailing slash tolerated
		}},
		Config{CanonicalURI: "https://hub.example/mcp"},
	)
	p, err := a.ValidateToken(context.Background(), "tok")
	require.NoError(t, err)
	assert.Equal(t, "sub-1", p.Subject)
	assert.Equal(t, "https://issuer", p.Issuer)
	assert.Equal(t, []string{"mcp:tools:read"}, p.Scopes)
}

func TestValidateTokenEmptyCanonicalDisablesCheck(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer(
		&fakeValidator{info: &oidc.TokenInfo{Subject: "s", Audience: nil}},
		Config{CanonicalURI: ""},
	)
	p, err := a.ValidateToken(context.Background(), "tok")
	require.NoError(t, err)
	assert.Equal(t, "s", p.Subject)
}

func TestRequiredScopesAndResourceMetadataURL(t *testing.T) {
	t.Parallel()
	r := NewMapScopeResolver(map[string][]string{"tools/call": {"mcp:tools:call"}}, nil)
	a := NewAuthorizer(nil, Config{ResourceMetadataURL: "https://hub/meta"}, WithScopeResolver(r))
	assert.Equal(t, []string{"mcp:tools:call"}, a.RequiredScopes("tools/call", ""))
	assert.Equal(t, "https://hub/meta", a.ResourceMetadataURL())
}

func TestEnforceScopes(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer(nil, Config{})
	assert.NoError(t, a.EnforceScopes(nil, nil)) // no required scopes
	assert.NoError(t, a.EnforceScopes([]string{"mcp:tools"}, []string{"mcp:tools:read"}))
	assert.ErrorIs(t, a.EnforceScopes([]string{"mcp:prompts"}, []string{"mcp:tools:read"}), ErrInsufficientScope)
}

func TestEnforceScopesWithNilResolverFallsBack(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer(nil, Config{})
	assert.NoError(t, a.EnforceScopesWith(nil, []string{"mcp:tools:read"}, []string{"mcp:tools:read"}))
}

func TestEnforcePolicy(t *testing.T) {
	t.Parallel()

	t.Run("allow-all default", func(t *testing.T) {
		t.Parallel()
		a := NewAuthorizer(nil, Config{})
		assert.NoError(t, a.EnforcePolicy(context.Background(), "p", "u", "prim", "m"))
	})

	t.Run("deny by default", func(t *testing.T) {
		t.Parallel()
		a := NewAuthorizer(nil, Config{PolicyMode: true})
		assert.ErrorIs(t, a.EnforcePolicy(context.Background(), "p", "u", "prim", "m"), ErrPolicyDenied)
	})
}

func TestPermitsPrimitive(t *testing.T) {
	t.Parallel()
	resolver := NewMapScopeResolver(map[string][]string{"tools/call": {"mcp:tools:call"}}, nil)
	a := NewAuthorizer(nil, Config{}, WithScopeResolver(resolver), WithPolicyEngine(AllowAllPolicy{}))

	p := &Principal{Subject: "alice", Scopes: []string{"mcp:tools:call"}}
	assert.True(t, a.PermitsPrimitive(context.Background(), resolver, p, "up1", "echo", "tools/call"))

	// Nil principal is never permitted.
	assert.False(t, a.PermitsPrimitive(context.Background(), resolver, nil, "up1", "echo", "tools/call"))

	// Insufficient scope filters it out.
	poor := &Principal{Subject: "bob", Scopes: []string{"mcp:prompts"}}
	assert.False(t, a.PermitsPrimitive(context.Background(), resolver, poor, "up1", "echo", "tools/call"))

	// Nil resolver falls back to default (no mapping -> allowed by scope).
	a2 := NewAuthorizer(nil, Config{})
	assert.True(t, a2.PermitsPrimitive(context.Background(), nil, p, "up1", "echo", "tools/call"))
}

func TestPermitsPrimitivePolicyDenied(t *testing.T) {
	t.Parallel()
	resolver := NewMapScopeResolver(nil, nil)
	a := NewAuthorizer(nil, Config{}, WithPolicyEngine(NewDenyByDefaultPolicy(nil)))
	p := &Principal{Subject: "alice"}
	assert.False(t, a.PermitsPrimitive(context.Background(), resolver, p, "up1", "echo", "tools/call"))
}

func TestNewOIDCValidatorRoundTrip(t *testing.T) {
	t.Parallel()
	// Ensure the constructor and adapter compile and delegate. A nil
	// provider would panic on use, so we only assert construction here.
	v := NewOIDCValidator(nil)
	require.NotNil(t, v)
}
