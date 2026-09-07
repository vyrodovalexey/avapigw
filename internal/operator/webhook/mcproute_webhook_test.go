// Package webhook provides admission webhooks for the operator.
//
// This file covers the MCPRoute admission webhook (requirement B): local spec
// validation, the create/update/delete lifecycle short-circuits, the
// cross-kind conflict wiring and the four Setup* wiring functions.
package webhook

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// newMCPRouteWithSpec builds a namespaced MCPRoute with the given spec.
func newMCPRouteWithSpec(name, namespace string, spec avapigwv1alpha1.MCPRouteSpec) *avapigwv1alpha1.MCPRoute {
	return &avapigwv1alpha1.MCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       spec,
	}
}

// newValidMCPRouteSpec returns a minimal valid MCPRoute spec: exact "/mcp"
// path plus one upstream.
func newValidMCPRouteSpec() avapigwv1alpha1.MCPRouteSpec {
	return avapigwv1alpha1.MCPRouteSpec{
		Match: []avapigwv1alpha1.MCPRouteMatch{
			{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}},
		},
		Upstreams: []string{"mcp-backend"},
	}
}

// newMCPValidatorWithObjects builds an MCPRouteValidator over a fake client
// pre-populated with objs, using a namespace-scoped DuplicateChecker built
// from the default config (mirrors NewDuplicateCheckerFromConfig wiring).
func newMCPValidatorWithObjects(t *testing.T, objs ...client.Object) *MCPRouteValidator {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	checker := NewDuplicateCheckerFromConfig(fakeClient, DefaultDuplicateCheckerConfig())
	t.Cleanup(checker.Stop)

	return &MCPRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: checker,
	}
}

// ============================================================================
// ValidateCreate — happy path (1.1)
// ============================================================================

func TestMCPRouteValidator_ValidateCreate_HappyPath(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)
	route := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())

	before := testutil.ToFloat64(
		GetWebhookMetrics().validationsTotal.WithLabelValues(kindMCPRoute, "create", "allowed"))

	warnings, err := validator.ValidateCreate(context.Background(), route)
	require.NoError(t, err)
	assert.Empty(t, warnings)

	after := testutil.ToFloat64(
		GetWebhookMetrics().validationsTotal.WithLabelValues(kindMCPRoute, "create", "allowed"))
	// The counter is a package-level singleton shared with other parallel
	// tests, so assert it advanced rather than an exact delta.
	assert.GreaterOrEqual(t, after, before+1, "allowed validation should be recorded")
}

// TestMCPRouteValidator_ValidateCreate_ValidRetryPolicy covers the fully-valid
// retry policy path (validateRetryPolicy returns nil).
func TestMCPRouteValidator_ValidateCreate_ValidRetryPolicy(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)
	route := newMCPRouteWithSpec("mcp-route", "default", avapigwv1alpha1.MCPRouteSpec{
		Match:     []avapigwv1alpha1.MCPRouteMatch{{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}},
		Upstreams: []string{"mcp-backend"},
		Timeout:   avapigwv1alpha1.Duration("30s"),
		Retries: &avapigwv1alpha1.RetryPolicy{
			Attempts:      3,
			PerTryTimeout: avapigwv1alpha1.Duration("5s"),
		},
	})

	warnings, err := validator.ValidateCreate(context.Background(), route)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// ============================================================================
// ValidateCreate — local-validation failures (1.2)
// ============================================================================

func TestMCPRouteValidator_ValidateCreate_LocalValidationFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spec    avapigwv1alpha1.MCPRouteSpec
		wantErr string
	}{
		{
			name: "path exact and prefix both set",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Match: []avapigwv1alpha1.MCPRouteMatch{
					{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp", Prefix: "/m"}},
				},
				Upstreams: []string{"mcp-backend"},
			},
			wantErr: "only one of exact, prefix, or regex",
		},
		{
			name: "path regex invalid",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Match: []avapigwv1alpha1.MCPRouteMatch{
					{Path: &avapigwv1alpha1.StringMatch{Regex: "[invalid("}},
				},
				Upstreams: []string{"mcp-backend"},
			},
			wantErr: "regex is invalid",
		},
		{
			name: "name regex invalid",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Match: []avapigwv1alpha1.MCPRouteMatch{
					{Name: &avapigwv1alpha1.StringMatch{Regex: "[invalid("}},
				},
				Upstreams: []string{"mcp-backend"},
			},
			wantErr: "regex is invalid",
		},
		{
			name: "header with empty name",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Match: []avapigwv1alpha1.MCPRouteMatch{
					{Headers: []avapigwv1alpha1.HeaderMatch{{Name: ""}}},
				},
				Upstreams: []string{"mcp-backend"},
			},
			wantErr: "headers[0].name is required",
		},
		{
			name: "header with bad regex",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Match: []avapigwv1alpha1.MCPRouteMatch{
					{Headers: []avapigwv1alpha1.HeaderMatch{{Name: "X-Test", Regex: "[invalid("}}},
				},
				Upstreams: []string{"mcp-backend"},
			},
			wantErr: "regex is invalid",
		},
		{
			name: "nil upstreams",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Match:     []avapigwv1alpha1.MCPRouteMatch{{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}},
				Upstreams: nil,
			},
			wantErr: "at least one upstream is required",
		},
		{
			name: "whitespace upstream",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Match:     []avapigwv1alpha1.MCPRouteMatch{{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}},
				Upstreams: []string{" "},
			},
			wantErr: "upstreams[0] must not be empty",
		},
		{
			name: "invalid timeout",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams: []string{"mcp-backend"},
				Timeout:   avapigwv1alpha1.Duration("notaduration"),
			},
			wantErr: "invalid timeout",
		},
		{
			name: "retry attempts above max",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams: []string{"mcp-backend"},
				Retries:   &avapigwv1alpha1.RetryPolicy{Attempts: MaxRetryAttempts + 1},
			},
			wantErr: "retries.attempts must be between",
		},
		{
			name: "retry attempts below min",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams: []string{"mcp-backend"},
				Retries:   &avapigwv1alpha1.RetryPolicy{Attempts: MinRetryAttempts - 1},
			},
			wantErr: "retries.attempts must be between",
		},
		{
			name: "retry perTryTimeout invalid",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams: []string{"mcp-backend"},
				Retries:   &avapigwv1alpha1.RetryPolicy{Attempts: 3, PerTryTimeout: avapigwv1alpha1.Duration("bad")},
			},
			wantErr: "retries.perTryTimeout is invalid",
		},
		{
			name: "invalid rate limit",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams: []string{"mcp-backend"},
				RateLimit: &avapigwv1alpha1.RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 0,
					Burst:             100,
				},
			},
			wantErr: "validation failed",
		},
		{
			name: "invalid cache",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams: []string{"mcp-backend"},
				Cache:     &avapigwv1alpha1.CacheConfig{TTL: avapigwv1alpha1.Duration("invalid")},
			},
			wantErr: "validation failed",
		},
		{
			name: "invalid CORS",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams: []string{"mcp-backend"},
				CORS:      &avapigwv1alpha1.CORSConfig{AllowMethods: []string{"INVALID"}},
			},
			wantErr: "validation failed",
		},
		{
			name: "invalid TLS",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams: []string{"mcp-backend"},
				TLS:       &avapigwv1alpha1.RouteTLSConfig{MinVersion: "TLS10"},
			},
			wantErr: "validation failed",
		},
		{
			name: "invalid authentication",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams:      []string{"mcp-backend"},
				Authentication: &avapigwv1alpha1.AuthenticationConfig{Enabled: true},
			},
			wantErr: "validation failed",
		},
		{
			name: "invalid authorization",
			spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams:     []string{"mcp-backend"},
				Authorization: &avapigwv1alpha1.AuthorizationConfig{Enabled: true},
			},
			wantErr: "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator := newMCPValidatorWithObjects(t)
			route := newMCPRouteWithSpec("mcp-route", "default", tt.spec)

			_, err := validator.ValidateCreate(context.Background(), route)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestMCPRouteValidator_ValidateCreate_MultipleErrorsJoined verifies that
// multiple local validation failures are joined into a single error.
func TestMCPRouteValidator_ValidateCreate_MultipleErrorsJoined(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)
	route := newMCPRouteWithSpec("mcp-route", "default", avapigwv1alpha1.MCPRouteSpec{
		// no upstreams AND invalid timeout → two joined errors.
		Timeout: avapigwv1alpha1.Duration("bad"),
	})

	_, err := validator.ValidateCreate(context.Background(), route)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed: ")
	assert.Contains(t, err.Error(), "; ", "multiple errors should be joined with '; '")
}

// ============================================================================
// collectMCPRouteWarnings (1.3)
// ============================================================================

func TestMCPRouteValidator_ValidateCreate_Warnings(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)
	route := newMCPRouteWithSpec("mcp-route", "default", avapigwv1alpha1.MCPRouteSpec{
		Upstreams: []string{"mcp-backend"},
		Authentication: &avapigwv1alpha1.AuthenticationConfig{
			Enabled: true,
			JWT: &avapigwv1alpha1.JWTAuthConfig{
				Enabled: true,
				Secret:  "plaintext-secret",
			},
		},
	})

	warnings, err := validator.ValidateCreate(context.Background(), route)
	require.NoError(t, err)
	assert.NotEmpty(t, warnings, "plaintext auth secret should produce a warning")
}

// TestMCPRouteValidator_CollectWarnings_NilAuthentication covers the
// spec.Authentication == nil guard inside collectMCPRouteWarnings.
func TestMCPRouteValidator_CollectWarnings_NilAuthentication(t *testing.T) {
	t.Parallel()

	spec := &avapigwv1alpha1.MCPRouteSpec{Upstreams: []string{"mcp-backend"}}
	warnings := collectMCPRouteWarnings(spec)
	assert.Empty(t, warnings)
}

// ============================================================================
// ValidateCreate — cross-conflict rejection (1.4)
// ============================================================================

func TestMCPRouteValidator_ValidateCreate_CrossConflictAPIRoute(t *testing.T) {
	t.Parallel()

	existingAPI := newAPIRoute("existing-api", "default",
		&avapigwv1alpha1.URIMatch{Exact: "/mcp"})
	validator := newMCPValidatorWithObjects(t, existingAPI)
	route := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())

	before := testutil.ToFloat64(
		GetWebhookMetrics().validationsTotal.WithLabelValues(kindMCPRoute, "create", "rejected"))

	_, err := validator.ValidateCreate(context.Background(), route)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has path conflict with APIRoute:")

	after := testutil.ToFloat64(
		GetWebhookMetrics().validationsTotal.WithLabelValues(kindMCPRoute, "create", "rejected"))
	assert.GreaterOrEqual(t, after, before+1, "rejected validation should be recorded")
}

func TestMCPRouteValidator_ValidateCreate_CrossConflictGraphQLRoute(t *testing.T) {
	t.Parallel()

	existingGQL := newCrossKindGraphQLRoute("existing-gql", "default",
		&avapigwv1alpha1.StringMatch{Exact: "/mcp"})
	validator := newMCPValidatorWithObjects(t, existingGQL)
	route := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())

	_, err := validator.ValidateCreate(context.Background(), route)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has path conflict with GraphQLRoute:")
}

// TestMCPRouteValidator_ValidateCreate_SameKindDuplicate exercises the
// same-kind duplicate rejection path through ValidateCreate.
func TestMCPRouteValidator_ValidateCreate_SameKindDuplicate(t *testing.T) {
	t.Parallel()

	existingMCP := newMCPRouteWithSpec("existing-mcp", "default", newValidMCPRouteSpec())
	validator := newMCPValidatorWithObjects(t, existingMCP)
	route := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())

	_, err := validator.ValidateCreate(context.Background(), route)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicts with existing route(s)")
}

// ============================================================================
// ValidateUpdate lifecycle (1.5 – 1.8)
// ============================================================================

func TestMCPRouteValidator_ValidateUpdate_DeletionShortCircuit(t *testing.T) {
	t.Parallel()

	// Existing APIRoute would conflict, but the deletion timestamp must
	// short-circuit before any cross-check runs.
	existingAPI := newAPIRoute("existing-api", "default",
		&avapigwv1alpha1.URIMatch{Exact: "/mcp"})
	validator := newMCPValidatorWithObjects(t, existingAPI)

	oldObj := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())
	newObj := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())
	now := metav1.Now()
	newObj.DeletionTimestamp = &now
	newObj.Finalizers = []string{"avapigw.io/finalizer"}

	warnings, err := validator.ValidateUpdate(context.Background(), oldObj, newObj)
	require.NoError(t, err)
	assert.Nil(t, warnings)
}

func TestMCPRouteValidator_ValidateUpdate_SpecUnchangedSkip(t *testing.T) {
	t.Parallel()

	// A conflicting APIRoute is present; a metadata-only update must skip
	// cross-checks and be admitted.
	existingAPI := newAPIRoute("existing-api", "default",
		&avapigwv1alpha1.URIMatch{Exact: "/mcp"})
	validator := newMCPValidatorWithObjects(t, existingAPI)

	oldObj := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())
	newObj := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())
	newObj.Labels = map[string]string{"changed": "true"} // metadata-only change

	before := testutil.ToFloat64(
		GetWebhookMetrics().validationsTotal.WithLabelValues(kindMCPRoute, "update", "allowed"))

	warnings, err := validator.ValidateUpdate(context.Background(), oldObj, newObj)
	require.NoError(t, err)
	assert.Empty(t, warnings)

	after := testutil.ToFloat64(
		GetWebhookMetrics().validationsTotal.WithLabelValues(kindMCPRoute, "update", "allowed"))
	assert.GreaterOrEqual(t, after, before+1)
}

func TestMCPRouteValidator_ValidateUpdate_ChangedSpecConflict(t *testing.T) {
	t.Parallel()

	existingAPI := newAPIRoute("existing-api", "default",
		&avapigwv1alpha1.URIMatch{Exact: "/mcp"})
	validator := newMCPValidatorWithObjects(t, existingAPI)

	oldObj := newMCPRouteWithSpec("mcp-route", "default", avapigwv1alpha1.MCPRouteSpec{
		Match:     []avapigwv1alpha1.MCPRouteMatch{{Path: &avapigwv1alpha1.StringMatch{Exact: "/other"}}},
		Upstreams: []string{"mcp-backend"},
	})
	// Changed spec introduces the colliding /mcp path.
	newObj := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())

	_, err := validator.ValidateUpdate(context.Background(), oldObj, newObj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has path conflict with APIRoute:")
}

func TestMCPRouteValidator_ValidateUpdate_LocalValidationFailure(t *testing.T) {
	t.Parallel()

	existingAPI := newAPIRoute("existing-api", "default",
		&avapigwv1alpha1.URIMatch{Exact: "/mcp"})
	validator := newMCPValidatorWithObjects(t, existingAPI)

	oldObj := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())
	newObj := newMCPRouteWithSpec("mcp-route", "default", avapigwv1alpha1.MCPRouteSpec{
		// invalid: no upstreams → rejected before cross-checks
		Match: []avapigwv1alpha1.MCPRouteMatch{{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}},
	})

	_, err := validator.ValidateUpdate(context.Background(), oldObj, newObj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one upstream is required")
}

func TestMCPRouteValidator_ValidateUpdate_ChangedSpecAllowed(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)

	oldObj := newMCPRouteWithSpec("mcp-route", "default", avapigwv1alpha1.MCPRouteSpec{
		Match:     []avapigwv1alpha1.MCPRouteMatch{{Path: &avapigwv1alpha1.StringMatch{Exact: "/old"}}},
		Upstreams: []string{"mcp-backend"},
	})
	newObj := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())

	warnings, err := validator.ValidateUpdate(context.Background(), oldObj, newObj)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// ============================================================================
// ValidateDelete (1.9)
// ============================================================================

func TestMCPRouteValidator_ValidateDelete(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)
	route := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())

	warnings, err := validator.ValidateDelete(context.Background(), route)
	require.NoError(t, err)
	assert.Nil(t, warnings)
}

// ============================================================================
// runMCPCrossChecks nil checker (1.10)
// ============================================================================

func TestMCPRouteValidator_RunMCPCrossChecks_NilChecker(t *testing.T) {
	t.Parallel()

	validator := &MCPRouteValidator{DuplicateChecker: nil}
	route := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())

	err := validator.runMCPCrossChecks(context.Background(), route)
	require.NoError(t, err)
}

// TestMCPRouteValidator_ValidateCreate_NilChecker admits when there is no
// DuplicateChecker wired (nil-guard through the full create path).
func TestMCPRouteValidator_ValidateCreate_NilChecker(t *testing.T) {
	t.Parallel()

	validator := &MCPRouteValidator{DuplicateChecker: nil}
	route := newMCPRouteWithSpec("mcp-route", "default", newValidMCPRouteSpec())

	warnings, err := validator.ValidateCreate(context.Background(), route)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// ============================================================================
// Setup* wiring functions (1.11)
// ============================================================================

// mcpMockManager is a minimal ctrl.Manager for exercising the MCPRoute Setup*
// functions: it provides the scheme, a no-op logger, an empty rest config and
// a real (default) webhook server so ctrl.NewWebhookManagedBy(...).Complete()
// can register the validating webhook without an API server.
type mcpMockManager struct {
	ctrl.Manager
	scheme     *runtime.Scheme
	whServer   webhook.Server
	fakeClient client.Client
}

func newMCPMockManager(t *testing.T) *mcpMockManager {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	return &mcpMockManager{
		scheme:     scheme,
		whServer:   webhook.NewServer(webhook.Options{}),
		fakeClient: fake.NewClientBuilder().WithScheme(scheme).Build(),
	}
}

func (m *mcpMockManager) GetScheme() *runtime.Scheme       { return m.scheme }
func (m *mcpMockManager) GetWebhookServer() webhook.Server { return m.whServer }
func (m *mcpMockManager) GetClient() client.Client         { return m.fakeClient }
func (m *mcpMockManager) GetLogger() logr.Logger           { return logr.Discard() }
func (m *mcpMockManager) GetConfig() *rest.Config          { return &rest.Config{} }

func TestSetupMCPRouteWebhook_Wiring(t *testing.T) {
	tests := []struct {
		name  string
		setup func(mgr ctrl.Manager) error
	}{
		{
			name: "SetupMCPRouteWebhook",
			setup: func(mgr ctrl.Manager) error {
				return SetupMCPRouteWebhook(mgr)
			},
		},
		{
			name: "SetupMCPRouteWebhookWithConfig",
			setup: func(mgr ctrl.Manager) error {
				return SetupMCPRouteWebhookWithConfig(mgr, DefaultDuplicateCheckerConfig())
			},
		},
		{
			name: "SetupMCPRouteWebhookWithConfigAndContext",
			setup: func(mgr ctrl.Manager) error {
				return SetupMCPRouteWebhookWithConfigAndContext(
					context.Background(), mgr, DefaultDuplicateCheckerConfig())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newMCPMockManager(t)
			err := tt.setup(mgr)
			require.NoError(t, err)
		})
	}
}

func TestSetupMCPRouteWebhookWithChecker_Wiring(t *testing.T) {
	mgr := newMCPMockManager(t)
	checker := NewDuplicateCheckerFromConfig(mgr.GetClient(), DefaultDuplicateCheckerConfig())
	t.Cleanup(checker.Stop)

	err := SetupMCPRouteWebhookWithChecker(mgr, checker)
	require.NoError(t, err)
}

// TestMCPRouteValidator_ValidateCreate_ErrorJoinFormat asserts the join
// separator used by the validate() aggregate error.
func TestMCPRouteValidator_ValidateCreate_ErrorJoinFormat(t *testing.T) {
	t.Parallel()

	validator := newMCPValidatorWithObjects(t)
	route := newMCPRouteWithSpec("mcp-route", "default", avapigwv1alpha1.MCPRouteSpec{})

	_, err := validator.ValidateCreate(context.Background(), route)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "validation failed:"))
}
