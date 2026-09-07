//go:build functional

// Package operator_test contains functional tests for the apigw-operator.
//
// This file black-boxes the MCPRoute admission webhook (webhook.MCPRouteValidator)
// through its public ValidateCreate API for the MCP weighted-routing feature. It
// mirrors the existing APIRoute weight webhook tests (apiroute_functional_test.go
// "invalid weight" / "invalid total weight" cases) and the MCPRoute cross-conflict
// functional test, asserting: an out-of-range weight is denied, a sum != 100 is
// denied, both upstreams + weightedUpstreams set is denied, a valid weighted
// route is admitted, and a mixed zero/positive split is admitted WITH a
// transparency warning (0% canary).
package operator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// weightedMCPRoute builds a namespaced MCPRoute with the given weighted upstream
// refs (and no legacy Upstreams unless explicitly provided by the caller).
func weightedMCPRoute(name string, refs []avapigwv1alpha1.MCPUpstreamRef) *avapigwv1alpha1.MCPRoute {
	return &avapigwv1alpha1.MCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       avapigwv1alpha1.MCPRouteSpec{WeightedUpstreams: refs},
	}
}

// newMCPValidator builds an MCPRouteValidator backed by an empty fake client so
// admission runs the schema/weight rules without cross-route conflicts.
func newMCPValidator(t *testing.T) *webhook.MCPRouteValidator {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	dc := webhook.NewDuplicateCheckerWithContext(context.Background(), fakeClient)
	return &webhook.MCPRouteValidator{Client: fakeClient, DuplicateChecker: dc}
}

// TestFunctional_Webhook_MCPRouteWeightedUpstreams drives the weighted-upstream
// admission matrix for the MCPRoute webhook.
func TestFunctional_Webhook_MCPRouteWeightedUpstreams(t *testing.T) {
	t.Parallel()

	t.Run("valid weighted route is admitted", func(t *testing.T) {
		t.Parallel()
		v := newMCPValidator(t)
		route := weightedMCPRoute("mcp-weight-ok", []avapigwv1alpha1.MCPUpstreamRef{
			{Name: "stable", Weight: 80},
			{Name: "canary", Weight: 20},
		})
		warnings, err := v.ValidateCreate(context.Background(), route)
		require.NoError(t, err, "a valid 80/20 weighted MCPRoute must be admitted")
		assert.Empty(t, warnings, "a clean weighted split must not emit warnings")
	})

	t.Run("out-of-range weight (150) is denied", func(t *testing.T) {
		t.Parallel()
		v := newMCPValidator(t)
		route := weightedMCPRoute("mcp-weight-range", []avapigwv1alpha1.MCPUpstreamRef{
			{Name: "stable", Weight: 150},
		})
		_, err := v.ValidateCreate(context.Background(), route)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})

	t.Run("negative weight is denied", func(t *testing.T) {
		t.Parallel()
		v := newMCPValidator(t)
		route := weightedMCPRoute("mcp-weight-negative", []avapigwv1alpha1.MCPUpstreamRef{
			{Name: "stable", Weight: -1},
			{Name: "canary", Weight: 101},
		})
		_, err := v.ValidateCreate(context.Background(), route)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "weight must be between 0 and 100")
	})

	t.Run("weights not summing to 100 are denied", func(t *testing.T) {
		t.Parallel()
		v := newMCPValidator(t)
		route := weightedMCPRoute("mcp-weight-sum", []avapigwv1alpha1.MCPUpstreamRef{
			{Name: "stable", Weight: 50},
			{Name: "canary", Weight: 40},
		})
		_, err := v.ValidateCreate(context.Background(), route)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "total weight")
	})

	t.Run("empty upstream name is denied", func(t *testing.T) {
		t.Parallel()
		v := newMCPValidator(t)
		route := weightedMCPRoute("mcp-weight-empty-name", []avapigwv1alpha1.MCPUpstreamRef{
			{Name: "", Weight: 100},
		})
		_, err := v.ValidateCreate(context.Background(), route)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be empty")
	})

	t.Run("both upstreams and weightedUpstreams set is denied", func(t *testing.T) {
		t.Parallel()
		v := newMCPValidator(t)
		route := &avapigwv1alpha1.MCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "mcp-weight-both", Namespace: "default"},
			Spec: avapigwv1alpha1.MCPRouteSpec{
				Upstreams:         []string{"stable"},
				WeightedUpstreams: []avapigwv1alpha1.MCPUpstreamRef{{Name: "canary", Weight: 100}},
			},
		}
		_, err := v.ValidateCreate(context.Background(), route)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only one of upstreams or weightedUpstreams")
	})

	t.Run("all-zero weights are admitted (uniform)", func(t *testing.T) {
		t.Parallel()
		v := newMCPValidator(t)
		route := weightedMCPRoute("mcp-weight-all-zero", []avapigwv1alpha1.MCPUpstreamRef{
			{Name: "a", Weight: 0},
			{Name: "b", Weight: 0},
		})
		warnings, err := v.ValidateCreate(context.Background(), route)
		require.NoError(t, err, "all-zero weights (uniform) must be admitted")
		assert.Empty(t, warnings, "all-zero weights must not emit the mixed-weight warning")
	})

	t.Run("mixed zero/positive weights are admitted with a warning", func(t *testing.T) {
		t.Parallel()
		v := newMCPValidator(t)
		route := weightedMCPRoute("mcp-weight-mixed", []avapigwv1alpha1.MCPUpstreamRef{
			{Name: "stable", Weight: 100},
			{Name: "canary", Weight: 0}, // 0% canary
		})
		warnings, err := v.ValidateCreate(context.Background(), route)
		require.NoError(t, err, "a 0% canary must be admitted (intentional)")
		require.NotEmpty(t, warnings, "a mixed zero/positive split must emit a transparency warning")
		assert.Contains(t, warnings[0], "no traffic")
	})
}
