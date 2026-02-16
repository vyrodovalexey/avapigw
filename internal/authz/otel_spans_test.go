package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestAuthorize_OTELSpans verifies that OTEL spans are created during
// authorization. These tests are NOT parallel because they modify the
// global OTEL tracer provider.
func TestAuthorize_OTELSpans(t *testing.T) {
	t.Run("allowed", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		authzTracer = otel.Tracer("avapigw/authz")
		defer func() {
			otel.SetTracerProvider(oldTP)
			authzTracer = otel.Tracer("avapigw/authz")
		}()

		config := &Config{
			Enabled: true,
			RBAC: &rbac.Config{
				Enabled: true,
				Policies: []rbac.Policy{
					{
						Name:      "admin-policy",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"GET", "POST"},
						Effect:    "allow",
					},
				},
			},
		}

		mockEngine := &mockRBACEngine{
			decision: &rbac.Decision{
				Allowed: true,
				Reason:  "admin role matched",
				Policy:  "admin-policy",
			},
		}

		authorizer, err := New(config,
			WithAuthorizerLogger(observability.NopLogger()),
			WithAuthorizerMetrics(&Metrics{}),
			WithRBACEngine(mockEngine),
		)
		require.NoError(t, err)
		defer authorizer.Close()

		req := &Request{
			Identity: &auth.Identity{
				Subject: "admin-user",
				Roles:   []string{"admin"},
			},
			Resource: "/api/users",
			Action:   "GET",
		}

		decision, err := authorizer.Authorize(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.True(t, decision.Allowed)

		spans := exporter.GetSpans()
		require.NotEmpty(t, spans, "expected at least one span")

		found := false
		for _, s := range spans {
			if s.Name == "authz.authorize" {
				found = true
				attrs := make(map[string]interface{})
				for _, a := range s.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Contains(t, attrs, "authz.resource")
				assert.Contains(t, attrs, "authz.action")
				assert.Equal(t, true, attrs["authz.allowed"])
				assert.Equal(t, "admin-user", attrs["authz.subject"])
				break
			}
		}
		assert.True(t, found, "expected authz.authorize span")
	})

	t.Run("disabled", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		authzTracer = otel.Tracer("avapigw/authz")
		defer func() {
			otel.SetTracerProvider(oldTP)
			authzTracer = otel.Tracer("avapigw/authz")
		}()

		config := &Config{
			Enabled: false,
		}

		authorizer, err := New(config,
			WithAuthorizerLogger(observability.NopLogger()),
			WithAuthorizerMetrics(&Metrics{}),
		)
		require.NoError(t, err)
		defer authorizer.Close()

		req := &Request{
			Identity: &auth.Identity{Subject: "user"},
			Resource: "/api/users",
			Action:   "GET",
		}

		decision, err := authorizer.Authorize(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.True(t, decision.Allowed)

		spans := exporter.GetSpans()
		require.NotEmpty(t, spans)

		found := false
		for _, s := range spans {
			if s.Name == "authz.authorize" {
				found = true
				attrs := make(map[string]interface{})
				for _, a := range s.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Equal(t, "disabled", attrs["authz.result"])
				break
			}
		}
		assert.True(t, found, "expected authz.authorize span with disabled result")
	})

	t.Run("no_identity", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		authzTracer = otel.Tracer("avapigw/authz")
		defer func() {
			otel.SetTracerProvider(oldTP)
			authzTracer = otel.Tracer("avapigw/authz")
		}()

		config := &Config{
			Enabled: true,
		}

		authorizer, err := New(config,
			WithAuthorizerLogger(observability.NopLogger()),
			WithAuthorizerMetrics(&Metrics{}),
		)
		require.NoError(t, err)
		defer authorizer.Close()

		req := &Request{
			Identity: nil,
			Resource: "/api/users",
			Action:   "GET",
		}

		decision, err := authorizer.Authorize(context.Background(), req)
		require.Error(t, err)
		assert.Nil(t, decision)

		spans := exporter.GetSpans()
		require.NotEmpty(t, spans)

		found := false
		for _, s := range spans {
			if s.Name == "authz.authorize" {
				found = true
				attrs := make(map[string]interface{})
				for _, a := range s.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Equal(t, "no_identity", attrs["authz.result"])
				break
			}
		}
		assert.True(t, found, "expected authz.authorize span with no_identity result")
	})
}
