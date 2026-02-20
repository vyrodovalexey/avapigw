package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestAuthenticate_OTELSpans verifies that OTEL spans are created during
// authentication. These tests are NOT parallel because they modify the
// global OTEL tracer provider. We use a single tracer provider and
// re-initialize the package-level authTracer for each subtest.
func TestAuthenticate_OTELSpans(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		// Re-initialize the package-level tracer so it uses the new provider
		authTracer = otel.Tracer("avapigw/auth")
		defer func() {
			otel.SetTracerProvider(oldTP)
			authTracer = otel.Tracer("avapigw/auth")
		}()

		config := &Config{
			JWT: &jwt.Config{
				Enabled: true,
			},
			Extraction: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
				},
			},
		}

		claims := &jwt.Claims{
			Subject:  "user123",
			Issuer:   "test-issuer",
			Audience: jwt.Audience{"test-audience"},
		}

		auth, err := NewAuthenticator(config,
			WithAuthenticatorLogger(observability.NopLogger()),
			WithJWTValidator(&mockJWTValidator{claims: claims}),
		)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		identity, err := auth.Authenticate(req)
		require.NoError(t, err)
		require.NotNil(t, identity)
		assert.Equal(t, "user123", identity.Subject)

		spans := exporter.GetSpans()
		require.NotEmpty(t, spans, "expected at least one span")

		found := false
		for _, s := range spans {
			if s.Name == "auth.authenticate" {
				found = true
				attrs := make(map[string]interface{})
				for _, a := range s.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Contains(t, attrs, "auth.path")
				assert.Contains(t, attrs, "auth.method")
				assert.Equal(t, "success", attrs["auth.result"])
				assert.Equal(t, string(AuthTypeJWT), attrs["auth.type"])
				break
			}
		}
		assert.True(t, found, "expected auth.authenticate span")
	})

	t.Run("skipped_path", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		authTracer = otel.Tracer("avapigw/auth")
		defer func() {
			otel.SetTracerProvider(oldTP)
			authTracer = otel.Tracer("avapigw/auth")
		}()

		config := &Config{
			JWT: &jwt.Config{
				Enabled: true,
			},
			SkipPaths: []string{"/health"},
			Extraction: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
				},
			},
		}

		auth, err := NewAuthenticator(config,
			WithAuthenticatorLogger(observability.NopLogger()),
			WithJWTValidator(&mockJWTValidator{claims: &jwt.Claims{Subject: "user"}}),
		)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/health", nil)

		identity, err := auth.Authenticate(req)
		require.NoError(t, err)
		require.NotNil(t, identity)
		assert.Equal(t, AuthTypeAnonymous, identity.AuthType)

		spans := exporter.GetSpans()
		require.NotEmpty(t, spans)

		found := false
		for _, s := range spans {
			if s.Name == "auth.authenticate" {
				found = true
				attrs := make(map[string]interface{})
				for _, a := range s.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Equal(t, "skipped", attrs["auth.result"])
				break
			}
		}
		assert.True(t, found, "expected auth.authenticate span with skipped result")
	})

	t.Run("failure", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		authTracer = otel.Tracer("avapigw/auth")
		defer func() {
			otel.SetTracerProvider(oldTP)
			authTracer = otel.Tracer("avapigw/auth")
		}()

		config := &Config{
			JWT: &jwt.Config{
				Enabled: true,
			},
			Extraction: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
				},
			},
		}

		auth, err := NewAuthenticator(config,
			WithAuthenticatorLogger(observability.NopLogger()),
			WithJWTValidator(&mockJWTValidator{err: ErrInvalidToken}),
		)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")

		identity, err := auth.Authenticate(req)
		require.Error(t, err)
		assert.Nil(t, identity)

		spans := exporter.GetSpans()
		require.NotEmpty(t, spans)

		found := false
		for _, s := range spans {
			if s.Name == "auth.authenticate" {
				found = true
				attrs := make(map[string]interface{})
				for _, a := range s.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Equal(t, "failure", attrs["auth.result"])
				assert.Contains(t, attrs, "auth.error")
				break
			}
		}
		assert.True(t, found, "expected auth.authenticate span with failure result")
	})
}
