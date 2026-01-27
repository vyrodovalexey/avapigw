//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func newIntegrationAuditLogger(cfg *audit.Config) (audit.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	logger, err := audit.NewLogger(
		cfg,
		audit.WithLoggerWriter(buf),
		audit.WithLoggerMetrics(&audit.Metrics{}),
	)
	if err != nil {
		panic(err)
	}
	return logger, buf
}

func TestIntegration_Audit_WithRealBackend(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("audit enabled does not interfere with proxy operation", func(t *testing.T) {
		auditCfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newIntegrationAuditLogger(auditCfg)
		defer auditLogger.Close()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/items"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		// Wrap proxy with audit middleware
		handler := middleware.Audit(auditLogger)(p)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Verify proxy still works correctly
		assert.Equal(t, http.StatusOK, rec.Code)

		var response helpers.BackendResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)
		assert.True(t, response.Success)

		// Verify audit events were logged
		assert.NotEmpty(t, buf.String(), "audit should produce output")
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2, "expected request + response events")
	})

	t.Run("audit captures correct status from backend", func(t *testing.T) {
		auditCfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newIntegrationAuditLogger(auditCfg)
		defer auditLogger.Close()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/items"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := middleware.Audit(auditLogger)(p)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "10.0.0.1:54321"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2)

		// Verify response event has correct status
		var respEvent audit.Event
		err = json.Unmarshal([]byte(lines[1]), &respEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
		require.NotNil(t, respEvent.Response)
		assert.Equal(t, http.StatusOK, respEvent.Response.StatusCode)
		assert.Equal(t, audit.OutcomeSuccess, respEvent.Outcome)
	})
}

func TestIntegration_Audit_SkipPaths_WithRealRequests(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("skip paths work with real backend requests", func(t *testing.T) {
		auditCfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
			SkipPaths: []string{
				"/health",
				"/metrics",
			},
		}

		auditLogger, buf := newIntegrationAuditLogger(auditCfg)
		defer auditLogger.Close()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "health",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/health"},
					Methods: []string{"GET"},
				},
			},
			DirectResponse: &config.DirectResponseConfig{
				Status: 200,
				Body:   `{"status":"healthy"}`,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
		})
		require.NoError(t, err)

		err = r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/items"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := middleware.Audit(auditLogger)(p)

		// Request to /health should be skipped
		buf.Reset()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, buf.String(), "/health should be skipped")

		// Request to /api/v1/items should be audited
		buf.Reset()
		req = httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.NotEmpty(t, buf.String(), "/api/v1/items should be audited")
	})
}

func TestIntegration_Audit_HTTPMethods_WithRealBackend(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	methods := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/items"},
		{http.MethodPost, "/api/v1/items"},
		{http.MethodPut, "/api/v1/items/test-id"},
		{http.MethodDelete, "/api/v1/items/test-id"},
	}

	for _, tc := range methods {
		tc := tc
		t.Run("audit with "+tc.method+" to real backend", func(t *testing.T) {
			auditCfg := &audit.Config{
				Enabled: true,
				Level:   audit.LevelInfo,
				Output:  "stdout",
				Format:  "json",
				Events: &audit.EventsConfig{
					Request:  true,
					Response: true,
				},
			}

			auditLogger, buf := newIntegrationAuditLogger(auditCfg)
			defer auditLogger.Close()

			r := router.New()
			err := r.AddRoute(config.Route{
				Name: "items-api",
				Match: []config.RouteMatch{
					{
						URI:     &config.URIMatch{Prefix: "/api/v1/items"},
						Methods: []string{"GET", "POST", "PUT", "DELETE"},
					},
				},
				Route: []config.RouteDestination{
					{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
				},
			})
			require.NoError(t, err)

			registry := backend.NewRegistry(observability.NopLogger())
			p := proxy.NewReverseProxy(r, registry)
			handler := middleware.Audit(auditLogger)(p)

			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.RemoteAddr = "192.168.1.1:12345"
			if tc.method == http.MethodPost || tc.method == http.MethodPut {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// Verify audit events were logged
			assert.NotEmpty(t, buf.String(), "audit should produce output for %s", tc.method)

			lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
			require.GreaterOrEqual(t, len(lines), 1)

			var reqEvent audit.Event
			err = json.Unmarshal([]byte(lines[0]), &reqEvent)
			require.NoError(t, err)
			assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)
			require.NotNil(t, reqEvent.Request)
			assert.Equal(t, tc.method, reqEvent.Request.Method)
		})
	}
}

func TestIntegration_Audit_NormalProxyOperation(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("audit does not modify response body", func(t *testing.T) {
		auditCfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, _ := newIntegrationAuditLogger(auditCfg)
		defer auditLogger.Close()

		// Make request directly to backend (without audit)
		directResp, err := helpers.MakeRequest(http.MethodGet, testCfg.Backend1URL+"/api/v1/items", nil)
		require.NoError(t, err)
		directBody, err := helpers.ReadResponseBody(directResp)
		require.NoError(t, err)

		// Make request through proxy with audit
		r := router.New()
		err = r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/items"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := middleware.Audit(auditLogger)(p)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		// Both responses should be valid JSON with success=true
		var directResponse helpers.BackendResponse
		err = json.Unmarshal([]byte(directBody), &directResponse)
		require.NoError(t, err)

		var auditedResponse helpers.BackendResponse
		err = json.NewDecoder(rec.Body).Decode(&auditedResponse)
		require.NoError(t, err)

		assert.Equal(t, directResponse.Success, auditedResponse.Success)
	})

	t.Run("audit does not modify response headers", func(t *testing.T) {
		auditCfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, _ := newIntegrationAuditLogger(auditCfg)
		defer auditLogger.Close()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/items"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := middleware.Audit(auditLogger)(p)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	})
}

func TestIntegration_Audit_DirectResponse(t *testing.T) {
	t.Parallel()

	t.Run("audit works with direct response routes", func(t *testing.T) {
		t.Parallel()

		auditCfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newIntegrationAuditLogger(auditCfg)
		defer auditLogger.Close()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "health",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/api/status"},
					Methods: []string{"GET"},
				},
			},
			DirectResponse: &config.DirectResponseConfig{
				Status: 200,
				Body:   `{"status":"ok"}`,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := middleware.Audit(auditLogger)(p)

		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "ok")

		// Verify audit events
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2)

		var reqEvent audit.Event
		err = json.Unmarshal([]byte(lines[0]), &reqEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)

		var respEvent audit.Event
		err = json.Unmarshal([]byte(lines[1]), &respEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
		require.NotNil(t, respEvent.Response)
		assert.Equal(t, http.StatusOK, respEvent.Response.StatusCode)
	})
}

func TestIntegration_Audit_RouteNotFound(t *testing.T) {
	t.Parallel()

	t.Run("audit captures 404 for unmatched routes", func(t *testing.T) {
		t.Parallel()

		auditCfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newIntegrationAuditLogger(auditCfg)
		defer auditLogger.Close()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "specific-route",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/specific"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := middleware.Audit(auditLogger)(p)

		req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)

		// Verify audit captured the 404
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2)

		var respEvent audit.Event
		err = json.Unmarshal([]byte(lines[1]), &respEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
		require.NotNil(t, respEvent.Response)
		assert.Equal(t, http.StatusNotFound, respEvent.Response.StatusCode)
		assert.Equal(t, audit.OutcomeFailure, respEvent.Outcome)
	})
}

func TestIntegration_Audit_TextFormat(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("audit with text format works with real backend", func(t *testing.T) {
		auditCfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "text",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newIntegrationAuditLogger(auditCfg)
		defer auditLogger.Close()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/items"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)
		handler := middleware.Audit(auditLogger)(p)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.NotEmpty(t, buf.String(), "text format audit should produce output")

		// Text format should contain readable event info
		output := buf.String()
		assert.Contains(t, output, "request")
		assert.Contains(t, output, "response")
	})
}

func TestIntegration_Audit_FullMiddlewareChain(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("audit works in full middleware chain with real backend", func(t *testing.T) {
		auditCfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newIntegrationAuditLogger(auditCfg)
		defer auditLogger.Close()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "items-api",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api/v1/items"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		// Full chain: RequestID -> Recovery -> Audit -> Proxy
		handler := middleware.RequestID()(
			middleware.Recovery(observability.NopLogger())(
				middleware.Audit(auditLogger)(p),
			),
		)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("X-Request-ID"))

		// Verify audit events
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2)

		// Verify request event has request_id in metadata
		var reqEvent audit.Event
		err = json.Unmarshal([]byte(lines[0]), &reqEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)
		require.NotNil(t, reqEvent.Metadata)
		assert.NotEmpty(t, reqEvent.Metadata["request_id"])
	})
}
