//go:build functional
// +build functional

package functional

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// noopMetrics returns a Metrics with nil counters that won't register with prometheus.
func noopMetrics() *audit.Metrics {
	return &audit.Metrics{}
}

func newBufferAuditLoggerWithBuffer(cfg *audit.Config) (audit.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	logger, err := audit.NewLogger(cfg, audit.WithLoggerWriter(buf), audit.WithLoggerMetrics(noopMetrics()))
	if err != nil {
		panic(err)
	}
	return logger, buf
}

func TestFunctional_AuditMiddleware_Enabled(t *testing.T) {
	t.Parallel()

	t.Run("audit middleware logs request and response events", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("User-Agent", "test-agent")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		// Parse audit log lines
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2, "expected at least 2 audit log lines (request + response)")

		// Verify request event
		var reqEvent audit.Event
		err := json.Unmarshal([]byte(lines[0]), &reqEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)
		assert.Equal(t, audit.ActionHTTPRequest, reqEvent.Action)

		// Verify response event
		var respEvent audit.Event
		err = json.Unmarshal([]byte(lines[1]), &respEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
		assert.Equal(t, audit.ActionHTTPResponse, respEvent.Action)
	})

	t.Run("audit middleware captures correct status code", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items/999", nil)
		req.RemoteAddr = "10.0.0.1:54321"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2)

		var respEvent audit.Event
		err := json.Unmarshal([]byte(lines[1]), &respEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
		assert.NotNil(t, respEvent.Response)
		assert.Equal(t, http.StatusNotFound, respEvent.Response.StatusCode)
		assert.Equal(t, audit.OutcomeFailure, respEvent.Outcome)
	})

	t.Run("audit middleware captures request details", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/v1/items?page=1", nil)
		req.RemoteAddr = "10.0.0.1:54321"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-client/1.0")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 1)

		var reqEvent audit.Event
		err := json.Unmarshal([]byte(lines[0]), &reqEvent)
		require.NoError(t, err)

		assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)
		require.NotNil(t, reqEvent.Request)
		assert.Equal(t, http.MethodPost, reqEvent.Request.Method)
		assert.Equal(t, "/api/v1/items", reqEvent.Request.Path)
		assert.Equal(t, "page=1", reqEvent.Request.Query)
		assert.Equal(t, "application/json", reqEvent.Request.ContentType)

		// Verify subject
		require.NotNil(t, reqEvent.Subject)
		assert.Equal(t, "test-client/1.0", reqEvent.Subject.UserAgent)
	})
}

func TestFunctional_AuditMiddleware_Disabled(t *testing.T) {
	t.Parallel()

	t.Run("disabled audit config produces no events", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: false,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, buf.String(), "disabled audit should produce no output")
	})

	t.Run("noop logger produces no events", func(t *testing.T) {
		t.Parallel()

		noopLogger := audit.NewNoopLogger()

		handler := middleware.Audit(noopLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "OK")
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "OK", rec.Body.String())
	})
}

func TestFunctional_AuditMiddleware_SkipPaths(t *testing.T) {
	t.Parallel()

	t.Run("audit middleware skips configured paths", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
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
				"/internal/*",
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// These paths should be skipped
		skipPaths := []string{"/health", "/metrics", "/internal/status"}
		for _, path := range skipPaths {
			buf.Reset()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Empty(t, buf.String(), "path %s should be skipped", path)
		}
	})

	t.Run("audit middleware does not skip non-configured paths", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
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

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// These paths should NOT be skipped
		auditPaths := []string{"/api/v1/items", "/api/v1/users", "/healthcheck"}
		for _, path := range auditPaths {
			buf.Reset()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.NotEmpty(t, buf.String(), "path %s should be audited", path)
		}
	})
}

func TestFunctional_AuditMiddleware_RedactFields(t *testing.T) {
	t.Parallel()

	t.Run("audit middleware redacts sensitive metadata fields", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
			RedactFields: []string{
				"password",
				"secret",
				"token",
				"authorization",
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("Authorization", "Bearer secret-token-123")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		// The audit log should not contain the raw authorization value
		output := buf.String()
		assert.NotEmpty(t, output)
		// The raw token should not appear in the output
		assert.NotContains(t, output, "secret-token-123")
	})
}

func TestFunctional_AuditMiddleware_EventTypes(t *testing.T) {
	t.Parallel()

	t.Run("only request events when response disabled", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: false,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		// Should have only request event
		require.Len(t, lines, 1)

		var reqEvent audit.Event
		err := json.Unmarshal([]byte(lines[0]), &reqEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)
	})

	t.Run("only response events when request disabled", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  false,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		// Should have only response event
		require.Len(t, lines, 1)

		var respEvent audit.Event
		err := json.Unmarshal([]byte(lines[0]), &respEvent)
		require.NoError(t, err)
		assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
	})

	t.Run("no events when both request and response disabled", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  false,
				Response: false,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Empty(t, buf.String())
	})
}

func TestFunctional_AuditMiddleware_RequestIDIntegration(t *testing.T) {
	t.Parallel()

	t.Run("audit middleware captures request ID from context", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		// Chain RequestID middleware before Audit middleware
		handler := middleware.RequestID()(
			middleware.Audit(auditLogger)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			),
		)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Request-ID", "test-req-id-123")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 1)

		var reqEvent audit.Event
		err := json.Unmarshal([]byte(lines[0]), &reqEvent)
		require.NoError(t, err)

		// Verify request_id is in metadata
		require.NotNil(t, reqEvent.Metadata)
		assert.Equal(t, "test-req-id-123", reqEvent.Metadata["request_id"])
	})
}

func TestFunctional_AuditMiddleware_ResponseWriterCapture(t *testing.T) {
	t.Parallel()

	t.Run("captures response body size", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		responseBody := `{"items":[{"id":"1","name":"test"}]}`
		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, responseBody)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, responseBody, rec.Body.String())

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2)

		var respEvent audit.Event
		err := json.Unmarshal([]byte(lines[1]), &respEvent)
		require.NoError(t, err)
		require.NotNil(t, respEvent.Response)
		assert.Equal(t, int64(len(responseBody)), respEvent.Response.ContentLength)
	})

	t.Run("captures default 200 status when WriteHeader not called", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Write body without calling WriteHeader - should default to 200
			_, _ = io.WriteString(w, "OK")
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2)

		var respEvent audit.Event
		err := json.Unmarshal([]byte(lines[1]), &respEvent)
		require.NoError(t, err)
		require.NotNil(t, respEvent.Response)
		assert.Equal(t, http.StatusOK, respEvent.Response.StatusCode)
	})
}

func TestFunctional_AuditMiddleware_HTTPMethods(t *testing.T) {
	t.Parallel()

	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, method := range methods {
		method := method
		t.Run("audit middleware handles "+method+" method", func(t *testing.T) {
			t.Parallel()

			cfg := &audit.Config{
				Enabled: true,
				Level:   audit.LevelInfo,
				Output:  "stdout",
				Format:  "json",
				Events: &audit.EventsConfig{
					Request:  true,
					Response: true,
				},
			}

			auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
			defer auditLogger.Close()

			handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(method, "/api/v1/items", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)

			lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
			require.GreaterOrEqual(t, len(lines), 1)

			var reqEvent audit.Event
			err := json.Unmarshal([]byte(lines[0]), &reqEvent)
			require.NoError(t, err)
			assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)
			require.NotNil(t, reqEvent.Request)
			assert.Equal(t, method, reqEvent.Request.Method)
		})
	}
}

func TestFunctional_AuditMiddleware_ResourceInfo(t *testing.T) {
	t.Parallel()

	t.Run("audit events contain resource information", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 1)

		var reqEvent audit.Event
		err := json.Unmarshal([]byte(lines[0]), &reqEvent)
		require.NoError(t, err)

		require.NotNil(t, reqEvent.Resource)
		assert.Equal(t, "http", reqEvent.Resource.Type)
		assert.Equal(t, "/api/v1/items", reqEvent.Resource.Path)
		assert.Equal(t, http.MethodGet, reqEvent.Resource.Method)
	})
}

func TestFunctional_AuditMiddleware_ChainWithOtherMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("audit middleware works in middleware chain", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		// Chain: RequestID -> Recovery -> Audit -> Handler
		handler := middleware.RequestID()(
			middleware.Recovery(observability.NopLogger())(
				middleware.Audit(auditLogger)(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						_, _ = io.WriteString(w, "OK")
					}),
				),
			),
		)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "OK", rec.Body.String())
		assert.NotEmpty(t, rec.Header().Get("X-Request-ID"))
		assert.NotEmpty(t, buf.String(), "audit should produce output")
	})
}

func TestFunctional_AuditMiddleware_DurationTracking(t *testing.T) {
	t.Parallel()

	t.Run("audit response event includes duration", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
		}

		auditLogger, buf := newBufferAuditLoggerWithBuffer(cfg)
		defer auditLogger.Close()

		handler := middleware.Audit(auditLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2)

		var respEvent audit.Event
		err := json.Unmarshal([]byte(lines[1]), &respEvent)
		require.NoError(t, err)
		assert.Greater(t, int64(respEvent.Duration), int64(0), "duration should be positive")
	})
}
