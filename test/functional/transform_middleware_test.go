//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
//
// This file black-boxes the HTTP transform middleware (internal/middleware.
// TransformFromConfig) by driving real *http.Request / http.ResponseWriter
// pairs through the full middleware -> handler chain and asserting on the
// bytes and headers the client actually observes.
//
// It complements transform_test.go, which exercises the transform package's
// pure logic in isolation. Here we specifically cover the response-recorder
// behavior hardened in the middleware layer: header replace-per-key (no
// duplication), non-JSON passthrough at the HTTP layer, JSON field rewrite
// through the recorder, and the >10MB buffer-exceeded streaming bypass.
package functional

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// transformTestTimeout bounds each request round-trip so a hang surfaces as a
// test failure rather than stalling CI.
const transformTestTimeout = 10 * time.Second

// buildTransformChain wires the transform middleware around the supplied
// backend handler and returns a ready-to-serve http.Handler. Any outer
// middleware is applied outside the transform layer so header-dedup behavior
// can be asserted realistically.
func buildTransformChain(
	cfg *config.TransformConfig,
	outer func(http.Handler) http.Handler,
	backend http.HandlerFunc,
) http.Handler {
	logger := observability.NopLogger()
	var h http.Handler = middleware.TransformFromConfig(cfg, logger)(backend)
	if outer != nil {
		h = outer(h)
	}
	return h
}

// serveTransform issues a single request through the handler and returns the
// resulting response. The request is bounded by transformTestTimeout.
func serveTransform(t *testing.T, h http.Handler, req *http.Request) *http.Response {
	t.Helper()

	ctx, cancel := context.WithTimeout(req.Context(), transformTestTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

// TestFunctional_TransformMiddleware_JSONFieldRewrite verifies that a JSON
// response body flowing through the transform middleware is actually rewritten
// according to the response transform config (field mapping + deny), and that
// the framing headers are corrected for the new body.
func TestFunctional_TransformMiddleware_JSONFieldRewrite(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Response: &config.ResponseTransformConfig{
			DenyFields: []string{"password"},
			FieldMappings: []config.FieldMapping{
				{Source: "user_name", Target: "name"},
			},
		},
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user_name":"John","password":"secret","id":"123"}`))
	})

	h := buildTransformChain(cfg, nil, backend)
	req := httptest.NewRequest(http.MethodGet, "/users/123", http.NoBody)
	resp := serveTransform(t, h, req)
	t.Cleanup(func() { _ = resp.Body.Close() })

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got), "transformed body must be valid JSON")

	// (c) a transform actually rewrites a JSON field.
	assert.Equal(t, "John", got["name"], "user_name should be mapped to name")
	assert.NotContains(t, got, "user_name", "source field should be removed after mapping")
	assert.NotContains(t, got, "password", "denied field should be stripped")
	assert.Equal(t, "123", got["id"], "unrelated field should survive")

	// Content-Length must match the rewritten body, not the backend's original.
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, len(body), int(resp.ContentLength),
		"Content-Length must be re-framed to the transformed body size")
}

// TestFunctional_TransformMiddleware_NoDuplicateHeaders verifies that headers
// set by an outer middleware are replaced-per-key rather than duplicated when
// the recorder flushes captured headers back to the client. This exercises the
// copyRecordedHeaders del-then-add semantics.
func TestFunctional_TransformMiddleware_NoDuplicateHeaders(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Response: &config.ResponseTransformConfig{
			DenyFields: []string{"secret"},
		},
	}

	// Outer middleware pre-sets X-Trace-Id; the backend sets the same key.
	// After transform, the client must see exactly one value.
	outer := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Trace-Id", "outer-value")
			next.ServeHTTP(w, r)
		})
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Trace-Id", "backend-value")
		w.Header().Set("X-Custom", "keep-me")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","secret":"x"}`))
	})

	h := buildTransformChain(cfg, outer, backend)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	resp := serveTransform(t, h, req)
	t.Cleanup(func() { _ = resp.Body.Close() })

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// (a) response headers are not duplicated: exactly one X-Trace-Id value,
	// and it is the backend's value (recorded headers replace outer values).
	traceVals := resp.Header.Values("X-Trace-Id")
	assert.Len(t, traceVals, 1, "X-Trace-Id must not be duplicated across layers")
	assert.Equal(t, "backend-value", traceVals[0],
		"recorded backend header should replace the outer value")

	assert.Equal(t, []string{"keep-me"}, resp.Header.Values("X-Custom"))

	// Content-Length header should not be duplicated either.
	assert.Len(t, resp.Header.Values("Content-Length"), 1,
		"Content-Length must appear at most once")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.NotContains(t, got, "secret")
}

// TestFunctional_TransformMiddleware_NonJSONPassthrough verifies that a
// non-JSON response body passes through the transform middleware byte-for-byte
// unchanged (passthrough, not an error), preserving the original headers.
func TestFunctional_TransformMiddleware_NonJSONPassthrough(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Response: &config.ResponseTransformConfig{
			// A non-empty response transform so the recorder path is taken.
			DenyFields: []string{"anything"},
		},
	}

	const originalBody = "plain text body, not JSON at all <html>?"

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Custom", "preserved")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(originalBody))
	})

	h := buildTransformChain(cfg, nil, backend)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	resp := serveTransform(t, h, req)
	t.Cleanup(func() { _ = resp.Body.Close() })

	// (b) non-JSON body passes through unchanged.
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"original status code must be preserved on passthrough")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, originalBody, string(body),
		"non-JSON body must pass through byte-for-byte unchanged")

	// Original content type and custom headers must survive, unduplicated.
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, []string{"preserved"}, resp.Header.Values("X-Custom"))
	assert.Len(t, resp.Header.Values("Content-Type"), 1)
}

// TestFunctional_TransformMiddleware_LargeBodyStreamPassthrough verifies that a
// JSON response body exceeding the 10MB transform buffer limit bypasses
// transformation entirely and is streamed through to the client unchanged.
// This exercises the recorder's bufferExceeded flush/stream path.
func TestFunctional_TransformMiddleware_LargeBodyStreamPassthrough(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Response: &config.ResponseTransformConfig{
			// Would strip "filler" if transformation were applied.
			DenyFields: []string{"filler"},
		},
	}

	// Build a >10MB JSON payload. The "filler" field would be removed by the
	// transform, so if it survives we know transformation was skipped.
	const overLimit = (10 << 20) + (1 << 20) // 11MB
	filler := strings.Repeat("a", overLimit)
	payload := `{"filler":"` + filler + `","keep":"yes"}`
	require.Greater(t, len(payload), 10<<20, "payload must exceed the 10MB buffer limit")

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write in chunks so the buffer-exceeded transition is crossed mid-stream.
		chunk := 64 << 10
		for i := 0; i < len(payload); i += chunk {
			end := i + chunk
			if end > len(payload) {
				end = len(payload)
			}
			_, _ = w.Write([]byte(payload[i:end]))
		}
	})

	h := buildTransformChain(cfg, nil, backend)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	resp := serveTransform(t, h, req)
	t.Cleanup(func() { _ = resp.Body.Close() })

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// The over-limit body must be delivered unchanged: transform is skipped,
	// so the "filler" field is still present and byte length matches.
	assert.Equal(t, len(payload), len(body),
		"large body must stream through unchanged (no transformation)")
	assert.True(t, strings.Contains(string(body), `"filler"`),
		"denied field must survive because transform is bypassed above 10MB")
	assert.True(t, strings.Contains(string(body), `"keep":"yes"`))
}
