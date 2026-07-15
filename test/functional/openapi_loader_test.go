//go:build functional
// +build functional

// OpenAPI spec URL loading functional tests.
//
// They cover the hardening added to remote spec fetching: every fetch is
// bounded (context deadline / 30s client timeout instead of kin-openapi's
// unbounded http.DefaultClient) and external $ref targets are denied by
// default, protecting startup and hot-reload against hung or hostile spec
// sources (SSRF / local-file reads).
package functional

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/openapi"
)

// minimalOpenAPISpec is a valid self-contained OpenAPI 3.0 document.
const minimalOpenAPISpec = `{
  "openapi": "3.0.0",
  "info": {"title": "loader-test", "version": "1.0.0"},
  "paths": {
    "/items": {
      "get": {
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}`

func TestFunctional_OpenAPI_SpecURLLoading(t *testing.T) {
	t.Parallel()

	t.Run("loads and caches spec from URL", func(t *testing.T) {
		t.Parallel()

		var hits int
		server := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				hits++
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(minimalOpenAPISpec))
			}))
		defer server.Close()

		loader := openapi.NewSpecLoader()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		doc, err := loader.LoadFromURL(ctx, server.URL)
		require.NoError(t, err)
		require.NotNil(t, doc)
		assert.Equal(t, "loader-test", doc.Info.Title)

		// Second load must come from the cache, not refetch.
		doc2, err := loader.LoadFromURL(ctx, server.URL)
		require.NoError(t, err)
		assert.Same(t, doc, doc2)
		assert.Equal(t, 1, hits, "cached spec must not be refetched")

		// Invalidate forces a refetch on next access.
		loader.Invalidate(server.URL)
		_, err = loader.LoadFromURL(ctx, server.URL)
		require.NoError(t, err)
		assert.Equal(t, 2, hits, "invalidated spec must be refetched")
	})

	t.Run("external references are denied by default", func(t *testing.T) {
		t.Parallel()

		// The referenced document would be valid — the fetch of the second
		// URL itself must be refused before it is ever read.
		external := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"components":{"schemas":{"Item":{"type":"object"}}}}`))
			}))
		defer external.Close()

		rootSpec := `{
  "openapi": "3.0.0",
  "info": {"title": "external-ref-test", "version": "1.0.0"},
  "paths": {
    "/items": {
      "get": {
        "responses": {
          "200": {
            "description": "OK",
            "content": {
              "application/json": {
                "schema": {"$ref": "` + external.URL + `/schemas.json#/components/schemas/Item"}
              }
            }
          }
        }
      }
    }
  }
}`
		root := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(rootSpec))
			}))
		defer root.Close()

		loader := openapi.NewSpecLoader()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := loader.LoadFromURL(ctx, root.URL)
		require.Error(t, err, "spec with external $ref must be rejected by default")
		assert.Contains(t, err.Error(), "disallowed external reference")
	})

	t.Run("hung spec source is bounded by the caller context", func(t *testing.T) {
		t.Parallel()

		release := make(chan struct{})
		t.Cleanup(func() { close(release) })

		server := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				// Never respond until the test finishes: simulates a hung
				// spec URL that previously stalled startup indefinitely.
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
		defer server.Close()

		loader := openapi.NewSpecLoader()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := loader.LoadFromURL(ctx, server.URL)
		elapsed := time.Since(start)

		require.Error(t, err, "hung spec fetch must fail, not hang")
		assert.Less(t, elapsed, 5*time.Second,
			"fetch must abort promptly once the context deadline expires")
		assert.True(t,
			strings.Contains(err.Error(), "context deadline exceeded") ||
				strings.Contains(err.Error(), "Client.Timeout"),
			"error should reflect the deadline, got: %v", err)
	})

	t.Run("spec fetch HTTP errors are surfaced", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			}))
		defer server.Close()

		loader := openapi.NewSpecLoader()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := loader.LoadFromURL(ctx, server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status code 500")
	})
}
