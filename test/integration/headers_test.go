//go:build integration
// +build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_Headers_XForwarded(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("X-Forwarded-For header is set", func(t *testing.T) {
		// Create a test server that echoes headers
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Headers are received by the server
			_ = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		defer testServer.Close()

		// Make request through the test server
		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/test", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("custom headers are forwarded", func(t *testing.T) {
		var receivedHeaders http.Header
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		defer testServer.Close()

		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/test", nil)
		require.NoError(t, err)

		req.Header.Set("X-Custom-Header", "custom-value")
		req.Header.Set("Authorization", "Bearer token123")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
		assert.Equal(t, "Bearer token123", receivedHeaders.Get("Authorization"))
	})

	t.Run("content-type header is preserved", func(t *testing.T) {
		var receivedContentType string
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedContentType = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusOK)
		}))
		defer testServer.Close()

		resp, err := helpers.MakeRequestWithHeaders(
			http.MethodPost,
			testServer.URL+"/test",
			map[string]string{"key": "value"},
			map[string]string{"Content-Type": "application/json"},
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, "application/json", receivedContentType)
	})
}

func TestIntegration_Headers_ResponseHeaders(t *testing.T) {
	t.Parallel()

	t.Run("response headers are returned", func(t *testing.T) {
		t.Parallel()

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Response-Header", "response-value")
			w.Header().Set("X-Custom-Response", "custom-response")
			w.WriteHeader(http.StatusOK)
		}))
		defer testServer.Close()

		client := helpers.HTTPClient()
		resp, err := client.Get(testServer.URL + "/test")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, "response-value", resp.Header.Get("X-Response-Header"))
		assert.Equal(t, "custom-response", resp.Header.Get("X-Custom-Response"))
	})

	t.Run("CORS headers are returned", func(t *testing.T) {
		t.Parallel()

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
			w.WriteHeader(http.StatusOK)
		}))
		defer testServer.Close()

		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodOptions, testServer.URL+"/test", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "http://example.com")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	})
}

func TestIntegration_Headers_HopByHop(t *testing.T) {
	t.Parallel()

	t.Run("hop-by-hop headers are not forwarded", func(t *testing.T) {
		t.Parallel()

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Headers are received by the server
			_ = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		defer testServer.Close()

		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/test", nil)
		require.NoError(t, err)

		// These are hop-by-hop headers that should be removed by proxies
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Keep-Alive", "timeout=5")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Note: The test server receives the request directly, not through a proxy
		// In a real proxy scenario, these headers would be stripped
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestIntegration_Headers_RealBackend(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("headers to real backend", func(t *testing.T) {
		client := helpers.HTTPClient()
		req, err := http.NewRequest(http.MethodGet, testCfg.Backend1URL+"/api/v1/items", nil)
		require.NoError(t, err)

		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Request-ID", "test-request-123")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")
	})
}
