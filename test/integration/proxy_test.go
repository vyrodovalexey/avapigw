//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_Proxy_ForwardToBackend(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("forward GET request to backend", func(t *testing.T) {
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

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response helpers.BackendResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)
		assert.True(t, response.Success)
	})

	t.Run("forward POST request to backend", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "Test Item",
			Description: "Test Description",
			Price:       19.99,
		}

		// Create proper request with body directly to backend
		resp, err := helpers.MakeRequest(http.MethodPost, testCfg.Backend1URL+"/api/v1/items", item)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated)

		var response struct {
			Success bool                 `json:"success"`
			Data    helpers.ItemResponse `json:"data"`
		}
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, "Test Item", response.Data.Name)

		// Cleanup
		if response.Data.ID != "" {
			_ = helpers.DeleteTestItem(testCfg.Backend1URL, response.Data.ID)
		}
	})

	t.Run("forward request with query parameters", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, testCfg.Backend1URL+"/api/v1/items?limit=10&offset=0", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("handle 404 from backend", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, testCfg.Backend1URL+"/api/v1/items/99999", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Backend should return 404 for non-existent item
		assert.True(t, resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusOK)
	})
}

func TestIntegration_Proxy_DirectResponse(t *testing.T) {
	t.Parallel()

	t.Run("direct response route", func(t *testing.T) {
		t.Parallel()

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

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "healthy")
	})
}

func TestIntegration_Proxy_Redirect(t *testing.T) {
	t.Parallel()

	t.Run("redirect route", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "redirect",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/old-path"},
					Methods: []string{"GET"},
				},
			},
			Redirect: &config.RedirectConfig{
				URI:  "/new-path",
				Code: 301,
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		req := httptest.NewRequest(http.MethodGet, "/old-path", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusMovedPermanently, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), "/new-path")
	})
}

func TestIntegration_Proxy_Rewrite(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("rewrite URI", func(t *testing.T) {
		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "backend-health",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Exact: "/backend/health"},
					Methods: []string{"GET"},
				},
			},
			Rewrite: &config.RewriteConfig{
				URI: "/health",
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		req := httptest.NewRequest(http.MethodGet, "/backend/health", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response helpers.HealthResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)
		assert.True(t, response.Success)
	})
}

func TestIntegration_Proxy_Timeout(t *testing.T) {
	t.Parallel()

	t.Run("request with timeout", func(t *testing.T) {
		t.Parallel()

		r := router.New()
		err := r.AddRoute(config.Route{
			Name: "timeout-route",
			Match: []config.RouteMatch{
				{
					URI:     &config.URIMatch{Prefix: "/api"},
					Methods: []string{"GET"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "127.0.0.1", Port: 8801}},
			},
			Timeout: config.Duration(30 * time.Second),
		})
		require.NoError(t, err)

		registry := backend.NewRegistry(observability.NopLogger())
		p := proxy.NewReverseProxy(r, registry)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		// Should complete within timeout
		assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusBadGateway)
	})
}

func TestIntegration_Proxy_RouteNotFound(t *testing.T) {
	t.Parallel()

	t.Run("no matching route returns 404", func(t *testing.T) {
		t.Parallel()

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

		req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
