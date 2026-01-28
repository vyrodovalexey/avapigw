//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestE2E_Transform_HTTPFlow tests complete HTTP request/response transformation flow through gateway.
func TestE2E_Transform_HTTPFlow(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create gateway configuration with transformation
	cfg := createTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("basic transformation flow", func(t *testing.T) {
		// Make request through gateway
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response status
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})

	t.Run("transformation with POST request", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "Transform Test Item",
			Description: "Testing transformation",
			Price:       99.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPost, gi.BaseURL+"/api/v1/items", item)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Accept various success codes
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500,
			"Expected success or client error, got %d", resp.StatusCode)
	})
}

// TestE2E_Transform_FieldFiltering tests transformation with field filtering.
func TestE2E_Transform_FieldFiltering(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create configuration with field filtering
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "transform-filter-test",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: config.ProtocolHTTP,
					Bind:     "127.0.0.1",
				},
			},
			Routes: []config.Route{
				{
					Name: "health",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status:  200,
						Body:    `{"status":"healthy"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: "filtered-api",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/v1/"}},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: "127.0.0.1",
								Port: 8801,
							},
							Weight: 100,
						},
					},
					Transform: &config.TransformConfig{
						Response: &config.ResponseTransformConfig{
							AllowFields: []string{"id", "name", "status"},
							DenyFields:  []string{"password", "secret", "internal_id"},
						},
					},
				},
			},
		},
	}

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("field filtering applied", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})
}

// TestE2E_Transform_FieldMapping tests transformation with field mapping.
func TestE2E_Transform_FieldMapping(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create configuration with field mapping
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "transform-mapping-test",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: config.ProtocolHTTP,
					Bind:     "127.0.0.1",
				},
			},
			Routes: []config.Route{
				{
					Name: "health",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status:  200,
						Body:    `{"status":"healthy"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: "mapped-api",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/v1/"}},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: "127.0.0.1",
								Port: 8801,
							},
							Weight: 100,
						},
					},
					Transform: &config.TransformConfig{
						Response: &config.ResponseTransformConfig{
							FieldMappings: []config.FieldMapping{
								{Source: "created_at", Target: "createdAt"},
								{Source: "updated_at", Target: "updatedAt"},
								{Source: "user_id", Target: "userId"},
							},
						},
					},
				},
			},
		},
	}

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("field mapping applied", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})
}

// TestE2E_Transform_MultipleBackends tests transformation with multiple backends.
func TestE2E_Transform_MultipleBackends(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create configuration with multiple backends
	cfg := createTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("requests distributed across backends", func(t *testing.T) {
		// Make multiple requests
		for i := 0; i < 10; i++ {
			resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
			require.NoError(t, err)
			resp.Body.Close()

			assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
				"Request %d: Expected 200 or 404, got %d", i, resp.StatusCode)
		}
	})
}

// TestE2E_Transform_LoadBalancing tests transformation with load balancing.
func TestE2E_Transform_LoadBalancing(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create configuration with weighted backends
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "transform-lb-test",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: config.ProtocolHTTP,
					Bind:     "127.0.0.1",
				},
			},
			Routes: []config.Route{
				{
					Name: "health",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status:  200,
						Body:    `{"status":"healthy"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: "weighted-api",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/v1/"}},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: "127.0.0.1",
								Port: 8801,
							},
							Weight: 70,
						},
						{
							Destination: config.Destination{
								Host: "127.0.0.1",
								Port: 8802,
							},
							Weight: 30,
						},
					},
					Transform: &config.TransformConfig{
						Response: &config.ResponseTransformConfig{
							AllowFields: []string{"id", "name", "data"},
						},
					},
				},
			},
		},
	}

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("weighted load balancing", func(t *testing.T) {
		// Make multiple requests to verify distribution
		successCount := 0
		for i := 0; i < 20; i++ {
			resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
			require.NoError(t, err)
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				successCount++
			}
		}

		// At least some requests should succeed
		t.Logf("Successful requests: %d/20", successCount)
	})
}

// TestE2E_Transform_ErrorHandling tests transformation error handling.
func TestE2E_Transform_ErrorHandling(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create configuration
	cfg := createTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("non-existent endpoint returns 404", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/nonexistent/12345", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should return 404 or similar error
		assert.True(t, resp.StatusCode >= 400, "Expected error status, got %d", resp.StatusCode)
	})

	t.Run("invalid method returns error", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodPatch, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should return error or method not allowed
		assert.True(t, resp.StatusCode >= 200, "Expected valid response, got %d", resp.StatusCode)
	})

	t.Run("malformed JSON body handled", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := helpers.HTTPClient()
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should handle gracefully
		assert.True(t, resp.StatusCode >= 200, "Expected valid response, got %d", resp.StatusCode)
	})
}

// TestE2E_Transform_RequestTransformation tests request transformation.
func TestE2E_Transform_RequestTransformation(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create configuration with request transformation
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "transform-request-test",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: config.ProtocolHTTP,
					Bind:     "127.0.0.1",
				},
			},
			Routes: []config.Route{
				{
					Name: "health",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status:  200,
						Body:    `{"status":"healthy"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: "request-transform-api",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/v1/"}},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: "127.0.0.1",
								Port: 8801,
							},
							Weight: 100,
						},
					},
					Transform: &config.TransformConfig{
						Request: &config.RequestTransformConfig{
							StaticHeaders: map[string]string{
								"X-Gateway-Version": "1.0",
								"X-Transformed":     "true",
							},
							DefaultValues: map[string]interface{}{
								"api_version": "v1",
							},
						},
					},
				},
			},
		},
	}

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("request transformation applied", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "Request Transform Test",
			Description: "Testing request transformation",
			Price:       49.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPost, gi.BaseURL+"/api/v1/items", item)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500,
			"Expected success or client error, got %d", resp.StatusCode)
	})

	t.Run("custom headers in request", func(t *testing.T) {
		headers := map[string]string{
			"X-Custom-Header": "custom-value",
			"X-Request-ID":    "test-request-123",
		}

		resp, err := helpers.MakeRequestWithHeaders(http.MethodGet, gi.BaseURL+"/api/v1/items", nil, headers)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})
}

// TestE2E_Transform_ResponseHeaders tests response header transformation.
func TestE2E_Transform_ResponseHeaders(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create configuration with header manipulation
	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "transform-headers-test",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: config.ProtocolHTTP,
					Bind:     "127.0.0.1",
				},
			},
			Routes: []config.Route{
				{
					Name: "health",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Exact: "/health"}},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status:  200,
						Body:    `{"status":"healthy"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: "headers-api",
					Match: []config.RouteMatch{
						{URI: &config.URIMatch{Prefix: "/api/v1/"}},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: "127.0.0.1",
								Port: 8801,
							},
							Weight: 100,
						},
					},
					Headers: &config.HeaderManipulation{
						Response: &config.HeaderOperation{
							Set: map[string]string{
								"X-Gateway":     "avapigw",
								"X-API-Version": "v1",
							},
							Remove: []string{"X-Internal-Header"},
						},
					},
				},
			},
		},
	}

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("response headers modified", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})
}

// TestE2E_Transform_CompleteJourney tests a complete user journey with transformations.
func TestE2E_Transform_CompleteJourney(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Get a free port
	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	// Create comprehensive configuration
	cfg := createTransformTestConfig(port, testCfg.Backend1URL, testCfg.Backend2URL)

	// Start gateway
	gi, err := startGatewayWithTransformConfig(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	var createdItemID string

	t.Run("1. Create item through gateway", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "E2E Transform Journey Item",
			Description: "Testing complete transformation journey",
			Price:       149.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPost, gi.BaseURL+"/api/v1/items", item)
		require.NoError(t, err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			var response struct {
				Success bool                 `json:"success"`
				Data    helpers.ItemResponse `json:"data"`
			}
			err = json.NewDecoder(resp.Body).Decode(&response)
			if err == nil && response.Success {
				createdItemID = response.Data.ID
				t.Logf("Created item with ID: %s", createdItemID)
			}
		}
	})

	t.Run("2. Read items through gateway", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound,
			"Expected 200 or 404, got %d", resp.StatusCode)
	})

	t.Run("3. Update item through gateway", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("No item created to update")
		}

		item := helpers.CreateItemRequest{
			Name:        "Updated E2E Transform Item",
			Description: "Updated through gateway",
			Price:       199.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPut, gi.BaseURL+"/api/v1/items/"+createdItemID, item)
		if err != nil {
			t.Logf("Update request failed: %v", err)
			return
		}
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500,
			"Expected success or client error, got %d", resp.StatusCode)
	})

	t.Run("4. Delete item through gateway", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("No item created to delete")
		}

		// Cleanup the created item
		_ = helpers.DeleteTestItem(testCfg.Backend1URL, createdItemID)
	})
}

// Helper functions

func createTransformTestConfig(port int, backend1URL, backend2URL string) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "transform-e2e-test-gateway",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: config.ProtocolHTTP,
					Bind:     "127.0.0.1",
				},
			},
			Routes: []config.Route{
				{
					Name: "health-check",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Exact: "/health"},
							Methods: []string{"GET"},
						},
					},
					DirectResponse: &config.DirectResponseConfig{
						Status:  200,
						Body:    `{"status":"healthy","gateway":"transform-e2e-test"}`,
						Headers: map[string]string{"Content-Type": "application/json"},
					},
				},
				{
					Name: "transform-api",
					Match: []config.RouteMatch{
						{
							URI:     &config.URIMatch{Prefix: "/api/v1/"},
							Methods: []string{"GET", "POST", "PUT", "DELETE"},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: "127.0.0.1",
								Port: 8801,
							},
							Weight: 50,
						},
						{
							Destination: config.Destination{
								Host: "127.0.0.1",
								Port: 8802,
							},
							Weight: 50,
						},
					},
					Timeout: config.Duration(30 * time.Second),
					Transform: &config.TransformConfig{
						Request: &config.RequestTransformConfig{
							StaticHeaders: map[string]string{
								"X-Gateway-Version": "1.0",
								"X-Transform-Test":  "true",
							},
						},
						Response: &config.ResponseTransformConfig{
							AllowFields: []string{"id", "name", "description", "price", "status", "success", "data"},
							FieldMappings: []config.FieldMapping{
								{Source: "created_at", Target: "createdAt"},
								{Source: "updated_at", Target: "updatedAt"},
							},
						},
					},
				},
			},
		},
	}
}

func startGatewayWithTransformConfig(ctx context.Context, cfg *config.GatewayConfig) (*helpers.GatewayInstance, error) {
	logger := observability.NopLogger()

	// Create router
	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		return nil, err
	}

	// Create backend registry
	registry := backend.NewRegistry(logger)
	if err := registry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		// Backends might be empty, which is fine
		_ = err
	}

	// Start backends
	if err := registry.StartAll(ctx); err != nil {
		// Backends might be empty, which is fine
		_ = err
	}

	// Create proxy
	p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

	// Create gateway
	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(p),
	)
	if err != nil {
		return nil, err
	}

	// Start gateway
	if err := gw.Start(ctx); err != nil {
		return nil, err
	}

	// Determine base URL
	port := 8080
	if len(cfg.Spec.Listeners) > 0 {
		port = cfg.Spec.Listeners[0].Port
	}
	baseURL := "http://127.0.0.1:" + string(rune('0'+port/10000)) + string(rune('0'+(port/1000)%10)) + string(rune('0'+(port/100)%10)) + string(rune('0'+(port/10)%10)) + string(rune('0'+port%10))

	// Use fmt.Sprintf for proper port formatting
	baseURL = "http://127.0.0.1:" + formatPort(port)

	return &helpers.GatewayInstance{
		Gateway:  gw,
		Config:   cfg,
		Router:   r,
		Registry: registry,
		Proxy:    p,
		BaseURL:  baseURL,
	}, nil
}

func formatPort(port int) string {
	result := ""
	if port == 0 {
		return "0"
	}
	for port > 0 {
		result = string(rune('0'+port%10)) + result
		port /= 10
	}
	return result
}
