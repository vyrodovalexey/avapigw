//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_Audit_GatewayLifecycle(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway with audit enabled starts and stops cleanly", func(t *testing.T) {
		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		// Use a unique port for this test
		cfg.Spec.Listeners[0].Port = 18090

		// Enable audit
		cfg.Spec.Audit = &config.AuditConfig{
			Enabled: true,
			Level:   "info",
			Output:  "stdout",
			Format:  "json",
			Events: &config.AuditEventsConfig{
				Request:  true,
				Response: true,
			},
		}

		ctx := context.Background()

		gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
		require.NoError(t, err)

		// Start gateway
		err = gw.Start(ctx)
		require.NoError(t, err)

		// Verify gateway is running
		assert.True(t, gw.IsRunning())
		assert.Equal(t, gateway.StateRunning, gw.State())

		// Verify uptime is positive
		time.Sleep(100 * time.Millisecond)
		assert.Greater(t, gw.Uptime(), time.Duration(0))

		// Stop gateway
		err = gw.Stop(ctx)
		require.NoError(t, err)

		// Verify gateway is stopped
		assert.False(t, gw.IsRunning())
		assert.Equal(t, gateway.StateStopped, gw.State())
	})

	t.Run("gateway with audit disabled starts and stops cleanly", func(t *testing.T) {
		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		cfg.Spec.Listeners[0].Port = 18091

		// Disable audit
		cfg.Spec.Audit = &config.AuditConfig{
			Enabled: false,
		}

		ctx := context.Background()

		gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		assert.True(t, gw.IsRunning())

		err = gw.Stop(ctx)
		require.NoError(t, err)

		assert.False(t, gw.IsRunning())
	})
}

func TestE2E_Audit_RequestProcessing(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("audit does not affect GET request processing", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response helpers.BackendResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)
		assert.True(t, response.Success)
	})

	t.Run("audit does not affect POST request processing", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "Audit E2E Test Item",
			Description: "Created during audit e2e test",
			Price:       19.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPost, gi.BaseURL+"/api/v1/items", item)
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

		// Cleanup
		if response.Data.ID != "" {
			_ = helpers.DeleteTestItem(testCfg.Backend1URL, response.Data.ID)
		}
	})

	t.Run("audit does not affect health endpoint", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/health", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := helpers.ReadResponseBody(resp)
		require.NoError(t, err)
		assert.Contains(t, body, "healthy")
	})
}

func TestE2E_Audit_ResponseTimes(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("audit does not significantly affect response times", func(t *testing.T) {
		const numRequests = 10
		const maxAcceptableLatency = 5 * time.Second

		for i := 0; i < numRequests; i++ {
			start := time.Now()

			resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
			require.NoError(t, err)
			resp.Body.Close()

			duration := time.Since(start)
			assert.Less(t, duration, maxAcceptableLatency,
				"request %d took %v, exceeding max acceptable latency", i, duration)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}
	})
}

func TestE2E_Audit_LoadBalancing(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("audit works with load balanced requests", func(t *testing.T) {
		const numRequests = 10
		var successCount int32

		for i := 0; i < numRequests; i++ {
			resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
			if err != nil {
				t.Logf("Request %d failed: %v", i, err)
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				atomic.AddInt32(&successCount, 1)
			}
		}

		// At least some requests should succeed
		assert.Greater(t, successCount, int32(0), "at least some requests should succeed")
	})
}

func TestE2E_Audit_ConcurrentRequests(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("audit handles concurrent requests correctly", func(t *testing.T) {
		const numConcurrent = 10
		var wg sync.WaitGroup
		var successCount int32
		var errorCount int32

		for i := 0; i < numConcurrent; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
				if err != nil {
					atomic.AddInt32(&errorCount, 1)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					atomic.AddInt32(&successCount, 1)
				}
			}(i)
		}

		wg.Wait()

		// Most requests should succeed
		assert.Greater(t, successCount, int32(0), "at least some concurrent requests should succeed")
		t.Logf("Concurrent requests: %d success, %d errors", successCount, errorCount)
	})
}

func TestE2E_Audit_BackendHealth(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("audit works with backend health check through gateway", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/backend/health", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response helpers.HealthResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)
		assert.True(t, response.Success)
	})
}

func TestE2E_Audit_CRUD_Journey(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	var createdItemID string

	t.Run("create item with audit enabled", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "Audit CRUD Test Item",
			Description: "Created during audit CRUD e2e test",
			Price:       49.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPost, gi.BaseURL+"/api/v1/items", item)
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
		createdItemID = response.Data.ID
	})

	t.Run("read items with audit enabled", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response helpers.BackendResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)
		assert.True(t, response.Success)
	})

	t.Run("update item with audit enabled", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("No item created")
		}

		item := helpers.CreateItemRequest{
			Name:        "Updated Audit CRUD Item",
			Description: "Updated during audit CRUD e2e test",
			Price:       59.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPut, gi.BaseURL+"/api/v1/items/"+createdItemID, item)
		if err != nil {
			t.Logf("Update request failed: %v", err)
			return
		}
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 300 || resp.StatusCode == 404)
	})

	t.Run("delete item with audit enabled", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("No item created")
		}

		_ = helpers.DeleteTestItem(testCfg.Backend1URL, createdItemID)
	})
}

func TestE2E_Audit_GatewayConfig(t *testing.T) {
	t.Parallel()

	t.Run("gateway with audit config returns config", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Spec.Listeners[0].Port = 18092
		cfg.Spec.Audit = &config.AuditConfig{
			Enabled: true,
			Level:   "info",
			Output:  "stdout",
			Format:  "json",
			Events: &config.AuditEventsConfig{
				Request:  true,
				Response: true,
			},
			SkipPaths: []string{"/health", "/metrics"},
		}

		ctx := context.Background()

		gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		// Get config
		returnedCfg := gw.Config()
		assert.Equal(t, cfg.Metadata.Name, returnedCfg.Metadata.Name)
		assert.NotNil(t, returnedCfg.Spec.Audit)
		assert.True(t, returnedCfg.Spec.Audit.Enabled)
		assert.Equal(t, "stdout", returnedCfg.Spec.Audit.Output)
	})
}

func TestE2E_Audit_MultipleHTTPMethods(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx := context.Background()

	gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
	require.NoError(t, err)
	require.NotNil(t, gi)

	t.Cleanup(func() {
		_ = gi.Stop(ctx)
	})

	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	methods := []struct {
		method     string
		path       string
		body       interface{}
		expectCode int
	}{
		{http.MethodGet, "/api/v1/items", nil, http.StatusOK},
		{http.MethodGet, "/health", nil, http.StatusOK},
		{http.MethodGet, "/backend/health", nil, http.StatusOK},
	}

	for _, tc := range methods {
		tc := tc
		t.Run("audit with "+tc.method+" to "+tc.path, func(t *testing.T) {
			resp, err := helpers.MakeRequest(tc.method, gi.BaseURL+tc.path, tc.body)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}
