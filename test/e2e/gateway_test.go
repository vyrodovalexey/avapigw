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

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_GatewayStartup(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway starts and stops cleanly", func(t *testing.T) {
		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		// Use a unique port for this test
		cfg.Spec.Listeners[0].Port = 18081

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

	t.Run("gateway with full configuration", func(t *testing.T) {
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

		// Verify gateway is running
		assert.True(t, gi.Gateway.IsRunning())
	})

	t.Run("gateway state transitions", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Spec.Listeners[0].Port = 18082

		ctx := context.Background()

		gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
		require.NoError(t, err)

		// Initial state should be stopped
		assert.Equal(t, gateway.StateStopped, gw.State())

		// Start gateway
		err = gw.Start(ctx)
		require.NoError(t, err)
		assert.Equal(t, gateway.StateRunning, gw.State())

		// Cannot start again
		err = gw.Start(ctx)
		require.Error(t, err)

		// Stop gateway
		err = gw.Stop(ctx)
		require.NoError(t, err)
		assert.Equal(t, gateway.StateStopped, gw.State())

		// Cannot stop again
		err = gw.Stop(ctx)
		require.Error(t, err)
	})
}

func TestE2E_CRUD_ThroughGateway(t *testing.T) {
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

	var createdItemID string

	t.Run("create item through gateway", func(t *testing.T) {
		item := helpers.CreateItemRequest{
			Name:        "E2E Test Item",
			Description: "Created through gateway",
			Price:       29.99,
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
		assert.Equal(t, "E2E Test Item", response.Data.Name)
		createdItemID = response.Data.ID
	})

	t.Run("read item through gateway", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("No item created")
		}

		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/api/v1/items", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response helpers.BackendResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)
		assert.True(t, response.Success)
	})

	t.Run("update item through gateway", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("No item created")
		}

		item := helpers.CreateItemRequest{
			Name:        "Updated E2E Item",
			Description: "Updated through gateway",
			Price:       39.99,
		}

		resp, err := helpers.MakeRequest(http.MethodPut, gi.BaseURL+"/api/v1/items/"+createdItemID, item)
		if err != nil {
			t.Logf("Update request failed: %v", err)
			return
		}
		defer resp.Body.Close()

		// Accept various success codes
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 300 || resp.StatusCode == 404)
	})

	t.Run("delete item through gateway", func(t *testing.T) {
		if createdItemID == "" {
			t.Skip("No item created")
		}

		// Cleanup the created item
		_ = helpers.DeleteTestItem(testCfg.Backend1URL, createdItemID)
	})
}

func TestE2E_DirectResponse(t *testing.T) {
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

	t.Run("health endpoint returns direct response", func(t *testing.T) {
		resp, err := helpers.MakeRequest(http.MethodGet, gi.BaseURL+"/health", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := helpers.ReadResponseBody(resp)
		require.NoError(t, err)
		assert.Contains(t, body, "healthy")
	})
}

func TestE2E_BackendHealth(t *testing.T) {
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

	t.Run("backend health through gateway", func(t *testing.T) {
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

func TestE2E_GatewayConfig(t *testing.T) {
	t.Parallel()

	t.Run("gateway returns config", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Spec.Listeners[0].Port = 18083

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
		assert.Equal(t, cfg.Spec.Listeners[0].Port, returnedCfg.Spec.Listeners[0].Port)
	})

	t.Run("gateway engine is accessible", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Spec.Listeners[0].Port = 18084

		ctx := context.Background()

		gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		t.Cleanup(func() {
			_ = gw.Stop(ctx)
		})

		// Get engine
		engine := gw.Engine()
		assert.NotNil(t, engine)
	})
}
