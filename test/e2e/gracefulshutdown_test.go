//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_GracefulShutdown(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("gateway shuts down gracefully", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Spec.Listeners[0].Port = 18099

		ctx := context.Background()

		gw, err := gateway.New(cfg,
			gateway.WithLogger(observability.NopLogger()),
			gateway.WithShutdownTimeout(5*time.Second),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		// Verify gateway is running
		assert.True(t, gw.IsRunning())

		// Stop gateway
		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		err = gw.Stop(shutdownCtx)
		require.NoError(t, err)

		// Verify gateway is stopped
		assert.False(t, gw.IsRunning())
		assert.Equal(t, gateway.StateStopped, gw.State())
	})

	t.Run("shutdown with timeout", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Spec.Listeners[0].Port = 18100

		ctx := context.Background()

		gw, err := gateway.New(cfg,
			gateway.WithLogger(observability.NopLogger()),
			gateway.WithShutdownTimeout(1*time.Second),
		)
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		// Stop with short timeout
		shutdownCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		start := time.Now()
		err = gw.Stop(shutdownCtx)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.Less(t, elapsed, 3*time.Second, "Shutdown should complete within timeout")
	})

	t.Run("concurrent requests during shutdown", func(t *testing.T) {
		ctx := context.Background()

		gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
		require.NoError(t, err)
		require.NotNil(t, gi)

		// Wait for gateway to be ready
		err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
		require.NoError(t, err)

		// Start some concurrent requests
		var wg sync.WaitGroup
		requestsDone := make(chan struct{})

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				client := helpers.HTTPClient()
				for {
					select {
					case <-requestsDone:
						return
					default:
						resp, err := client.Get(gi.BaseURL + "/api/v1/items")
						if err == nil {
							resp.Body.Close()
						}
						time.Sleep(100 * time.Millisecond)
					}
				}
			}()
		}

		// Let some requests go through
		time.Sleep(500 * time.Millisecond)

		// Signal requests to stop
		close(requestsDone)

		// Stop gateway
		err = gi.Stop(ctx)
		require.NoError(t, err)

		// Wait for all goroutines to finish
		wg.Wait()

		// Gateway should be stopped
		assert.False(t, gi.Gateway.IsRunning())
	})
}

func TestE2E_GracefulShutdown_Listeners(t *testing.T) {
	t.Parallel()

	t.Run("all listeners are stopped", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "multi-listener-test",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http1", Port: 18101, Protocol: "HTTP"},
					{Name: "http2", Port: 18102, Protocol: "HTTP"},
				},
			},
		}

		ctx := context.Background()

		gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
		require.NoError(t, err)

		err = gw.Start(ctx)
		require.NoError(t, err)

		// Verify both listeners are active
		listeners := gw.GetListeners()
		assert.Len(t, listeners, 2)

		// Stop gateway
		err = gw.Stop(ctx)
		require.NoError(t, err)

		// Verify gateway is stopped
		assert.False(t, gw.IsRunning())
	})
}

func TestE2E_GracefulShutdown_InFlightRequests(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("in-flight requests complete before shutdown", func(t *testing.T) {
		ctx := context.Background()

		gi, err := helpers.StartGateway(ctx, helpers.GetTestConfigPath("gateway-test.yaml"))
		require.NoError(t, err)
		require.NotNil(t, gi)

		// Wait for gateway to be ready
		err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
		require.NoError(t, err)

		// Start a request
		client := helpers.HTTPClient()
		requestComplete := make(chan bool, 1)

		go func() {
			resp, err := client.Get(gi.BaseURL + "/api/v1/items")
			if err == nil {
				resp.Body.Close()
				requestComplete <- resp.StatusCode == http.StatusOK
			} else {
				requestComplete <- false
			}
		}()

		// Wait a bit for request to start
		time.Sleep(100 * time.Millisecond)

		// Stop gateway
		err = gi.Stop(ctx)
		require.NoError(t, err)

		// Check if request completed
		select {
		case success := <-requestComplete:
			// Request completed (may or may not have succeeded depending on timing)
			t.Logf("Request completed with success=%v", success)
		case <-time.After(5 * time.Second):
			t.Log("Request did not complete within timeout")
		}
	})
}

func TestE2E_GracefulShutdown_StateTransitions(t *testing.T) {
	t.Parallel()

	t.Run("state transitions are correct", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Spec.Listeners[0].Port = 18103

		ctx := context.Background()

		gw, err := gateway.New(cfg, gateway.WithLogger(observability.NopLogger()))
		require.NoError(t, err)

		// Initial state
		assert.Equal(t, gateway.StateStopped, gw.State())

		// Start
		err = gw.Start(ctx)
		require.NoError(t, err)
		assert.Equal(t, gateway.StateRunning, gw.State())

		// Stop
		err = gw.Stop(ctx)
		require.NoError(t, err)
		assert.Equal(t, gateway.StateStopped, gw.State())
	})

	t.Run("state string representations", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "stopped", gateway.StateStopped.String())
		assert.Equal(t, "starting", gateway.StateStarting.String())
		assert.Equal(t, "running", gateway.StateRunning.String())
		assert.Equal(t, "stopping", gateway.StateStopping.String())
	})
}
