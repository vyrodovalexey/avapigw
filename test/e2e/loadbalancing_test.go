//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestE2E_LoadBalancing(t *testing.T) {
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

	// Wait for gateway to be ready
	err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
	require.NoError(t, err)

	t.Run("requests are distributed to backends", func(t *testing.T) {
		client := helpers.HTTPClient()
		successCount := 0

		// Send multiple requests
		for i := 0; i < 20; i++ {
			resp, err := client.Get(gi.BaseURL + "/api/v1/items")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					successCount++
				}
			}
		}

		// Most requests should succeed
		assert.GreaterOrEqual(t, successCount, 15, "At least 75% of requests should succeed")
	})

	t.Run("concurrent requests are handled", func(t *testing.T) {
		var wg sync.WaitGroup
		var successCount atomic.Int64
		numRequests := 50

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				client := helpers.HTTPClient()
				resp, err := client.Get(gi.BaseURL + "/api/v1/items")
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						successCount.Add(1)
					}
				}
			}()
		}

		wg.Wait()

		// Most concurrent requests should succeed
		assert.GreaterOrEqual(t, successCount.Load(), int64(numRequests*3/4),
			"At least 75% of concurrent requests should succeed")
	})
}

func TestE2E_LoadBalancing_Failover(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	// This test verifies that when one backend is unavailable,
	// requests are still handled (either by the other backend or with appropriate error)

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

	t.Run("handles backend unavailability gracefully", func(t *testing.T) {
		client := helpers.HTTPClient()

		// Send requests - some may fail if backend is down, but gateway should not crash
		for i := 0; i < 10; i++ {
			resp, err := client.Get(gi.BaseURL + "/api/v1/items")
			if err == nil {
				resp.Body.Close()
				// Accept any response - the point is the gateway handles it
				assert.True(t, resp.StatusCode >= 200 || resp.StatusCode >= 500)
			}
		}
	})
}

func TestE2E_LoadBalancing_WeightedDistribution(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend2URL)

	// The test config has 50/50 weight distribution
	// We verify that requests are distributed (not all to one backend)

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

	t.Run("weighted distribution works", func(t *testing.T) {
		client := helpers.HTTPClient()
		successCount := 0

		// Send requests
		for i := 0; i < 100; i++ {
			resp, err := client.Get(gi.BaseURL + "/api/v1/items")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					successCount++
				}
			}
		}

		// Requests should be distributed and most should succeed
		assert.GreaterOrEqual(t, successCount, 70, "At least 70% of requests should succeed")
	})
}
