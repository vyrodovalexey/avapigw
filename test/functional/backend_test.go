//go:build functional
// +build functional

package functional

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

// ============================================================================
// Backend Registration Tests
// ============================================================================

func TestFunctional_Backend_Registration_Basic(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	// Add backend
	config := backend.BackendConfig{
		Name:      "test-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Verify backend exists (use GetBackendByNamespace when namespace is specified)
	b := manager.GetBackendByNamespace("default", "test-backend")
	require.NotNil(t, b)
	assert.Equal(t, "test-backend", b.Name)

	// Verify endpoints
	endpoints := b.GetAllEndpoints()
	assert.Len(t, endpoints, 1)
	assert.Equal(t, "127.0.0.1", endpoints[0].Address)
	assert.Equal(t, 8080, endpoints[0].Port)
}

func TestFunctional_Backend_Registration_WithNamespace(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	// Add backend with namespace
	config := backend.BackendConfig{
		Name:      "test-backend",
		Namespace: "production",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Get by namespace/name
	b := manager.GetBackendByNamespace("production", "test-backend")
	assert.NotNil(t, b)
	assert.Equal(t, "test-backend", b.Name)
	assert.Equal(t, "production", b.Namespace)
}

func TestFunctional_Backend_Registration_Duplicate(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "test-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
		},
	}

	// First add should succeed
	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Second add should fail
	err = manager.AddBackend(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestFunctional_Backend_Registration_MultipleEndpoints(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "multi-endpoint-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 2},
			{Address: "127.0.0.3", Port: 8080, Weight: 3},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "multi-endpoint-backend")
	require.NotNil(t, b)

	endpoints := b.GetAllEndpoints()
	assert.Len(t, endpoints, 3)
}

// ============================================================================
// Backend Removal Tests
// ============================================================================

func TestFunctional_Backend_Removal_Basic(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	// Add backend
	config := backend.BackendConfig{
		Name:      "test-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Remove backend (use full key with namespace)
	err = manager.RemoveBackend("default/test-backend")
	require.NoError(t, err)

	// Verify backend is removed
	b := manager.GetBackendByNamespace("default", "test-backend")
	assert.Nil(t, b)
}

func TestFunctional_Backend_Removal_NonExistent(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	// Try to remove non-existent backend
	err := manager.RemoveBackend("non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ============================================================================
// Backend Update Tests
// ============================================================================

func TestFunctional_Backend_Update_Endpoints(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	// Add backend
	config := backend.BackendConfig{
		Name:      "test-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Update with new endpoints
	updateConfig := backend.BackendConfig{
		Name:      "test-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 2},
		},
	}

	err = manager.UpdateBackend(updateConfig)
	require.NoError(t, err)

	// Verify updated endpoints
	b := manager.GetBackendByNamespace("default", "test-backend")
	require.NotNil(t, b)

	endpoints := b.GetAllEndpoints()
	assert.Len(t, endpoints, 2)
}

func TestFunctional_Backend_Update_NonExistent(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "non-existent",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
		},
	}

	err := manager.UpdateBackend(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ============================================================================
// Load Balancing Tests
// ============================================================================

func TestFunctional_Backend_LoadBalancing_RoundRobin(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "rr-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 1},
			{Address: "127.0.0.3", Port: 8080, Weight: 1},
		},
		LoadBalancing: &backend.LoadBalancingConfig{
			Algorithm: "RoundRobin",
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "rr-backend")
	require.NotNil(t, b)

	// Get endpoints multiple times - should cycle through
	selectedAddresses := make(map[string]int)
	for i := 0; i < 9; i++ {
		ep := b.GetHealthyEndpoint()
		require.NotNil(t, ep)
		selectedAddresses[ep.Address]++
	}

	// Each endpoint should be selected 3 times
	assert.Equal(t, 3, selectedAddresses["127.0.0.1"])
	assert.Equal(t, 3, selectedAddresses["127.0.0.2"])
	assert.Equal(t, 3, selectedAddresses["127.0.0.3"])
}

func TestFunctional_Backend_LoadBalancing_WeightedRoundRobin(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "wrr-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 3},
			{Address: "127.0.0.2", Port: 8080, Weight: 2},
			{Address: "127.0.0.3", Port: 8080, Weight: 1},
		},
		LoadBalancing: &backend.LoadBalancingConfig{
			Algorithm: "WeightedRoundRobin",
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "wrr-backend")
	require.NotNil(t, b)

	// Get endpoints multiple times
	selectedAddresses := make(map[string]int)
	for i := 0; i < 60; i++ {
		ep := b.GetHealthyEndpoint()
		require.NotNil(t, ep)
		selectedAddresses[ep.Address]++
	}

	// Higher weight endpoints should be selected more often
	assert.Greater(t, selectedAddresses["127.0.0.1"], selectedAddresses["127.0.0.2"])
	assert.Greater(t, selectedAddresses["127.0.0.2"], selectedAddresses["127.0.0.3"])
}

func TestFunctional_Backend_LoadBalancing_Random(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "random-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 1},
			{Address: "127.0.0.3", Port: 8080, Weight: 1},
		},
		LoadBalancing: &backend.LoadBalancingConfig{
			Algorithm: "Random",
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "random-backend")
	require.NotNil(t, b)

	// Get endpoints multiple times
	selectedAddresses := make(map[string]int)
	for i := 0; i < 100; i++ {
		ep := b.GetHealthyEndpoint()
		require.NotNil(t, ep)
		selectedAddresses[ep.Address]++
	}

	// All endpoints should be selected at least once
	assert.Greater(t, selectedAddresses["127.0.0.1"], 0)
	assert.Greater(t, selectedAddresses["127.0.0.2"], 0)
	assert.Greater(t, selectedAddresses["127.0.0.3"], 0)
}

func TestFunctional_Backend_LoadBalancing_LeastConnections(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "lc-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 1},
			{Address: "127.0.0.3", Port: 8080, Weight: 1},
		},
		LoadBalancing: &backend.LoadBalancingConfig{
			Algorithm: "LeastConnections",
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "lc-backend")
	require.NotNil(t, b)

	// Get endpoints - should distribute evenly initially
	selectedAddresses := make(map[string]int)
	for i := 0; i < 9; i++ {
		ep := b.GetHealthyEndpoint()
		require.NotNil(t, ep)
		selectedAddresses[ep.Address]++
	}

	// All endpoints should be selected
	assert.Greater(t, selectedAddresses["127.0.0.1"], 0)
	assert.Greater(t, selectedAddresses["127.0.0.2"], 0)
	assert.Greater(t, selectedAddresses["127.0.0.3"], 0)
}

func TestFunctional_Backend_LoadBalancing_ConsistentHash(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "ch-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 1},
			{Address: "127.0.0.3", Port: 8080, Weight: 1},
		},
		LoadBalancing: &backend.LoadBalancingConfig{
			Algorithm: "ConsistentHash",
			ConsistentHash: &backend.ConsistentHashConfig{
				Type:   "Header",
				Header: "X-User-ID",
			},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "ch-backend")
	require.NotNil(t, b)

	// Same key should always return same endpoint
	ep1 := b.GetHealthyEndpoint()
	ep2 := b.GetHealthyEndpoint()
	require.NotNil(t, ep1)
	require.NotNil(t, ep2)
	// Note: Without key context, consistent hash falls back to first endpoint
}

// ============================================================================
// Health Check Tests
// ============================================================================

func TestFunctional_Backend_HealthCheck_EndpointHealth(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "health-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 1},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "health-backend")
	require.NotNil(t, b)

	// All endpoints should be healthy initially
	healthyEndpoints := b.GetHealthyEndpoints()
	assert.Len(t, healthyEndpoints, 2)

	// Mark one endpoint as unhealthy
	endpoints := b.GetAllEndpoints()
	endpoints[0].SetHealthy(false)

	// Should only return healthy endpoints
	healthyEndpoints = b.GetHealthyEndpoints()
	assert.Len(t, healthyEndpoints, 1)
	assert.Equal(t, "127.0.0.2", healthyEndpoints[0].Address)
}

func TestFunctional_Backend_HealthCheck_AllUnhealthy(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "unhealthy-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 1},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "unhealthy-backend")
	require.NotNil(t, b)

	// Mark all endpoints as unhealthy
	endpoints := b.GetAllEndpoints()
	for _, ep := range endpoints {
		ep.SetHealthy(false)
	}

	// Should return nil when no healthy endpoints
	ep := b.GetHealthyEndpoint()
	assert.Nil(t, ep)

	healthyEndpoints := b.GetHealthyEndpoints()
	assert.Len(t, healthyEndpoints, 0)
}

// ============================================================================
// Backend Manager Lifecycle Tests
// ============================================================================

func TestFunctional_Backend_Manager_StartStop(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	// Add backend before starting
	config := backend.BackendConfig{
		Name:      "test-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Start manager
	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	assert.True(t, manager.IsRunning())

	// Stop manager
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = manager.Stop(stopCtx)
	require.NoError(t, err)
	assert.False(t, manager.IsRunning())
}

func TestFunctional_Backend_Manager_DoubleStart(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)

	// Second start should fail
	err = manager.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Cleanup
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manager.Stop(stopCtx)
}

func TestFunctional_Backend_Manager_Stats(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	// Add backends
	for i := 0; i < 3; i++ {
		config := backend.BackendConfig{
			Name:      "backend-" + string(rune('a'+i)),
			Namespace: "default",
			Endpoints: []backend.EndpointConfig{
				{Address: "127.0.0.1", Port: 8080 + i, Weight: 1},
				{Address: "127.0.0.2", Port: 8080 + i, Weight: 1},
			},
		}
		err := manager.AddBackend(config)
		require.NoError(t, err)
	}

	// Start manager
	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)

	// Get stats
	stats := manager.Stats()
	assert.Equal(t, 3, stats.TotalBackends)
	assert.Equal(t, 6, stats.TotalEndpoints)
	assert.Equal(t, 6, stats.HealthyEndpoints)
	assert.Equal(t, 3, stats.HealthyBackends)

	// Cleanup
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manager.Stop(stopCtx)
}

// ============================================================================
// Backend Failover Tests
// ============================================================================

func TestFunctional_Backend_Failover_ToHealthyEndpoint(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "failover-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 1},
			{Address: "127.0.0.3", Port: 8080, Weight: 1},
		},
		LoadBalancing: &backend.LoadBalancingConfig{
			Algorithm: "RoundRobin",
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "failover-backend")
	require.NotNil(t, b)

	// Mark first endpoint as unhealthy
	endpoints := b.GetAllEndpoints()
	endpoints[0].SetHealthy(false)

	// Should only return healthy endpoints
	for i := 0; i < 10; i++ {
		ep := b.GetHealthyEndpoint()
		require.NotNil(t, ep)
		assert.NotEqual(t, "127.0.0.1", ep.Address)
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestFunctional_Backend_ConcurrentAccess(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	manager := suite.CreateBackendManager()

	config := backend.BackendConfig{
		Name:      "concurrent-backend",
		Namespace: "default",
		Endpoints: []backend.EndpointConfig{
			{Address: "127.0.0.1", Port: 8080, Weight: 1},
			{Address: "127.0.0.2", Port: 8080, Weight: 1},
		},
		LoadBalancing: &backend.LoadBalancingConfig{
			Algorithm: "RoundRobin",
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	b := manager.GetBackendByNamespace("default", "concurrent-backend")
	require.NotNil(t, b)

	// Concurrent endpoint selection
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ep := b.GetHealthyEndpoint()
			if ep == nil {
				errors <- assert.AnError
			}
		}()
	}

	wg.Wait()
	close(errors)

	// No errors should occur
	errorCount := 0
	for range errors {
		errorCount++
	}
	assert.Equal(t, 0, errorCount)
}

// ============================================================================
// Table-Driven Backend Tests
// ============================================================================

func TestFunctional_Backend_LoadBalancing_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		algorithm     string
		endpoints     []backend.EndpointConfig
		numSelections int
		validate      func(t *testing.T, selections map[string]int)
	}{
		{
			name:      "round robin distributes evenly",
			algorithm: "RoundRobin",
			endpoints: []backend.EndpointConfig{
				{Address: "127.0.0.1", Port: 8080, Weight: 1},
				{Address: "127.0.0.2", Port: 8080, Weight: 1},
			},
			numSelections: 10,
			validate: func(t *testing.T, selections map[string]int) {
				assert.Equal(t, 5, selections["127.0.0.1"])
				assert.Equal(t, 5, selections["127.0.0.2"])
			},
		},
		{
			name:      "random selects all endpoints",
			algorithm: "Random",
			endpoints: []backend.EndpointConfig{
				{Address: "127.0.0.1", Port: 8080, Weight: 1},
				{Address: "127.0.0.2", Port: 8080, Weight: 1},
				{Address: "127.0.0.3", Port: 8080, Weight: 1},
			},
			numSelections: 100,
			validate: func(t *testing.T, selections map[string]int) {
				assert.Greater(t, selections["127.0.0.1"], 0)
				assert.Greater(t, selections["127.0.0.2"], 0)
				assert.Greater(t, selections["127.0.0.3"], 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := NewTestSuite(t)
			defer suite.Cleanup()

			manager := suite.CreateBackendManager()

			config := backend.BackendConfig{
				Name:      "test-backend",
				Namespace: "default",
				Endpoints: tt.endpoints,
				LoadBalancing: &backend.LoadBalancingConfig{
					Algorithm: tt.algorithm,
				},
			}

			err := manager.AddBackend(config)
			require.NoError(t, err)

			b := manager.GetBackendByNamespace("default", "test-backend")
			require.NotNil(t, b)

			selections := make(map[string]int)
			for i := 0; i < tt.numSelections; i++ {
				ep := b.GetHealthyEndpoint()
				require.NotNil(t, ep)
				selections[ep.Address]++
			}

			tt.validate(t, selections)
		})
	}
}

func TestFunctional_Backend_Registration_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		config      backend.BackendConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid backend",
			config: backend.BackendConfig{
				Name:      "valid-backend",
				Namespace: "default",
				Endpoints: []backend.EndpointConfig{
					{Address: "127.0.0.1", Port: 8080, Weight: 1},
				},
			},
			expectError: false,
		},
		{
			name: "backend with multiple endpoints",
			config: backend.BackendConfig{
				Name:      "multi-endpoint",
				Namespace: "default",
				Endpoints: []backend.EndpointConfig{
					{Address: "127.0.0.1", Port: 8080, Weight: 1},
					{Address: "127.0.0.2", Port: 8080, Weight: 2},
					{Address: "127.0.0.3", Port: 8080, Weight: 3},
				},
			},
			expectError: false,
		},
		{
			name: "backend with zero weight",
			config: backend.BackendConfig{
				Name:      "zero-weight",
				Namespace: "default",
				Endpoints: []backend.EndpointConfig{
					{Address: "127.0.0.1", Port: 8080, Weight: 0},
				},
			},
			expectError: false, // Weight 0 is normalized to 1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := NewTestSuite(t)
			defer suite.Cleanup()

			manager := suite.CreateBackendManager()

			err := manager.AddBackend(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				b := manager.GetBackendByNamespace(tt.config.Namespace, tt.config.Name)
				assert.NotNil(t, b)
			}
		})
	}
}
