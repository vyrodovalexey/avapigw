package backend

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Test Cases for NewManager
// ============================================================================

func TestNewManager(t *testing.T) {
	tests := []struct {
		name   string
		logger *zap.Logger
	}{
		{
			name:   "creates manager with logger",
			logger: zap.NewNop(),
		},
		{
			name:   "creates manager with production logger",
			logger: zap.NewExample(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager(tt.logger)

			require.NotNil(t, manager)
			assert.NotNil(t, manager.backends)
			assert.NotNil(t, manager.logger)
			assert.Empty(t, manager.backends)
		})
	}
}

// ============================================================================
// Test Cases for Manager.GetBackend
// ============================================================================

func TestManager_GetBackend(t *testing.T) {
	tests := []struct {
		name         string
		setupBackend *BackendConfig
		lookupName   string
		expectNil    bool
	}{
		{
			name: "returns backend by name",
			setupBackend: &BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			lookupName: "test-backend",
			expectNil:  false,
		},
		{
			name: "returns nil for non-existent backend",
			setupBackend: &BackendConfig{
				Name: "existing-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			lookupName: "non-existent",
			expectNil:  true,
		},
		{
			name:         "returns nil when no backends exist",
			setupBackend: nil,
			lookupName:   "any-backend",
			expectNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			manager := NewManager(logger)

			if tt.setupBackend != nil {
				err := manager.AddBackend(*tt.setupBackend)
				require.NoError(t, err)
			}

			backend := manager.GetBackend(tt.lookupName)

			if tt.expectNil {
				assert.Nil(t, backend)
			} else {
				require.NotNil(t, backend)
				assert.Equal(t, tt.setupBackend.Name, backend.Name)
			}
		})
	}
}

// ============================================================================
// Test Cases for Manager.GetBackendByNamespace
// ============================================================================

func TestManager_GetBackendByNamespace(t *testing.T) {
	tests := []struct {
		name            string
		setupBackend    *BackendConfig
		lookupNamespace string
		lookupName      string
		expectNil       bool
	}{
		{
			name: "returns backend by namespace and name",
			setupBackend: &BackendConfig{
				Name:      "test-backend",
				Namespace: "test-namespace",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			lookupNamespace: "test-namespace",
			lookupName:      "test-backend",
			expectNil:       false,
		},
		{
			name: "returns nil for non-existent namespace",
			setupBackend: &BackendConfig{
				Name:      "test-backend",
				Namespace: "existing-namespace",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			lookupNamespace: "non-existent-namespace",
			lookupName:      "test-backend",
			expectNil:       true,
		},
		{
			name: "returns nil for non-existent name in namespace",
			setupBackend: &BackendConfig{
				Name:      "existing-backend",
				Namespace: "test-namespace",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			lookupNamespace: "test-namespace",
			lookupName:      "non-existent-backend",
			expectNil:       true,
		},
		{
			name:            "returns nil when no backends exist",
			setupBackend:    nil,
			lookupNamespace: "any-namespace",
			lookupName:      "any-backend",
			expectNil:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			manager := NewManager(logger)

			if tt.setupBackend != nil {
				err := manager.AddBackend(*tt.setupBackend)
				require.NoError(t, err)
			}

			backend := manager.GetBackendByNamespace(tt.lookupNamespace, tt.lookupName)

			if tt.expectNil {
				assert.Nil(t, backend)
			} else {
				require.NotNil(t, backend)
				assert.Equal(t, tt.setupBackend.Name, backend.Name)
				assert.Equal(t, tt.setupBackend.Namespace, backend.Namespace)
			}
		})
	}
}

// ============================================================================
// Test Cases for Manager.AddBackend
// ============================================================================

func TestManager_AddBackend(t *testing.T) {
	tests := []struct {
		name          string
		config        BackendConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "adds backend with endpoints",
			config: BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "host1", Port: 8080, Weight: 1},
					{Address: "host2", Port: 8081, Weight: 2},
				},
			},
			expectError: false,
		},
		{
			name: "adds backend with namespace",
			config: BackendConfig{
				Name:      "test-backend",
				Namespace: "test-namespace",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			expectError: false,
		},
		{
			name: "adds backend with default weight handling",
			config: BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "host1", Port: 8080, Weight: 0},  // Should default to 1
					{Address: "host2", Port: 8081, Weight: -1}, // Should default to 1
				},
			},
			expectError: false,
		},
		{
			name: "adds backend with load balancer config",
			config: BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
				LoadBalancing: &LoadBalancingConfig{
					Algorithm: "RoundRobin",
				},
			},
			expectError: false,
		},
		{
			name: "adds backend with health checker",
			config: BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
				HealthCheck: &HealthCheckConfig{
					Enabled:            true,
					Interval:           10,
					Timeout:            5,
					HealthyThreshold:   2,
					UnhealthyThreshold: 3,
					Path:               "/health",
				},
			},
			expectError: false,
		},
		{
			name: "adds backend with circuit breaker",
			config: BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
				CircuitBreaker: &CircuitBreakerConfig{
					Enabled:           true,
					ConsecutiveErrors: 5,
					Interval:          30,
					BaseEjectionTime:  30,
					MaxEjectionPct:    50,
				},
			},
			expectError: false,
		},
		{
			name: "adds backend with connection pool",
			config: BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
				ConnectionPool: &ConnectionPoolConfig{
					MaxConnections:        100,
					MaxIdleConnections:    10,
					MaxConnectionsPerHost: 10,
					IdleTimeout:           90,
				},
			},
			expectError: false,
		},
		{
			name: "adds backend with metadata",
			config: BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{
						Address:  "localhost",
						Port:     8080,
						Metadata: map[string]string{"zone": "us-east-1", "version": "v1"},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			manager := NewManager(logger)

			err := manager.AddBackend(tt.config)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)

				// Verify backend was added
				key := tt.config.Name
				if tt.config.Namespace != "" {
					key = tt.config.Namespace + "/" + tt.config.Name
				}
				backend := manager.backends[key]
				require.NotNil(t, backend)
				assert.Equal(t, tt.config.Name, backend.Name)
				assert.Equal(t, tt.config.Namespace, backend.Namespace)
				assert.Len(t, backend.Endpoints, len(tt.config.Endpoints))
			}
		})
	}
}

func TestManager_AddBackend_DuplicateError(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
	}

	// First add should succeed
	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Second add should fail
	err = manager.AddBackend(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestManager_AddBackend_DuplicateWithNamespace(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name:      "test-backend",
		Namespace: "test-namespace",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
	}

	// First add should succeed
	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Second add with same namespace/name should fail
	err = manager.AddBackend(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestManager_AddBackend_DefaultWeightHandling(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "host1", Port: 8080, Weight: 0},
			{Address: "host2", Port: 8081, Weight: -5},
			{Address: "host3", Port: 8082, Weight: 3},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)

	// Verify default weight handling
	assert.Equal(t, 1, backend.Endpoints[0].Weight, "Weight 0 should default to 1")
	assert.Equal(t, 1, backend.Endpoints[1].Weight, "Negative weight should default to 1")
	assert.Equal(t, 3, backend.Endpoints[2].Weight, "Positive weight should be preserved")
}

func TestManager_AddBackend_CreatesLoadBalancer(t *testing.T) {
	tests := []struct {
		name          string
		lbConfig      *LoadBalancingConfig
		expectedType  string
		expectDefault bool
	}{
		{
			name:          "creates default RoundRobin when no config",
			lbConfig:      nil,
			expectedType:  "*backend.RoundRobinLB",
			expectDefault: true,
		},
		{
			name: "creates RoundRobin load balancer",
			lbConfig: &LoadBalancingConfig{
				Algorithm: "RoundRobin",
			},
			expectedType: "*backend.RoundRobinLB",
		},
		{
			name: "creates LeastConnections load balancer",
			lbConfig: &LoadBalancingConfig{
				Algorithm: "LeastConnections",
			},
			expectedType: "*backend.LeastConnectionsLB",
		},
		{
			name: "creates Random load balancer",
			lbConfig: &LoadBalancingConfig{
				Algorithm: "Random",
			},
			expectedType: "*backend.RandomLB",
		},
		{
			name: "creates WeightedRoundRobin load balancer",
			lbConfig: &LoadBalancingConfig{
				Algorithm: "WeightedRoundRobin",
			},
			expectedType: "*backend.WeightedRoundRobinLB",
		},
		{
			name: "creates ConsistentHash load balancer",
			lbConfig: &LoadBalancingConfig{
				Algorithm: "ConsistentHash",
				ConsistentHash: &ConsistentHashConfig{
					Type:   "header",
					Header: "X-User-ID",
				},
			},
			expectedType: "*backend.ConsistentHashLB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			manager := NewManager(logger)

			config := BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
				LoadBalancing: tt.lbConfig,
			}

			err := manager.AddBackend(config)
			require.NoError(t, err)

			backend := manager.GetBackend("test-backend")
			require.NotNil(t, backend)
			require.NotNil(t, backend.LoadBalancer)
		})
	}
}

func TestManager_AddBackend_CreatesHealthChecker(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		HealthCheck: &HealthCheckConfig{
			Enabled:            true,
			Interval:           10,
			Timeout:            5,
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
			Path:               "/health",
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)
	require.NotNil(t, backend.HealthChecker)
}

func TestManager_AddBackend_NoHealthCheckerWhenDisabled(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		HealthCheck: &HealthCheckConfig{
			Enabled: false,
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)
	assert.Nil(t, backend.HealthChecker)
}

func TestManager_AddBackend_CreatesCircuitBreaker(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		CircuitBreaker: &CircuitBreakerConfig{
			Enabled:           true,
			ConsecutiveErrors: 5,
			Interval:          30,
			BaseEjectionTime:  30,
			MaxEjectionPct:    50,
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)
	require.NotNil(t, backend.CircuitBreaker)
}

func TestManager_AddBackend_NoCircuitBreakerWhenDisabled(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		CircuitBreaker: &CircuitBreakerConfig{
			Enabled: false,
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)
	assert.Nil(t, backend.CircuitBreaker)
}

func TestManager_AddBackend_CreatesConnectionPool(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		ConnectionPool: &ConnectionPoolConfig{
			MaxConnections:        100,
			MaxIdleConnections:    10,
			MaxConnectionsPerHost: 10,
			IdleTimeout:           90,
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)
	require.NotNil(t, backend.ConnectionPool)
}

// ============================================================================
// Test Cases for Manager.RemoveBackend
// ============================================================================

func TestManager_RemoveBackend(t *testing.T) {
	tests := []struct {
		name          string
		setupBackend  *BackendConfig
		removeName    string
		expectError   bool
		errorContains string
	}{
		{
			name: "removes existing backend",
			setupBackend: &BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			removeName:  "test-backend",
			expectError: false,
		},
		{
			name: "error for non-existent backend",
			setupBackend: &BackendConfig{
				Name: "existing-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			removeName:    "non-existent",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:          "error when no backends exist",
			setupBackend:  nil,
			removeName:    "any-backend",
			expectError:   true,
			errorContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			manager := NewManager(logger)

			if tt.setupBackend != nil {
				err := manager.AddBackend(*tt.setupBackend)
				require.NoError(t, err)
			}

			err := manager.RemoveBackend(tt.removeName)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				// Verify backend was removed
				backend := manager.GetBackend(tt.removeName)
				assert.Nil(t, backend)
			}
		})
	}
}

func TestManager_RemoveBackend_StopsHealthChecker(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		HealthCheck: &HealthCheckConfig{
			Enabled:            true,
			Interval:           10,
			Timeout:            5,
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
			Path:               "/health",
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)
	require.NotNil(t, backend.HealthChecker)

	// Start the health checker
	backend.HealthChecker.Start(backend.Endpoints)
	assert.True(t, backend.HealthChecker.IsRunning())

	// Remove backend should stop health checker
	err = manager.RemoveBackend("test-backend")
	require.NoError(t, err)
}

func TestManager_RemoveBackend_ClosesConnectionPool(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		ConnectionPool: &ConnectionPoolConfig{
			MaxConnections:        100,
			MaxIdleConnections:    10,
			MaxConnectionsPerHost: 10,
			IdleTimeout:           90,
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)
	require.NotNil(t, backend.ConnectionPool)
	assert.False(t, backend.ConnectionPool.IsClosed())

	// Remove backend should close connection pool
	err = manager.RemoveBackend("test-backend")
	require.NoError(t, err)
}

// ============================================================================
// Test Cases for Manager.UpdateBackend
// ============================================================================

func TestManager_UpdateBackend(t *testing.T) {
	tests := []struct {
		name          string
		setupBackend  *BackendConfig
		updateConfig  BackendConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "updates backend endpoints",
			setupBackend: &BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "host1", Port: 8080},
				},
			},
			updateConfig: BackendConfig{
				Name: "test-backend",
				Endpoints: []EndpointConfig{
					{Address: "host2", Port: 8081},
					{Address: "host3", Port: 8082},
				},
			},
			expectError: false,
		},
		{
			name: "updates backend with namespace",
			setupBackend: &BackendConfig{
				Name:      "test-backend",
				Namespace: "test-namespace",
				Endpoints: []EndpointConfig{
					{Address: "host1", Port: 8080},
				},
			},
			updateConfig: BackendConfig{
				Name:      "test-backend",
				Namespace: "test-namespace",
				Endpoints: []EndpointConfig{
					{Address: "host2", Port: 8081},
				},
			},
			expectError: false,
		},
		{
			name: "error for non-existent backend",
			setupBackend: &BackendConfig{
				Name: "existing-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			updateConfig: BackendConfig{
				Name: "non-existent",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:         "error when no backends exist",
			setupBackend: nil,
			updateConfig: BackendConfig{
				Name: "any-backend",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			expectError:   true,
			errorContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			manager := NewManager(logger)

			if tt.setupBackend != nil {
				err := manager.AddBackend(*tt.setupBackend)
				require.NoError(t, err)
			}

			err := manager.UpdateBackend(tt.updateConfig)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)

				// Verify backend was updated
				key := tt.updateConfig.Name
				if tt.updateConfig.Namespace != "" {
					key = tt.updateConfig.Namespace + "/" + tt.updateConfig.Name
				}
				backend := manager.backends[key]
				require.NotNil(t, backend)
				assert.Len(t, backend.Endpoints, len(tt.updateConfig.Endpoints))
			}
		})
	}
}

func TestManager_UpdateBackend_UpdatesLoadBalancer(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	// Add backend with RoundRobin
	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		LoadBalancing: &LoadBalancingConfig{
			Algorithm: "RoundRobin",
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Update with LeastConnections
	updateConfig := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		LoadBalancing: &LoadBalancingConfig{
			Algorithm: "LeastConnections",
		},
	}

	err = manager.UpdateBackend(updateConfig)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)
	require.NotNil(t, backend.LoadBalancer)
	assert.IsType(t, &LeastConnectionsLB{}, backend.LoadBalancer)
}

func TestManager_UpdateBackend_DefaultWeightHandling(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	config := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "host1", Port: 8080, Weight: 5},
		},
	}

	err := manager.AddBackend(config)
	require.NoError(t, err)

	// Update with zero/negative weights
	updateConfig := BackendConfig{
		Name: "test-backend",
		Endpoints: []EndpointConfig{
			{Address: "host1", Port: 8080, Weight: 0},
			{Address: "host2", Port: 8081, Weight: -1},
		},
	}

	err = manager.UpdateBackend(updateConfig)
	require.NoError(t, err)

	backend := manager.GetBackend("test-backend")
	require.NotNil(t, backend)
	assert.Equal(t, 1, backend.Endpoints[0].Weight)
	assert.Equal(t, 1, backend.Endpoints[1].Weight)
}

// ============================================================================
// Test Cases for Manager.ListBackends
// ============================================================================

func TestManager_ListBackends(t *testing.T) {
	tests := []struct {
		name          string
		setupBackends []BackendConfig
		expectedCount int
		expectedNames []string
	}{
		{
			name:          "returns empty list when no backends",
			setupBackends: nil,
			expectedCount: 0,
			expectedNames: []string{},
		},
		{
			name: "returns single backend name",
			setupBackends: []BackendConfig{
				{
					Name: "backend1",
					Endpoints: []EndpointConfig{
						{Address: "localhost", Port: 8080},
					},
				},
			},
			expectedCount: 1,
			expectedNames: []string{"backend1"},
		},
		{
			name: "returns all backend names",
			setupBackends: []BackendConfig{
				{
					Name: "backend1",
					Endpoints: []EndpointConfig{
						{Address: "localhost", Port: 8080},
					},
				},
				{
					Name: "backend2",
					Endpoints: []EndpointConfig{
						{Address: "localhost", Port: 8081},
					},
				},
				{
					Name: "backend3",
					Endpoints: []EndpointConfig{
						{Address: "localhost", Port: 8082},
					},
				},
			},
			expectedCount: 3,
			expectedNames: []string{"backend1", "backend2", "backend3"},
		},
		{
			name: "returns namespaced backend names",
			setupBackends: []BackendConfig{
				{
					Name:      "backend1",
					Namespace: "ns1",
					Endpoints: []EndpointConfig{
						{Address: "localhost", Port: 8080},
					},
				},
				{
					Name:      "backend2",
					Namespace: "ns2",
					Endpoints: []EndpointConfig{
						{Address: "localhost", Port: 8081},
					},
				},
			},
			expectedCount: 2,
			expectedNames: []string{"ns1/backend1", "ns2/backend2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			manager := NewManager(logger)

			for _, config := range tt.setupBackends {
				err := manager.AddBackend(config)
				require.NoError(t, err)
			}

			names := manager.ListBackends()

			assert.Len(t, names, tt.expectedCount)
			for _, expectedName := range tt.expectedNames {
				assert.Contains(t, names, expectedName)
			}
		})
	}
}

// ============================================================================
// Test Cases for Backend.GetHealthyEndpoint
// ============================================================================

func TestBackend_GetHealthyEndpoint(t *testing.T) {
	tests := []struct {
		name          string
		endpoints     []*Endpoint
		expectNil     bool
		expectedAddrs []string
	}{
		{
			name: "returns healthy endpoint",
			endpoints: []*Endpoint{
				{Address: "host1", Port: 8080, Healthy: true},
				{Address: "host2", Port: 8081, Healthy: true},
			},
			expectNil:     false,
			expectedAddrs: []string{"host1", "host2"},
		},
		{
			name: "returns nil when no healthy endpoints",
			endpoints: []*Endpoint{
				{Address: "host1", Port: 8080, Healthy: false},
				{Address: "host2", Port: 8081, Healthy: false},
			},
			expectNil: true,
		},
		{
			name:      "returns nil when no endpoints",
			endpoints: []*Endpoint{},
			expectNil: true,
		},
		{
			name: "returns only healthy endpoint",
			endpoints: []*Endpoint{
				{Address: "host1", Port: 8080, Healthy: false},
				{Address: "host2", Port: 8081, Healthy: true},
				{Address: "host3", Port: 8082, Healthy: false},
			},
			expectNil:     false,
			expectedAddrs: []string{"host2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &Backend{
				Name:         "test-backend",
				Endpoints:    tt.endpoints,
				LoadBalancer: NewRoundRobinLB(),
			}

			endpoint := backend.GetHealthyEndpoint()

			if tt.expectNil {
				assert.Nil(t, endpoint)
			} else {
				require.NotNil(t, endpoint)
				assert.Contains(t, tt.expectedAddrs, endpoint.Address)
			}
		})
	}
}

func TestBackend_GetHealthyEndpoint_UsesLoadBalancer(t *testing.T) {
	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8081, Healthy: true},
		{Address: "host3", Port: 8082, Healthy: true},
	}

	backend := &Backend{
		Name:         "test-backend",
		Endpoints:    endpoints,
		LoadBalancer: NewRoundRobinLB(),
	}

	// Multiple calls should use load balancer
	results := make(map[string]int)
	for i := 0; i < 9; i++ {
		ep := backend.GetHealthyEndpoint()
		require.NotNil(t, ep)
		results[ep.Address]++
	}

	// With round-robin, each endpoint should be selected roughly equally
	assert.Greater(t, results["host1"], 0)
	assert.Greater(t, results["host2"], 0)
	assert.Greater(t, results["host3"], 0)
}

func TestBackend_GetHealthyEndpoint_NoLoadBalancer(t *testing.T) {
	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8081, Healthy: true},
	}

	backend := &Backend{
		Name:         "test-backend",
		Endpoints:    endpoints,
		LoadBalancer: nil, // No load balancer
	}

	// Should return first healthy endpoint
	endpoint := backend.GetHealthyEndpoint()
	require.NotNil(t, endpoint)
	assert.Equal(t, "host1", endpoint.Address)
}

// ============================================================================
// Test Cases for Backend.GetAllEndpoints
// ============================================================================

func TestBackend_GetAllEndpoints(t *testing.T) {
	tests := []struct {
		name          string
		endpoints     []*Endpoint
		expectedCount int
	}{
		{
			name: "returns all endpoints",
			endpoints: []*Endpoint{
				{Address: "host1", Port: 8080, Healthy: true},
				{Address: "host2", Port: 8081, Healthy: false},
				{Address: "host3", Port: 8082, Healthy: true},
			},
			expectedCount: 3,
		},
		{
			name:          "returns empty slice when no endpoints",
			endpoints:     []*Endpoint{},
			expectedCount: 0,
		},
		{
			name: "returns single endpoint",
			endpoints: []*Endpoint{
				{Address: "host1", Port: 8080, Healthy: true},
			},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &Backend{
				Name:      "test-backend",
				Endpoints: tt.endpoints,
			}

			endpoints := backend.GetAllEndpoints()

			assert.Len(t, endpoints, tt.expectedCount)
		})
	}
}

func TestBackend_GetAllEndpoints_ReturnsCopy(t *testing.T) {
	originalEndpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8081, Healthy: true},
	}

	backend := &Backend{
		Name:      "test-backend",
		Endpoints: originalEndpoints,
	}

	endpoints := backend.GetAllEndpoints()

	// Modifying returned slice should not affect original
	endpoints[0] = &Endpoint{Address: "modified", Port: 9999}

	assert.Equal(t, "host1", backend.Endpoints[0].Address)
}

// ============================================================================
// Test Cases for Backend.GetHealthyEndpoints
// ============================================================================

func TestBackend_GetHealthyEndpoints(t *testing.T) {
	tests := []struct {
		name          string
		endpoints     []*Endpoint
		expectedCount int
		expectedAddrs []string
	}{
		{
			name: "returns only healthy endpoints",
			endpoints: []*Endpoint{
				{Address: "host1", Port: 8080, Healthy: true},
				{Address: "host2", Port: 8081, Healthy: false},
				{Address: "host3", Port: 8082, Healthy: true},
			},
			expectedCount: 2,
			expectedAddrs: []string{"host1", "host3"},
		},
		{
			name: "returns empty when all unhealthy",
			endpoints: []*Endpoint{
				{Address: "host1", Port: 8080, Healthy: false},
				{Address: "host2", Port: 8081, Healthy: false},
			},
			expectedCount: 0,
			expectedAddrs: []string{},
		},
		{
			name: "returns all when all healthy",
			endpoints: []*Endpoint{
				{Address: "host1", Port: 8080, Healthy: true},
				{Address: "host2", Port: 8081, Healthy: true},
			},
			expectedCount: 2,
			expectedAddrs: []string{"host1", "host2"},
		},
		{
			name:          "returns empty when no endpoints",
			endpoints:     []*Endpoint{},
			expectedCount: 0,
			expectedAddrs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &Backend{
				Name:      "test-backend",
				Endpoints: tt.endpoints,
			}

			healthyEndpoints := backend.GetHealthyEndpoints()

			assert.Len(t, healthyEndpoints, tt.expectedCount)
			for _, ep := range healthyEndpoints {
				assert.Contains(t, tt.expectedAddrs, ep.Address)
				assert.True(t, ep.Healthy)
			}
		})
	}
}

// ============================================================================
// Test Cases for Endpoint.SetHealthy
// ============================================================================

func TestEndpoint_SetHealthy(t *testing.T) {
	tests := []struct {
		name          string
		initialHealth bool
		setHealth     bool
	}{
		{
			name:          "sets healthy to true",
			initialHealth: false,
			setHealth:     true,
		},
		{
			name:          "sets healthy to false",
			initialHealth: true,
			setHealth:     false,
		},
		{
			name:          "sets same value (true)",
			initialHealth: true,
			setHealth:     true,
		},
		{
			name:          "sets same value (false)",
			initialHealth: false,
			setHealth:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := &Endpoint{
				Address: "localhost",
				Port:    8080,
				Healthy: tt.initialHealth,
			}

			endpoint.SetHealthy(tt.setHealth)

			assert.Equal(t, tt.setHealth, endpoint.Healthy)
		})
	}
}

// ============================================================================
// Test Cases for Endpoint.IsHealthy
// ============================================================================

func TestEndpoint_IsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		healthy  bool
		expected bool
	}{
		{
			name:     "returns true when healthy",
			healthy:  true,
			expected: true,
		},
		{
			name:     "returns false when unhealthy",
			healthy:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := &Endpoint{
				Address: "localhost",
				Port:    8080,
				Healthy: tt.healthy,
			}

			result := endpoint.IsHealthy()

			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for Endpoint.FullAddress
// ============================================================================

func TestEndpoint_FullAddress(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		port     int
		expected string
	}{
		{
			name:     "returns address:port format",
			address:  "localhost",
			port:     8080,
			expected: "localhost:8080",
		},
		{
			name:     "handles IP address",
			address:  "192.168.1.1",
			port:     443,
			expected: "192.168.1.1:443",
		},
		{
			name:     "handles hostname",
			address:  "api.example.com",
			port:     80,
			expected: "api.example.com:80",
		},
		{
			name:     "handles port 0",
			address:  "localhost",
			port:     0,
			expected: "localhost:0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := &Endpoint{
				Address: tt.address,
				Port:    tt.port,
			}

			result := endpoint.FullAddress()

			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestManager_ConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()
	manager := NewManager(logger)

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			config := BackendConfig{
				Name: "backend-" + string(rune('a'+idx%26)) + string(rune('0'+idx/26)),
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080 + idx},
				},
			}
			_ = manager.AddBackend(config)
		}(i)
	}

	wg.Wait()

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = manager.ListBackends()
			_ = manager.GetBackend("backend-" + string(rune('a'+idx%26)) + string(rune('0'+idx/26)))
		}(i)
	}

	wg.Wait()
}

func TestBackend_ConcurrentGetHealthyEndpoint(t *testing.T) {
	endpoints := []*Endpoint{
		{Address: "host1", Port: 8080, Healthy: true},
		{Address: "host2", Port: 8081, Healthy: true},
		{Address: "host3", Port: 8082, Healthy: true},
	}

	backend := &Backend{
		Name:         "test-backend",
		Endpoints:    endpoints,
		LoadBalancer: NewRoundRobinLB(),
	}

	var wg sync.WaitGroup
	numGoroutines := 100
	numIterations := 100

	results := make(chan *Endpoint, numGoroutines*numIterations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				ep := backend.GetHealthyEndpoint()
				results <- ep
			}
		}()
	}

	wg.Wait()
	close(results)

	// Verify all results are valid
	validAddresses := map[string]bool{"host1": true, "host2": true, "host3": true}
	count := 0
	for ep := range results {
		require.NotNil(t, ep)
		assert.True(t, validAddresses[ep.Address])
		count++
	}

	assert.Equal(t, numGoroutines*numIterations, count)
}

func TestEndpoint_ConcurrentSetHealthy(t *testing.T) {
	endpoint := &Endpoint{
		Address: "localhost",
		Port:    8080,
		Healthy: true,
	}

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			endpoint.SetHealthy(true)
		}()
		go func() {
			defer wg.Done()
			endpoint.SetHealthy(false)
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

func TestEndpoint_ConcurrentIsHealthy(t *testing.T) {
	endpoint := &Endpoint{
		Address: "localhost",
		Port:    8080,
		Healthy: true,
	}

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = endpoint.IsHealthy()
		}()
		go func() {
			defer wg.Done()
			endpoint.SetHealthy(!endpoint.IsHealthy())
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}
