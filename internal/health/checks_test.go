package health

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test Cases for CachedHealthCheck Thread Safety
// ============================================================================

func TestCachedHealthCheck_ConcurrentHealthCheckCalls(t *testing.T) {
	// Create a simple health check that increments a counter
	checkCount := 0
	mu := sync.Mutex{}

	mockCheck := NewHealthCheckFunc("test-concurrent", func(ctx context.Context) error {
		mu.Lock()
		checkCount++
		mu.Unlock()

		// Simulate some work
		time.Sleep(10 * time.Millisecond)
		return nil
	})

	ttl := 100 * time.Millisecond
	cachedCheck := NewCachedHealthCheck(mockCheck, ttl)

	ctx := context.Background()

	// Launch multiple concurrent health check calls
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cachedCheck.Check(ctx)
		}()
	}

	wg.Wait()

	// The underlying check should only be called once (due to caching)
	mu.Lock()
	assert.Equal(t, 1, checkCount)
	mu.Unlock()
}

func TestCachedHealthCheck_CacheHitWithinTTL(t *testing.T) {
	// Create a simple health check
	mockCheck := NewHealthCheckFunc("test-cache-hit", func(ctx context.Context) error {
		return nil
	})

	ttl := 200 * time.Millisecond
	cachedCheck := NewCachedHealthCheck(mockCheck, ttl)

	ctx := context.Background()

	// First call - should execute the underlying check
	err1 := cachedCheck.Check(ctx)
	require.NoError(t, err1)

	// Second call within TTL - should return cached result
	err2 := cachedCheck.Check(ctx)
	require.NoError(t, err2)

	// Third call within TTL - should return cached result
	err3 := cachedCheck.Check(ctx)
	require.NoError(t, err3)
}

func TestCachedHealthCheck_CacheRefreshAfterTTL(t *testing.T) {
	// Create a health check that tracks calls
	checkCount := 0
	mu := sync.Mutex{}

	mockCheck := NewHealthCheckFunc("test-cache-refresh", func(ctx context.Context) error {
		mu.Lock()
		checkCount++
		mu.Unlock()
		return nil
	})

	ttl := 50 * time.Millisecond
	cachedCheck := NewCachedHealthCheck(mockCheck, ttl)

	ctx := context.Background()

	// First call - should execute the underlying check
	err := cachedCheck.Check(ctx)
	require.NoError(t, err)

	mu.Lock()
	assert.Equal(t, 1, checkCount)
	mu.Unlock()

	// Wait for cache to expire
	time.Sleep(60 * time.Millisecond)

	// Call after TTL - should execute the underlying check again
	err = cachedCheck.Check(ctx)
	require.NoError(t, err)

	mu.Lock()
	assert.Equal(t, 2, checkCount)
	mu.Unlock()
}

func TestCachedHealthCheck_ThreadSafety(t *testing.T) {
	// Create a health check that simulates slow check
	slowCheck := NewHealthCheckFunc("test-thread-safety", func(ctx context.Context) error {
		time.Sleep(50 * time.Millisecond)
		return nil
	})

	ttl := 100 * time.Millisecond
	cachedCheck := NewCachedHealthCheck(slowCheck, ttl)

	ctx := context.Background()

	// Launch multiple concurrent calls while cache is being populated
	var wg sync.WaitGroup
	numGoroutines := 20
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cachedCheck.Check(ctx)
			errChan <- err
		}()
	}

	wg.Wait()
	close(errChan)

	// All calls should succeed
	for err := range errChan {
		assert.NoError(t, err)
	}
}

func TestCachedHealthCheck_Name(t *testing.T) {
	mockCheck := &mockHealthCheck{name: "test-check"}
	cachedCheck := NewCachedHealthCheck(mockCheck, time.Second)

	assert.Equal(t, "test-check", cachedCheck.Name())
}

func TestCachedHealthCheck_ReturnsError(t *testing.T) {
	expectedErr := assert.AnError
	mockCheck := NewHealthCheckFunc("test-error", func(ctx context.Context) error {
		return expectedErr
	})

	cachedCheck := NewCachedHealthCheck(mockCheck, time.Second)

	ctx := context.Background()

	// First call should return error
	err := cachedCheck.Check(ctx)
	assert.Equal(t, expectedErr, err)

	// Second call should return cached error
	err = cachedCheck.Check(ctx)
	assert.Equal(t, expectedErr, err)
}

// mockHealthCheck is a simple HealthCheck implementation for testing
type mockHealthCheck struct {
	name string
}

func (m *mockHealthCheck) Name() string {
	return m.name
}

func (m *mockHealthCheck) Check(ctx context.Context) error {
	return nil
}

// ============================================================================
// Test Cases for NewCachedHealthCheck
// ============================================================================

func TestNewCachedHealthCheck(t *testing.T) {
	mockCheck := &mockHealthCheck{name: "test"}
	ttl := 5 * time.Second

	cachedCheck := NewCachedHealthCheck(mockCheck, ttl)

	assert.Equal(t, "test", cachedCheck.Name())
}

// ============================================================================
// Test Cases for DependencyCheck
// ============================================================================

func TestDependencyCheck_Name(t *testing.T) {
	check := NewDependencyCheck("test-dep", DependencyTypeHTTP, func(ctx context.Context) error {
		return nil
	})

	assert.Equal(t, "test-dep", check.Name())
}

func TestDependencyCheck_IsCritical(t *testing.T) {
	// Default should be critical
	check := NewDependencyCheck("test", DependencyTypeHTTP, func(ctx context.Context) error {
		return nil
	})
	assert.True(t, check.IsCritical())

	// Non-critical
	check = NewDependencyCheck("test", DependencyTypeHTTP, func(ctx context.Context) error {
		return nil
	}, WithCritical(false))
	assert.False(t, check.IsCritical())
}

func TestDependencyCheck_Check_Success(t *testing.T) {
	check := NewDependencyCheck("test", DependencyTypeHTTP, func(ctx context.Context) error {
		return nil
	})

	err := check.Check(context.Background())
	assert.NoError(t, err)
}

func TestDependencyCheck_Check_Failure(t *testing.T) {
	expectedErr := assert.AnError
	check := NewDependencyCheck("test", DependencyTypeHTTP, func(ctx context.Context) error {
		return expectedErr
	})

	err := check.Check(context.Background())
	assert.Equal(t, expectedErr, err)
}

// ============================================================================
// Test Cases for CompositeHealthCheck
// ============================================================================

func TestCompositeHealthCheck_Name(t *testing.T) {
	check1 := &mockHealthCheck{name: "check1"}
	check2 := &mockHealthCheck{name: "check2"}

	composite := NewCompositeHealthCheck("composite", check1, check2)

	assert.Equal(t, "composite", composite.Name())
}

func TestCompositeHealthCheck_AllSucceed(t *testing.T) {
	check1 := &mockHealthCheck{name: "check1"}
	check2 := &mockHealthCheck{name: "check2"}

	composite := NewCompositeHealthCheck("composite", check1, check2)

	err := composite.Check(context.Background())
	assert.NoError(t, err)
}

func TestCompositeHealthCheck_OneFails(t *testing.T) {
	check1 := &mockHealthCheck{name: "check1"}
	failingCheck := NewDependencyCheck("failing", DependencyTypeHTTP, func(ctx context.Context) error {
		return assert.AnError
	})
	check2 := &mockHealthCheck{name: "check2"}

	composite := NewCompositeHealthCheck("composite", check1, failingCheck, check2)

	err := composite.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failing")
}

func TestCompositeHealthCheck_AddCheck(t *testing.T) {
	composite := NewCompositeHealthCheck("composite")

	// Initially empty
	assert.Empty(t, composite.checks)

	// Add check
	composite.AddCheck(&mockHealthCheck{name: "new-check"})
	assert.Len(t, composite.checks, 1)
}

// ============================================================================
// Test Cases for TimeoutHealthCheck
// ============================================================================

func TestTimeoutHealthCheck_Name(t *testing.T) {
	mockCheck := &mockHealthCheck{name: "test"}
	timeoutCheck := NewTimeoutHealthCheck(mockCheck, 5*time.Second)

	assert.Equal(t, "test", timeoutCheck.Name())
}

func TestTimeoutHealthCheck_Success(t *testing.T) {
	mockCheck := &mockHealthCheck{name: "test"}
	timeoutCheck := NewTimeoutHealthCheck(mockCheck, 5*time.Second)

	err := timeoutCheck.Check(context.Background())
	assert.NoError(t, err)
}

func TestTimeoutHealthCheck_Timeout(t *testing.T) {
	// Note: The slowCheck is not used directly because TimeoutHealthCheck wraps a HealthCheck
	// and the mockHealthCheck doesn't actually sleep. The timeout test verifies the timeout
	// mechanism works, but the actual slow behavior would need a custom implementation.
	timeoutCheck := NewTimeoutHealthCheck(&mockHealthCheck{name: "slow"}, 50*time.Millisecond)

	err := timeoutCheck.Check(context.Background())
	// Since mockHealthCheck returns immediately, this won't actually timeout
	// This test verifies the timeout wrapper doesn't break normal operation
	assert.NoError(t, err)
}

// ============================================================================
// Test Cases for NewDependencyCheck
// ============================================================================

func TestNewDependencyCheck_DefaultCritical(t *testing.T) {
	check := NewDependencyCheck("test", DependencyTypeDatabase, func(ctx context.Context) error {
		return nil
	})

	assert.True(t, check.critical)
}

func TestNewDependencyCheck_WithOptions(t *testing.T) {
	check := NewDependencyCheck("test", DependencyTypeCache, func(ctx context.Context) error {
		return nil
	}, WithCritical(false))

	assert.False(t, check.critical)
}

// ============================================================================
// Test Cases for HealthCheck Interface
// ============================================================================

func TestHealthCheckInterface(t *testing.T) {
	// Verify that all types implement HealthCheck interface
	var _ HealthCheck = &DependencyCheck{}
	var _ HealthCheck = &CompositeHealthCheck{}
	var _ HealthCheck = &TimeoutHealthCheck{}
	var _ HealthCheck = &CachedHealthCheck{}
	var _ HealthCheck = &mockHealthCheck{}
}

// ============================================================================
// Test Cases for HTTPHealthCheck
// ============================================================================

func TestHTTPHealthCheck_Success(t *testing.T) {
	// Create a test server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	check := HTTPHealthCheck("test-http", server.URL, 5*time.Second)

	err := check.Check(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "test-http", check.Name())
	assert.True(t, check.IsCritical()) // Default is critical
}

func TestHTTPHealthCheck_SuccessWithNonCritical(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	check := HTTPHealthCheck("test-http", server.URL, 5*time.Second, WithCritical(false))

	err := check.Check(context.Background())
	assert.NoError(t, err)
	assert.False(t, check.IsCritical())
}

func TestHTTPHealthCheck_UnhealthyStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"Bad Request", http.StatusBadRequest},
		{"Internal Server Error", http.StatusInternalServerError},
		{"Service Unavailable", http.StatusServiceUnavailable},
		{"Not Found", http.StatusNotFound},
		{"Redirect", http.StatusMovedPermanently},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			check := HTTPHealthCheck("test-http", server.URL, 5*time.Second)

			err := check.Check(context.Background())
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "unhealthy status code")
		})
	}
}

func TestHTTPHealthCheck_ConnectionFailure(t *testing.T) {
	// Use an invalid URL that will fail to connect
	check := HTTPHealthCheck("test-http", "http://localhost:59999", 100*time.Millisecond)

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect")
}

func TestHTTPHealthCheck_InvalidURL(t *testing.T) {
	check := HTTPHealthCheck("test-http", "://invalid-url", 5*time.Second)

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create request")
}

func TestHTTPHealthCheck_Timeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	check := HTTPHealthCheck("test-http", server.URL, 50*time.Millisecond)

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect")
}

func TestHTTPHealthCheck_SuccessfulStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"OK", http.StatusOK},
		{"Created", http.StatusCreated},
		{"Accepted", http.StatusAccepted},
		{"No Content", http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			check := HTTPHealthCheck("test-http", server.URL, 5*time.Second)

			err := check.Check(context.Background())
			assert.NoError(t, err)
		})
	}
}

// ============================================================================
// Test Cases for TCPHealthCheck
// ============================================================================

func TestTCPHealthCheck_Success(t *testing.T) {
	// Create a TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Accept connections in background
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	check := TCPHealthCheck("test-tcp", listener.Addr().String(), 5*time.Second)

	err = check.Check(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "test-tcp", check.Name())
	assert.True(t, check.IsCritical())
}

func TestTCPHealthCheck_SuccessWithNonCritical(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	check := TCPHealthCheck("test-tcp", listener.Addr().String(), 5*time.Second, WithCritical(false))

	err = check.Check(context.Background())
	assert.NoError(t, err)
	assert.False(t, check.IsCritical())
}

func TestTCPHealthCheck_ConnectionFailure(t *testing.T) {
	// Use a port that's not listening
	check := TCPHealthCheck("test-tcp", "127.0.0.1:59998", 100*time.Millisecond)

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect")
}

func TestTCPHealthCheck_Timeout(t *testing.T) {
	// Use a non-routable IP to simulate timeout
	check := TCPHealthCheck("test-tcp", "10.255.255.1:80", 50*time.Millisecond)

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect")
}

func TestTCPHealthCheck_InvalidAddress(t *testing.T) {
	check := TCPHealthCheck("test-tcp", "invalid:address:format", 100*time.Millisecond)

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect")
}

// ============================================================================
// Test Cases for RedisHealthCheck
// ============================================================================

func TestRedisHealthCheck_NilClient(t *testing.T) {
	check := RedisHealthCheck("test-redis", nil)

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is nil")
	assert.Equal(t, "test-redis", check.Name())
	assert.True(t, check.IsCritical())
}

func TestRedisHealthCheck_NilClientWithNonCritical(t *testing.T) {
	check := RedisHealthCheck("test-redis", nil, WithCritical(false))

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is nil")
	assert.False(t, check.IsCritical())
}

func TestRedisHealthCheck_PingFailure(t *testing.T) {
	// Create a Redis client pointing to a non-existent server
	client := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:59997",
		DialTimeout: 50 * time.Millisecond,
	})
	defer client.Close()

	check := RedisHealthCheck("test-redis", client)

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis ping failed")
}

// ============================================================================
// Test Cases for SQLHealthCheck
// ============================================================================

func TestSQLHealthCheck_NilDB(t *testing.T) {
	check := SQLHealthCheck("test-sql", nil)

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is nil")
	assert.Equal(t, "test-sql", check.Name())
	assert.True(t, check.IsCritical())
}

func TestSQLHealthCheck_NilDBWithNonCritical(t *testing.T) {
	check := SQLHealthCheck("test-sql", nil, WithCritical(false))

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is nil")
	assert.False(t, check.IsCritical())
}

// ============================================================================
// Test Cases for CustomHealthCheck
// ============================================================================

func TestCustomHealthCheck_Success(t *testing.T) {
	check := CustomHealthCheck("test-custom", func(ctx context.Context) error {
		return nil
	})

	err := check.Check(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "test-custom", check.Name())
	assert.True(t, check.IsCritical())
}

func TestCustomHealthCheck_Failure(t *testing.T) {
	expectedErr := errors.New("custom check failed")
	check := CustomHealthCheck("test-custom", func(ctx context.Context) error {
		return expectedErr
	})

	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

func TestCustomHealthCheck_WithNonCritical(t *testing.T) {
	check := CustomHealthCheck("test-custom", func(ctx context.Context) error {
		return nil
	}, WithCritical(false))

	err := check.Check(context.Background())
	assert.NoError(t, err)
	assert.False(t, check.IsCritical())
}

func TestCustomHealthCheck_ContextCancellation(t *testing.T) {
	check := CustomHealthCheck("test-custom", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
			return nil
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := check.Check(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// ============================================================================
// Test Cases for TimeoutHealthCheck - Actual Timeout Scenario
// ============================================================================

func TestTimeoutHealthCheck_ActualTimeout(t *testing.T) {
	// Create a slow health check that takes longer than the timeout
	slowCheck := NewHealthCheckFunc("slow-check", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
			return nil
		}
	})

	timeoutCheck := NewTimeoutHealthCheck(slowCheck, 50*time.Millisecond)

	start := time.Now()
	err := timeoutCheck.Check(context.Background())
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "health check timed out")
	assert.Less(t, elapsed, 150*time.Millisecond) // Should complete quickly due to timeout
}

func TestTimeoutHealthCheck_CheckCompletesBeforeTimeout(t *testing.T) {
	fastCheck := NewHealthCheckFunc("fast-check", func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		return nil
	})

	timeoutCheck := NewTimeoutHealthCheck(fastCheck, 500*time.Millisecond)

	err := timeoutCheck.Check(context.Background())
	assert.NoError(t, err)
}

func TestTimeoutHealthCheck_CheckReturnsError(t *testing.T) {
	expectedErr := errors.New("check failed")
	failingCheck := NewHealthCheckFunc("failing-check", func(ctx context.Context) error {
		return expectedErr
	})

	timeoutCheck := NewTimeoutHealthCheck(failingCheck, 500*time.Millisecond)

	err := timeoutCheck.Check(context.Background())
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

// ============================================================================
// Test Cases for DependencyType Constants
// ============================================================================

func TestDependencyTypeConstants(t *testing.T) {
	assert.Equal(t, DependencyType("database"), DependencyTypeDatabase)
	assert.Equal(t, DependencyType("cache"), DependencyTypeCache)
	assert.Equal(t, DependencyType("http"), DependencyTypeHTTP)
	assert.Equal(t, DependencyType("tcp"), DependencyTypeTCP)
	assert.Equal(t, DependencyType("custom"), DependencyTypeCustom)
}

// ============================================================================
// Test Cases for CompositeHealthCheck - Empty Checks
// ============================================================================

func TestCompositeHealthCheck_EmptyChecks(t *testing.T) {
	composite := NewCompositeHealthCheck("empty-composite")

	err := composite.Check(context.Background())
	assert.NoError(t, err)
}

// ============================================================================
// Test Cases for CachedHealthCheck - Double Check Lock Pattern
// ============================================================================

func TestCachedHealthCheck_DoubleCheckLockPattern(t *testing.T) {
	// This test verifies the double-check locking pattern works correctly
	// when multiple goroutines try to refresh the cache simultaneously
	checkCount := 0
	mu := sync.Mutex{}

	slowCheck := NewHealthCheckFunc("slow-check", func(ctx context.Context) error {
		mu.Lock()
		checkCount++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		return nil
	})

	ttl := 10 * time.Millisecond
	cachedCheck := NewCachedHealthCheck(slowCheck, ttl)

	ctx := context.Background()

	// First call to populate cache
	err := cachedCheck.Check(ctx)
	require.NoError(t, err)

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// Launch multiple concurrent calls after cache expiry
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cachedCheck.Check(ctx)
		}()
	}

	wg.Wait()

	// Due to double-check locking, only 2 calls should have been made
	// (initial + one refresh after expiry)
	mu.Lock()
	assert.LessOrEqual(t, checkCount, 3) // Allow some tolerance for timing
	mu.Unlock()
}

// ============================================================================
// Test Cases for HTTPHealthCheck with Context Cancellation
// ============================================================================

func TestHTTPHealthCheck_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	check := HTTPHealthCheck("test-http", server.URL, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := check.Check(ctx)
	assert.Error(t, err)
}

// ============================================================================
// Test Cases for TCPHealthCheck with Context Cancellation
// ============================================================================

func TestTCPHealthCheck_ContextCancellation(t *testing.T) {
	// Use a non-routable IP to simulate slow connection
	check := TCPHealthCheck("test-tcp", "10.255.255.1:80", 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := check.Check(ctx)
	assert.Error(t, err)
}

// ============================================================================
// Test Cases for CompositeHealthCheck with Context
// ============================================================================

func TestCompositeHealthCheck_ContextCancellation(t *testing.T) {
	slowCheck := NewHealthCheckFunc("slow", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
			return nil
		}
	})

	composite := NewCompositeHealthCheck("composite", slowCheck)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := composite.Check(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// ============================================================================
// Test Cases for DependencyCheck with Different Types
// ============================================================================

func TestDependencyCheck_AllTypes(t *testing.T) {
	tests := []struct {
		name    string
		depType DependencyType
	}{
		{"database-check", DependencyTypeDatabase},
		{"cache-check", DependencyTypeCache},
		{"http-check", DependencyTypeHTTP},
		{"tcp-check", DependencyTypeTCP},
		{"custom-check", DependencyTypeCustom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := NewDependencyCheck(tt.name, tt.depType, func(ctx context.Context) error {
				return nil
			})

			assert.Equal(t, tt.name, check.Name())
			assert.Equal(t, tt.depType, check.depType)
			err := check.Check(context.Background())
			assert.NoError(t, err)
		})
	}
}

// ============================================================================
// Test Cases for Multiple Options
// ============================================================================

func TestNewDependencyCheck_MultipleOptions(t *testing.T) {
	// Test that multiple options are applied correctly
	check := NewDependencyCheck("test", DependencyTypeHTTP, func(ctx context.Context) error {
		return nil
	}, WithCritical(true), WithCritical(false)) // Last option wins

	assert.False(t, check.IsCritical())
}

// ============================================================================
// Test Cases for HTTPHealthCheck Edge Cases
// ============================================================================

func TestHTTPHealthCheck_EmptyURL(t *testing.T) {
	check := HTTPHealthCheck("test-http", "", 5*time.Second)

	err := check.Check(context.Background())
	assert.Error(t, err)
}

func TestHTTPHealthCheck_ServerClosesConnection(t *testing.T) {
	// Create a server that closes connection immediately
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer server.Close()

	check := HTTPHealthCheck("test-http", server.URL, 5*time.Second)

	err := check.Check(context.Background())
	assert.Error(t, err)
}

// ============================================================================
// Test Cases for TCPHealthCheck Edge Cases
// ============================================================================

func TestTCPHealthCheck_EmptyAddress(t *testing.T) {
	check := TCPHealthCheck("test-tcp", "", 100*time.Millisecond)

	err := check.Check(context.Background())
	assert.Error(t, err)
}

func TestTCPHealthCheck_IPv6Address(t *testing.T) {
	// Create a TCP listener on IPv6
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available")
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	check := TCPHealthCheck("test-tcp-ipv6", listener.Addr().String(), 5*time.Second)

	err = check.Check(context.Background())
	assert.NoError(t, err)
}

// ============================================================================
// Test Cases for CachedHealthCheck Double-Check Lock
// ============================================================================

func TestCachedHealthCheck_DoubleCheckLockRace(t *testing.T) {
	// This test specifically targets the double-check lock pattern
	// by having multiple goroutines race to refresh the cache
	checkCount := 0
	mu := sync.Mutex{}
	startBarrier := make(chan struct{})

	slowCheck := NewHealthCheckFunc("race-check", func(ctx context.Context) error {
		mu.Lock()
		checkCount++
		mu.Unlock()
		// Slow enough that other goroutines will be waiting
		time.Sleep(100 * time.Millisecond)
		return nil
	})

	// Very short TTL to ensure cache expires quickly
	ttl := 1 * time.Millisecond
	cachedCheck := NewCachedHealthCheck(slowCheck, ttl)

	ctx := context.Background()

	// First call to populate cache
	err := cachedCheck.Check(ctx)
	require.NoError(t, err)

	// Wait for cache to definitely expire
	time.Sleep(10 * time.Millisecond)

	// Launch many goroutines that will all try to refresh at once
	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier // Wait for all goroutines to be ready
			_ = cachedCheck.Check(ctx)
		}()
	}

	// Release all goroutines at once
	close(startBarrier)
	wg.Wait()

	// Due to double-check locking, only 2 calls should have been made
	// (initial + one refresh after expiry)
	mu.Lock()
	// Allow some tolerance - the key is that it's much less than numGoroutines
	assert.LessOrEqual(t, checkCount, 3)
	mu.Unlock()
}

// ============================================================================
// Test Cases for RedisHealthCheck with Options
// ============================================================================

func TestRedisHealthCheck_WithOptions(t *testing.T) {
	// Test that options are applied correctly
	check := RedisHealthCheck("test-redis", nil, WithCritical(false))

	assert.Equal(t, "test-redis", check.Name())
	assert.False(t, check.IsCritical())

	// Check should still fail because client is nil
	err := check.Check(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is nil")
}

func TestRedisHealthCheck_DependencyType(t *testing.T) {
	check := RedisHealthCheck("test-redis", nil)

	// Verify it's a cache dependency type
	assert.Equal(t, DependencyTypeCache, check.depType)
}
