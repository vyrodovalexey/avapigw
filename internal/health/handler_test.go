package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

// ============================================================================
// Test Cases for NewHandler/NewHandlerWithConfig
// ============================================================================

func TestNewHandler_CreatesHandlerWithDefaultConfig(t *testing.T) {
	logger := newTestLogger()

	handler := NewHandler(logger)

	require.NotNil(t, handler)
	assert.NotNil(t, handler.logger)
	assert.NotNil(t, handler.config)
	assert.Equal(t, DefaultReadinessProbeTimeout, handler.config.ReadinessProbeTimeout)
	assert.Equal(t, DefaultLivenessProbeTimeout, handler.config.LivenessProbeTimeout)
	assert.Empty(t, handler.checks)
}

func TestNewHandlerWithConfig_CreatesHandlerWithCustomConfig(t *testing.T) {
	logger := newTestLogger()
	config := &HandlerConfig{
		ReadinessProbeTimeout: 10 * time.Second,
		LivenessProbeTimeout:  20 * time.Second,
	}

	handler := NewHandlerWithConfig(logger, config)

	require.NotNil(t, handler)
	assert.Equal(t, 10*time.Second, handler.config.ReadinessProbeTimeout)
	assert.Equal(t, 20*time.Second, handler.config.LivenessProbeTimeout)
}

func TestNewHandlerWithConfig_NilConfigUsesDefaults(t *testing.T) {
	logger := newTestLogger()

	handler := NewHandlerWithConfig(logger, nil)

	require.NotNil(t, handler)
	assert.Equal(t, DefaultReadinessProbeTimeout, handler.config.ReadinessProbeTimeout)
	assert.Equal(t, DefaultLivenessProbeTimeout, handler.config.LivenessProbeTimeout)
}

// ============================================================================
// Test Cases for Handler.SetConfig/GetConfig
// ============================================================================

func TestHandler_SetConfig(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	newConfig := &HandlerConfig{
		ReadinessProbeTimeout: 15 * time.Second,
		LivenessProbeTimeout:  25 * time.Second,
	}

	handler.SetConfig(newConfig)

	assert.Equal(t, 15*time.Second, handler.config.ReadinessProbeTimeout)
	assert.Equal(t, 25*time.Second, handler.config.LivenessProbeTimeout)
}

func TestHandler_SetConfig_NilConfigIsIgnored(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)
	originalConfig := handler.config

	handler.SetConfig(nil)

	assert.Equal(t, originalConfig, handler.config)
}

func TestHandler_GetConfig(t *testing.T) {
	logger := newTestLogger()
	config := &HandlerConfig{
		ReadinessProbeTimeout: 12 * time.Second,
		LivenessProbeTimeout:  22 * time.Second,
	}
	handler := NewHandlerWithConfig(logger, config)

	result := handler.GetConfig()

	assert.Equal(t, config, result)
}

// ============================================================================
// Test Cases for Handler.AddCheck/RemoveCheck
// ============================================================================

func TestHandler_AddCheck(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check := NewHealthCheckFunc("test-check", func(ctx context.Context) error {
		return nil
	})

	handler.AddCheck(check)

	assert.Len(t, handler.checks, 1)
	assert.Equal(t, "test-check", handler.checks[0].Name())
}

func TestHandler_AddCheck_MultipleChecks(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check1 := NewHealthCheckFunc("check1", func(ctx context.Context) error { return nil })
	check2 := NewHealthCheckFunc("check2", func(ctx context.Context) error { return nil })
	check3 := NewHealthCheckFunc("check3", func(ctx context.Context) error { return nil })

	handler.AddCheck(check1)
	handler.AddCheck(check2)
	handler.AddCheck(check3)

	assert.Len(t, handler.checks, 3)
}

func TestHandler_RemoveCheck(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check1 := NewHealthCheckFunc("check1", func(ctx context.Context) error { return nil })
	check2 := NewHealthCheckFunc("check2", func(ctx context.Context) error { return nil })

	handler.AddCheck(check1)
	handler.AddCheck(check2)
	assert.Len(t, handler.checks, 2)

	handler.RemoveCheck("check1")

	assert.Len(t, handler.checks, 1)
	assert.Equal(t, "check2", handler.checks[0].Name())
}

func TestHandler_RemoveCheck_NonExistentCheck(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check := NewHealthCheckFunc("existing", func(ctx context.Context) error { return nil })
	handler.AddCheck(check)

	// Should not panic or error when removing non-existent check
	handler.RemoveCheck("non-existent")

	assert.Len(t, handler.checks, 1)
}

func TestHandler_RemoveCheck_EmptyChecks(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	// Should not panic when removing from empty checks
	handler.RemoveCheck("any")

	assert.Empty(t, handler.checks)
}

// ============================================================================
// Test Cases for Handler.LivenessHandler
// ============================================================================

func TestHandler_LivenessHandler_Returns200OK(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/livez", handler.LivenessHandler())

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_LivenessHandler_ResponseContainsStatusAndTimestamp(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/livez", handler.LivenessHandler())

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "ok", response["status"])
	assert.NotEmpty(t, response["timestamp"])
}

// ============================================================================
// Test Cases for Handler.ReadinessHandler
// ============================================================================

func TestHandler_ReadinessHandler_Returns200WhenAllChecksPass(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check1 := NewHealthCheckFunc("check1", func(ctx context.Context) error { return nil })
	check2 := NewHealthCheckFunc("check2", func(ctx context.Context) error { return nil })
	handler.AddCheck(check1)
	handler.AddCheck(check2)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/readyz", handler.ReadinessHandler())

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response HealthStatus
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "ok", response.Status)
}

func TestHandler_ReadinessHandler_Returns503WhenAnyCheckFails(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check1 := NewHealthCheckFunc("check1", func(ctx context.Context) error { return nil })
	check2 := NewHealthCheckFunc("check2", func(ctx context.Context) error {
		return errors.New("check failed")
	})
	handler.AddCheck(check1)
	handler.AddCheck(check2)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/readyz", handler.ReadinessHandler())

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var response HealthStatus
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "error", response.Status)
}

func TestHandler_ReadinessHandler_RespectsTimeout(t *testing.T) {
	logger := newTestLogger()
	config := &HandlerConfig{
		ReadinessProbeTimeout: 50 * time.Millisecond,
		LivenessProbeTimeout:  10 * time.Second,
	}
	handler := NewHandlerWithConfig(logger, config)

	// Add a slow check that respects context cancellation
	slowCheck := NewHealthCheckFunc("slow", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
			return nil
		}
	})
	handler.AddCheck(slowCheck)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/readyz", handler.ReadinessHandler())

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	start := time.Now()
	router.ServeHTTP(w, req)
	elapsed := time.Since(start)

	// Should complete within timeout + some buffer
	assert.Less(t, elapsed, 150*time.Millisecond)
}

func TestHandler_ReadinessHandler_NoChecks(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/readyz", handler.ReadinessHandler())

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response HealthStatus
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "ok", response.Status)
}

// ============================================================================
// Test Cases for Handler.HealthHandler
// ============================================================================

func TestHandler_HealthHandler_Returns200WhenAllChecksPass(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check := NewHealthCheckFunc("check", func(ctx context.Context) error { return nil })
	handler.AddCheck(check)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", handler.HealthHandler())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_HealthHandler_Returns503WhenAnyCheckFails(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check := NewHealthCheckFunc("failing", func(ctx context.Context) error {
		return errors.New("service unavailable")
	})
	handler.AddCheck(check)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", handler.HealthHandler())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandler_HealthHandler_IncludesUptimeInResponse(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", handler.HealthHandler())

	// Wait a bit to have measurable uptime
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var response HealthStatus
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.Uptime)
}

func TestHandler_HealthHandler_IncludesCheckDetails(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check1 := NewHealthCheckFunc("database", func(ctx context.Context) error { return nil })
	check2 := NewHealthCheckFunc("cache", func(ctx context.Context) error { return nil })
	handler.AddCheck(check1)
	handler.AddCheck(check2)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", handler.HealthHandler())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var response HealthStatus
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Len(t, response.Checks, 2)
	assert.Contains(t, response.Checks, "database")
	assert.Contains(t, response.Checks, "cache")
}

// ============================================================================
// Test Cases for Handler.HTTPHandler
// ============================================================================

func TestHandler_HTTPHandler_ReturnsCorrectStatusCodes(t *testing.T) {
	tests := []struct {
		name           string
		checkError     error
		expectedStatus int
	}{
		{
			name:           "All checks pass",
			checkError:     nil,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Check fails",
			checkError:     errors.New("check failed"),
			expectedStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := newTestLogger()
			handler := NewHandler(logger)

			check := NewHealthCheckFunc("test", func(ctx context.Context) error {
				return tt.checkError
			})
			handler.AddCheck(check)

			httpHandler := handler.HTTPHandler()

			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			w := httptest.NewRecorder()

			httpHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestHandler_HTTPHandler_StandardHTTPHandlerInterface(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	httpHandler := handler.HTTPHandler()

	// Verify it implements http.Handler
	var _ http.Handler = httpHandler

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	httpHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestHandler_HTTPHandler_IncludesUptime(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	httpHandler := handler.HTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	httpHandler.ServeHTTP(w, req)

	var response HealthStatus
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.Uptime)
}

// ============================================================================
// Test Cases for Handler.LivenessHTTPHandler
// ============================================================================

func TestHandler_LivenessHTTPHandler_Returns200OK(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	httpHandler := handler.LivenessHTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	w := httptest.NewRecorder()

	httpHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_LivenessHTTPHandler_ResponseIsJSON(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	httpHandler := handler.LivenessHTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	w := httptest.NewRecorder()

	httpHandler.ServeHTTP(w, req)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "ok", response["status"])
	assert.NotEmpty(t, response["timestamp"])
}

// ============================================================================
// Test Cases for Handler.ReadinessHTTPHandler
// ============================================================================

func TestHandler_ReadinessHTTPHandler_ReturnsCorrectStatusBasedOnChecks(t *testing.T) {
	tests := []struct {
		name           string
		checkError     error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "All checks pass",
			checkError:     nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
		},
		{
			name:           "Check fails",
			checkError:     errors.New("check failed"),
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := newTestLogger()
			handler := NewHandler(logger)

			check := NewHealthCheckFunc("test", func(ctx context.Context) error {
				return tt.checkError
			})
			handler.AddCheck(check)

			httpHandler := handler.ReadinessHTTPHandler()

			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			w := httptest.NewRecorder()

			httpHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response HealthStatus
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response.Status)
		})
	}
}

func TestHandler_ReadinessHTTPHandler_ResponseIsJSON(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	httpHandler := handler.ReadinessHTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	httpHandler.ServeHTTP(w, req)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// ============================================================================
// Test Cases for Handler.runChecks
// ============================================================================

func TestHandler_runChecks_RunsAllChecksConcurrently(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	var mu sync.Mutex
	checkOrder := make([]string, 0)

	check1 := NewHealthCheckFunc("check1", func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		checkOrder = append(checkOrder, "check1")
		mu.Unlock()
		return nil
	})
	check2 := NewHealthCheckFunc("check2", func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		checkOrder = append(checkOrder, "check2")
		mu.Unlock()
		return nil
	})
	check3 := NewHealthCheckFunc("check3", func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		checkOrder = append(checkOrder, "check3")
		mu.Unlock()
		return nil
	})

	handler.AddCheck(check1)
	handler.AddCheck(check2)
	handler.AddCheck(check3)

	start := time.Now()
	status := handler.runChecks(context.Background())
	elapsed := time.Since(start)

	// If running concurrently, should complete in ~10ms, not ~30ms
	assert.Less(t, elapsed, 25*time.Millisecond)
	assert.Equal(t, "ok", status.Status)
	assert.Len(t, status.Checks, 3)
}

func TestHandler_runChecks_AggregatesResultsCorrectly(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check1 := NewHealthCheckFunc("passing", func(ctx context.Context) error { return nil })
	check2 := NewHealthCheckFunc("failing", func(ctx context.Context) error {
		return errors.New("service down")
	})

	handler.AddCheck(check1)
	handler.AddCheck(check2)

	status := handler.runChecks(context.Background())

	assert.Equal(t, "error", status.Status)
	assert.Len(t, status.Checks, 2)

	assert.Equal(t, "ok", status.Checks["passing"].Status)
	assert.Equal(t, "error", status.Checks["failing"].Status)
	assert.Equal(t, "service down", status.Checks["failing"].Error)
}

func TestHandler_runChecks_HandlesCheckErrors(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	expectedError := errors.New("database connection failed")
	check := NewHealthCheckFunc("database", func(ctx context.Context) error {
		return expectedError
	})

	handler.AddCheck(check)

	status := handler.runChecks(context.Background())

	assert.Equal(t, "error", status.Status)
	assert.Equal(t, "error", status.Checks["database"].Status)
	assert.Equal(t, expectedError.Error(), status.Checks["database"].Error)
}

func TestHandler_runChecks_NoChecks(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	status := handler.runChecks(context.Background())

	assert.Equal(t, "ok", status.Status)
	assert.Empty(t, status.Checks)
}

func TestHandler_runChecks_IncludesDuration(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check := NewHealthCheckFunc("slow", func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		return nil
	})

	handler.AddCheck(check)

	status := handler.runChecks(context.Background())

	assert.NotEmpty(t, status.Checks["slow"].Duration)
}

// ============================================================================
// Test Cases for HealthCheckFunc
// ============================================================================

func TestHealthCheckFunc_Name(t *testing.T) {
	check := NewHealthCheckFunc("my-check", func(ctx context.Context) error {
		return nil
	})

	assert.Equal(t, "my-check", check.Name())
}

func TestHealthCheckFunc_Check(t *testing.T) {
	expectedError := errors.New("check error")
	check := NewHealthCheckFunc("test", func(ctx context.Context) error {
		return expectedError
	})

	err := check.Check(context.Background())

	assert.Equal(t, expectedError, err)
}

func TestHealthCheckFunc_CheckSuccess(t *testing.T) {
	check := NewHealthCheckFunc("test", func(ctx context.Context) error {
		return nil
	})

	err := check.Check(context.Background())

	assert.NoError(t, err)
}

// ============================================================================
// Test Cases for NewHealthCheckFunc
// ============================================================================

func TestNewHealthCheckFunc_CreatesHealthCheckWithNameAndFunction(t *testing.T) {
	called := false
	check := NewHealthCheckFunc("custom-check", func(ctx context.Context) error {
		called = true
		return nil
	})

	assert.Equal(t, "custom-check", check.Name())

	err := check.Check(context.Background())
	assert.NoError(t, err)
	assert.True(t, called)
}

// ============================================================================
// Test Cases for DefaultHandlerConfig
// ============================================================================

func TestDefaultHandlerConfig(t *testing.T) {
	config := DefaultHandlerConfig()

	assert.Equal(t, DefaultReadinessProbeTimeout, config.ReadinessProbeTimeout)
	assert.Equal(t, DefaultLivenessProbeTimeout, config.LivenessProbeTimeout)
}

// ============================================================================
// Test Cases for getReadinessTimeout/getLivenessTimeout
// ============================================================================

func TestHandler_getReadinessTimeout_ReturnsConfiguredTimeout(t *testing.T) {
	logger := newTestLogger()
	config := &HandlerConfig{
		ReadinessProbeTimeout: 15 * time.Second,
		LivenessProbeTimeout:  25 * time.Second,
	}
	handler := NewHandlerWithConfig(logger, config)

	timeout := handler.getReadinessTimeout()

	assert.Equal(t, 15*time.Second, timeout)
}

func TestHandler_getReadinessTimeout_ReturnsDefaultWhenZero(t *testing.T) {
	logger := newTestLogger()
	config := &HandlerConfig{
		ReadinessProbeTimeout: 0,
		LivenessProbeTimeout:  25 * time.Second,
	}
	handler := NewHandlerWithConfig(logger, config)

	timeout := handler.getReadinessTimeout()

	assert.Equal(t, DefaultReadinessProbeTimeout, timeout)
}

func TestHandler_getLivenessTimeout_ReturnsConfiguredTimeout(t *testing.T) {
	logger := newTestLogger()
	config := &HandlerConfig{
		ReadinessProbeTimeout: 15 * time.Second,
		LivenessProbeTimeout:  25 * time.Second,
	}
	handler := NewHandlerWithConfig(logger, config)

	timeout := handler.getLivenessTimeout()

	assert.Equal(t, 25*time.Second, timeout)
}

func TestHandler_getLivenessTimeout_ReturnsDefaultWhenZero(t *testing.T) {
	logger := newTestLogger()
	config := &HandlerConfig{
		ReadinessProbeTimeout: 15 * time.Second,
		LivenessProbeTimeout:  0,
	}
	handler := NewHandlerWithConfig(logger, config)

	timeout := handler.getLivenessTimeout()

	assert.Equal(t, DefaultLivenessProbeTimeout, timeout)
}

// ============================================================================
// Test Cases for RegisterRoutes
// ============================================================================

func TestHandler_RegisterRoutes(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	routes := []string{"/health", "/healthz", "/livez", "/readyz", "/ready"}

	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

// ============================================================================
// Test Cases for RegisterRoutesOnGroup
// ============================================================================

func TestHandler_RegisterRoutesOnGroup(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	group := router.Group("/api/v1")
	handler.RegisterRoutesOnGroup(group)

	routes := []string{"/api/v1/health", "/api/v1/healthz", "/api/v1/livez", "/api/v1/readyz", "/api/v1/ready"}

	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

// ============================================================================
// Test Cases for Concurrent Access
// ============================================================================

func TestHandler_ConcurrentAddRemoveCheck(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	var wg sync.WaitGroup

	// Concurrent adds
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			check := NewHealthCheckFunc("check-"+string(rune('a'+idx)), func(ctx context.Context) error {
				return nil
			})
			handler.AddCheck(check)
		}(i)
	}

	wg.Wait()

	// Concurrent removes
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			handler.RemoveCheck("check-" + string(rune('a'+idx)))
		}(i)
	}

	wg.Wait()
}

func TestHandler_ConcurrentRunChecks(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check := NewHealthCheckFunc("test", func(ctx context.Context) error {
		return nil
	})
	handler.AddCheck(check)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status := handler.runChecks(context.Background())
			assert.Equal(t, "ok", status.Status)
		}()
	}

	wg.Wait()
}

func TestHandler_ConcurrentConfigAccess(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = handler.GetConfig()
		}()
	}

	// Concurrent writes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler.SetConfig(&HandlerConfig{
				ReadinessProbeTimeout: 10 * time.Second,
				LivenessProbeTimeout:  20 * time.Second,
			})
		}()
	}

	wg.Wait()
}

// ============================================================================
// Test Cases for HealthCheck Interface Compliance
// ============================================================================

func TestHealthCheckFuncImplementsInterface(t *testing.T) {
	// Verify HealthCheckFunc implements HealthCheck interface
	var _ HealthCheck = &HealthCheckFunc{}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestHandler_CheckWithContextCancellation(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check := NewHealthCheckFunc("cancellable", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
			return nil
		}
	})
	handler.AddCheck(check)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	status := handler.runChecks(ctx)

	// Check should have been cancelled
	assert.Equal(t, "error", status.Status)
}

func TestHandler_MultipleFailingChecks(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check1 := NewHealthCheckFunc("fail1", func(ctx context.Context) error {
		return errors.New("error 1")
	})
	check2 := NewHealthCheckFunc("fail2", func(ctx context.Context) error {
		return errors.New("error 2")
	})
	check3 := NewHealthCheckFunc("pass", func(ctx context.Context) error {
		return nil
	})

	handler.AddCheck(check1)
	handler.AddCheck(check2)
	handler.AddCheck(check3)

	status := handler.runChecks(context.Background())

	assert.Equal(t, "error", status.Status)
	assert.Equal(t, "error", status.Checks["fail1"].Status)
	assert.Equal(t, "error", status.Checks["fail2"].Status)
	assert.Equal(t, "ok", status.Checks["pass"].Status)
}

func TestHandler_CheckResultTimestamp(t *testing.T) {
	logger := newTestLogger()
	handler := NewHandler(logger)

	check := NewHealthCheckFunc("test", func(ctx context.Context) error {
		return nil
	})
	handler.AddCheck(check)

	before := time.Now().UTC()
	status := handler.runChecks(context.Background())
	after := time.Now().UTC()

	// Status timestamp should be between before and after
	assert.True(t, status.Timestamp.After(before) || status.Timestamp.Equal(before))
	assert.True(t, status.Timestamp.Before(after) || status.Timestamp.Equal(after))

	// Check result timestamp should also be valid
	checkResult := status.Checks["test"]
	assert.True(t, checkResult.Timestamp.After(before) || checkResult.Timestamp.Equal(before))
	assert.True(t, checkResult.Timestamp.Before(after) || checkResult.Timestamp.Equal(after))
}
