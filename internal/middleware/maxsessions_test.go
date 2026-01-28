package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewMaxSessionsLimiter(t *testing.T) {
	tests := []struct {
		name          string
		maxConcurrent int
		queueSize     int
		queueTimeout  time.Duration
	}{
		{
			name:          "basic limiter",
			maxConcurrent: 10,
			queueSize:     0,
			queueTimeout:  0,
		},
		{
			name:          "limiter with queue",
			maxConcurrent: 5,
			queueSize:     10,
			queueTimeout:  time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msl := NewMaxSessionsLimiter(tt.maxConcurrent, tt.queueSize, tt.queueTimeout)
			if msl == nil {
				t.Fatal("expected non-nil limiter")
			}
			if msl.MaxConcurrent() != int64(tt.maxConcurrent) {
				t.Errorf("expected maxConcurrent %d, got %d", tt.maxConcurrent, msl.MaxConcurrent())
			}
			if msl.Current() != 0 {
				t.Errorf("expected current 0, got %d", msl.Current())
			}
		})
	}
}

func TestMaxSessionsLimiter_Acquire_Release(t *testing.T) {
	msl := NewMaxSessionsLimiter(2, 0, 0)
	ctx := context.Background()

	// First acquire should succeed
	if !msl.Acquire(ctx) {
		t.Error("first acquire should succeed")
	}
	if msl.Current() != 1 {
		t.Errorf("expected current 1, got %d", msl.Current())
	}

	// Second acquire should succeed
	if !msl.Acquire(ctx) {
		t.Error("second acquire should succeed")
	}
	if msl.Current() != 2 {
		t.Errorf("expected current 2, got %d", msl.Current())
	}

	// Third acquire should fail (no queue)
	if msl.Acquire(ctx) {
		t.Error("third acquire should fail")
	}

	// Release one
	msl.Release()
	if msl.Current() != 1 {
		t.Errorf("expected current 1 after release, got %d", msl.Current())
	}

	// Now acquire should succeed again
	if !msl.Acquire(ctx) {
		t.Error("acquire after release should succeed")
	}
}

func TestMaxSessionsLimiter_WithQueue(t *testing.T) {
	msl := NewMaxSessionsLimiter(1, 5, 100*time.Millisecond)
	ctx := context.Background()

	// Acquire the only slot
	if !msl.Acquire(ctx) {
		t.Fatal("first acquire should succeed")
	}

	// Start a goroutine that will release after a short delay
	go func() {
		time.Sleep(20 * time.Millisecond)
		msl.Release()
	}()

	// This should wait in queue and succeed
	if !msl.Acquire(ctx) {
		t.Error("queued acquire should succeed after release")
	}

	msl.Release()
}

func TestMaxSessionsLimiter_QueueTimeout(t *testing.T) {
	msl := NewMaxSessionsLimiter(1, 5, 50*time.Millisecond)
	ctx := context.Background()

	// Acquire the only slot
	if !msl.Acquire(ctx) {
		t.Fatal("first acquire should succeed")
	}

	// This should timeout waiting in queue
	start := time.Now()
	if msl.Acquire(ctx) {
		t.Error("queued acquire should timeout")
	}
	elapsed := time.Since(start)

	// Should have waited approximately the queue timeout
	if elapsed < 40*time.Millisecond {
		t.Errorf("expected to wait at least 40ms, waited %v", elapsed)
	}

	msl.Release()
}

func TestMaxSessionsLimiter_QueueFull(t *testing.T) {
	msl := NewMaxSessionsLimiter(1, 2, time.Second)
	ctx := context.Background()

	// Acquire the only slot
	if !msl.Acquire(ctx) {
		t.Fatal("first acquire should succeed")
	}

	// Fill the queue with waiting goroutines
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msl.Acquire(ctx)
		}()
	}

	// Give goroutines time to enter queue
	time.Sleep(10 * time.Millisecond)

	// Queue should be full, this should fail immediately
	if msl.Acquire(ctx) {
		t.Error("acquire with full queue should fail immediately")
	}

	// Release to let queued goroutines complete
	msl.Release()
	time.Sleep(20 * time.Millisecond)
	msl.Release()
	msl.Release()

	wg.Wait()
}

func TestMaxSessionsLimiter_Concurrent(t *testing.T) {
	maxConcurrent := 5
	msl := NewMaxSessionsLimiter(maxConcurrent, 0, 0)
	ctx := context.Background()

	var wg sync.WaitGroup
	var maxObserved atomic.Int64
	var successCount atomic.Int64

	// Start many goroutines trying to acquire
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if msl.Acquire(ctx) {
				successCount.Add(1)
				current := msl.Current()
				for {
					old := maxObserved.Load()
					if current <= old || maxObserved.CompareAndSwap(old, current) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				msl.Release()
			}
		}()
	}

	wg.Wait()

	if maxObserved.Load() > int64(maxConcurrent) {
		t.Errorf("max observed %d exceeded limit %d", maxObserved.Load(), maxConcurrent)
	}

	if msl.Current() != 0 {
		t.Errorf("expected current 0 after all releases, got %d", msl.Current())
	}
}

func TestMaxSessionsLimiter_Stop(t *testing.T) {
	msl := NewMaxSessionsLimiter(1, 5, time.Second)
	ctx := context.Background()

	// Acquire the only slot
	if !msl.Acquire(ctx) {
		t.Fatal("first acquire should succeed")
	}

	// Start a goroutine waiting in queue
	done := make(chan bool)
	go func() {
		result := msl.Acquire(ctx)
		done <- result
	}()

	// Give goroutine time to enter queue
	time.Sleep(10 * time.Millisecond)

	// Stop the limiter
	msl.Stop()

	// Waiting goroutine should return false
	select {
	case result := <-done:
		if result {
			t.Error("acquire should fail after stop")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("waiting goroutine should have returned")
	}
}

func TestMaxSessions_Middleware(t *testing.T) {
	msl := NewMaxSessionsLimiter(2, 0, 0, WithMaxSessionsLogger(observability.NopLogger()))

	handler := MaxSessions(msl)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))

	// First two requests should succeed
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rec.Code)
			}
		}()
	}

	// Give first requests time to start
	time.Sleep(5 * time.Millisecond)

	// Third request should be rejected
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}

	wg.Wait()
}

func TestMaxSessionsFromConfig(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.MaxSessionsConfig
		expectLimiter  bool
		expectPassthru bool
	}{
		{
			name:           "nil config",
			cfg:            nil,
			expectLimiter:  false,
			expectPassthru: true,
		},
		{
			name: "disabled config",
			cfg: &config.MaxSessionsConfig{
				Enabled:       false,
				MaxConcurrent: 10,
			},
			expectLimiter:  false,
			expectPassthru: true,
		},
		{
			name: "enabled config",
			cfg: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 10,
				QueueSize:     5,
				QueueTimeout:  config.Duration(time.Second),
			},
			expectLimiter:  true,
			expectPassthru: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, limiter := MaxSessionsFromConfig(tt.cfg, observability.NopLogger())

			if tt.expectLimiter && limiter == nil {
				t.Error("expected limiter to be non-nil")
			}
			if !tt.expectLimiter && limiter != nil {
				t.Error("expected limiter to be nil")
			}

			if middleware == nil {
				t.Fatal("middleware should never be nil")
			}

			// Test that middleware works
			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rec.Code)
			}

			if limiter != nil {
				limiter.Stop()
			}
		})
	}
}

func TestMaxSessionsLimiter_QueueLength(t *testing.T) {
	msl := NewMaxSessionsLimiter(1, 5, time.Second)
	ctx := context.Background()

	// Initially queue should be empty
	if msl.QueueLength() != 0 {
		t.Errorf("expected queue length 0, got %d", msl.QueueLength())
	}

	// Acquire the only slot
	if !msl.Acquire(ctx) {
		t.Fatal("first acquire should succeed")
	}

	// Start goroutines that will wait in queue
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msl.Acquire(ctx)
			msl.Release()
		}()
	}

	// Give goroutines time to enter queue
	time.Sleep(20 * time.Millisecond)

	queueLen := msl.QueueLength()
	if queueLen != 3 {
		t.Errorf("expected queue length 3, got %d", queueLen)
	}

	// Release to let queued goroutines complete
	msl.Release()
	wg.Wait()
}

func TestMaxSessionsLimiter_QueueLength_NoQueue(t *testing.T) {
	msl := NewMaxSessionsLimiter(10, 0, 0)

	// Queue length should be 0 when no queue is configured
	if msl.QueueLength() != 0 {
		t.Errorf("expected queue length 0, got %d", msl.QueueLength())
	}
}

func TestMaxSessionsLimiter_ContextCancellation(t *testing.T) {
	msl := NewMaxSessionsLimiter(1, 5, time.Second)

	// Acquire the only slot
	ctx := context.Background()
	if !msl.Acquire(ctx) {
		t.Fatal("first acquire should succeed")
	}

	// Create a context that will be cancelled
	cancelCtx, cancel := context.WithCancel(context.Background())

	// Start a goroutine waiting in queue
	done := make(chan bool)
	go func() {
		result := msl.Acquire(cancelCtx)
		done <- result
	}()

	// Give goroutine time to enter queue
	time.Sleep(10 * time.Millisecond)

	// Cancel the context
	cancel()

	// Waiting goroutine should return false
	select {
	case result := <-done:
		if result {
			t.Error("acquire should fail after context cancellation")
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("waiting goroutine should have returned")
	}

	msl.Release()
}

func TestMaxSessions_Middleware_Headers(t *testing.T) {
	msl := NewMaxSessionsLimiter(1, 0, 0, WithMaxSessionsLogger(observability.NopLogger()))

	handler := MaxSessions(msl)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))

	// Start a request that will hold the slot
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}()

	// Give first request time to start
	time.Sleep(10 * time.Millisecond)

	// Second request should be rejected with proper headers
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}

	// Check headers
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Retry-After") != "1" {
		t.Errorf("expected Retry-After 1, got %s", rec.Header().Get("Retry-After"))
	}

	// Check body
	body := rec.Body.String()
	if body != `{"error":"max sessions exceeded","message":"server at capacity"}` {
		t.Errorf("unexpected body: %s", body)
	}

	wg.Wait()
}

func TestMaxSessionsFromConfig_WithQueueTimeout(t *testing.T) {
	cfg := &config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 5,
		QueueSize:     10,
		QueueTimeout:  config.Duration(100 * time.Millisecond),
	}

	middleware, limiter := MaxSessionsFromConfig(cfg, observability.NopLogger())

	if limiter == nil {
		t.Fatal("expected limiter to be non-nil")
	}

	if middleware == nil {
		t.Fatal("middleware should never be nil")
	}

	// Verify limiter configuration
	if limiter.MaxConcurrent() != 5 {
		t.Errorf("expected maxConcurrent 5, got %d", limiter.MaxConcurrent())
	}

	limiter.Stop()
}

func TestMaxSessionsLimiter_MultipleStops(t *testing.T) {
	msl := NewMaxSessionsLimiter(10, 5, time.Second)

	// Multiple stops should not panic
	msl.Stop()
	msl.Stop()
	msl.Stop()
}

func TestMaxSessionsLimiter_AcquireAfterStop(t *testing.T) {
	msl := NewMaxSessionsLimiter(1, 5, time.Second)
	ctx := context.Background()

	// Acquire the only slot
	if !msl.Acquire(ctx) {
		t.Fatal("first acquire should succeed")
	}

	// Stop the limiter
	msl.Stop()

	// New acquire attempts that would queue should fail
	// (immediate acquire might still succeed if slot is available)
	msl.Release()

	// After stop, immediate acquires should still work
	if !msl.Acquire(ctx) {
		t.Error("immediate acquire should still work after stop")
	}
}

func TestMaxSessionsLimiter_ConcurrentUpdateConfig(t *testing.T) {
	maxConcurrent := 10
	msl := NewMaxSessionsLimiter(maxConcurrent, 0, 0, WithMaxSessionsLogger(observability.NopLogger()))
	ctx := context.Background()

	var wg sync.WaitGroup

	// Start goroutines that acquire and release
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if msl.Acquire(ctx) {
					time.Sleep(time.Millisecond)
					msl.Release()
				}
			}
		}()
	}

	// Concurrently update config
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			time.Sleep(time.Duration(idx) * time.Millisecond)
			msl.UpdateConfig(&config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 5 + idx,
			})
		}(i)
	}

	wg.Wait()

	// After all goroutines complete, current should be 0
	if msl.Current() != 0 {
		t.Errorf("expected current 0 after all releases, got %d", msl.Current())
	}
}

func TestMaxSessionsLimiter_ConcurrentAcquireRelease(t *testing.T) {
	maxConcurrent := 10
	msl := NewMaxSessionsLimiter(maxConcurrent, 0, 0)
	ctx := context.Background()

	var wg sync.WaitGroup
	var maxObserved atomic.Int64
	var successCount atomic.Int64
	var failCount atomic.Int64

	// Start many goroutines trying to acquire
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if msl.Acquire(ctx) {
				successCount.Add(1)
				current := msl.Current()
				for {
					old := maxObserved.Load()
					if current <= old || maxObserved.CompareAndSwap(old, current) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				msl.Release()
			} else {
				failCount.Add(1)
			}
		}()
	}

	wg.Wait()

	if maxObserved.Load() > int64(maxConcurrent) {
		t.Errorf("max observed %d exceeded limit %d", maxObserved.Load(), maxConcurrent)
	}

	if msl.Current() != 0 {
		t.Errorf("expected current 0 after all releases, got %d", msl.Current())
	}

	// Some requests should have succeeded
	if successCount.Load() == 0 {
		t.Error("expected some successful acquires")
	}
}

func TestMaxSessionsLimiter_UpdateConfig(t *testing.T) {
	msl := NewMaxSessionsLimiter(2, 0, 0, WithMaxSessionsLogger(observability.NopLogger()))
	ctx := context.Background()

	// Acquire 2 slots (at limit)
	if !msl.Acquire(ctx) {
		t.Fatal("first acquire should succeed")
	}
	if !msl.Acquire(ctx) {
		t.Fatal("second acquire should succeed")
	}

	// Third should fail
	if msl.Acquire(ctx) {
		t.Error("third acquire should fail at limit 2")
	}

	// Update to allow more concurrent sessions
	msl.UpdateConfig(&config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 5,
	})

	if msl.MaxConcurrent() != 5 {
		t.Errorf("expected maxConcurrent 5, got %d", msl.MaxConcurrent())
	}

	// Now third acquire should succeed
	if !msl.Acquire(ctx) {
		t.Error("third acquire should succeed after update to 5")
	}

	// Release all
	msl.Release()
	msl.Release()
	msl.Release()
}

func TestMaxSessionsLimiter_UpdateConfig_NilConfig(t *testing.T) {
	msl := NewMaxSessionsLimiter(10, 0, 0)
	original := msl.MaxConcurrent()

	// Nil config should be a no-op
	msl.UpdateConfig(nil)

	if msl.MaxConcurrent() != original {
		t.Errorf("expected maxConcurrent %d, got %d", original, msl.MaxConcurrent())
	}
}

func TestMaxSessionsLimiter_UpdateConfig_ReduceLimit(t *testing.T) {
	msl := NewMaxSessionsLimiter(10, 0, 0, WithMaxSessionsLogger(observability.NopLogger()))
	ctx := context.Background()

	// Acquire 5 slots
	for i := 0; i < 5; i++ {
		if !msl.Acquire(ctx) {
			t.Fatalf("acquire %d should succeed", i)
		}
	}

	// Reduce limit to 3 (below current usage)
	msl.UpdateConfig(&config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 3,
	})

	// New acquires should fail since current (5) > new limit (3)
	if msl.Acquire(ctx) {
		t.Error("acquire should fail when current exceeds new limit")
	}

	// Release down to 2 (below new limit)
	msl.Release()
	msl.Release()
	msl.Release()

	// Now acquire should succeed
	if !msl.Acquire(ctx) {
		t.Error("acquire should succeed after releasing below limit")
	}

	// Clean up
	msl.Release()
	msl.Release()
	msl.Release()
}
