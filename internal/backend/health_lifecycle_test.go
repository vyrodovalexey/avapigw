package backend

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// captureLogger is a minimal observability.Logger implementation that
// records Warn messages so tests can assert on emitted warnings.
type captureLogger struct {
	mu    sync.Mutex
	warns []string
}

func (l *captureLogger) Debug(string, ...observability.Field) {
	// no-op: only warnings are relevant for these tests
}

func (l *captureLogger) Info(string, ...observability.Field) {
	// no-op: only warnings are relevant for these tests
}

func (l *captureLogger) Warn(msg string, _ ...observability.Field) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}

func (l *captureLogger) Error(string, ...observability.Field) {
	// no-op: only warnings are relevant for these tests
}

func (l *captureLogger) Fatal(string, ...observability.Field) {
	// no-op: only warnings are relevant for these tests
}

func (l *captureLogger) With(...observability.Field) observability.Logger { return l }

func (l *captureLogger) WithContext(context.Context) observability.Logger { return l }

func (l *captureLogger) Sync() error { return nil }

// warnMessages returns a copy of the recorded warning messages.
func (l *captureLogger) warnMessages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.warns...)
}

// REGRESSION: Start -> Stop -> Start -> Stop cycles must not panic with
// "close of closed channel", and the checker must actually probe backends
// in every generation.
func TestHealthChecker_RestartCycles_NoClosedChannelPanic(t *testing.T) {
	t.Parallel()

	var probes atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			probes.Add(1)
			w.WriteHeader(http.StatusOK)
		},
	))
	defer server.Close()

	addr, ok := server.Listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	host := NewHost(addr.IP.String(), addr.Port, 1)

	cfg := config.HealthCheck{
		Path:             "/health",
		Interval:         config.Duration(20 * time.Millisecond),
		HealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-restart-cycles"),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for cycle := 1; cycle <= 3; cycle++ {
		before := probes.Load()

		hc.Start(ctx)
		assert.True(t, hc.IsRunning(), "cycle %d: checker must be running after Start", cycle)

		require.Eventually(t, func() bool {
			return probes.Load() > before
		}, 2*time.Second, 5*time.Millisecond,
			"cycle %d: checker did not probe the backend after restart", cycle)

		hc.Stop()
		assert.False(t, hc.IsRunning(), "cycle %d: checker must not be running after Stop", cycle)
	}
}

// EDGE: when the run loop exits because its context is canceled, the
// running flag must reset, a subsequent Stop must return promptly, and
// the checker must be restartable afterwards.
func TestHealthChecker_ContextCanceled_ResetsRunning(t *testing.T) {
	t.Parallel()

	cfg := config.HealthCheck{
		Path:     "/health",
		Interval: config.Duration(time.Hour), // loop parks in select
	}

	hc := NewHealthChecker([]*Host{}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	hc.Start(ctx)
	require.True(t, hc.IsRunning())

	cancel()

	require.Eventually(t, func() bool {
		return !hc.IsRunning()
	}, 2*time.Second, 5*time.Millisecond,
		"running flag must reset after context cancellation")

	// Subsequent Stop must take the fast not-running path (no unbounded
	// wait, no stop-timeout wait).
	start := time.Now()
	hc.Stop()
	assert.Less(t, time.Since(start), 2*time.Second,
		"Stop after context cancellation must return promptly")

	// The checker must be restartable after a context-canceled exit.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	hc.Start(ctx2)
	assert.True(t, hc.IsRunning())

	hc.Stop()
	assert.False(t, hc.IsRunning())
}

// ERROR: if the run loop never acknowledges shutdown (stoppedCh never
// closes), Stop must return after the bounded stop timeout and log a
// warning instead of hanging forever.
func TestHealthChecker_Stop_TimesOutWhenRunLoopStuck(t *testing.T) {
	t.Parallel()

	logger := &captureLogger{}
	hc := NewHealthChecker([]*Host{}, config.HealthCheck{Path: "/health"},
		WithHealthCheckLogger(logger),
		WithBackendName("test-stuck-run"),
	)
	hc.stopTimeout = 50 * time.Millisecond

	// Simulate a stuck generation: mark the checker running without
	// launching the run goroutine, so this generation's stoppedCh is
	// never closed.
	hc.mu.Lock()
	hc.running = true
	hc.mu.Unlock()

	start := time.Now()
	hc.Stop()
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond,
		"Stop must wait for the stop timeout before giving up")
	assert.Less(t, elapsed, 3*time.Second,
		"Stop must not wait unboundedly for a stuck run loop")
	assert.False(t, hc.IsRunning())
	assert.Contains(t, logger.warnMessages(),
		"timeout waiting for health check loop to stop")

	// A second Stop must be a fast idempotent no-op.
	start = time.Now()
	hc.Stop()
	assert.Less(t, time.Since(start), time.Second)
}

// EDGE: a non-positive stop timeout falls back to the default instead of
// firing immediately.
func TestHealthChecker_Stop_ZeroTimeoutFallsBackToDefault(t *testing.T) {
	t.Parallel()

	cfg := config.HealthCheck{
		Path:     "/health",
		Interval: config.Duration(time.Hour),
	}

	hc := NewHealthChecker([]*Host{}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
	)
	hc.stopTimeout = 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hc.Start(ctx)
	require.True(t, hc.IsRunning())

	// The loop exits promptly on stopCh, so Stop returns fast even
	// though the effective timeout is the 5s default.
	hc.Stop()
	assert.False(t, hc.IsRunning())
}

// GUARD: Stop before Start and double Stop must neither panic nor hang.
func TestHealthChecker_StopBeforeStart_NoPanicNoHang(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker([]*Host{}, config.HealthCheck{Path: "/health"},
		WithHealthCheckLogger(observability.NopLogger()),
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		hc.Stop() // Stop before any Start
		hc.Stop() // double Stop
	}()

	select {
	case <-done:
		// Both Stop calls returned without panicking.
	case <-time.After(3 * time.Second):
		t.Fatal("Stop before Start hung")
	}

	assert.False(t, hc.IsRunning())
}

// RACE: concurrent Start/Stop hammering must not double-close channels,
// deadlock, or trip the race detector.
func TestHealthChecker_ConcurrentStartStop_NoPanic(t *testing.T) {
	t.Parallel()

	cfg := config.HealthCheck{
		Path:     "/health",
		Interval: config.Duration(time.Hour),
	}

	hc := NewHealthChecker([]*Host{}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		goroutines = 8
		iterations = 25
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				hc.Start(ctx)
				hc.Stop()
			}
		}()
	}
	wg.Wait()

	// Final cleanup: every generation must have been retired.
	hc.Stop()
	assert.False(t, hc.IsRunning())
}
