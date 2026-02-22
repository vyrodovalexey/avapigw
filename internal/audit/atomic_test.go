package audit

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Mock audit logger for testing
// ============================================================================

// mockAuditLogger is a thread-safe test double for audit.Logger.
type mockAuditLogger struct {
	mu                     sync.Mutex
	name                   string
	events                 []*Event
	logEventCalls          int
	logAuthenticationCalls int
	logAuthorizationCalls  int
	logSecurityCalls       int
	closeCalls             int
	closeErr               error
	lastEvent              *Event
	lastAction             Action
	lastOutcome            Outcome
	lastSubject            *Subject
	lastResource           *Resource
	lastDetails            map[string]interface{}
}

func (m *mockAuditLogger) LogEvent(_ context.Context, event *Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logEventCalls++
	m.lastEvent = event
	m.events = append(m.events, event)
}

func (m *mockAuditLogger) LogAuthentication(
	_ context.Context,
	action Action,
	outcome Outcome,
	subject *Subject,
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logAuthenticationCalls++
	m.lastAction = action
	m.lastOutcome = outcome
	m.lastSubject = subject
}

func (m *mockAuditLogger) LogAuthorization(
	_ context.Context,
	outcome Outcome,
	subject *Subject,
	resource *Resource,
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logAuthorizationCalls++
	m.lastOutcome = outcome
	m.lastSubject = subject
	m.lastResource = resource
}

func (m *mockAuditLogger) LogSecurity(
	_ context.Context,
	action Action,
	outcome Outcome,
	subject *Subject,
	details map[string]interface{},
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logSecurityCalls++
	m.lastAction = action
	m.lastOutcome = outcome
	m.lastSubject = subject
	m.lastDetails = details
}

func (m *mockAuditLogger) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalls++
	return m.closeErr
}

// getLogEventCalls returns the number of LogEvent calls in a thread-safe way.
func (m *mockAuditLogger) getLogEventCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logEventCalls
}

// Ensure mockAuditLogger satisfies the Logger interface.
var _ Logger = (*mockAuditLogger)(nil)

// ============================================================================
// Interface compliance
// ============================================================================

func TestAtomicAuditLogger_ImplementsLogger(t *testing.T) {
	t.Parallel()

	// Compile-time check (already in atomic.go, but verify at runtime too)
	var l Logger = NewAtomicAuditLogger(NewNoopLogger())
	assert.NotNil(t, l)

	// Verify the concrete type satisfies the interface
	_, ok := l.(*AtomicAuditLogger)
	assert.True(t, ok, "AtomicAuditLogger should implement Logger interface")
}

// ============================================================================
// Constructor tests
// ============================================================================

func TestNewAtomicAuditLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		logger     Logger
		wantNoop   bool
		wantSame   bool
		wantNotNil bool
	}{
		{
			name:       "creates with valid logger",
			logger:     &mockAuditLogger{name: "test"},
			wantNoop:   false,
			wantSame:   true,
			wantNotNil: true,
		},
		{
			name:       "creates with noop logger",
			logger:     NewNoopLogger(),
			wantNoop:   true,
			wantSame:   true,
			wantNotNil: true,
		},
		{
			name:       "nil logger uses noopLogger",
			logger:     nil,
			wantNoop:   true,
			wantSame:   false,
			wantNotNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			al := NewAtomicAuditLogger(tt.logger)

			require.NotNil(t, al, "AtomicAuditLogger should not be nil")

			loaded := al.Load()
			assert.NotNil(t, loaded, "Load() should never return nil")

			if tt.wantSame {
				assert.Equal(t, tt.logger, loaded, "Load() should return the same logger")
			}

			if tt.wantNoop {
				_, isNoop := loaded.(*noopLogger)
				assert.True(t, isNoop, "Load() should return a noopLogger")
			}
		})
	}
}

func TestNewAtomicAuditLogger_Nil(t *testing.T) {
	t.Parallel()

	al := NewAtomicAuditLogger(nil)

	require.NotNil(t, al)

	loaded := al.Load()
	require.NotNil(t, loaded, "Load() should return noopLogger, not nil")

	_, isNoop := loaded.(*noopLogger)
	assert.True(t, isNoop, "nil input should result in noopLogger")
}

// ============================================================================
// Load tests
// ============================================================================

func TestAtomicAuditLogger_Load_Default(t *testing.T) {
	t.Parallel()

	// Zero-value AtomicAuditLogger (no Store called)
	al := &AtomicAuditLogger{}

	loaded := al.Load()
	assert.NotNil(t, loaded, "Load() on zero-value should return noopLogger")

	_, isNoop := loaded.(*noopLogger)
	assert.True(t, isNoop, "Load() on zero-value should return noopLogger")
}

func TestAtomicAuditLogger_Load_ReturnsSameLogger(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{name: "test-load"}
	al := NewAtomicAuditLogger(mock)

	// Multiple loads should return the same logger
	l1 := al.Load()
	l2 := al.Load()
	assert.Equal(t, l1, l2, "consecutive Load() calls should return the same logger")
	assert.Equal(t, mock, l1, "Load() should return the stored logger")
}

// ============================================================================
// Swap tests
// ============================================================================

func TestAtomicAuditLogger_Swap(t *testing.T) {
	t.Parallel()

	mock1 := &mockAuditLogger{name: "logger1"}
	mock2 := &mockAuditLogger{name: "logger2"}

	al := NewAtomicAuditLogger(mock1)

	// Swap should return old logger
	old := al.Swap(mock2)
	assert.Equal(t, mock1, old, "Swap should return the previous logger")

	// Load should return new logger
	current := al.Load()
	assert.Equal(t, mock2, current, "Load() should return the new logger after Swap")
}

func TestAtomicAuditLogger_Swap_Nil(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{name: "original"}
	al := NewAtomicAuditLogger(mock)

	// Swap with nil should store noopLogger
	old := al.Swap(nil)
	assert.Equal(t, mock, old, "Swap(nil) should return the previous logger")

	loaded := al.Load()
	assert.NotNil(t, loaded, "Load() after Swap(nil) should not return nil")

	_, isNoop := loaded.(*noopLogger)
	assert.True(t, isNoop, "Swap(nil) should store a noopLogger")
}

func TestAtomicAuditLogger_MultipleSwaps(t *testing.T) {
	t.Parallel()

	loggers := make([]*mockAuditLogger, 5)
	for i := range loggers {
		loggers[i] = &mockAuditLogger{name: "logger"}
	}

	al := NewAtomicAuditLogger(loggers[0])

	for i := 1; i < len(loggers); i++ {
		old := al.Swap(loggers[i])
		assert.Equal(t, loggers[i-1], old, "Swap should return the previous logger")
		assert.Equal(t, loggers[i], al.Load(), "Load() should return the latest logger")
	}
}

func TestAtomicAuditLogger_SwapPreservesNewLogger(t *testing.T) {
	t.Parallel()

	mock1 := &mockAuditLogger{name: "old"}
	mock2 := &mockAuditLogger{name: "new"}

	al := NewAtomicAuditLogger(mock1)
	al.Swap(mock2)

	ctx := context.Background()
	event := NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess)
	subject := &Subject{ID: "user1"}
	resource := &Resource{Path: "/api/v1/users"}
	details := map[string]interface{}{"key": "value"}

	// All methods should use the new logger
	al.LogEvent(ctx, event)
	al.LogAuthentication(ctx, ActionLogin, OutcomeSuccess, subject)
	al.LogAuthorization(ctx, OutcomeSuccess, subject, resource)
	al.LogSecurity(ctx, ActionRateLimitExceeded, OutcomeFailure, subject, details)

	// Verify mock1 (old) received no calls
	assert.Equal(t, 0, mock1.logEventCalls, "old logger should not receive LogEvent calls")
	assert.Equal(t, 0, mock1.logAuthenticationCalls, "old logger should not receive LogAuthentication calls")
	assert.Equal(t, 0, mock1.logAuthorizationCalls, "old logger should not receive LogAuthorization calls")
	assert.Equal(t, 0, mock1.logSecurityCalls, "old logger should not receive LogSecurity calls")

	// Verify mock2 (new) received all calls
	assert.Equal(t, 1, mock2.logEventCalls, "new logger should receive LogEvent call")
	assert.Equal(t, 1, mock2.logAuthenticationCalls, "new logger should receive LogAuthentication call")
	assert.Equal(t, 1, mock2.logAuthorizationCalls, "new logger should receive LogAuthorization call")
	assert.Equal(t, 1, mock2.logSecurityCalls, "new logger should receive LogSecurity call")
}

func TestAtomicAuditLogger_Swap_ZeroValue(t *testing.T) {
	t.Parallel()

	// Swap on zero-value AtomicAuditLogger
	al := &AtomicAuditLogger{}
	mock := &mockAuditLogger{name: "new"}

	old := al.Swap(mock)
	// old should be nil since no logger was stored
	assert.Nil(t, old, "Swap on zero-value should return nil")

	// After swap, Load should return the new logger
	assert.Equal(t, mock, al.Load())
}

// ============================================================================
// Delegation tests
// ============================================================================

func TestAtomicAuditLogger_LogEvent(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	event := NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess)
	al.LogEvent(context.Background(), event)

	assert.Equal(t, 1, mock.logEventCalls, "LogEvent should delegate to inner logger")
	assert.Equal(t, event, mock.lastEvent, "LogEvent should pass the event to inner logger")
}

func TestAtomicAuditLogger_LogEvent_NilEvent(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	// Should not panic with nil event
	al.LogEvent(context.Background(), nil)

	assert.Equal(t, 1, mock.logEventCalls, "LogEvent should delegate even with nil event")
	assert.Nil(t, mock.lastEvent, "nil event should be passed through")
}

func TestAtomicAuditLogger_LogAuthentication(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	subject := &Subject{ID: "user1", AuthMethod: "jwt"}
	al.LogAuthentication(context.Background(), ActionLogin, OutcomeSuccess, subject)

	assert.Equal(t, 1, mock.logAuthenticationCalls, "LogAuthentication should delegate")
	assert.Equal(t, ActionLogin, mock.lastAction)
	assert.Equal(t, OutcomeSuccess, mock.lastOutcome)
	assert.Equal(t, subject, mock.lastSubject)
}

func TestAtomicAuditLogger_LogAuthentication_NilSubject(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	al.LogAuthentication(context.Background(), ActionLogout, OutcomeFailure, nil)

	assert.Equal(t, 1, mock.logAuthenticationCalls)
	assert.Nil(t, mock.lastSubject)
}

func TestAtomicAuditLogger_LogAuthorization(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	subject := &Subject{ID: "user1"}
	resource := &Resource{Path: "/api/v1/users", Method: "GET"}
	al.LogAuthorization(context.Background(), OutcomeSuccess, subject, resource)

	assert.Equal(t, 1, mock.logAuthorizationCalls, "LogAuthorization should delegate")
	assert.Equal(t, OutcomeSuccess, mock.lastOutcome)
	assert.Equal(t, subject, mock.lastSubject)
	assert.Equal(t, resource, mock.lastResource)
}

func TestAtomicAuditLogger_LogAuthorization_NilArgs(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	al.LogAuthorization(context.Background(), OutcomeDenied, nil, nil)

	assert.Equal(t, 1, mock.logAuthorizationCalls)
	assert.Nil(t, mock.lastSubject)
	assert.Nil(t, mock.lastResource)
}

func TestAtomicAuditLogger_LogSecurity(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	subject := &Subject{ID: "user1", IPAddress: "192.168.1.1"}
	details := map[string]interface{}{
		"reason":   "rate_limit",
		"attempts": 5,
	}
	al.LogSecurity(context.Background(), ActionRateLimitExceeded, OutcomeFailure, subject, details)

	assert.Equal(t, 1, mock.logSecurityCalls, "LogSecurity should delegate")
	assert.Equal(t, ActionRateLimitExceeded, mock.lastAction)
	assert.Equal(t, OutcomeFailure, mock.lastOutcome)
	assert.Equal(t, subject, mock.lastSubject)
	assert.Equal(t, details, mock.lastDetails)
}

func TestAtomicAuditLogger_LogSecurity_NilArgs(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	al.LogSecurity(context.Background(), ActionSuspiciousActivity, OutcomeFailure, nil, nil)

	assert.Equal(t, 1, mock.logSecurityCalls)
	assert.Nil(t, mock.lastSubject)
	assert.Nil(t, mock.lastDetails)
}

func TestAtomicAuditLogger_Close(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	err := al.Close()

	assert.NoError(t, err)
	assert.Equal(t, 1, mock.closeCalls, "Close should delegate to inner logger")
}

func TestAtomicAuditLogger_Close_Error(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("close failed: file descriptor invalid")
	mock := &mockAuditLogger{closeErr: expectedErr}
	al := NewAtomicAuditLogger(mock)

	err := al.Close()

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err, "Close should return error from inner logger")
	assert.Equal(t, 1, mock.closeCalls)
}

func TestAtomicAuditLogger_Close_ZeroValue(t *testing.T) {
	t.Parallel()

	// Close on zero-value should not panic (Load returns noopLogger)
	al := &AtomicAuditLogger{}
	err := al.Close()
	assert.NoError(t, err, "Close on zero-value should return nil (noopLogger)")
}

// ============================================================================
// Delegation on zero-value AtomicAuditLogger
// ============================================================================

func TestAtomicAuditLogger_ZeroValue_AllMethods(t *testing.T) {
	t.Parallel()

	// Zero-value AtomicAuditLogger should not panic on any method call
	al := &AtomicAuditLogger{}
	ctx := context.Background()

	// All these should delegate to noopLogger and not panic
	al.LogEvent(ctx, NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess))
	al.LogAuthentication(ctx, ActionLogin, OutcomeSuccess, &Subject{ID: "user1"})
	al.LogAuthorization(ctx, OutcomeSuccess, &Subject{ID: "user1"}, &Resource{Path: "/api"})
	al.LogSecurity(ctx, ActionSuspiciousActivity, OutcomeFailure, nil, nil)

	err := al.Close()
	assert.NoError(t, err)
}

// ============================================================================
// Swap behavior tests
// ============================================================================

func TestAtomicAuditLogger_SwapDuringLogging(t *testing.T) {
	t.Parallel()

	mock1 := &mockAuditLogger{name: "logger1"}
	mock2 := &mockAuditLogger{name: "logger2"}
	al := NewAtomicAuditLogger(mock1)

	const iterations = 1000
	var wg sync.WaitGroup

	// Start logging in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			event := NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess)
			al.LogEvent(context.Background(), event)
		}
	}()

	// Swap midway through logging
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Let some events go to mock1 first
		for i := 0; i < iterations/2; i++ {
			// Busy-wait to let some events through
		}
		al.Swap(mock2)
	}()

	wg.Wait()

	// Both loggers should have received some events (total = iterations)
	totalCalls := mock1.getLogEventCalls() + mock2.getLogEventCalls()
	assert.Equal(t, iterations, totalCalls,
		"total events should equal iterations: mock1=%d, mock2=%d",
		mock1.getLogEventCalls(), mock2.getLogEventCalls())
}

// ============================================================================
// Concurrency tests
// ============================================================================

func TestAtomicAuditLogger_ConcurrentLogEvent(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	const goroutines = 50
	const iterations = 100
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				event := NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess)
				al.LogEvent(context.Background(), event)
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, goroutines*iterations, mock.logEventCalls,
		"all concurrent LogEvent calls should be counted")
}

func TestAtomicAuditLogger_ConcurrentSwapAndLog(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	const logGoroutines = 50
	const swapGoroutines = 10
	const logIterations = 100
	const swapIterations = 50
	var wg sync.WaitGroup

	// Concurrent LogEvent calls
	for i := 0; i < logGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < logIterations; j++ {
				event := NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess)
				al.LogEvent(context.Background(), event)
			}
		}()
	}

	// Concurrent Swap calls
	for i := 0; i < swapGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < swapIterations; j++ {
				newMock := &mockAuditLogger{}
				al.Swap(newMock)
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions or panics occur
}

func TestAtomicAuditLogger_ConcurrentAllMethods(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)

	const goroutines = 20
	const iterations = 50
	var wg sync.WaitGroup

	ctx := context.Background()

	// Concurrent LogEvent
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				al.LogEvent(ctx, NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess))
			}
		}()
	}

	// Concurrent LogAuthentication
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				al.LogAuthentication(ctx, ActionLogin, OutcomeSuccess, &Subject{ID: "user1"})
			}
		}()
	}

	// Concurrent LogAuthorization
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				al.LogAuthorization(ctx, OutcomeSuccess, &Subject{ID: "user1"}, &Resource{Path: "/api"})
			}
		}()
	}

	// Concurrent LogSecurity
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				al.LogSecurity(ctx, ActionSuspiciousActivity, OutcomeFailure, nil, nil)
			}
		}()
	}

	// Concurrent Swap
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				al.Swap(&mockAuditLogger{})
			}
		}()
	}

	// Concurrent Load
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				l := al.Load()
				assert.NotNil(t, l)
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions or panics occur
}

func TestAtomicAuditLogger_RaceDetection(t *testing.T) {
	t.Parallel()

	// This test is specifically designed to trigger the race detector
	// if the implementation is not thread-safe.
	al := NewAtomicAuditLogger(&mockAuditLogger{})

	const goroutines = 100
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(3)

		// Reader goroutine
		go func() {
			defer wg.Done()
			l := al.Load()
			l.LogEvent(context.Background(), NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess))
		}()

		// Writer goroutine
		go func() {
			defer wg.Done()
			al.Swap(&mockAuditLogger{})
		}()

		// Direct method goroutine
		go func() {
			defer wg.Done()
			al.LogEvent(context.Background(), NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess))
		}()
	}

	wg.Wait()
	// If the race detector doesn't fire, the implementation is safe
}

// ============================================================================
// Table-driven delegation tests
// ============================================================================

func TestAtomicAuditLogger_DelegationMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		callFn   func(al *AtomicAuditLogger)
		verifyFn func(t *testing.T, mock *mockAuditLogger)
	}{
		{
			name: "LogEvent delegates correctly",
			callFn: func(al *AtomicAuditLogger) {
				event := NewEvent(EventTypeAuthentication, ActionLogin, OutcomeSuccess)
				al.LogEvent(context.Background(), event)
			},
			verifyFn: func(t *testing.T, mock *mockAuditLogger) {
				t.Helper()
				assert.Equal(t, 1, mock.logEventCalls)
				assert.NotNil(t, mock.lastEvent)
				assert.Equal(t, EventTypeAuthentication, mock.lastEvent.Type)
			},
		},
		{
			name: "LogAuthentication delegates correctly",
			callFn: func(al *AtomicAuditLogger) {
				al.LogAuthentication(context.Background(), ActionLogin, OutcomeSuccess, &Subject{ID: "u1"})
			},
			verifyFn: func(t *testing.T, mock *mockAuditLogger) {
				t.Helper()
				assert.Equal(t, 1, mock.logAuthenticationCalls)
				assert.Equal(t, ActionLogin, mock.lastAction)
				assert.Equal(t, OutcomeSuccess, mock.lastOutcome)
				assert.Equal(t, "u1", mock.lastSubject.ID)
			},
		},
		{
			name: "LogAuthorization delegates correctly",
			callFn: func(al *AtomicAuditLogger) {
				al.LogAuthorization(context.Background(), OutcomeDenied, &Subject{ID: "u2"}, &Resource{Path: "/secret"})
			},
			verifyFn: func(t *testing.T, mock *mockAuditLogger) {
				t.Helper()
				assert.Equal(t, 1, mock.logAuthorizationCalls)
				assert.Equal(t, OutcomeDenied, mock.lastOutcome)
				assert.Equal(t, "u2", mock.lastSubject.ID)
				assert.Equal(t, "/secret", mock.lastResource.Path)
			},
		},
		{
			name: "LogSecurity delegates correctly",
			callFn: func(al *AtomicAuditLogger) {
				al.LogSecurity(context.Background(), ActionBruteForceDetected, OutcomeFailure,
					&Subject{ID: "attacker"}, map[string]interface{}{"attempts": 100})
			},
			verifyFn: func(t *testing.T, mock *mockAuditLogger) {
				t.Helper()
				assert.Equal(t, 1, mock.logSecurityCalls)
				assert.Equal(t, ActionBruteForceDetected, mock.lastAction)
				assert.Equal(t, OutcomeFailure, mock.lastOutcome)
				assert.Equal(t, "attacker", mock.lastSubject.ID)
				assert.Equal(t, 100, mock.lastDetails["attempts"])
			},
		},
		{
			name: "Close delegates correctly",
			callFn: func(al *AtomicAuditLogger) {
				_ = al.Close()
			},
			verifyFn: func(t *testing.T, mock *mockAuditLogger) {
				t.Helper()
				assert.Equal(t, 1, mock.closeCalls)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mock := &mockAuditLogger{}
			al := NewAtomicAuditLogger(mock)

			tt.callFn(al)
			tt.verifyFn(t, mock)
		})
	}
}

// ============================================================================
// Edge case tests
// ============================================================================

func TestAtomicAuditLogger_SwapAndClose(t *testing.T) {
	t.Parallel()

	mock1 := &mockAuditLogger{name: "first"}
	mock2 := &mockAuditLogger{name: "second"}

	al := NewAtomicAuditLogger(mock1)

	// Swap to mock2
	old := al.Swap(mock2)
	assert.Equal(t, mock1, old)

	// Close should close mock2 (the current logger), not mock1
	err := al.Close()
	assert.NoError(t, err)

	assert.Equal(t, 0, mock1.closeCalls, "old logger should not be closed by Close()")
	assert.Equal(t, 1, mock2.closeCalls, "current logger should be closed by Close()")
}

func TestAtomicAuditLogger_SwapReturnsOldForCleanup(t *testing.T) {
	t.Parallel()

	mock1 := &mockAuditLogger{name: "first"}
	mock2 := &mockAuditLogger{name: "second"}

	al := NewAtomicAuditLogger(mock1)

	// Swap and close the old logger (typical hot-reload pattern)
	old := al.Swap(mock2)
	require.NotNil(t, old)

	err := old.Close()
	assert.NoError(t, err)

	assert.Equal(t, 1, mock1.closeCalls, "old logger should be closed by caller")
	assert.Equal(t, 0, mock2.closeCalls, "new logger should not be closed")
}

func TestAtomicAuditLogger_ContextPropagation(t *testing.T) {
	t.Parallel()

	// Verify that context is properly passed through to the inner logger
	type ctxKey string
	key := ctxKey("test-key")

	var receivedCtx context.Context
	mock := &mockAuditLogger{}

	// Override LogEvent to capture context
	customLogger := &contextCapturingLogger{
		capturedCtx: &receivedCtx,
	}

	al := NewAtomicAuditLogger(customLogger)

	ctx := context.WithValue(context.Background(), key, "test-value")
	al.LogEvent(ctx, NewEvent(EventTypeRequest, ActionHTTPRequest, OutcomeSuccess))

	require.NotNil(t, receivedCtx)
	assert.Equal(t, "test-value", (*customLogger.capturedCtx).Value(key))

	_ = mock // suppress unused warning
}

// contextCapturingLogger captures the context passed to LogEvent.
type contextCapturingLogger struct {
	capturedCtx *context.Context
}

func (l *contextCapturingLogger) LogEvent(ctx context.Context, _ *Event) {
	*l.capturedCtx = ctx
}

func (l *contextCapturingLogger) LogAuthentication(_ context.Context, _ Action, _ Outcome, _ *Subject) {
}

func (l *contextCapturingLogger) LogAuthorization(_ context.Context, _ Outcome, _ *Subject, _ *Resource) {
}

func (l *contextCapturingLogger) LogSecurity(_ context.Context, _ Action, _ Outcome, _ *Subject, _ map[string]interface{}) {
}

func (l *contextCapturingLogger) Close() error { return nil }

var _ Logger = (*contextCapturingLogger)(nil)

// ============================================================================
// Multiple event types through atomic logger
// ============================================================================

func TestAtomicAuditLogger_AllEventTypes(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{}
	al := NewAtomicAuditLogger(mock)
	ctx := context.Background()

	eventTypes := []struct {
		eventType EventType
		action    Action
		outcome   Outcome
	}{
		{EventTypeAuthentication, ActionLogin, OutcomeSuccess},
		{EventTypeAuthorization, ActionAccess, OutcomeDenied},
		{EventTypeRequest, ActionHTTPRequest, OutcomeSuccess},
		{EventTypeResponse, ActionHTTPResponse, OutcomeFailure},
		{EventTypeConfiguration, ActionConfigUpdate, OutcomeSuccess},
		{EventTypeAdministrative, ActionUserCreate, OutcomeSuccess},
		{EventTypeSecurity, ActionBruteForceDetected, OutcomeFailure},
	}

	for _, et := range eventTypes {
		event := NewEvent(et.eventType, et.action, et.outcome)
		al.LogEvent(ctx, event)
	}

	assert.Equal(t, len(eventTypes), mock.logEventCalls,
		"all event types should be delegated")
}

// ============================================================================
// Swap with same logger
// ============================================================================

func TestAtomicAuditLogger_SwapWithSameLogger(t *testing.T) {
	t.Parallel()

	mock := &mockAuditLogger{name: "same"}
	al := NewAtomicAuditLogger(mock)

	// Swap with the same logger
	old := al.Swap(mock)
	assert.Equal(t, mock, old, "Swap with same logger should return the same logger")
	assert.Equal(t, mock, al.Load(), "Load should still return the same logger")
}

// ============================================================================
// Concurrent swap and close
// ============================================================================

func TestAtomicAuditLogger_ConcurrentSwapAndClose(t *testing.T) {
	t.Parallel()

	al := NewAtomicAuditLogger(&mockAuditLogger{})

	const goroutines = 50
	var wg sync.WaitGroup

	// Concurrent swaps
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			al.Swap(&mockAuditLogger{})
		}()
	}

	// Concurrent closes
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = al.Close()
		}()
	}

	wg.Wait()
	// No panics or race conditions
}
