package audit

import (
	"context"
	"sync/atomic"
)

// AtomicAuditLogger wraps an audit.Logger with an atomic pointer for
// lock-free hot-reload. All Logger method calls are delegated to the
// currently stored logger. Swap() atomically replaces the inner logger,
// making all subsequent calls use the new one without requiring
// consumers to be re-wired.
//
// This solves the stale-reference problem where HTTP middleware and gRPC
// interceptors capture the logger at creation time via closures. By
// passing an AtomicAuditLogger instead, the closures always delegate to
// the current logger.
type AtomicAuditLogger struct {
	current atomic.Pointer[Logger]
}

// Ensure AtomicAuditLogger satisfies the Logger interface.
var _ Logger = (*AtomicAuditLogger)(nil)

// defaultNoopLogger is a package-level singleton used by Load() to avoid
// allocating a new noopLogger on every call when the atomic pointer is nil
// (zero-value struct). This is a minor optimization for defensive code paths.
var defaultNoopLogger Logger = &noopLogger{}

// NewAtomicAuditLogger creates a new AtomicAuditLogger wrapping the
// given logger. If logger is nil, a NoopLogger is used as the initial
// delegate to guarantee nil-safe operation.
func NewAtomicAuditLogger(logger Logger) *AtomicAuditLogger {
	if logger == nil {
		logger = NewNoopLogger()
	}
	a := &AtomicAuditLogger{}
	a.current.Store(&logger)
	return a
}

// Swap atomically replaces the inner logger and returns the previous
// one. The caller is responsible for closing the previous logger if
// needed. If newLogger is nil, a NoopLogger is stored instead.
func (a *AtomicAuditLogger) Swap(newLogger Logger) Logger {
	if newLogger == nil {
		newLogger = NewNoopLogger()
	}
	old := a.current.Swap(&newLogger)
	if old != nil {
		return *old
	}
	return nil
}

// Load returns the current inner logger. If the internal pointer is
// nil (should not happen under normal usage), a NoopLogger is returned
// to guarantee nil-safe operation.
func (a *AtomicAuditLogger) Load() Logger {
	if ptr := a.current.Load(); ptr != nil {
		return *ptr
	}
	return defaultNoopLogger
}

// LogEvent delegates to the current inner logger.
func (a *AtomicAuditLogger) LogEvent(ctx context.Context, event *Event) {
	a.Load().LogEvent(ctx, event)
}

// LogAuthentication delegates to the current inner logger.
func (a *AtomicAuditLogger) LogAuthentication(
	ctx context.Context,
	action Action,
	outcome Outcome,
	subject *Subject,
) {
	a.Load().LogAuthentication(ctx, action, outcome, subject)
}

// LogAuthorization delegates to the current inner logger.
func (a *AtomicAuditLogger) LogAuthorization(
	ctx context.Context,
	outcome Outcome,
	subject *Subject,
	resource *Resource,
) {
	a.Load().LogAuthorization(ctx, outcome, subject, resource)
}

// LogSecurity delegates to the current inner logger.
func (a *AtomicAuditLogger) LogSecurity(
	ctx context.Context,
	action Action,
	outcome Outcome,
	subject *Subject,
	details map[string]interface{},
) {
	a.Load().LogSecurity(ctx, action, outcome, subject, details)
}

// Close closes the current inner logger.
func (a *AtomicAuditLogger) Close() error {
	return a.Load().Close()
}
