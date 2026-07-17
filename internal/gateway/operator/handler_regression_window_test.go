// Package operator contains tests for the post-reconnect snapshot regression
// guard: within a short window after an operator (re)connect, FULL_SYNC
// snapshots whose resource count regresses versus the running configuration
// are deferred (operator-restart partial-snapshot protection), while growing
// snapshots and post-window shrinks apply normally.
package operator

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// routeResource marshals a config.Route into a snapshot resource.
func routeResource(t *testing.T, name string) *operatorv1alpha1.ConfigurationResource {
	t.Helper()
	routeJSON, err := json.Marshal(config.Route{Name: name})
	require.NoError(t, err)
	return &operatorv1alpha1.ConfigurationResource{
		Type:     operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
		Name:     name,
		SpecJson: routeJSON,
	}
}

// snapshotWithRoutes builds a FULL_SYNC snapshot carrying n API routes.
func snapshotWithRoutes(t *testing.T, version string, n int) *operatorv1alpha1.ConfigurationSnapshot {
	t.Helper()
	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        version,
		TotalResources: int32(n), //nolint:gosec // test counts are tiny
	}
	for i := 0; i < n; i++ {
		snapshot.ApiRoutes = append(snapshot.ApiRoutes,
			routeResource(t, "route-"+version+"-"+string(rune('a'+i))))
	}
	return snapshot
}

// newRegressionTestHandler builds a handler pre-seeded with a 3-route running
// configuration applied through a full snapshot.
func newRegressionTestHandler(t *testing.T) (*ConfigHandler, *MockConfigApplier) {
	t.Helper()
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)
	require.NoError(t, handler.HandleSnapshot(context.Background(), snapshotWithRoutes(t, "seed", 3)))
	require.Equal(t, 3, handler.runningResourceCount())
	return handler, applier
}

// TestConfigHandler_RegressingSnapshotDeferredWithinWindow is the regression
// test for the operator-restart partial-snapshot bug: a FULL_SYNC with FEWER
// resources than the running configuration, arriving within the reconnect
// window, must be deferred (last-known-good kept).
func TestConfigHandler_RegressingSnapshotDeferredWithinWindow(t *testing.T) {
	handler, _ := newRegressionTestHandler(t)

	handler.MarkReconnected()

	err := handler.HandleSnapshot(context.Background(), snapshotWithRoutes(t, "partial", 1))
	require.NoError(t, err, "deferring a regressing snapshot must not be an error")

	assert.Equal(t, 3, handler.runningResourceCount(),
		"running configuration must be untouched by the deferred partial snapshot")
}

// TestConfigHandler_GrowingSnapshotAppliedWithinWindow verifies growing
// snapshots always apply — the guard must not delay recovery.
func TestConfigHandler_GrowingSnapshotAppliedWithinWindow(t *testing.T) {
	handler, _ := newRegressionTestHandler(t)

	handler.MarkReconnected()

	err := handler.HandleSnapshot(context.Background(), snapshotWithRoutes(t, "grown", 5))
	require.NoError(t, err)

	assert.Equal(t, 5, handler.runningResourceCount(),
		"a growing snapshot within the window must be applied")
}

// TestConfigHandler_EqualSnapshotAppliedWithinWindow verifies same-size
// snapshots (content changes without count changes) apply within the window.
func TestConfigHandler_EqualSnapshotAppliedWithinWindow(t *testing.T) {
	handler, _ := newRegressionTestHandler(t)

	handler.MarkReconnected()

	err := handler.HandleSnapshot(context.Background(), snapshotWithRoutes(t, "same", 3))
	require.NoError(t, err)

	routes, _, _, _, _, _ := handler.GetCurrentState()
	require.Len(t, routes, 3)
	assert.Contains(t, routes[0].Name, "route-same-",
		"an equal-size snapshot must replace the running configuration")
}

// TestConfigHandler_GenuineShrinkAppliedAfterWindow verifies a shrink is
// honored once the stabilization window has passed.
func TestConfigHandler_GenuineShrinkAppliedAfterWindow(t *testing.T) {
	handler, _ := newRegressionTestHandler(t)

	// Simulate a reconnect that happened before the window.
	handler.reconnectedAt.Store(time.Now().Add(-snapshotRegressionWindow - time.Second).UnixNano())

	err := handler.HandleSnapshot(context.Background(), snapshotWithRoutes(t, "shrunk", 1))
	require.NoError(t, err)

	assert.Equal(t, 1, handler.runningResourceCount(),
		"a genuine shrink after the window must be applied")
}

// TestConfigHandler_ShrinkAppliedWithoutReconnectSignal verifies the guard is
// inert when no reconnect was ever signaled (embedded use without the
// listener wiring): snapshots always apply.
func TestConfigHandler_ShrinkAppliedWithoutReconnectSignal(t *testing.T) {
	handler, _ := newRegressionTestHandler(t)

	err := handler.HandleSnapshot(context.Background(), snapshotWithRoutes(t, "shrunk", 1))
	require.NoError(t, err)

	assert.Equal(t, 1, handler.runningResourceCount(),
		"without a reconnect signal the regression window must be inactive")
}

// TestConfigHandler_EmptySnapshotGuardStillWins verifies the pre-existing
// empty-snapshot guard still short-circuits before the regression guard.
func TestConfigHandler_EmptySnapshotGuardStillWins(t *testing.T) {
	handler, applier := newRegressionTestHandler(t)

	handler.MarkReconnected()

	err := handler.HandleSnapshot(context.Background(), &operatorv1alpha1.ConfigurationSnapshot{Version: "empty"})
	require.NoError(t, err)

	assert.Equal(t, 3, handler.runningResourceCount())
	// Seed apply is the only expected full-config application.
	applier.AssertNumberOfCalls(t, "ApplyFullConfig", 1)
}

// TestConfigHandler_ShouldDeferRegressingSnapshot_Counts verifies the count
// bookkeeping used in the deferral decision and its log fields.
func TestConfigHandler_ShouldDeferRegressingSnapshot_Counts(t *testing.T) {
	handler, _ := newRegressionTestHandler(t)
	handler.MarkReconnected()

	newCount, runningCount, deferred := handler.shouldDeferRegressingSnapshot(
		snapshotWithRoutes(t, "partial", 2))
	assert.Equal(t, 2, newCount)
	assert.Equal(t, 3, runningCount)
	assert.True(t, deferred)

	newCount, runningCount, deferred = handler.shouldDeferRegressingSnapshot(
		snapshotWithRoutes(t, "bigger", 4))
	assert.Equal(t, 4, newCount)
	assert.Equal(t, 3, runningCount)
	assert.False(t, deferred)
}

// TestConfigHandler_MarkReconnected_RestartsWindow verifies each reconnect
// re-arms the window.
func TestConfigHandler_MarkReconnected_RestartsWindow(t *testing.T) {
	handler := NewConfigHandler(nil)

	assert.False(t, handler.withinReconnectWindow(), "window inactive before any reconnect")

	handler.MarkReconnected()
	assert.True(t, handler.withinReconnectWindow(), "window active right after reconnect")

	// Expire the window, then re-arm it with a fresh reconnect.
	handler.reconnectedAt.Store(time.Now().Add(-snapshotRegressionWindow - time.Second).UnixNano())
	assert.False(t, handler.withinReconnectWindow(), "window expired")

	handler.MarkReconnected()
	assert.True(t, handler.withinReconnectWindow(), "window re-armed by a new reconnect")
}
