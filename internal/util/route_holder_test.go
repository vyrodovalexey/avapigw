package util

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRouteHolder_SetGet covers basic set/get plus nil-safety and the
// empty-write guard.
func TestRouteHolder_SetGet(t *testing.T) {
	t.Parallel()

	var nilHolder *RouteHolder
	assert.Equal(t, "", nilHolder.Get(), "nil holder must read empty")
	nilHolder.Set("x") // must not panic

	h := &RouteHolder{}
	assert.Equal(t, "", h.Get(), "fresh holder is empty")

	h.Set("orders")
	assert.Equal(t, "orders", h.Get())

	h.Set("") // empty writes are ignored so a match is never erased
	assert.Equal(t, "orders", h.Get())

	h.Set("payments")
	assert.Equal(t, "payments", h.Get(), "later non-empty writes win")
}

// TestContextWithRouteHolder_RoundTrip verifies holder installation and
// extraction plus the nil-context-value fallback.
func TestContextWithRouteHolder_RoundTrip(t *testing.T) {
	t.Parallel()

	assert.Nil(t, RouteHolderFromContext(context.Background()),
		"no holder installed -> nil")

	h := &RouteHolder{}
	ctx := ContextWithRouteHolder(context.Background(), h)
	assert.Same(t, h, RouteHolderFromContext(ctx))
}

// TestContextWithRoute_FeedsInstalledHolder is the regression test for the
// unmatched-label fix: a route recorded DOWNSTREAM via ContextWithRoute must
// become visible through the holder installed UPSTREAM.
func TestContextWithRoute_FeedsInstalledHolder(t *testing.T) {
	t.Parallel()

	holder := &RouteHolder{}
	ctx := ContextWithRouteHolder(context.Background(), holder)

	derived := ContextWithRoute(ctx, "matched-route")

	assert.Equal(t, "matched-route", RouteFromContext(derived),
		"downstream readers see the direct context value")
	assert.Equal(t, "matched-route", holder.Get(),
		"upstream observers see the match through the holder")
}

// TestRouteHolder_ConcurrentAccess exercises the holder under the race
// detector.
func TestRouteHolder_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	h := &RouteHolder{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			h.Set("route-a")
		}()
		go func() {
			defer wg.Done()
			_ = h.Get()
		}()
	}
	wg.Wait()
	assert.Equal(t, "route-a", h.Get())
}
