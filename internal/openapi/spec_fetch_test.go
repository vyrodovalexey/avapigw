package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxBoundedWait is the generous CI-safe ceiling within which a bounded spec
// load must fail. The actual configured timeouts in these tests are ~150ms.
const maxBoundedWait = 5 * time.Second

// testLoadTimeout is the shortened spec-load timeout injected via the
// unexported Validator seam so hang tests stay fast.
const testLoadTimeout = 150 * time.Millisecond

// withSpecLoadTimeout overrides the validator's spec-load timeout.
// Test-only seam using the unexported loadTimeout field.
func withSpecLoadTimeout(d time.Duration) Option {
	return func(v *Validator) { v.loadTimeout = d }
}

// hangingHandler blocks until the client abandons the request, simulating an
// unresponsive spec source without long test sleeps or leaked goroutines.
func hangingHandler() http.HandlerFunc {
	return func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}
}

// minimalSpecData reads the minimal valid OpenAPI spec fixture.
func minimalSpecData(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir(), "minimal.yaml"))
	require.NoError(t, err)
	return data
}

// countingSpecServer serves the minimal spec and counts requests.
func countingSpecServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	specData := minimalSpecData(t)

	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(specData)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func TestNewSpecLoader_DefaultFetchTimeout(t *testing.T) {
	t.Parallel()

	loader := NewSpecLoader()
	require.NotNil(t, loader.httpClient, "spec loader must use a dedicated HTTP client")
	assert.Equal(t, defaultSpecFetchTimeout, loader.httpClient.Timeout,
		"spec fetch client must be bounded by defaultSpecFetchTimeout")
	assert.Equal(t, 30*time.Second, defaultSpecFetchTimeout)
}

// HAPPY: a valid spec URL loads through the timeout-bounded client.
func TestSpecLoader_LoadFromURL_HappyWithBoundedClient(t *testing.T) {
	t.Parallel()

	server, calls := countingSpecServer(t)

	loader := NewSpecLoader()
	doc, err := loader.LoadFromURL(context.Background(), server.URL+"/spec.yaml")

	require.NoError(t, err)
	require.NotNil(t, doc)
	assert.NotEmpty(t, doc.Info.Title)
	assert.Equal(t, int64(1), calls.Load())
}

// ERROR: a hanging spec URL fails within the bounded fetch timeout instead of
// hanging forever (short timeout injected via the unexported httpClient seam).
func TestSpecLoader_LoadFromURL_HangingURL_FailsWithinTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(hangingHandler())
	defer server.Close()

	loader := NewSpecLoader()
	loader.httpClient = &http.Client{Timeout: testLoadTimeout}

	start := time.Now()
	doc, err := loader.LoadFromURL(context.Background(), server.URL+"/spec.yaml")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, doc)
	assert.Contains(t, err.Error(), "failed to load OpenAPI spec from URL")
	assert.Less(t, elapsed, maxBoundedWait,
		"hanging spec URL must fail within the bounded fetch timeout")
}

// EDGE: a pre-canceled caller context aborts the load immediately.
func TestSpecLoader_LoadFromURL_ContextCanceledBeforeLoad(t *testing.T) {
	t.Parallel()

	server, calls := countingSpecServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	loader := NewSpecLoader()
	start := time.Now()
	doc, err := loader.LoadFromURL(ctx, server.URL+"/spec.yaml")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, doc)
	require.ErrorIs(t, err, context.Canceled, "caller cancellation must propagate")
	assert.Less(t, elapsed, maxBoundedWait)
	assert.Equal(t, int64(0), calls.Load(), "no fetch should complete after cancellation")
}

// EDGE: canceling the caller context mid-fetch aborts the load promptly.
func TestSpecLoader_LoadFromURL_ContextCanceledMidFlight(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(hangingHandler())
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(50*time.Millisecond, cancel)
	defer timer.Stop()

	loader := NewSpecLoader()
	start := time.Now()
	doc, err := loader.LoadFromURL(ctx, server.URL+"/spec.yaml")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, doc)
	require.ErrorIs(t, err, context.Canceled, "mid-flight cancellation must propagate")
	assert.Less(t, elapsed, maxBoundedWait,
		"canceled load must abort promptly instead of waiting for the server")
}

// SECURITY: the custom URI reader must preserve kin-openapi's deny-by-default
// external-reference policy — only the root document may be fetched.
func TestSpecLoader_LoadFromURL_ExternalRefDenied(t *testing.T) {
	t.Parallel()

	const specWithExternalRef = `openapi: "3.0.3"
info:
  title: Ref API
  version: "1.0.0"
paths:
  /items:
    get:
      responses:
        "200":
          description: OK
          content:
            application/json:
              schema:
                $ref: "other.yaml#/components/schemas/Item"
`

	var refCalls atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/spec.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte(specWithExternalRef))
	})
	mux.HandleFunc("/other.yaml", func(w http.ResponseWriter, _ *http.Request) {
		refCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	loader := NewSpecLoader()
	doc, err := loader.LoadFromURL(context.Background(), server.URL+"/spec.yaml")

	require.Error(t, err)
	assert.Nil(t, doc)
	assert.Contains(t, err.Error(), "disallowed external reference")
	assert.Equal(t, int64(0), refCalls.Load(),
		"external reference must not be fetched when external refs are disallowed")
}

// ERROR: validator construction against a hanging spec URL fails within the
// bounded load timeout (injected via the unexported loadTimeout seam).
func TestNewValidator_HangingSpecURL_FailsWithinLoadTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(hangingHandler())
	defer server.Close()

	start := time.Now()
	v, err := NewValidator(
		WithSpecURL(server.URL+"/spec.yaml"),
		withSpecLoadTimeout(testLoadTimeout),
	)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, v)
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"bounded load context must cut off the hanging fetch")
	assert.Less(t, elapsed, maxBoundedWait,
		"validator construction must fail within the bounded load timeout")
}

// ERROR: Reload against a spec URL that starts hanging fails within the
// bounded load timeout instead of stalling the reload path.
func TestValidator_Reload_HangingSpecURL_FailsWithinLoadTimeout(t *testing.T) {
	t.Parallel()

	specData := minimalSpecData(t)

	var served atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if served.CompareAndSwap(false, true) {
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write(specData)
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()

	v, err := NewValidator(
		WithSpecURL(server.URL+"/spec.yaml"),
		withSpecLoadTimeout(testLoadTimeout),
	)
	require.NoError(t, err)
	require.NotNil(t, v)

	start := time.Now()
	err = v.Reload()
	elapsed := time.Since(start)

	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, maxBoundedWait,
		"reload must fail within the bounded load timeout")
}

// Reload must genuinely refetch a URL spec after invalidation: the per-load
// byte cache must not serve stale content across Invalidate/Reload cycles.
func TestValidator_Reload_RefetchesURLSpec(t *testing.T) {
	t.Parallel()

	server, calls := countingSpecServer(t)

	v, err := NewValidator(WithSpecURL(server.URL + "/spec.yaml"))
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, int64(1), calls.Load())

	require.NoError(t, v.Reload())
	assert.Equal(t, int64(2), calls.Load(),
		"reload must refetch the spec after cache invalidation")
}

// ctxCapturingLoader records the deadline of every context passed to it,
// proving that loadSpec receives a bounded context rather than a bare
// context.Background().
type ctxCapturingLoader struct {
	mu           sync.Mutex
	deadlines    []time.Time
	hasDeadlines []bool
	doc          *openapi3.T
}

func (c *ctxCapturingLoader) capture(ctx context.Context) {
	deadline, ok := ctx.Deadline()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines = append(c.deadlines, deadline)
	c.hasDeadlines = append(c.hasDeadlines, ok)
}

func (c *ctxCapturingLoader) LoadFromFile(ctx context.Context, _ string) (*openapi3.T, error) {
	c.capture(ctx)
	return c.doc, nil
}

func (c *ctxCapturingLoader) LoadFromURL(ctx context.Context, _ string) (*openapi3.T, error) {
	c.capture(ctx)
	return c.doc, nil
}

func (c *ctxCapturingLoader) LoadFromData(ctx context.Context, _ []byte) (*openapi3.T, error) {
	c.capture(ctx)
	return c.doc, nil
}

func (c *ctxCapturingLoader) Invalidate(_ string) {}

// snapshot returns copies of the captured deadline slices.
func (c *ctxCapturingLoader) snapshot() ([]time.Time, []bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadlines := make([]time.Time, len(c.deadlines))
	copy(deadlines, c.deadlines)
	hasDeadlines := make([]bool, len(c.hasDeadlines))
	copy(hasDeadlines, c.hasDeadlines)
	return deadlines, hasDeadlines
}

// loadRouterCompatibleDoc loads a parsed spec fixture usable for router creation.
func loadRouterCompatibleDoc(t *testing.T) *openapi3.T {
	t.Helper()
	doc, err := NewSpecLoader().LoadFromFile(
		context.Background(), filepath.Join(testdataDir(), "minimal.yaml"))
	require.NoError(t, err)
	return doc
}

// loadSpec must receive a bounded context on both construction and reload.
func TestValidator_LoadSpec_ContextHasDeadline(t *testing.T) {
	t.Parallel()

	cl := &ctxCapturingLoader{doc: loadRouterCompatibleDoc(t)}

	before := time.Now()
	v, err := NewValidator(WithLoader(cl), WithSpecFile("test.yaml"))
	require.NoError(t, err)
	require.NotNil(t, v)

	require.NoError(t, v.Reload())

	deadlines, hasDeadlines := cl.snapshot()
	require.Len(t, deadlines, 2, "expected one load on construction and one on reload")
	for i, has := range hasDeadlines {
		assert.True(t, has, "loadSpec call %d must receive a deadline-bounded context", i)
		assert.WithinDuration(t, before.Add(defaultSpecFetchTimeout), deadlines[i], maxBoundedWait,
			"loadSpec call %d deadline must be about defaultSpecFetchTimeout from now", i)
	}
}

// A non-positive load timeout must fall back to the default bound instead of
// producing an already-expired context.
func TestValidator_LoadSpecBounded_NonPositiveTimeoutFallsBack(t *testing.T) {
	t.Parallel()

	cl := &ctxCapturingLoader{doc: loadRouterCompatibleDoc(t)}

	before := time.Now()
	v, err := NewValidator(
		WithLoader(cl),
		WithSpecFile("test.yaml"),
		withSpecLoadTimeout(-1),
	)
	require.NoError(t, err)
	require.NotNil(t, v)

	deadlines, hasDeadlines := cl.snapshot()
	require.Len(t, deadlines, 1)
	assert.True(t, hasDeadlines[0])
	assert.WithinDuration(t, before.Add(defaultSpecFetchTimeout), deadlines[0], maxBoundedWait,
		"non-positive timeout must fall back to defaultSpecFetchTimeout")
}
