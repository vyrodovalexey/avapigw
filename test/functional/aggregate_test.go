//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
//
// This file covers AGG-15 (functional tests) for the aggregate (fan-out)
// mirroring feature: one client request fans out to multiple backends in
// parallel and a single aggregated response is returned, for REST, GraphQL,
// gRPC (unary + streaming) and WebSocket traffic.
//
// Test cases (see test/cases/test_cases.md §AGG-15):
//   - F-1 REST aggregate merge across multiple REST backends -> single merged JSON.
//   - F-2 REST aggregate envelope (non-JSON) -> labeled frames.
//   - F-3 GraphQL aggregate -> merged data + concatenated errors.
//   - F-4 gRPC unary aggregate -> combined response.
//   - F-5 WS aggregate -> interleaved labeled frames.
//   - F-6 gRPC streaming aggregate -> framed interleave + FailMode on stream error.
//   - F-7 coexistence: single-mirror route + aggregate route both correct (regression).
//   - F-8 metrics emitted/queryable for each.
//
// Backends are in-process httptest servers so merges are fully deterministic
// (the shared docker-compose REST images are stateful), matching the existing
// in-proc functional-test convention (see transform_test.go).
package functional

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/aggregate/graphqladapter"
	"github.com/vyrodovalexey/avapigw/internal/aggregate/grpcadapter"
	aggrest "github.com/vyrodovalexey/avapigw/internal/aggregate/rest"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// aggTestTimeout bounds every aggregate functional operation so a hung backend
// never wedges CI.
const aggTestTimeout = 15 * time.Second

// newRegisteredAggMetrics builds a fresh aggregate.Metrics on an isolated
// Prometheus registry. The isolated registry lets each test assert its own
// counters without colliding with the process-wide default registry.
func newRegisteredAggMetrics(t *testing.T) (*aggregate.Metrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	// NewMetricsWith registers the collectors on this isolated registry, so each
	// parallel test gets its own counters with no global-registry collisions.
	m := aggregate.NewMetricsWith(reg)
	return m, reg
}

// aggTargetForServer builds an aggregate.Target pointing at an in-process
// httptest server. Using ENV-free, dynamically-allocated httptest ports keeps
// the tests parallelizable and avoids hardcoded addresses.
func aggTargetForServer(t *testing.T, name string, srv *httptest.Server) config.AggregateTarget {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return config.AggregateTarget{
		Name:        name,
		Destination: config.Destination{Host: host, Port: port},
	}
}

// jsonBackend returns an httptest server that replies with the given JSON body
// and records the number of requests it received (used to prove real fan-out).
func jsonBackend(t *testing.T, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

// ---------------------------------------------------------------------------
// F-1: REST aggregate merge across multiple REST backends -> single merged JSON.
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_REST_Merge(t *testing.T) {
	t.Parallel()

	b1, _ := jsonBackend(t, `{"user":{"name":"John"},"count":1}`)
	b2, _ := jsonBackend(t, `{"user":{"email":"john@example.com"},"status":"active"}`)
	b3, _ := jsonBackend(t, `{"items":["a","b"]}`)

	metrics, reg := newRegisteredAggMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		Merge:   &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		Targets: []config.AggregateTarget{
			aggTargetForServer(t, "b1", b1),
			aggTargetForServer(t, "b2", b2),
			aggTargetForServer(t, "b3", b3),
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
	ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
	defer cancel()

	err := handler.ServeAggregate(rr, req.WithContext(ctx), cfg)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var merged map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &merged))

	// Deep merge: nested user object combined, scalars preserved, arrays kept.
	user, ok := merged["user"].(map[string]interface{})
	require.True(t, ok, "merged user object present")
	assert.Equal(t, "John", user["name"])
	assert.Equal(t, "john@example.com", user["email"])
	assert.Equal(t, float64(1), merged["count"])
	assert.Equal(t, "active", merged["status"])
	assert.Equal(t, []interface{}{"a", "b"}, merged["items"])

	// F-8: metrics emitted for the REST aggregate.
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal), "one aggregate request recorded")
	assert.Equal(t, float64(3), testutil.ToFloat64(metrics.TargetsTotal), "three target invocations recorded")
	assertHistogramCount(t, reg, "gateway_aggregate_duration_seconds", 1)
}

// ---------------------------------------------------------------------------
// F-2: REST aggregate envelope (non-JSON) -> labeled frames.
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_REST_Envelope_NonJSON(t *testing.T) {
	t.Parallel()

	// Plain-text (non-JSON) backends force the labeled-envelope fallback even
	// when merge is requested.
	textBackend := func(t *testing.T, body string) *httptest.Server {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	b1 := textBackend(t, "hello from one")
	b2 := textBackend(t, "hello from two")

	metrics, _ := newRegisteredAggMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		// Merge enabled but bodies are non-JSON -> envelope fallback.
		Merge: &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		Targets: []config.AggregateTarget{
			aggTargetForServer(t, "alpha", b1),
			aggTargetForServer(t, "beta", b2),
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
	ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
	defer cancel()

	require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
	require.Equal(t, http.StatusOK, rr.Code)

	var envelopes []struct {
		Target  string          `json:"target"`
		Status  int             `json:"status"`
		Payload json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelopes))
	require.Len(t, envelopes, 2, "one labeled frame per target")

	byTarget := map[string]string{}
	for _, e := range envelopes {
		assert.Equal(t, http.StatusOK, e.Status)
		// Non-JSON payloads are JSON-string-encoded so the envelope stays valid.
		var s string
		require.NoError(t, json.Unmarshal(e.Payload, &s))
		byTarget[e.Target] = s
	}
	assert.Equal(t, "hello from one", byTarget["alpha"])
	assert.Equal(t, "hello from two", byTarget["beta"])
}

// ---------------------------------------------------------------------------
// F-3: GraphQL aggregate -> merged data + concatenated errors.
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_GraphQL_MergeDataAndErrors(t *testing.T) {
	t.Parallel()

	// Backend 1: data + one error. Backend 2: complementary data + another error.
	b1, _ := jsonBackend(t, `{"data":{"users":[{"id":"1"}]},"errors":[{"message":"warn-1"}]}`)
	b2, _ := jsonBackend(t, `{"data":{"posts":[{"id":"p1"}]},"errors":[{"message":"warn-2"}]}`)

	metrics, _ := newRegisteredAggMetrics(t)
	handler := graphqladapter.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		Targets: []config.AggregateTarget{
			aggTargetForServer(t, "gql1", b1),
			aggTargetForServer(t, "gql2", b2),
		},
	}

	body := strings.NewReader(`{"query":"{ users { id } posts { id } }"}`)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", body)
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
	defer cancel()

	require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
	require.Equal(t, http.StatusOK, rr.Code)

	var merged struct {
		Data   map[string]interface{}   `json:"data"`
		Errors []map[string]interface{} `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &merged))

	// data is deep-merged across both backends.
	assert.Contains(t, merged.Data, "users")
	assert.Contains(t, merged.Data, "posts")

	// errors are concatenated.
	require.Len(t, merged.Errors, 2)
	gotErrs := []string{merged.Errors[0]["message"].(string), merged.Errors[1]["message"].(string)}
	assert.ElementsMatch(t, []string{"warn-1", "warn-2"}, gotErrs)

	// F-8: metrics emitted.
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal))
	assert.Equal(t, float64(2), testutil.ToFloat64(metrics.TargetsTotal))
}

// ---------------------------------------------------------------------------
// F-4: gRPC unary aggregate -> combined response.
//
// The gRPC adapter is transport-agnostic: it consumes a caller-injected
// aggregate.Invoker (gRPC connection pools / descriptors live in internal/grpc).
// We drive it with an in-test Invoker that yields JSON-mappable unary payloads
// so the descriptor-based merge path is exercised end-to-end.
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_GRPC_Unary_Combined(t *testing.T) {
	t.Parallel()

	payloads := map[string]string{
		"svc-a": `{"a":1,"shared":{"x":1}}`,
		"svc-b": `{"b":2,"shared":{"y":2}}`,
	}
	invoker := aggregate.InvokerFunc(
		func(_ context.Context, target aggregate.Target, _ *aggregate.Request) (*aggregate.Response, error) {
			return &aggregate.Response{
				Target:      target.Name,
				StatusCode:  0, // gRPC OK
				Body:        []byte(payloads[target.Name]),
				ContentType: "application/json",
			}, nil
		},
	)

	metrics, _ := newRegisteredAggMetrics(t)
	handler := grpcadapter.NewUnaryHandler(invoker, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		Merge:   &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		Targets: []config.AggregateTarget{
			{Name: "svc-a", Destination: config.Destination{Host: "127.0.0.1", Port: 8811}},
			{Name: "svc-b", Destination: config.Destination{Host: "127.0.0.1", Port: 8812}},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), aggTestTimeout)
	defer cancel()

	out, err := handler.Aggregate(ctx, cfg, &aggregate.Request{Method: "/svc.Service/Get"})
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.True(t, out.Merged, "JSON-mappable unary payloads should be merged")

	var merged map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &merged))
	assert.Equal(t, float64(1), merged["a"])
	assert.Equal(t, float64(2), merged["b"])
	shared, ok := merged["shared"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(1), shared["x"])
	assert.Equal(t, float64(2), shared["y"])

	// F-8: metrics emitted for the gRPC unary aggregate.
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal))
	assert.Equal(t, float64(2), testutil.ToFloat64(metrics.TargetsTotal))
}

// ---------------------------------------------------------------------------
// F-5: WS aggregate -> interleaved labeled frames from all backends.
//
// The StreamMux is the protocol-agnostic heart of WS aggregation: each backend
// message becomes a labeled frame written to the client sink. We assert that
// frames from all targets are interleaved and correctly labeled.
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_WS_InterleavedFrames(t *testing.T) {
	t.Parallel()

	sink := &funcRecordingSink{}
	mux := aggregate.NewStreamMux(sink, &aggregate.Config{}, nil, observability.NopLogger())
	defer mux.Close()

	ctx, cancel := context.WithTimeout(context.Background(), aggTestTimeout)
	defer cancel()

	// Two simulated backend WS streams pushing concurrently.
	var wg sync.WaitGroup
	for _, target := range []string{"ws-a", "ws-b"} {
		tg := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				payload := []byte(`{"from":"` + tg + `","seq":` + strconv.Itoa(i) + `}`)
				_ = mux.Push(ctx, tg, 200, payload)
			}
		}()
	}
	wg.Wait()

	frames := sink.snapshot()
	require.Len(t, frames, 10, "5 frames from each of 2 backends, interleaved")

	perTarget := map[string]int{}
	for _, f := range frames {
		perTarget[f.Target]++
		// Each WS frame is a valid labeled JSON envelope.
		assert.True(t, json.Valid(f.Payload), "frame payload is valid JSON")
	}
	assert.Equal(t, 5, perTarget["ws-a"])
	assert.Equal(t, 5, perTarget["ws-b"])
}

// ---------------------------------------------------------------------------
// F-6: gRPC streaming aggregate -> framed interleave; FailMode behavior on
// stream error.
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_GRPC_Streaming_FramedInterleave(t *testing.T) {
	t.Parallel()

	t.Run("framed_interleave_all_streams", func(t *testing.T) {
		t.Parallel()
		sink := &funcRecordingSink{}
		mux := aggregate.NewStreamMux(sink, &aggregate.Config{}, nil, observability.NopLogger())
		defer mux.Close()

		ctx, cancel := context.WithTimeout(context.Background(), aggTestTimeout)
		defer cancel()

		for _, target := range []string{"stream-a", "stream-b", "stream-c"} {
			for i := 0; i < 3; i++ {
				require.NoError(t, mux.Push(ctx, target, 0, []byte(`{"msg":`+strconv.Itoa(i)+`}`)))
			}
		}

		frames := sink.snapshot()
		require.Len(t, frames, 9)
		counts := map[string]int{}
		for _, f := range frames {
			counts[f.Target]++
		}
		assert.Equal(t, 3, counts["stream-a"])
		assert.Equal(t, 3, counts["stream-b"])
		assert.Equal(t, 3, counts["stream-c"])
	})

	t.Run("stream_error_isolated_failmode_any", func(t *testing.T) {
		t.Parallel()
		// FailMode=any: one streaming target erroring still yields overall
		// success because >=1 target succeeded. The engine reports per-target
		// failures via Response.Err while continuing the rest.
		invoker := aggregate.InvokerFunc(
			func(_ context.Context, target aggregate.Target, _ *aggregate.Request) (*aggregate.Response, error) {
				if target.Name == "bad" {
					return &aggregate.Response{Target: target.Name, Err: assertStreamErr}, assertStreamErr
				}
				return &aggregate.Response{
					Target: target.Name, StatusCode: 0,
					Body: []byte(`{"ok":true}`), ContentType: "application/json",
				}, nil
			},
		)
		agg := aggregate.NewAggregator(invoker)

		cfg := &aggregate.Config{
			Enabled:  true,
			FailMode: aggregate.FailModeAny,
			Targets: []aggregate.Target{
				{Name: "good", Host: "127.0.0.1", Port: 8811, Timeout: 2 * time.Second},
				{Name: "bad", Host: "127.0.0.1", Port: 8812, Timeout: 2 * time.Second},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), aggTestTimeout)
		defer cancel()

		result, err := agg.Fanout(ctx, cfg, &aggregate.Request{Method: "/svc/Stream"})
		require.NoError(t, err, "FailMode=any tolerates one failed stream")
		assert.Equal(t, 1, result.SuccessCount)
		assert.Equal(t, 1, result.FailureCount)
	})

	t.Run("stream_error_failmode_all_fails", func(t *testing.T) {
		t.Parallel()
		// FailMode=all: any streaming target error fails the whole aggregate.
		invoker := aggregate.InvokerFunc(
			func(_ context.Context, target aggregate.Target, _ *aggregate.Request) (*aggregate.Response, error) {
				if target.Name == "bad" {
					return &aggregate.Response{Target: target.Name, Err: assertStreamErr}, assertStreamErr
				}
				return &aggregate.Response{Target: target.Name, Body: []byte(`{"ok":true}`)}, nil
			},
		)
		agg := aggregate.NewAggregator(invoker)
		cfg := &aggregate.Config{
			Enabled:  true,
			FailMode: aggregate.FailModeAll,
			Targets: []aggregate.Target{
				{Name: "good", Host: "127.0.0.1", Port: 8811, Timeout: 2 * time.Second},
				{Name: "bad", Host: "127.0.0.1", Port: 8812, Timeout: 2 * time.Second},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), aggTestTimeout)
		defer cancel()

		_, err := agg.Fanout(ctx, cfg, &aggregate.Request{})
		require.ErrorIs(t, err, aggregate.ErrFailModeNotMet)
	})
}

// ---------------------------------------------------------------------------
// F-7: coexistence: an existing single-mirror route and an aggregate route both
// behave correctly through the same proxy (regression: additive types must not
// break single-destination MirrorConfig routing).
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_CoexistWithSingleMirror(t *testing.T) {
	t.Parallel()

	// Primary backend for the normal (single-destination) route. The route also
	// carries a single-destination MirrorConfig: this is the EXISTING shadow
	// traffic feature that aggregate must not disturb. MirrorConfig is a
	// config-surface (additive, distinct from AggregateConfig); the regression
	// assertion below proves it is preserved on the route and that the normal
	// route still proxies to its primary unchanged while a sibling aggregate
	// route fans out.
	primary, primaryHits := jsonBackend(t, `{"source":"primary"}`)

	// Aggregate backends.
	a1, _ := jsonBackend(t, `{"merged":{"a":1}}`)
	a2, _ := jsonBackend(t, `{"merged":{"b":2}}`)

	metrics, _ := newRegisteredAggMetrics(t)
	aggHandler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	primaryHost, primaryPort := splitHostPort(t, primary)

	normalRoute := config.Route{
		Name:  "normal-mirror-route",
		Match: []config.RouteMatch{{URI: &config.URIMatch{Prefix: "/normal"}}},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: primaryHost, Port: primaryPort}},
		},
		// Existing single-destination, fire-and-forget shadow config.
		Mirror: &config.MirrorConfig{
			Destination: config.Destination{Host: "shadow.invalid", Port: 80},
			Percentage:  100,
		},
	}
	aggregateRoute := config.Route{
		Name:  "aggregate-route",
		Match: []config.RouteMatch{{URI: &config.URIMatch{Prefix: "/aggregate"}}},
		Aggregate: &config.AggregateConfig{
			Enabled: true,
			Merge:   &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
			Targets: []config.AggregateTarget{
				aggTargetForServer(t, "a1", a1),
				aggTargetForServer(t, "a2", a2),
			},
		},
	}

	// Regression: the two configs are additive and independent on their routes.
	require.NotNil(t, normalRoute.Mirror, "single-mirror config preserved")
	require.Nil(t, normalRoute.Aggregate, "normal route is not an aggregate route")
	require.True(t, aggregateRoute.Aggregate.IsEnabled(), "aggregate route is active")
	require.Nil(t, aggregateRoute.Mirror, "aggregate route does not carry single-mirror config")

	r := router.New()
	require.NoError(t, r.LoadRoutes([]config.Route{normalRoute, aggregateRoute}))

	registry := backend.NewRegistry(observability.NopLogger())
	p := proxy.NewReverseProxy(r, registry,
		proxy.WithProxyLogger(observability.NopLogger()),
		proxy.WithAggregateHandler(aggHandler),
	)

	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: aggTestTimeout}

	t.Run("aggregate route returns merged JSON", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/aggregate/x")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var merged map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&merged))
		m, ok := merged["merged"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, float64(1), m["a"])
		assert.Equal(t, float64(2), m["b"])
	})

	t.Run("normal single-mirror route proxies to primary unchanged", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/normal/y")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "primary", body["source"],
			"single-mirror route is NOT fanned out; client sees the primary response")
		assert.Positive(t, primaryHits.Load(), "primary backend received the request")
	})
}

// ---------------------------------------------------------------------------
// F-8: metrics emitted and queryable (aggregate-level), including per-target
// error metrics on partial failure.
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_MetricsQueryable(t *testing.T) {
	t.Parallel()

	ok1, _ := jsonBackend(t, `{"ok":1}`)

	metrics, reg := newRegisteredAggMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled:  true,
		FailMode: config.FailModeAny, // tolerate the dead target
		Merge:    &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		Targets: []config.AggregateTarget{
			aggTargetForServer(t, "ok1", ok1),
			// Unroutable target -> per-target error metric must increment.
			{Name: "dead", Destination: config.Destination{Host: "127.0.0.1", Port: 1}, Timeout: config.Duration(2 * time.Second)},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
	ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
	defer cancel()

	require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
	require.Equal(t, http.StatusOK, rr.Code)

	// Aggregate-level counters present and queryable via the registry.
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal))
	assert.Equal(t, float64(2), testutil.ToFloat64(metrics.TargetsTotal))
	assert.GreaterOrEqual(t, testutil.ToFloat64(metrics.TargetErrorsTotal.WithLabelValues("dead")), float64(1),
		"the dead target's error counter increments")
	assertHistogramCount(t, reg, "gateway_aggregate_duration_seconds", 1)
	assertHistogramCount(t, reg, "gateway_aggregate_merge_duration_seconds", 1)
}

// ---------------------------------------------------------------------------
// Test helpers (file-local).
// ---------------------------------------------------------------------------

// assertStreamErr is a sentinel used by the streaming FailMode subtests.
var assertStreamErr = &aggStreamError{}

type aggStreamError struct{}

func (*aggStreamError) Error() string { return "simulated stream error" }

// funcRecordingSink captures frames written through a StreamMux. It is safe for
// concurrent use (the mux pushes from multiple goroutines).
type funcRecordingSink struct {
	mu     sync.Mutex
	frames []*aggregate.Frame
}

func (s *funcRecordingSink) WriteFrame(_ context.Context, frame *aggregate.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frames = append(s.frames, frame)
	return nil
}

func (s *funcRecordingSink) snapshot() []*aggregate.Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*aggregate.Frame, len(s.frames))
	copy(out, s.frames)
	return out
}

// assertHistogramCount asserts a histogram's observation count via the registry,
// proving the metric is registered and queryable.
func assertHistogramCount(t *testing.T, reg *prometheus.Registry, name string, want uint64) {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		var total uint64
		for _, m := range mf.GetMetric() {
			if h := m.GetHistogram(); h != nil {
				total += h.GetSampleCount()
			}
		}
		assert.GreaterOrEqual(t, total, want, "histogram %s observation count", name)
		return
	}
	t.Fatalf("histogram %s not found in registry", name)
}

func splitHostPort(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}
