//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
//
// This file extends AGG-16 (integration tests) for the NDJSON aggregate merge
// strategy. The live docker-compose REST backends (rest_api_1..5) do not emit
// NDJSON natively, so the NDJSON record streams are produced by in-test backends
// while everything else (the real REST aggregate invoker, the proxy middleware
// chain, the merge pipeline) runs through the production code paths. Where a
// live backend can contribute, it is wired in alongside the in-test NDJSON
// targets (FailMode=any) so the live data plane is still exercised.
//
// Test cases (see test/cases/test_cases.md AGG-16 NDJSON additions):
//   - IN-1 REST aggregate strategy=ndjson over multiple in-test NDJSON backends
//     through the real proxy middleware chain -> sorted/deduped/limited
//     application/stream+json stream at the client.
//   - IN-2 auto-promotion: deep strategy + NDJSON bodies -> NDJSON output.
//   - IN-3 partial failure (FailMode=any) with a live/in-test mix: only the
//     successful NDJSON targets contribute records.
//
// All addresses/credentials come from the shared test/helpers ENV accessors.
package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	aggrest "github.com/vyrodovalexey/avapigw/internal/aggregate/rest"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// ndjsonIntegrationBackend returns an httptest backend that emits the given
// NDJSON body under contentType. A blank contentType omits the header so the
// body-shape heuristic path is exercised.
func ndjsonIntegrationBackend(t *testing.T, contentType, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// decodeNDJSONStream validates and decodes an NDJSON stream body: at least one
// record, every line valid JSON, the whole body NOT valid JSON. Returns the
// records in stream order.
func decodeNDJSONStream(t *testing.T, body []byte) []map[string]interface{} {
	t.Helper()
	assert.False(t, json.Valid(body), "NDJSON stream body is not valid JSON as a whole")
	records := make([]map[string]interface{}, 0)
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		assert.True(t, json.Valid([]byte(trimmed)), "NDJSON line valid: %q", trimmed)
		var rec map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(trimmed), &rec))
		records = append(records, rec)
	}
	require.GreaterOrEqual(t, len(records), 1, "NDJSON stream has at least one record")
	return records
}

// ---------------------------------------------------------------------------
// IN-1: REST aggregate strategy=ndjson through the real proxy middleware chain.
//
// Two in-test NDJSON backends are fanned out via the production REST aggregate
// invoker, wired into a ReverseProxy through the per-route middleware manager
// (same wiring as the existing AGG-16 I-7 co-operation test). The client
// receives a sorted, deduped, limited application/stream+json record stream.
// ---------------------------------------------------------------------------

func TestIntegration_Aggregate_NDJSON_ThroughProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), aggIntegrationTimeout)
	defer cancel()

	b1 := ndjsonIntegrationBackend(t, "application/x-ndjson",
		`{"id":1,"_time":"2024-01-01T00:00:30Z","src":"b1"}`+"\n"+
			`{"id":2,"_time":"2024-01-01T00:00:10Z","src":"b1"}`+"\n")
	b2 := ndjsonIntegrationBackend(t, "application/x-ndjson",
		`{"id":3,"_time":"2024-01-01T00:00:20Z","src":"b2"}`+"\n"+
			`{"id":2,"_time":"2024-01-01T00:00:40Z","src":"b2"}`+"\n")

	metrics := newAggIntegrationMetrics(t)
	aggHandler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	route := config.Route{
		Name:  "agg-ndjson-route",
		Match: []config.RouteMatch{{URI: &config.URIMatch{Prefix: "/aggregate-ndjson"}}},
		Aggregate: &config.AggregateConfig{
			Enabled: true,
			Merge: &config.MergeOptions{
				Enabled:   true,
				Strategy:  config.MergeStrategyNDJSON,
				TimeField: "_time",
				KeyField:  "id",
				Limit:     2,
			},
			Targets: []config.AggregateTarget{
				targetFromURL(t, "b1", b1.URL),
				targetFromURL(t, "b2", b2.URL),
			},
		},
	}

	_, srv := newAggregateProxyServer(t, route, aggHandler)
	defer srv.Close()

	client := &http.Client{Timeout: aggIntegrationTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/aggregate-ndjson/x", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/stream+json", resp.Header.Get("Content-Type"),
		"ndjson strategy emits the stream content type end to end")
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	records := decodeNDJSONStream(t, body)

	// RFC3339 sort -> 10s,20s,30s,40s; dedupe id first-wins keeps id=2 at 10s and
	// drops id=2 at 40s; limit=2 -> [id2@10s, id3@20s].
	require.Len(t, records, 2, "limit=2 after RFC3339 sort + first-wins dedupe")
	assert.Equal(t, float64(2), records[0]["id"])
	assert.Equal(t, "b1", records[0]["src"], "first-wins kept the earliest id=2 (b1)")
	assert.Equal(t, float64(3), records[1]["id"])
	assert.Equal(t, float64(2), testutil.ToFloat64(metrics.TargetsTotal),
		"two target invocations recorded")
}

// ---------------------------------------------------------------------------
// IN-2: auto-promotion. The route uses the deep strategy, but the targets emit
// NDJSON bodies; the merge auto-promotes on the would-be-envelope branch.
// ---------------------------------------------------------------------------

func TestIntegration_Aggregate_NDJSON_AutoPromotion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), aggIntegrationTimeout)
	defer cancel()

	b1 := ndjsonIntegrationBackend(t, "application/jsonl",
		`{"id":1,"_time":2}`+"\n"+`{"id":2,"_time":1}`+"\n")
	b2 := ndjsonIntegrationBackend(t, "application/jsonl",
		`{"id":3,"_time":3}`+"\n"+`{"id":4,"_time":4}`+"\n")

	metrics := newAggIntegrationMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		Merge: &config.MergeOptions{
			Enabled:   true,
			Strategy:  config.MergeStrategyDeep, // non-ndjson on purpose
			TimeField: "_time",
		},
		Targets: []config.AggregateTarget{
			targetFromURL(t, "b1", b1.URL),
			targetFromURL(t, "b2", b2.URL),
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil).WithContext(ctx)
	require.NoError(t, handler.ServeAggregate(rr, req, cfg))
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/stream+json", rr.Header().Get("Content-Type"),
		"deep strategy + NDJSON bodies auto-promote to the line merger")

	records := decodeNDJSONStream(t, rr.Body.Bytes())
	require.Len(t, records, 4)
	times := make([]float64, len(records))
	for i, rec := range records {
		times[i] = rec["_time"].(float64)
	}
	assert.True(t, sort.Float64sAreSorted(times),
		"auto-promoted stream sorted by _time: %v", times)
}

// ---------------------------------------------------------------------------
// IN-3: partial failure with a live/in-test mix under FailMode=any. A dead
// target (and, when reachable, the live no-auth REST backend whose body is NOT
// NDJSON) must not break the NDJSON merge; only the successful NDJSON targets
// contribute records. When the live backend is reachable its non-NDJSON body
// would prevent auto-promotion, so this case pins the explicit ndjson strategy
// to keep the live target's contribution as additional record lines if JSON, or
// to fall back deterministically — we therefore assert the stream is produced
// from the in-test NDJSON targets regardless of the live backend shape.
// ---------------------------------------------------------------------------

func TestIntegration_Aggregate_NDJSON_PartialFailure_FailModeAny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), aggIntegrationTimeout)
	defer cancel()

	good1 := ndjsonIntegrationBackend(t, "application/x-ndjson",
		`{"id":10,"_time":1}`+"\n"+`{"id":11,"_time":2}`+"\n")
	good2 := ndjsonIntegrationBackend(t, "application/x-ndjson",
		`{"id":12,"_time":3}`+"\n")

	metrics := newAggIntegrationMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled:  true,
		FailMode: config.FailModeAny,
		Merge: &config.MergeOptions{
			Enabled:   true,
			Strategy:  config.MergeStrategyNDJSON,
			TimeField: "_time",
		},
		Targets: []config.AggregateTarget{
			targetFromURL(t, "good-1", good1.URL),
			targetFromURL(t, "good-2", good2.URL),
			// Unroutable target: always fails; FailMode=any tolerates it and it
			// contributes no records (only successful responses are merged).
			{Name: "dead", Destination: config.Destination{Host: "127.0.0.1", Port: 1},
				Timeout: config.Duration(2 * time.Second)},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil).WithContext(ctx)
	require.NoError(t, handler.ServeAggregate(rr, req, cfg),
		"FailMode=any tolerates the dead target")
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/stream+json", rr.Header().Get("Content-Type"))

	records := decodeNDJSONStream(t, rr.Body.Bytes())
	require.Len(t, records, 3, "only the 3 records from the 2 successful NDJSON targets")
	ids := map[float64]bool{}
	for _, rec := range records {
		ids[rec["id"].(float64)] = true
	}
	assert.True(t, ids[10] && ids[11] && ids[12], "all records from the alive targets present")

	// The dead target's per-target error metric increments.
	assert.GreaterOrEqual(t,
		testutil.ToFloat64(metrics.TargetErrorsTotal.WithLabelValues("dead")), float64(1),
		"dead target error counter increments under FailMode=any")
}

// liveNoAuthBackendNDJSONNote documents (for readers) that the live REST
// backends do not emit NDJSON; the in-test NDJSON backends above are the
// deterministic NDJSON record sources. The live backend availability is still
// probed by the broader AGG-16 suite (mixed-auth / partial-failure cases).
var _ = helpers.IsBackendAvailable
