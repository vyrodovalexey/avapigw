//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
//
// This file extends AGG-15 (functional tests) for the NDJSON aggregate merge
// strategy: fan out, collect newline-delimited JSON records across successful
// targets, optionally sort by a time field, de-dupe by a key field, apply a
// limit, and emit a single application/stream+json record stream.
//
// Test cases (see test/cases/test_cases.md AGG-15 NDJSON additions):
//   - FN-1 explicit strategy=ndjson across multiple in-proc NDJSON backends ->
//     records collected, sorted by _time, deduped by a key, limited; output
//     Content-Type application/stream+json and body is valid NDJSON (each line
//     valid JSON, whole body NOT valid JSON).
//   - FN-2 auto-detection: backends returning application/x-ndjson (and jsonl /
//     stream+json) bodies with merge enabled + a non-ndjson strategy are
//     auto-promoted to NDJSON on the would-be-envelope branch.
//   - FN-3 regression: deep/shallow/replace JSON merge still produces identical
//     JSON (NOT promoted); merge-disabled still envelopes; existing
//     single-mirror + aggregate coexistence is preserved.
//
// Backends are in-process httptest servers so merges are fully deterministic,
// matching the existing in-proc functional-test convention (see
// aggregate_test.go).
package functional

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	aggrest "github.com/vyrodovalexey/avapigw/internal/aggregate/rest"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// ndjsonBackend returns an httptest server that replies with the given NDJSON
// body under the supplied content type. A blank contentType omits the header so
// the body-shape heuristic is exercised.
func ndjsonBackend(t *testing.T, contentType, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// assertValidNDJSONStream asserts that body is a valid NDJSON stream: it has at
// least one non-empty line, every non-empty line is valid JSON on its own, and
// the body as a whole is NOT valid JSON (so it is a record stream, not a single
// document). It returns the decoded records in stream order.
func assertValidNDJSONStream(t *testing.T, body []byte) []map[string]interface{} {
	t.Helper()
	assert.False(t, json.Valid(body),
		"NDJSON stream body must NOT be valid JSON as a whole")

	records := make([]map[string]interface{}, 0)
	nonEmpty := 0
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		nonEmpty++
		assert.True(t, json.Valid([]byte(trimmed)),
			"each NDJSON line must be valid JSON: %q", trimmed)
		var rec map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(trimmed), &rec),
			"NDJSON line decodes to an object: %q", trimmed)
		records = append(records, rec)
	}
	require.GreaterOrEqual(t, nonEmpty, 1, "NDJSON stream has at least one record")
	return records
}

// ---------------------------------------------------------------------------
// FN-1: explicit strategy=ndjson across multiple NDJSON backends -> records
// collected, sorted by _time, deduped by id, limited; output is valid NDJSON
// with Content-Type application/stream+json.
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_NDJSON_Explicit_SortDedupeLimit(t *testing.T) {
	t.Parallel()

	// Two NDJSON backends. Records are intentionally out of _time order and
	// contain a duplicate id (id=2 appears in both backends) so sort + dedupe +
	// limit are all exercised end to end.
	b1 := ndjsonBackend(t, "application/x-ndjson",
		`{"id":1,"_time":30,"src":"b1"}`+"\n"+
			`{"id":2,"_time":10,"src":"b1"}`+"\n")
	b2 := ndjsonBackend(t, "application/x-ndjson",
		`{"id":3,"_time":20,"src":"b2"}`+"\n"+
			`{"id":2,"_time":40,"src":"b2"}`+"\n")

	metrics, _ := newRegisteredAggMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		Merge: &config.MergeOptions{
			Enabled:   true,
			Strategy:  config.MergeStrategyNDJSON,
			TimeField: "_time",
			KeyField:  "id",
			Limit:     2,
		},
		Targets: []config.AggregateTarget{
			aggTargetForServer(t, "b1", b1),
			aggTargetForServer(t, "b2", b2),
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
	ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
	defer cancel()

	require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
	require.Equal(t, http.StatusOK, rr.Code)

	// Output content type is the canonical NDJSON media type (+ nosniff).
	assert.Equal(t, "application/stream+json", rr.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))

	records := assertValidNDJSONStream(t, rr.Body.Bytes())

	// Pipeline: collect 4 records -> stable sort by _time (10,20,30,40) ->
	// dedupe id first-wins (id=2 first seen at _time=10 kept; the _time=40 dup
	// dropped) -> limit 2.
	// Sorted unique stream is: id=2(_time10), id=3(_time20), id=1(_time30).
	// After limit=2 -> id=2(_time10), id=3(_time20).
	require.Len(t, records, 2, "limit=2 truncates after sort+dedupe")
	assert.Equal(t, float64(2), records[0]["id"], "first record is the earliest _time")
	assert.Equal(t, float64(10), records[0]["_time"])
	assert.Equal(t, "b1", records[0]["src"], "first-wins kept the b1 copy of id=2")
	assert.Equal(t, float64(3), records[1]["id"], "second record by _time order")
	assert.Equal(t, float64(20), records[1]["_time"])
}

// FN-1b: explicit ndjson with no sort/dedupe/limit preserves cross-target,
// in-file order (plain concat) and still emits the stream content type.
func TestFunctional_Aggregate_NDJSON_Explicit_PlainConcatOrder(t *testing.T) {
	t.Parallel()

	b1 := ndjsonBackend(t, "application/x-ndjson",
		`{"n":"a"}`+"\n"+`{"n":"b"}`+"\n")
	b2 := ndjsonBackend(t, "application/x-ndjson",
		`{"n":"c"}`+"\n"+`{"n":"d"}`+"\n")

	metrics, _ := newRegisteredAggMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		Merge: &config.MergeOptions{
			Enabled: true,
			// Explicit ndjson with TimeField empty disables sorting (plain concat).
			Strategy:  config.MergeStrategyNDJSON,
			TimeField: "",
		},
		Targets: []config.AggregateTarget{
			aggTargetForServer(t, "b1", b1),
			aggTargetForServer(t, "b2", b2),
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
	ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
	defer cancel()

	require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/stream+json", rr.Header().Get("Content-Type"))

	records := assertValidNDJSONStream(t, rr.Body.Bytes())
	require.Len(t, records, 4)
	// Cross-target order (b1 then b2), in-file order within each.
	order := make([]string, len(records))
	for i, r := range records {
		order[i] = r["n"].(string)
	}
	assert.Equal(t, []string{"a", "b", "c", "d"}, order,
		"plain concat preserves target-then-line order")
}

// ---------------------------------------------------------------------------
// FN-2: auto-detection / auto-promotion. Backends return NDJSON bodies while the
// route is configured with a non-ndjson (deep) strategy. Because the JSON-doc
// decode would otherwise fall back to a labeled envelope, and EVERY successful
// body is detected NDJSON, the merger auto-promotes to the NDJSON line merger.
// ---------------------------------------------------------------------------

func TestFunctional_Aggregate_NDJSON_AutoPromotion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		contentType string
		// useHeuristic, when true, omits the content type so promotion relies on
		// the valid-per-line/invalid-whole body heuristic alone.
		useHeuristic bool
	}{
		{name: "x-ndjson", contentType: "application/x-ndjson"},
		{name: "jsonl", contentType: "application/jsonl"},
		{name: "stream+json", contentType: "application/stream+json"},
		{name: "charset_param", contentType: "application/x-ndjson; charset=utf-8"},
		{name: "body_heuristic_no_ct", useHeuristic: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ct := tc.contentType
			if tc.useHeuristic {
				// text/plain content type so detection must use the body shape:
				// valid-JSON-per-line but invalid-as-a-whole.
				ct = "text/plain"
			}

			// Each backend emits >=2 records so the body is invalid-as-a-whole
			// (required for the body-shape heuristic case where the content type
			// is not an NDJSON media type).
			b1 := ndjsonBackend(t, ct,
				`{"id":1,"_time":2}`+"\n"+`{"id":2,"_time":1}`+"\n")
			b2 := ndjsonBackend(t, ct,
				`{"id":3,"_time":3}`+"\n"+`{"id":4,"_time":4}`+"\n")

			metrics, _ := newRegisteredAggMetrics(t)
			handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

			// Non-ndjson strategy (deep) on purpose: promotion happens only on
			// the would-be-envelope branch.
			cfg := &config.AggregateConfig{
				Enabled: true,
				Merge: &config.MergeOptions{
					Enabled:   true,
					Strategy:  config.MergeStrategyDeep,
					TimeField: "_time",
				},
				Targets: []config.AggregateTarget{
					aggTargetForServer(t, "b1", b1),
					aggTargetForServer(t, "b2", b2),
				},
			}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
			ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
			defer cancel()

			require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
			require.Equal(t, http.StatusOK, rr.Code)

			// Auto-promoted: output is the NDJSON stream content type, NOT an
			// envelope JSON array.
			assert.Equal(t, "application/stream+json", rr.Header().Get("Content-Type"),
				"deep strategy + NDJSON bodies auto-promote to the line merger")

			records := assertValidNDJSONStream(t, rr.Body.Bytes())
			require.Len(t, records, 4, "all NDJSON records collected across targets")
			// TimeField=_time is honored by the auto path too -> sorted by _time.
			ids := make([]float64, len(records))
			times := make([]float64, len(records))
			for i, rec := range records {
				ids[i] = rec["id"].(float64)
				times[i] = rec["_time"].(float64)
			}
			assert.Equal(t, []float64{1, 2, 3, 4}, times,
				"auto path sorts records by _time ascending")
			assert.Equal(t, []float64{2, 1, 3, 4}, ids,
				"auto path orders ids by their _time: _time1(id2),2(id1),3(id3),4(id4)")
		})
	}
}

// FN-2b: NEGATIVE auto-promotion. A mix of one NDJSON body and one non-JSON
// (binary/text) body must NOT promote (not ALL bodies are NDJSON) and must fall
// back to the labeled envelope, exactly as before.
func TestFunctional_Aggregate_NDJSON_NoPromotion_MixedNonJSON(t *testing.T) {
	t.Parallel()

	ndj := ndjsonBackend(t, "application/x-ndjson",
		`{"id":1}`+"\n"+`{"id":2}`+"\n")
	// Non-JSON text backend -> not NDJSON, not JSON.
	txt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("plain words not json"))
	}))
	t.Cleanup(txt.Close)

	metrics, _ := newRegisteredAggMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		Merge:   &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		Targets: []config.AggregateTarget{
			aggTargetForServer(t, "ndj", ndj),
			aggTargetForServer(t, "txt", txt),
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
	ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
	defer cancel()

	require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
	require.Equal(t, http.StatusOK, rr.Code)

	// NOT promoted: labeled envelope JSON array, application/json.
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	var envelopes []struct {
		Target string `json:"target"`
		Status int    `json:"status"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelopes),
		"mixed NDJSON + non-JSON falls back to labeled envelope array")
	require.Len(t, envelopes, 2)
}

// ---------------------------------------------------------------------------
// FN-3: regressions. NDJSON detection must not disturb the existing JSON merge
// paths nor the envelope/merge-disabled behavior.
// ---------------------------------------------------------------------------

// FN-3a: deep/shallow/replace JSON merge over plain JSON-whole bodies still
// produces identical JSON and is NEVER promoted to NDJSON.
func TestFunctional_Aggregate_NDJSON_Regression_JSONMergeUnchanged(t *testing.T) {
	t.Parallel()

	strategies := []string{
		config.MergeStrategyDeep,
		config.MergeStrategyShallow,
		config.MergeStrategyReplace,
	}

	for _, strategy := range strategies {
		strategy := strategy
		t.Run(strategy, func(t *testing.T) {
			t.Parallel()

			b1, _ := jsonBackend(t, `{"user":{"name":"John"},"count":1}`)
			b2, _ := jsonBackend(t, `{"user":{"email":"john@example.com"},"status":"ok"}`)

			metrics, _ := newRegisteredAggMetrics(t)
			handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

			cfg := &config.AggregateConfig{
				Enabled: true,
				Merge:   &config.MergeOptions{Enabled: true, Strategy: strategy},
				Targets: []config.AggregateTarget{
					aggTargetForServer(t, "b1", b1),
					aggTargetForServer(t, "b2", b2),
				},
			}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
			ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
			defer cancel()

			require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
			require.Equal(t, http.StatusOK, rr.Code)

			// Critical regression guarantee: JSON-whole bodies are NEVER promoted;
			// the output stays application/json (a single JSON document).
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"),
				"valid-JSON-whole bodies are never promoted to NDJSON")
			assert.True(t, json.Valid(rr.Body.Bytes()),
				"merged output is a single valid JSON document")

			var merged map[string]interface{}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &merged))
			user, ok := merged["user"].(map[string]interface{})
			require.True(t, ok, "merged user object present")

			switch strategy {
			case config.MergeStrategyDeep:
				// Deep merge: nested user object combined, all top-level keys kept.
				assert.Equal(t, "John", user["name"])
				assert.Equal(t, "john@example.com", user["email"])
				assert.Contains(t, merged, "count")
				assert.Contains(t, merged, "status")
			case config.MergeStrategyShallow:
				// Shallow merge: top-level keys merged (last wins on conflict),
				// nested user object replaced wholesale by the last value.
				assert.Equal(t, "john@example.com", user["email"])
				assert.NotContains(t, user, "name",
					"shallow merge replaces the nested object, not deep-merging it")
				assert.Contains(t, merged, "count")
				assert.Contains(t, merged, "status")
			case config.MergeStrategyReplace:
				// Replace: the last document wins entirely.
				assert.Equal(t, "john@example.com", user["email"])
				assert.Contains(t, merged, "status")
				assert.NotContains(t, merged, "count",
					"replace strategy keeps only the last document's keys")
			}
		})
	}
}

// FN-3b: explicit deep-merge fixture produces byte-identical output regardless
// of the NDJSON code path being present (the auto-detection branch is never
// reached for valid-JSON-whole bodies).
func TestFunctional_Aggregate_NDJSON_Regression_DeepMergeByteIdentical(t *testing.T) {
	t.Parallel()

	b1, _ := jsonBackend(t, `{"a":{"x":1},"list":["p"]}`)
	b2, _ := jsonBackend(t, `{"a":{"y":2},"list":["q"]}`)

	metrics, _ := newRegisteredAggMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		Merge:   &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		Targets: []config.AggregateTarget{
			aggTargetForServer(t, "b1", b1),
			aggTargetForServer(t, "b2", b2),
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
	ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
	defer cancel()

	require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
	require.Equal(t, http.StatusOK, rr.Code)

	var merged map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &merged))

	a, ok := merged["a"].(map[string]interface{})
	require.True(t, ok, "nested object deep-merged")
	assert.Equal(t, float64(1), a["x"])
	assert.Equal(t, float64(2), a["y"])
	list, ok := merged["list"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"p", "q"}, list,
		"arrays concatenated by deep merge (unchanged behavior)")
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

// FN-3c: merge DISABLED over NDJSON bodies still envelopes (NDJSON detection
// only fires on the would-be-envelope branch of an ENABLED non-ndjson merge).
func TestFunctional_Aggregate_NDJSON_Regression_MergeDisabledEnvelopes(t *testing.T) {
	t.Parallel()

	b1 := ndjsonBackend(t, "application/x-ndjson", `{"id":1}`+"\n"+`{"id":2}`+"\n")
	b2 := ndjsonBackend(t, "application/x-ndjson", `{"id":3}`+"\n")

	metrics, _ := newRegisteredAggMetrics(t)
	handler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	cfg := &config.AggregateConfig{
		Enabled: true,
		// Merge disabled -> labeled envelope regardless of NDJSON bodies.
		Merge: &config.MergeOptions{Enabled: false},
		Targets: []config.AggregateTarget{
			aggTargetForServer(t, "b1", b1),
			aggTargetForServer(t, "b2", b2),
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/aggregate", nil)
	ctx, cancel := context.WithTimeout(req.Context(), aggTestTimeout)
	defer cancel()

	require.NoError(t, handler.ServeAggregate(rr, req.WithContext(ctx), cfg))
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"),
		"merge disabled keeps the labeled envelope content type")

	var envelopes []struct {
		Target  string          `json:"target"`
		Status  int             `json:"status"`
		Payload json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelopes))
	require.Len(t, envelopes, 2, "one labeled frame per target, no NDJSON promotion")
}

// FN-3d: an NDJSON aggregate route coexists with a single-mirror normal route
// through the same proxy (additive-config regression, mirroring the existing
// F-7 coexistence guarantee for the NDJSON strategy).
func TestFunctional_Aggregate_NDJSON_CoexistWithSingleMirror(t *testing.T) {
	t.Parallel()

	primary, primaryHits := jsonBackend(t, `{"source":"primary"}`)

	a1 := ndjsonBackend(t, "application/x-ndjson",
		`{"id":1,"_time":2}`+"\n"+`{"id":2,"_time":1}`+"\n")
	a2 := ndjsonBackend(t, "application/x-ndjson",
		`{"id":3,"_time":3}`+"\n")

	metrics, _ := newRegisteredAggMetrics(t)
	aggHandler := aggrest.NewHandler(nil, observability.NopLogger(), metrics, aggregate.NopTracer())

	primaryHost, primaryPort := splitHostPort(t, primary)

	normalRoute := config.Route{
		Name:  "ndjson-coexist-normal",
		Match: []config.RouteMatch{{URI: &config.URIMatch{Prefix: "/normal"}}},
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: primaryHost, Port: primaryPort}},
		},
		Mirror: &config.MirrorConfig{
			Destination: config.Destination{Host: "shadow.invalid", Port: 80},
			Percentage:  100,
		},
	}
	aggregateRoute := config.Route{
		Name:  "ndjson-aggregate-route",
		Match: []config.RouteMatch{{URI: &config.URIMatch{Prefix: "/aggregate"}}},
		Aggregate: &config.AggregateConfig{
			Enabled: true,
			Merge: &config.MergeOptions{
				Enabled:   true,
				Strategy:  config.MergeStrategyNDJSON,
				TimeField: "_time",
			},
			Targets: []config.AggregateTarget{
				aggTargetForServer(t, "a1", a1),
				aggTargetForServer(t, "a2", a2),
			},
		},
	}

	// Additive-config regression: the two route configs are independent.
	require.NotNil(t, normalRoute.Mirror, "single-mirror config preserved")
	require.Nil(t, normalRoute.Aggregate, "normal route is not an aggregate route")
	require.True(t, aggregateRoute.Aggregate.IsEnabled(), "ndjson aggregate route active")
	require.Nil(t, aggregateRoute.Mirror, "aggregate route carries no single-mirror config")

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

	t.Run("ndjson aggregate route returns a sorted NDJSON stream", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/aggregate/x")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/stream+json", resp.Header.Get("Content-Type"))

		body := readAllBody(t, resp)
		records := assertValidNDJSONStream(t, body)
		require.Len(t, records, 3)
		times := make([]float64, len(records))
		for i, rec := range records {
			times[i] = rec["_time"].(float64)
		}
		assert.True(t, sort.Float64sAreSorted(times),
			"NDJSON records are sorted by _time ascending: %v", times)
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

// readAllBody reads and returns the full response body, failing the test on
// error. Bounded by the client/request context timeouts above.
func readAllBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	deadline := time.Now().Add(aggTestTimeout)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("readAllBody exceeded %s", aggTestTimeout)
		}
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf
}
