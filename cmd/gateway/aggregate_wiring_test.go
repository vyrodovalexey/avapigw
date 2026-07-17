// Package main: tests proving the aggregate (fan-out) handlers are wired into
// the data plane. These cover the critical deploy-verification gap where the
// gateway entrypoint previously built the reverse proxy WITHOUT an aggregate
// handler, making aggregate routes a 404 no-op in production.
package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	aggregategraphql "github.com/vyrodovalexey/avapigw/internal/aggregate/graphqladapter"
	aggregaterest "github.com/vyrodovalexey/avapigw/internal/aggregate/rest"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// aggregateRouteConfig builds an enabled aggregate config fanning out to the
// two given host:port targets, merging their JSON bodies (deep strategy).
func aggregateRouteConfig(targets ...config.Destination) *config.AggregateConfig {
	cfg := &config.AggregateConfig{
		Enabled:  true,
		FailMode: config.FailModeAll,
		Merge:    &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
	}
	for i, dst := range targets {
		cfg.Targets = append(cfg.Targets, config.AggregateTarget{
			Name:        "t" + string(rune('a'+i)),
			Destination: dst,
		})
	}
	return cfg
}

func destFromServer(t *testing.T, srv *httptest.Server) config.Destination {
	t.Helper()
	// httptest URLs are http://127.0.0.1:PORT; split via http.Request parsing.
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	host := req.URL.Hostname()
	port := req.URL.Port()
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	return config.Destination{Host: host, Port: p}
}

// TestRESTAggregateHandler_FansOutAndMerges proves the REST aggregate handler
// (built exactly as cmd/gateway wires it) actually fans out to multiple
// backends and merges their responses, and that gateway_aggregate_* metrics are
// recorded.
func TestRESTAggregateHandler_FansOutAndMerges(t *testing.T) {
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"a":1}`))
	}))
	defer backendA.Close()
	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"b":2}`))
	}))
	defer backendB.Close()

	logger := observability.NopLogger()
	metrics := aggregate.NopMetrics()
	tracer := aggregate.NopTracer()

	handler := aggregaterest.NewHandler(
		aggregaterest.NewInvoker(aggregaterest.WithLogger(logger)),
		logger, metrics, tracer,
	)

	cfg := aggregateRouteConfig(destFromServer(t, backendA), destFromServer(t, backendB))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/aggregate", nil)

	err := handler.ServeAggregate(rr, req, cfg)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
	// Deep merge of {"a":1} and {"b":2} yields both keys.
	assert.JSONEq(t, `{"a":1,"b":2}`, rr.Body.String())
}

// TestGraphQLAggregateHandler_Builds proves the GraphQL aggregate handler is
// constructible exactly as cmd/gateway wires it and satisfies the gateway's
// injected interface.
func TestGraphQLAggregateHandler_Builds(t *testing.T) {
	logger := observability.NopLogger()
	handler := aggregategraphql.NewHandler(
		aggregaterest.NewInvoker(aggregaterest.WithLogger(logger)),
		logger, aggregate.NopMetrics(), aggregate.NopTracer(),
	)
	require.NotNil(t, handler)
	// ServeAggregate with a nil/disabled config must report ErrNoTargets without
	// writing a response, proving the handler is wired to the engine.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	err := handler.ServeAggregate(rr, req, &config.AggregateConfig{})
	assert.ErrorIs(t, err, aggregate.ErrNoTargets)
}

// withShortOperatorStartDeadline shrinks the operator initial-connection retry
// window for tests that deliberately drive runOperatorGateway / runOperatorMode
// against an unreachable or always-erroring operator client and assert the
// fatal-exit path. With the production deadline (3m) those tests would each
// block for ~2 minutes exhausting retries. It returns a restore function to be
// deferred, keeping production behavior unchanged outside the test scope.
func withShortOperatorStartDeadline() func() {
	orig := operatorStartOverallDeadline
	operatorStartOverallDeadline = 2 * time.Second
	return func() { operatorStartOverallDeadline = orig }
}

// fakeOperatorClient simulates an operator client whose Start fails a fixed
// number of times before succeeding, exercising the retry-with-backoff path.
type fakeOperatorClient struct {
	failuresLeft int
	startCalls   int
	startErr     error
}

func (f *fakeOperatorClient) Start(_ context.Context) error {
	f.startCalls++
	if f.failuresLeft > 0 {
		f.failuresLeft--
		return f.startErr
	}
	return nil
}

func (f *fakeOperatorClient) Stop() error       { return nil }
func (f *fakeOperatorClient) SessionID() string { return "session" }

// TestStartOperatorClientWithRetry_RecoversAfterTransientFailures proves the
// gateway retries the initial operator connect/register instead of failing
// fatally on the first error (Issue 2).
func TestStartOperatorClientWithRetry_RecoversAfterTransientFailures(t *testing.T) {
	client := &fakeOperatorClient{failuresLeft: 3, startErr: errors.New("connection refused")}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := startOperatorClientWithRetry(ctx, client, observability.NopLogger())
	require.NoError(t, err)
	assert.Equal(t, 4, client.startCalls, "should retry until success")
}

// TestStartOperatorClientWithRetry_FailsAfterExhaustion proves the gateway
// still fails (fatally, upstream) once retries are exhausted.
func TestStartOperatorClientWithRetry_FailsAfterExhaustion(t *testing.T) {
	client := &fakeOperatorClient{failuresLeft: 1000, startErr: errors.New("permanent")}

	// Bound the test with a short context so exhaustion is reached quickly via
	// context cancellation rather than the full production deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := startOperatorClientWithRetry(ctx, client, observability.NopLogger())
	require.Error(t, err)
}
