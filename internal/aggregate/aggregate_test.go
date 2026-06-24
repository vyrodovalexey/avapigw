package aggregate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockInvoker is a controllable Invoker for engine tests.
type mockInvoker struct {
	mu       sync.Mutex
	calls    map[string]int
	fn       func(ctx context.Context, target Target, req *Request) (*Response, error)
	maxSeen  int32
	inflight int32
}

func newMockInvoker(fn func(ctx context.Context, target Target, req *Request) (*Response, error)) *mockInvoker {
	return &mockInvoker{calls: make(map[string]int), fn: fn}
}

func (m *mockInvoker) Invoke(ctx context.Context, target Target, req *Request) (*Response, error) {
	cur := atomic.AddInt32(&m.inflight, 1)
	for {
		old := atomic.LoadInt32(&m.maxSeen)
		if cur <= old || atomic.CompareAndSwapInt32(&m.maxSeen, old, cur) {
			break
		}
	}
	defer atomic.AddInt32(&m.inflight, -1)

	m.mu.Lock()
	m.calls[target.Name]++
	m.mu.Unlock()
	return m.fn(ctx, target, req)
}

func (m *mockInvoker) callCount(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[name]
}

func okResponse(name string) *Response {
	return &Response{Target: name, StatusCode: 200, Body: []byte(`{"ok":true}`), ContentType: "application/json"}
}

func targets(names ...string) []Target {
	out := make([]Target, 0, len(names))
	for _, n := range names {
		out = append(out, Target{Name: n, Host: "h", Port: 80, Timeout: time.Second, Retries: 0})
	}
	return out
}

// U-ENG-1 happy: N targets succeed → aggregated result, order-independent.
func TestEngine_Fanout_AllSucceed(t *testing.T) {
	inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		return okResponse(tg.Name), nil
	})
	agg := NewAggregator(inv)
	cfg := &Config{Targets: targets("a", "b", "c"), FailMode: FailModeAll}

	result, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 3, result.SuccessCount)
	assert.Equal(t, 0, result.FailureCount)
	require.Len(t, result.Responses, 3)
	// Responses are in stable target order.
	assert.Equal(t, "a", result.Responses[0].Target)
	assert.Equal(t, "b", result.Responses[1].Target)
	assert.Equal(t, "c", result.Responses[2].Target)
}

// U-ENG-2 edge: empty target list → ErrNoTargets.
func TestEngine_Fanout_NoTargets(t *testing.T) {
	agg := NewAggregator(newMockInvoker(nil))

	_, err := agg.Fanout(context.Background(), &Config{}, &Request{})
	assert.ErrorIs(t, err, ErrNoTargets)

	_, err = agg.Fanout(context.Background(), nil, &Request{})
	assert.ErrorIs(t, err, ErrNoTargets)
}

// U-ENG-3 edge: single target passthrough.
func TestEngine_Fanout_SingleTarget(t *testing.T) {
	inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		return okResponse(tg.Name), nil
	})
	agg := NewAggregator(inv)
	cfg := &Config{Targets: targets("solo"), FailMode: FailModeAll}

	result, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.SuccessCount)
	require.Len(t, result.SuccessfulResponses(), 1)
}

// U-ENG-4 error: one target errors, FailMode=all → overall error.
func TestEngine_Fanout_FailModeAll(t *testing.T) {
	inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		if tg.Name == "b" {
			return nil, errors.New("boom")
		}
		return okResponse(tg.Name), nil
	})
	agg := NewAggregator(inv)
	cfg := &Config{Targets: targets("a", "b", "c"), FailMode: FailModeAll}

	result, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.ErrorIs(t, err, ErrFailModeNotMet)
	require.NotNil(t, result)
	assert.Equal(t, 2, result.SuccessCount)
	assert.Equal(t, 1, result.FailureCount)
}

// U-ENG-5 happy: FailMode=any succeeds if ≥1 succeeds.
func TestEngine_Fanout_FailModeAny(t *testing.T) {
	tests := []struct {
		name      string
		failing   map[string]bool
		wantErr   bool
		wantOKMin int
	}{
		{"one success suffices", map[string]bool{"a": true, "b": true}, false, 1},
		{"all fail errors", map[string]bool{"a": true, "b": true, "c": true}, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
				if tt.failing[tg.Name] {
					return nil, errors.New("fail")
				}
				return okResponse(tg.Name), nil
			})
			agg := NewAggregator(inv)
			cfg := &Config{Targets: targets("a", "b", "c"), FailMode: FailModeAny}

			result, err := agg.Fanout(context.Background(), cfg, &Request{})
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrFailModeNotMet)
			} else {
				assert.NoError(t, err)
				assert.GreaterOrEqual(t, result.SuccessCount, tt.wantOKMin)
			}
		})
	}
}

// U-ENG-6 quorum: success at threshold, fail below.
func TestEngine_Fanout_FailModeQuorum(t *testing.T) {
	tests := []struct {
		name        string
		quorumCount int
		successCnt  int // first N targets succeed
		wantErr     bool
	}{
		{"majority of 3 reached (2 ok)", 0, 2, false},
		{"majority of 3 not reached (1 ok)", 0, 1, true},
		{"explicit quorum 3 reached", 3, 3, false},
		{"explicit quorum 3 not reached (2 ok)", 3, 2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			succeeded := 0
			var mu sync.Mutex
			order := map[string]int{"a": 0, "b": 1, "c": 2}
			inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
				mu.Lock()
				defer mu.Unlock()
				_ = succeeded
				if order[tg.Name] < tt.successCnt {
					return okResponse(tg.Name), nil
				}
				return nil, errors.New("fail")
			})
			agg := NewAggregator(inv)
			cfg := &Config{
				Targets:     targets("a", "b", "c"),
				FailMode:    FailModeQuorum,
				QuorumCount: tt.quorumCount,
			}
			_, err := agg.Fanout(context.Background(), cfg, &Request{})
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrFailModeNotMet)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// U-ENG-7 edge: per-target timeout fires → marked failed, others proceed.
func TestEngine_Fanout_PerTargetTimeout(t *testing.T) {
	inv := newMockInvoker(func(ctx context.Context, tg Target, _ *Request) (*Response, error) {
		if tg.Name == "slow" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return okResponse(tg.Name), nil
	})
	agg := NewAggregator(inv)
	cfg := &Config{
		Targets: []Target{
			{Name: "fast", Host: "h", Port: 80, Timeout: time.Second},
			{Name: "slow", Host: "h", Port: 80, Timeout: 20 * time.Millisecond},
		},
		FailMode: FailModeAny,
	}

	result, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.SuccessCount)
	assert.Equal(t, 1, result.FailureCount)
	slow := findResponse(result, "slow")
	require.NotNil(t, slow)
	assert.False(t, slow.Succeeded())
}

// U-ENG-8 edge: context cancel propagates → all targets fail, no leak.
func TestEngine_Fanout_ContextCancel(t *testing.T) {
	inv := newMockInvoker(func(ctx context.Context, _ Target, _ *Request) (*Response, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	agg := NewAggregator(inv)
	cfg := &Config{Targets: targets("a", "b", "c"), FailMode: FailModeAll, MaxParallel: 1}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before fanout

	result, err := agg.Fanout(ctx, cfg, &Request{})
	require.ErrorIs(t, err, ErrFailModeNotMet)
	assert.Equal(t, 0, result.SuccessCount)
}

// U-ENG-9 edge: bounded parallelism respected.
func TestEngine_Fanout_BoundedParallelism(t *testing.T) {
	var inflight int32
	var maxObserved int32
	inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		cur := atomic.AddInt32(&inflight, 1)
		for {
			old := atomic.LoadInt32(&maxObserved)
			if cur <= old || atomic.CompareAndSwapInt32(&maxObserved, old, cur) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&inflight, -1)
		return okResponse(tg.Name), nil
	})
	agg := NewAggregator(inv)
	cfg := &Config{Targets: targets("a", "b", "c", "d", "e", "f"), FailMode: FailModeAll, MaxParallel: 2}

	_, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.NoError(t, err)
	assert.LessOrEqual(t, int(atomic.LoadInt32(&maxObserved)), 2, "max concurrency must respect MaxParallel")
}

// U-ENG-10 error: retry with exp backoff on transient error.
func TestEngine_Fanout_RetryTransient(t *testing.T) {
	var attempts int32
	inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			return &Response{Target: tg.Name, StatusCode: 503}, nil
		}
		return okResponse(tg.Name), nil
	})
	agg := NewAggregator(inv)
	cfg := &Config{
		Targets:  []Target{{Name: "a", Host: "h", Port: 80, Timeout: 5 * time.Second, Retries: 5}},
		FailMode: FailModeAll,
	}

	result, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.SuccessCount)
	assert.GreaterOrEqual(t, int(atomic.LoadInt32(&attempts)), 3)
}

func TestEngine_Fanout_NoRetryOnPermanentSuccess(t *testing.T) {
	inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		return &Response{Target: tg.Name, StatusCode: 404}, nil // 4xx is not transient
	})
	agg := NewAggregator(inv)
	cfg := &Config{
		Targets:  []Target{{Name: "a", Host: "h", Port: 80, Timeout: time.Second, Retries: 3}},
		FailMode: FailModeAll,
	}
	_, _ = agg.Fanout(context.Background(), cfg, &Request{})
	assert.Equal(t, 1, inv.callCount("a"), "non-transient status must not be retried")
}

// U-ENG-11 race: -race clean under concurrent targets.
func TestEngine_Fanout_Race(t *testing.T) {
	inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		return okResponse(tg.Name), nil
	})
	agg := NewAggregator(inv)
	cfg := &Config{Targets: targets("a", "b", "c", "d", "e", "f", "g", "h"), FailMode: FailModeAll, MaxParallel: 8}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := agg.Fanout(context.Background(), cfg, &Request{})
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}

// Transport-level error (Invoke returns err) marks target failed.
func TestEngine_Fanout_TransportError(t *testing.T) {
	inv := newMockInvoker(func(_ context.Context, _ Target, _ *Request) (*Response, error) {
		return nil, errors.New("connection refused")
	})
	agg := NewAggregator(inv)
	cfg := &Config{
		Targets:  []Target{{Name: "a", Host: "h", Port: 80, Timeout: 50 * time.Millisecond, Retries: 0}},
		FailMode: FailModeAny,
	}
	result, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.ErrorIs(t, err, ErrFailModeNotMet)
	assert.Equal(t, 1, result.FailureCount)
	assert.Error(t, result.Responses[0].Err)
}

// Invoker returning nil response with nil error is normalized to a target name.
func TestEngine_Fanout_NilResponseNormalized(t *testing.T) {
	inv := newMockInvoker(func(_ context.Context, _ Target, _ *Request) (*Response, error) {
		return nil, nil
	})
	agg := NewAggregator(inv)
	cfg := &Config{Targets: targets("a"), FailMode: FailModeAll}
	result, err := agg.Fanout(context.Background(), cfg, &Request{})
	require.NoError(t, err)
	assert.Equal(t, "a", result.Responses[0].Target)
}

func TestResponse_Succeeded(t *testing.T) {
	assert.False(t, (*Response)(nil).Succeeded())
	assert.True(t, (&Response{}).Succeeded())
	assert.False(t, (&Response{Err: errors.New("x")}).Succeeded())
}

func TestInvokerFunc(t *testing.T) {
	called := false
	var f InvokerFunc = func(_ context.Context, _ Target, _ *Request) (*Response, error) {
		called = true
		return &Response{Target: "x"}, nil
	}
	resp, err := f.Invoke(context.Background(), Target{Name: "x"}, &Request{})
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "x", resp.Target)
}

func TestResult_SuccessfulResponses(t *testing.T) {
	r := &Result{Responses: []*Response{
		{Target: "a"},
		{Target: "b", Err: errors.New("x")},
		{Target: "c"},
	}}
	ok := r.SuccessfulResponses()
	require.Len(t, ok, 2)
	assert.Equal(t, "a", ok[0].Target)
	assert.Equal(t, "c", ok[1].Target)
}

func TestResult_SortedByTarget(t *testing.T) {
	r := &Result{Responses: []*Response{
		{Target: "c"}, {Target: "a"}, {Target: "b"},
	}}
	sorted := r.SortedByTarget()
	require.Len(t, sorted, 3)
	assert.Equal(t, "a", sorted[0].Target)
	assert.Equal(t, "b", sorted[1].Target)
	assert.Equal(t, "c", sorted[2].Target)
	// Original is unchanged.
	assert.Equal(t, "c", r.Responses[0].Target)
}

func TestDefaultShouldRetry(t *testing.T) {
	tests := []struct {
		name string
		resp *Response
		err  error
		want bool
	}{
		{"transport error retries", nil, errors.New("x"), true},
		{"nil resp no error no retry", nil, nil, false},
		{"response err retries", &Response{Err: errors.New("x")}, nil, true},
		{"5xx retries", &Response{StatusCode: 500}, nil, true},
		{"503 retries", &Response{StatusCode: 503}, nil, true},
		{"200 no retry", &Response{StatusCode: 200}, nil, false},
		{"404 no retry", &Response{StatusCode: 404}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, defaultShouldRetry(tt.resp, tt.err))
		})
	}
}

func TestWithRetryClassifier(t *testing.T) {
	var seen int32
	classifier := func(_ *Response, _ error) bool {
		atomic.AddInt32(&seen, 1)
		return false
	}
	inv := newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		return &Response{Target: tg.Name, StatusCode: 500}, nil
	})
	agg := NewAggregator(inv, WithRetryClassifier(classifier))
	cfg := &Config{Targets: targets("a"), FailMode: FailModeAny}
	_, _ = agg.Fanout(context.Background(), cfg, &Request{})
	assert.GreaterOrEqual(t, int(atomic.LoadInt32(&seen)), 1)
	// custom classifier returned false -> no retry beyond first call
	assert.Equal(t, 1, inv.callCount("a"))
}

func TestNewAggregator_OptionsIgnoreNil(t *testing.T) {
	// Passing nil options must not override defaults (no panic).
	agg := NewAggregator(newMockInvoker(func(_ context.Context, tg Target, _ *Request) (*Response, error) {
		return okResponse(tg.Name), nil
	}), WithLogger(nil), WithMetrics(nil), WithTracer(nil), WithRetryClassifier(nil))
	cfg := &Config{Targets: targets("a"), FailMode: FailModeAll}
	_, err := agg.Fanout(context.Background(), cfg, &Request{})
	assert.NoError(t, err)
}

func findResponse(r *Result, name string) *Response {
	for _, resp := range r.Responses {
		if resp.Target == name {
			return resp
		}
	}
	return nil
}
