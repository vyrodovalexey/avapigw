package aggregate

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
)

// Sentinel errors for the aggregate engine.
var (
	// ErrNoTargets is returned when an aggregate request has no targets.
	ErrNoTargets = errors.New("aggregate: no targets configured")

	// ErrFailModeNotMet is returned when the configured FailMode success
	// threshold is not met.
	ErrFailModeNotMet = errors.New("aggregate: fail-mode success threshold not met")

	// errRetryStatus is an internal sentinel used to drive retry.Do when a
	// response is retryable by status code (e.g. 5xx) but carries no per-target
	// or transport error. It never escapes invokeTarget.
	errRetryStatus = errors.New("aggregate: retryable response status")
)

// Request is a protocol-agnostic description of a single target invocation.
type Request struct {
	// Method is the request method (HTTP verb, gRPC full method, etc.).
	Method string

	// Path is the request path or resource identifier.
	Path string

	// Headers carries request headers/metadata. Implementations must treat it
	// as read-only.
	Headers map[string][]string

	// Body is the request payload. Implementations must treat it as read-only.
	Body []byte
}

// Response is the result of a single target invocation.
type Response struct {
	// Target is the name of the target that produced this response.
	Target string

	// StatusCode is the protocol status code (HTTP status, gRPC code, etc.).
	StatusCode int

	// Headers carries response headers/metadata.
	Headers map[string][]string

	// Body is the response payload.
	Body []byte

	// ContentType is the detected/declared content type of Body.
	ContentType string

	// Err is the per-target error, if any.
	Err error

	// Duration is the wall-clock duration of the invocation.
	Duration time.Duration
}

// Succeeded reports whether the target invocation succeeded.
func (r *Response) Succeeded() bool {
	return r != nil && r.Err == nil
}

// Invoker performs a single backend invocation for a target. Callers inject an
// Invoker to decouple the engine from the concrete transport (HTTP, gRPC, ...),
// mirroring the RouteMiddlewareApplier pattern used elsewhere.
type Invoker interface {
	// Invoke calls the given target with the request and returns its response.
	// A non-nil returned error indicates a transport-level failure; per-target
	// application failures should be reported via Response.Err.
	Invoke(ctx context.Context, target Target, req *Request) (*Response, error)
}

// InvokerFunc adapts a function to the Invoker interface.
type InvokerFunc func(ctx context.Context, target Target, req *Request) (*Response, error)

// Invoke implements the Invoker interface.
func (f InvokerFunc) Invoke(ctx context.Context, target Target, req *Request) (*Response, error) {
	return f(ctx, target, req)
}

// Result is the outcome of an aggregate fan-out.
type Result struct {
	// Responses holds every per-target response in stable target order.
	Responses []*Response

	// SuccessCount is the number of successful targets.
	SuccessCount int

	// FailureCount is the number of failed targets.
	FailureCount int
}

// Aggregator fans a request out to multiple targets and collects their
// responses.
type Aggregator interface {
	// Fanout invokes every configured target in parallel (bounded by
	// MaxParallel) and returns the collected per-target responses. The returned
	// error is non-nil only when the FailMode success threshold is not met or
	// the input is invalid; individual target failures are reported via
	// Response.Err.
	Fanout(ctx context.Context, cfg *Config, req *Request) (*Result, error)
}

// ShouldRetry classifies whether a per-target error is transient and should be
// retried. Callers may override the default via WithRetryClassifier.
type ShouldRetry func(*Response, error) bool

// engine is the default Aggregator implementation.
type engine struct {
	invoker     Invoker
	logger      observability.Logger
	metrics     *Metrics
	tracer      Tracer
	shouldRetry ShouldRetry
}

// Option configures the aggregate engine.
type Option func(*engine)

// WithLogger sets the structured logger.
func WithLogger(logger observability.Logger) Option {
	return func(e *engine) {
		if logger != nil {
			e.logger = logger
		}
	}
}

// WithMetrics sets the Prometheus metrics recorder.
func WithMetrics(m *Metrics) Option {
	return func(e *engine) {
		if m != nil {
			e.metrics = m
		}
	}
}

// WithTracer sets the OTLP tracer.
func WithTracer(t Tracer) Option {
	return func(e *engine) {
		if t != nil {
			e.tracer = t
		}
	}
}

// WithRetryClassifier overrides the transient-error classifier.
func WithRetryClassifier(fn ShouldRetry) Option {
	return func(e *engine) {
		if fn != nil {
			e.shouldRetry = fn
		}
	}
}

// NewAggregator creates a new Aggregator backed by the given Invoker.
func NewAggregator(invoker Invoker, opts ...Option) Aggregator {
	e := &engine{
		invoker:     invoker,
		logger:      observability.NopLogger(),
		metrics:     NopMetrics(),
		tracer:      NopTracer(),
		shouldRetry: defaultShouldRetry,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// defaultShouldRetry retries on transport errors and 5xx-style status codes.
func defaultShouldRetry(resp *Response, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return false
	}
	if resp.Err != nil {
		return true
	}
	return resp.StatusCode >= 500
}

// Fanout implements the Aggregator interface.
func (e *engine) Fanout(ctx context.Context, cfg *Config, req *Request) (*Result, error) {
	if cfg == nil || len(cfg.Targets) == 0 {
		return nil, ErrNoTargets
	}

	ctx, span := e.tracer.Start(ctx, "aggregate.fanout")
	defer span.End()

	start := time.Now()
	e.metrics.RecordRequest(len(cfg.Targets))
	e.logger.Info("aggregate fan-out started",
		observability.Int("targets", len(cfg.Targets)),
		observability.String("failMode", string(cfg.FailMode)),
	)

	responses := e.invokeAll(ctx, cfg, req)

	result := buildResult(cfg.Targets, responses)
	e.metrics.RecordDuration(time.Since(start))
	e.recordOutcome(result)

	if result.SuccessCount < cfg.successThreshold() {
		span.RecordError(ErrFailModeNotMet)
		e.logger.Warn("aggregate fan-out below success threshold",
			observability.Int("success", result.SuccessCount),
			observability.Int("required", cfg.successThreshold()),
		)
		return result, ErrFailModeNotMet
	}

	return result, nil
}

// invokeAll fans out to every target with bounded parallelism and collects the
// responses keyed by target name.
func (e *engine) invokeAll(ctx context.Context, cfg *Config, req *Request) map[string]*Response {
	sem := make(chan struct{}, cfg.EffectiveMaxParallel())
	results := make(map[string]*Response, len(cfg.Targets))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := range cfg.Targets {
		target := cfg.Targets[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				resp := &Response{Target: target.Name, Err: ctx.Err()}
				e.store(&mu, results, resp)
				return
			}
			resp := e.invokeTarget(ctx, &target, req)
			e.store(&mu, results, resp)
		}()
	}

	wg.Wait()
	return results
}

// store records a response under the target name with mutual exclusion.
func (e *engine) store(mu *sync.Mutex, results map[string]*Response, resp *Response) {
	mu.Lock()
	results[resp.Target] = resp
	mu.Unlock()
}

// invokeTarget invokes a single target with a per-target timeout and retry with
// exponential backoff for transient errors.
func (e *engine) invokeTarget(ctx context.Context, target *Target, req *Request) *Response {
	ctx, span := e.tracer.Start(ctx, "aggregate.target")
	defer span.End()

	timeout := target.Timeout
	if timeout <= 0 {
		timeout = DefaultTargetTimeout
	}
	targetCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	var final *Response

	retryCfg := &retry.Config{MaxRetries: target.Retries}
	_ = retry.Do(targetCtx, retryCfg, func() error {
		resp, err := e.invoker.Invoke(targetCtx, *target, req)
		final = normalizeResponse(target.Name, resp, err)
		if e.shouldRetry(final, err) {
			if final.Err == nil && err != nil {
				final.Err = err
			}
			if final.Err != nil {
				return final.Err
			}
			// Retryable by status (e.g. 5xx) but no error attached: drive a
			// retry without contaminating the response's Err field.
			return errRetryStatus
		}
		return nil
	}, &retry.Options{
		ShouldRetry: func(error) bool { return true },
	})

	if final == nil {
		final = &Response{Target: target.Name, Err: ctx.Err()}
	}
	final.Duration = time.Since(start)

	if !final.Succeeded() {
		e.metrics.RecordTargetError(target.Name)
		span.RecordError(final.Err)
		e.logger.Debug("aggregate target failed",
			observability.String("target", target.Name),
			observability.Error(final.Err),
		)
	} else {
		e.logger.Debug("aggregate target succeeded",
			observability.String("target", target.Name),
			observability.Int("status", final.StatusCode),
		)
	}
	return final
}

// normalizeResponse guarantees a non-nil Response carrying the target name and
// any transport error.
func normalizeResponse(name string, resp *Response, err error) *Response {
	if resp == nil {
		resp = &Response{Target: name}
	}
	if resp.Target == "" {
		resp.Target = name
	}
	if resp.Err == nil && err != nil {
		resp.Err = err
	}
	return resp
}

// buildResult assembles the ordered Result from the keyed responses.
func buildResult(targets []Target, responses map[string]*Response) *Result {
	result := &Result{Responses: make([]*Response, 0, len(targets))}
	for i := range targets {
		resp := responses[targets[i].Name]
		if resp == nil {
			resp = &Response{Target: targets[i].Name, Err: context.Canceled}
		}
		result.Responses = append(result.Responses, resp)
		if resp.Succeeded() {
			result.SuccessCount++
		} else {
			result.FailureCount++
		}
	}
	return result
}

// recordOutcome records the aggregate-level success/failure metric.
func (e *engine) recordOutcome(result *Result) {
	e.metrics.RecordResult(result.SuccessCount, result.FailureCount)
}

// SuccessfulResponses returns only the successful responses in stable order.
func (r *Result) SuccessfulResponses() []*Response {
	out := make([]*Response, 0, len(r.Responses))
	for _, resp := range r.Responses {
		if resp.Succeeded() {
			out = append(out, resp)
		}
	}
	return out
}

// SortedByTarget returns the responses sorted by target name (stable ordering
// for deterministic output regardless of completion order).
func (r *Result) SortedByTarget() []*Response {
	out := make([]*Response, len(r.Responses))
	copy(out, r.Responses)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Target < out[j].Target
	})
	return out
}
