// Package proxy provides a reverse proxy for GraphQL requests.
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/config"
	avahttputil "github.com/vyrodovalexey/avapigw/internal/httputil"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// tracerName is the OpenTelemetry tracer name for GraphQL proxy operations.
const tracerName = "avapigw/graphql-proxy"

// Proxy is a reverse proxy for GraphQL requests.
type Proxy struct {
	mu          sync.RWMutex
	backends    map[string]*backendTarget
	transport   http.RoundTripper
	logger      observability.Logger
	metrics     MetricsRecorder
	timeout     time.Duration
	maxBodySize int64
}

// backendTarget represents a resolved backend target.
type backendTarget struct {
	name    string
	hosts   []config.BackendHost
	current atomic.Int64 // Atomic counter for lock-free round-robin selection
}

// MetricsRecorder records proxy metrics.
type MetricsRecorder interface {
	RecordRequest(backend, operation string, statusCode int, duration time.Duration)
	RecordError(backend, operation, errorType string)
}

// Option is a functional option for configuring the proxy.
type Option func(*Proxy)

// WithLogger sets the logger for the proxy.
func WithLogger(logger observability.Logger) Option {
	return func(p *Proxy) {
		p.logger = logger
	}
}

// WithTransport sets the HTTP transport for the proxy.
func WithTransport(transport http.RoundTripper) Option {
	return func(p *Proxy) {
		p.transport = transport
	}
}

// WithMetrics sets the metrics recorder for the proxy.
func WithMetrics(metrics MetricsRecorder) Option {
	return func(p *Proxy) {
		p.metrics = metrics
	}
}

// WithTimeout sets the default request timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(p *Proxy) {
		p.timeout = timeout
	}
}

// WithMaxBodySize sets the maximum request body size.
func WithMaxBodySize(maxBodySize int64) Option {
	return func(p *Proxy) {
		p.maxBodySize = maxBodySize
	}
}

// defaultTimeout is the default proxy request timeout.
const defaultTimeout = 30 * time.Second

// defaultMaxBodySize is the default maximum request body size (10MB).
const defaultMaxBodySize = 10 * 1024 * 1024

// Default transport pooling. Mirrors the HTTP reverse proxy's plaintext
// pooled transport (internal/proxy): the previous 10 idle connections per
// host forced per-request dials at load, churning ephemeral ports.
const (
	// defaultMaxIdleConns caps idle connections across all GraphQL backends.
	defaultMaxIdleConns = 512

	// defaultMaxIdleConnsPerHost keeps enough warm connections per backend
	// host to avoid per-request dials at load.
	defaultMaxIdleConnsPerHost = 100

	// defaultIdleConnTimeout matches the backend pool convention.
	defaultIdleConnTimeout = 90 * time.Second

	// defaultDialTimeout bounds backend TCP connection establishment.
	defaultDialTimeout = 30 * time.Second

	// defaultDialKeepAlive is the TCP keep-alive probe interval.
	defaultDialKeepAlive = 30 * time.Second

	// defaultTLSHandshakeTimeout bounds TLS handshakes.
	defaultTLSHandshakeTimeout = 10 * time.Second

	// defaultExpectContinueTimeout matches http.DefaultTransport.
	defaultExpectContinueTimeout = 1 * time.Second
)

// newDefaultTransport builds the pooled transport used when no custom
// transport is injected via WithTransport.
func newDefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: defaultDialKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          defaultMaxIdleConns,
		MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultExpectContinueTimeout,
	}
}

// New creates a new GraphQL reverse proxy.
func New(opts ...Option) *Proxy {
	p := &Proxy{
		backends:    make(map[string]*backendTarget),
		timeout:     defaultTimeout,
		maxBodySize: defaultMaxBodySize,
		logger:      observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(p)
	}

	if p.transport == nil {
		p.transport = newDefaultTransport()
	}

	return p
}

// Transport returns the proxy's HTTP transport. Exposed for configuration
// assertions in tests.
func (p *Proxy) Transport() http.RoundTripper {
	return p.transport
}

// UpdateBackends updates the backend targets for the proxy.
func (p *Proxy) UpdateBackends(backends []config.GraphQLBackend) {
	p.mu.Lock()
	defer p.mu.Unlock()

	newBackends := make(map[string]*backendTarget, len(backends))
	for _, b := range backends {
		newBackends[b.Name] = &backendTarget{
			name:  b.Name,
			hosts: b.Hosts,
		}
	}
	p.backends = newBackends

	p.logger.Info("GraphQL backends updated",
		observability.Int("count", len(backends)),
	)
}

// Forward forwards a GraphQL request to the appropriate backend.
//
// The returned response's Body MUST be closed by the caller. The per-request
// timeout context stays alive until the body is closed: canceling it earlier
// (the previous `defer cancel()`) made net/http's read loop observe
// ctx.Done() before the caller finished reading the body, so every pooled
// connection was torn down instead of returned to the idle pool — a dial per
// request that exhausted ephemeral ports under load (PT-05/06 Finding 1).
func (p *Proxy) Forward(ctx context.Context, backendName string, r *http.Request) (*http.Response, error) {
	tracer := otel.Tracer(tracerName)
	ctx, span := tracer.Start(ctx, "graphql.proxy.forward",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("graphql.backend", backendName),
			attribute.String("http.method", r.Method),
		),
	)
	defer span.End()

	start := time.Now()

	target, err := p.resolveBackend(backendName)
	if err != nil {
		if p.metrics != nil {
			p.metrics.RecordError(backendName, "forward", "backend_not_found")
		}
		span.RecordError(err)
		return nil, err
	}

	// Apply timeout
	timeout := p.timeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	// The cancel func is deliberately NOT deferred: it is invoked on every
	// error path below and otherwise handed to cancelOnCloseBody so the
	// context (and its timer) is released when the caller closes the body.
	// The timeout thereby bounds the WHOLE exchange including body streaming.
	ctx, cancel := context.WithTimeout(ctx, timeout)

	// Build the target URL
	targetURL := p.buildTargetURL(target)
	span.SetAttributes(attribute.String("http.url", targetURL.String()))

	// Create the proxied request
	proxyReq, err := p.createProxyRequest(ctx, r, targetURL)
	if err != nil {
		cancel()
		if p.metrics != nil {
			p.metrics.RecordError(backendName, "forward", "request_creation_failed")
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create proxy request: %w", err)
	}

	// Execute the request
	resp, err := p.transport.RoundTrip(proxyReq)
	if err != nil {
		cancel()
		if p.metrics != nil {
			p.metrics.RecordError(backendName, "forward", "transport_error")
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to forward request to %s: %w", backendName, err)
	}

	// Tie the context lifetime to the response body so the pooled
	// connection is recycled after the caller drains and closes it.
	if resp.Body != nil {
		resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}
	} else {
		// Defensive: RoundTrippers must return a non-nil Body, but test
		// doubles may not; release the context immediately in that case.
		cancel()
	}

	duration := time.Since(start)
	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.Float64("http.duration_ms", float64(duration.Milliseconds())),
	)

	if p.metrics != nil {
		p.metrics.RecordRequest(backendName, "forward", resp.StatusCode, duration)
	}

	p.logger.Debug("GraphQL request forwarded",
		observability.String("backend", backendName),
		observability.Int("status", resp.StatusCode),
		observability.Duration("duration", duration),
	)

	return resp, nil
}

// resolveBackend resolves a backend by name and returns the next target host.
func (p *Proxy) resolveBackend(name string) (*backendTarget, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	target, ok := p.backends[name]
	if !ok {
		return nil, fmt.Errorf("backend %q not found", name)
	}

	if len(target.hosts) == 0 {
		return nil, fmt.Errorf("backend %q has no hosts", name)
	}

	return target, nil
}

// buildTargetURL builds the target URL from the backend target using round-robin selection.
// Uses atomic counter for lock-free concurrent access.
func (p *Proxy) buildTargetURL(target *backendTarget) *url.URL {
	idx := int(target.current.Add(1)-1) % len(target.hosts)
	host := target.hosts[idx]
	return &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", host.Address, host.Port),
	}
}

// createProxyRequest creates a new HTTP request for proxying.
func (p *Proxy) createProxyRequest(
	ctx context.Context, original *http.Request, targetURL *url.URL,
) (*http.Request, error) {
	// Read and buffer the body
	var body io.Reader
	if original.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(original.Body, p.maxBodySize))
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		body = bytes.NewReader(bodyBytes)
	}

	// Build the full target URL preserving the original path
	reqURL := *targetURL
	reqURL.Path = original.URL.Path
	reqURL.RawQuery = original.URL.RawQuery

	req, err := http.NewRequestWithContext(ctx, original.Method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}

	// Copy headers, excluding hop-by-hop headers
	copyHeaders(req.Header, original.Header)

	// Set forwarding headers
	if clientIP := original.RemoteAddr; clientIP != "" {
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
				req.Header.Set("X-Forwarded-For", prior+", "+host)
			} else {
				req.Header.Set("X-Forwarded-For", host)
			}
		}
	}

	req.Header.Set("X-Forwarded-Host", original.Host)
	if original.TLS != nil {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}

	return req, nil
}

// cancelOnCloseBody ties a per-request timeout context's cancel func to the
// response body lifecycle. net/http only returns a connection to the idle
// pool once the body is fully read AND the request context is still alive;
// canceling before Close tears the connection down (forcing a dial per
// request). Close is safe to call multiple times: CancelFunc is idempotent.
type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

// Close closes the underlying body, then releases the request context.
func (b *cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// copyHeaders copies headers from src to dst, excluding hop-by-hop headers.
// Uses the shared httputil package for a single source of truth (RFC 2616/7230).
func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if avahttputil.IsHopByHop(key) {
			continue
		}
		// Skip WebSocket upgrade headers for regular proxy
		if strings.EqualFold(key, "Upgrade") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// Close closes the proxy and releases resources.
func (p *Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if transport, ok := p.transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}

	p.backends = make(map[string]*backendTarget)
	p.logger.Info("GraphQL proxy closed")
}
