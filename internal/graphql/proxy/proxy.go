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
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/config"
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
	current int
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
		p.transport = &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
	}

	return p
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

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build the target URL
	targetURL := p.buildTargetURL(target)
	span.SetAttributes(attribute.String("http.url", targetURL.String()))

	// Create the proxied request
	proxyReq, err := p.createProxyRequest(ctx, r, targetURL)
	if err != nil {
		if p.metrics != nil {
			p.metrics.RecordError(backendName, "forward", "request_creation_failed")
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create proxy request: %w", err)
	}

	// Execute the request
	resp, err := p.transport.RoundTrip(proxyReq)
	if err != nil {
		if p.metrics != nil {
			p.metrics.RecordError(backendName, "forward", "transport_error")
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to forward request to %s: %w", backendName, err)
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
func (p *Proxy) buildTargetURL(target *backendTarget) *url.URL {
	p.mu.Lock()
	idx := target.current % len(target.hosts)
	target.current++
	p.mu.Unlock()

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

// hopByHopHeaders are headers that should not be forwarded.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// copyHeaders copies headers from src to dst, excluding hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if hopByHopHeaders[key] {
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
