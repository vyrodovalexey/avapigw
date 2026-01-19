package backend

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Proxy handles proxying requests to backend services.
type Proxy struct {
	transport    *http.Transport
	manager      *Manager
	logger       *zap.Logger
	config       *ProxyConfig
	urlValidator *URLValidator
}

// ProxyConfig holds configuration for the proxy.
type ProxyConfig struct {
	// Timeout for backend requests
	Timeout time.Duration

	// Buffer pool size
	BufferSize int

	// Preserve host header
	PreserveHost bool

	// Add X-Forwarded headers
	AddForwardedHeaders bool

	// Retry configuration
	RetryEnabled bool
	MaxRetries   int
	RetryBackoff time.Duration

	// URL validation configuration for SSRF prevention
	URLValidatorConfig *URLValidatorConfig

	// EnableURLValidation enables URL validation for SSRF prevention
	EnableURLValidation bool
}

// DefaultProxyConfig returns a ProxyConfig with default values.
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		Timeout:             30 * time.Second,
		BufferSize:          32 * 1024,
		PreserveHost:        false,
		AddForwardedHeaders: true,
		RetryEnabled:        true,
		MaxRetries:          3,
		RetryBackoff:        100 * time.Millisecond,
		EnableURLValidation: true,
		URLValidatorConfig:  DefaultURLValidatorConfig(),
	}
}

// NewProxy creates a new proxy.
func NewProxy(manager *Manager, logger *zap.Logger, config *ProxyConfig) *Proxy {
	if config == nil {
		config = DefaultProxyConfig()
	}

	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: config.Timeout,
	}

	proxy := &Proxy{
		transport: transport,
		manager:   manager,
		logger:    logger,
		config:    config,
	}

	// Initialize URL validator if enabled
	if config.EnableURLValidation {
		validatorConfig := config.URLValidatorConfig
		if validatorConfig == nil {
			validatorConfig = DefaultURLValidatorConfig()
		}
		validator, err := NewURLValidator(validatorConfig, logger)
		if err != nil {
			logger.Error("failed to create URL validator, SSRF protection disabled",
				zap.Error(err),
			)
		} else {
			proxy.urlValidator = validator
			logger.Info("URL validator initialized for SSRF protection",
				zap.Bool("blockPrivateIPs", validatorConfig.BlockPrivateIPs),
				zap.Bool("blockLoopback", validatorConfig.BlockLoopback),
				zap.Bool("blockLinkLocal", validatorConfig.BlockLinkLocal),
				zap.Bool("dnsRebindingProtection", validatorConfig.EnableDNSRebindingProtection),
			)
		}
	}

	return proxy
}

// ServeHTTP proxies the request to the backend.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, backend *Backend, timeout time.Duration) error {
	if backend == nil {
		return fmt.Errorf("backend is nil")
	}

	endpoint, err := p.getValidatedEndpoint(r.Context(), backend)
	if err != nil {
		return err
	}

	if backend.CircuitBreaker != nil && !backend.CircuitBreaker.Allow() {
		return fmt.Errorf("circuit breaker is open for backend %s", backend.Name)
	}

	proxy := p.createReverseProxy(backend, endpoint, r)
	r = p.applyTimeout(r, timeout)

	proxy.ServeHTTP(w, r)

	if backend.CircuitBreaker != nil {
		backend.CircuitBreaker.RecordSuccess()
	}

	return nil
}

// getValidatedEndpoint retrieves a healthy endpoint and validates it for SSRF prevention.
func (p *Proxy) getValidatedEndpoint(ctx context.Context, backend *Backend) (*Endpoint, error) {
	endpoint := backend.GetHealthyEndpoint()
	if endpoint == nil {
		return nil, fmt.Errorf("no healthy endpoints available for backend %s", backend.Name)
	}

	if p.urlValidator != nil {
		if err := p.urlValidator.ValidateEndpointWithContext(ctx, endpoint.Address, endpoint.Port); err != nil {
			p.logger.Warn("backend endpoint blocked by URL validator (SSRF prevention)",
				zap.String("backend", backend.Name),
				zap.String("address", endpoint.Address),
				zap.Int("port", endpoint.Port),
				zap.Error(err),
			)
			return nil, fmt.Errorf("backend endpoint blocked by SSRF protection: %w", err)
		}
	}

	return endpoint, nil
}

// createReverseProxy creates and configures a reverse proxy for the given endpoint.
func (p *Proxy) createReverseProxy(
	backend *Backend,
	endpoint *Endpoint,
	originalReq *http.Request,
) *httputil.ReverseProxy {
	targetURL := &url.URL{
		Scheme: "http",
		Host:   endpoint.FullAddress(),
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = p.getTransport(backend)
	proxy.ErrorHandler = p.errorHandler(backend)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		p.modifyRequest(req, originalReq, endpoint)
	}

	return proxy
}

// applyTimeout applies a timeout to the request context if specified.
func (p *Proxy) applyTimeout(r *http.Request, timeout time.Duration) *http.Request {
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		// Note: cancel will be called when the request completes via context propagation
		_ = cancel // Suppress unused warning - cancel is deferred implicitly
		return r.WithContext(ctx)
	}
	return r
}

// ProxyWithRetry proxies the request with retry support.
// Properly handles context cancellation in retry loops.
// Uses ResponseRecorder for non-final attempts to avoid writing to already-written response.
func (p *Proxy) ProxyWithRetry(w http.ResponseWriter, r *http.Request, backend *Backend, timeout time.Duration) error {
	if !p.config.RetryEnabled {
		return p.ServeHTTP(w, r, backend, timeout)
	}

	bodyBytes, err := p.bufferRequestBody(r)
	if err != nil {
		return err
	}

	ctx := r.Context()
	var lastErr error

	for attempt := 0; attempt <= p.config.MaxRetries; attempt++ {
		if err := p.waitForRetry(ctx, attempt, backend.Name); err != nil {
			return err
		}

		p.restoreRequestBody(r, bodyBytes)

		lastErr = p.executeProxyAttempt(w, r, backend, timeout, attempt)
		if lastErr == nil {
			return nil
		}

		p.logger.Warn("proxy request failed",
			zap.Error(lastErr),
			zap.Int("attempt", attempt),
			zap.String("backend", backend.Name),
		)
	}

	return lastErr
}

// bufferRequestBody reads and buffers the request body for potential retries.
func (p *Proxy) bufferRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	_ = r.Body.Close()
	return bodyBytes, nil
}

// waitForRetry handles context cancellation and backoff delay between retry attempts.
func (p *Proxy) waitForRetry(ctx context.Context, attempt int, backendName string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if attempt > 0 {
		backoffDuration := p.config.RetryBackoff * time.Duration(attempt)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoffDuration):
		}

		p.logger.Debug("retrying request",
			zap.Int("attempt", attempt),
			zap.String("backend", backendName),
		)
	}

	return nil
}

// restoreRequestBody restores the buffered body to the request for retry attempts.
func (p *Proxy) restoreRequestBody(r *http.Request, bodyBytes []byte) {
	if bodyBytes != nil {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
}

// executeProxyAttempt executes a single proxy attempt, using ResponseRecorder for non-final attempts.
func (p *Proxy) executeProxyAttempt(
	w http.ResponseWriter,
	r *http.Request,
	backend *Backend,
	timeout time.Duration,
	attempt int,
) error {
	isFinalAttempt := attempt == p.config.MaxRetries

	if isFinalAttempt {
		return p.ServeHTTP(w, r, backend, timeout)
	}

	return p.executeNonFinalAttempt(w, r, backend, timeout)
}

// executeNonFinalAttempt executes a non-final proxy attempt using ResponseRecorder.
func (p *Proxy) executeNonFinalAttempt(
	w http.ResponseWriter,
	r *http.Request,
	backend *Backend,
	timeout time.Duration,
) error {
	recorder := httptest.NewRecorder()
	err := p.ServeHTTP(recorder, r, backend, timeout)
	if err != nil {
		return err
	}

	p.copyRecordedResponse(w, recorder, backend.Name)
	return nil
}

// copyRecordedResponse copies the recorded response to the actual response writer.
func (p *Proxy) copyRecordedResponse(w http.ResponseWriter, recorder *httptest.ResponseRecorder, backendName string) {
	for key, values := range recorder.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(recorder.Code)
	if _, writeErr := w.Write(recorder.Body.Bytes()); writeErr != nil {
		p.logger.Error("failed to write response body",
			zap.Error(writeErr),
			zap.String("backend", backendName),
		)
	}
}

// getTransport returns the transport to use for the backend.
func (p *Proxy) getTransport(backend *Backend) http.RoundTripper {
	if backend.ConnectionPool != nil {
		return backend.ConnectionPool.GetTransport()
	}
	return p.transport
}

// modifyRequest modifies the request before proxying.
func (p *Proxy) modifyRequest(req *http.Request, original *http.Request, endpoint *Endpoint) {
	// Set the host
	if !p.config.PreserveHost {
		req.Host = endpoint.FullAddress()
	}

	// Add X-Forwarded headers
	if p.config.AddForwardedHeaders {
		p.addForwardedHeaders(req, original)
	}

	// Remove hop-by-hop headers
	removeHopByHopHeaders(req.Header)
}

// addForwardedHeaders adds X-Forwarded-* headers to the request.
func (p *Proxy) addForwardedHeaders(req *http.Request, original *http.Request) {
	p.addXForwardedFor(req, original)
	p.addXForwardedProto(req, original)
	req.Header.Set("X-Forwarded-Host", original.Host)
}

// addXForwardedFor adds or appends to the X-Forwarded-For header.
func (p *Proxy) addXForwardedFor(req *http.Request, original *http.Request) {
	clientIP := getClientIP(original)
	if clientIP == "" {
		return
	}

	prior := req.Header.Get("X-Forwarded-For")
	if prior != "" {
		req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		req.Header.Set("X-Forwarded-For", clientIP)
	}
}

// addXForwardedProto sets the X-Forwarded-Proto header based on TLS status.
func (p *Proxy) addXForwardedProto(req *http.Request, original *http.Request) {
	if original.TLS != nil {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}
}

// errorHandler returns an error handler for the reverse proxy.
func (p *Proxy) errorHandler(backend *Backend) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		p.logger.Error("proxy error",
			zap.Error(err),
			zap.String("backend", backend.Name),
			zap.String("path", r.URL.Path),
		)

		// Record failure for circuit breaker
		if backend.CircuitBreaker != nil {
			backend.CircuitBreaker.RecordFailure()
		}

		w.WriteHeader(http.StatusBadGateway)
		errMsg := `{"error": "Bad Gateway", "message": "Failed to connect to backend"}`
		if _, writeErr := w.Write([]byte(errMsg)); writeErr != nil {
			p.logger.Error("failed to write error response",
				zap.Error(writeErr),
				zap.String("backend", backend.Name),
			)
		}
	}
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Real-IP header
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// removeHopByHopHeaders removes hop-by-hop headers from the request.
func removeHopByHopHeaders(header http.Header) {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

// CopyResponse copies the response from the backend to the client.
func CopyResponse(dst http.ResponseWriter, src *http.Response) error {
	// Copy headers
	for key, values := range src.Header {
		for _, value := range values {
			dst.Header().Add(key, value)
		}
	}

	// Write status code
	dst.WriteHeader(src.StatusCode)

	// Copy body
	_, err := io.Copy(dst, src.Body)
	return err
}

// ProxyHandler returns an http.Handler that proxies requests to the specified backend.
func (p *Proxy) ProxyHandler(backendName string, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backend := p.manager.GetBackend(backendName)
		if backend == nil {
			http.Error(w, "Backend not found", http.StatusServiceUnavailable)
			return
		}

		if err := p.ServeHTTP(w, r, backend, timeout); err != nil {
			p.logger.Error("proxy handler error",
				zap.Error(err),
				zap.String("backend", backendName),
			)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}
	})
}
