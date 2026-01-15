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

	// Get a healthy endpoint
	endpoint := backend.GetHealthyEndpoint()
	if endpoint == nil {
		return fmt.Errorf("no healthy endpoints available for backend %s", backend.Name)
	}

	// Validate endpoint URL for SSRF prevention
	if p.urlValidator != nil {
		if err := p.urlValidator.ValidateEndpointWithContext(r.Context(), endpoint.Address, endpoint.Port); err != nil {
			p.logger.Warn("backend endpoint blocked by URL validator (SSRF prevention)",
				zap.String("backend", backend.Name),
				zap.String("address", endpoint.Address),
				zap.Int("port", endpoint.Port),
				zap.Error(err),
			)
			return fmt.Errorf("backend endpoint blocked by SSRF protection: %w", err)
		}
	}

	// Check circuit breaker
	if backend.CircuitBreaker != nil && !backend.CircuitBreaker.Allow() {
		return fmt.Errorf("circuit breaker is open for backend %s", backend.Name)
	}

	// Create target URL
	targetURL := &url.URL{
		Scheme: "http",
		Host:   endpoint.FullAddress(),
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = p.getTransport(backend)
	proxy.ErrorHandler = p.errorHandler(backend)

	// Modify the request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		p.modifyRequest(req, r, endpoint)
	}

	// Set timeout
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
	}

	// Proxy the request
	proxy.ServeHTTP(w, r)

	// Record success
	if backend.CircuitBreaker != nil {
		backend.CircuitBreaker.RecordSuccess()
	}

	return nil
}

// ProxyWithRetry proxies the request with retry support.
// Properly handles context cancellation in retry loops.
// Uses ResponseRecorder for non-final attempts to avoid writing to already-written response.
func (p *Proxy) ProxyWithRetry(w http.ResponseWriter, r *http.Request, backend *Backend, timeout time.Duration) error {
	if !p.config.RetryEnabled {
		return p.ServeHTTP(w, r, backend, timeout)
	}

	ctx := r.Context()
	var lastErr error

	// Buffer the request body for retries if it exists
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		_ = r.Body.Close() // Ignore error on close after successful read
	}

	for attempt := 0; attempt <= p.config.MaxRetries; attempt++ {
		// Check context cancellation before each attempt
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if attempt > 0 {
			// Wait before retry with context cancellation support
			backoffDuration := p.config.RetryBackoff * time.Duration(attempt)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoffDuration):
			}

			p.logger.Debug("retrying request",
				zap.Int("attempt", attempt),
				zap.String("backend", backend.Name),
			)
		}

		// Restore the request body for each attempt
		if bodyBytes != nil {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// For non-final attempts, use a ResponseRecorder to avoid writing to the actual response
		isFinalAttempt := attempt == p.config.MaxRetries
		if isFinalAttempt {
			// Final attempt - write directly to the response
			err := p.ServeHTTP(w, r, backend, timeout)
			if err == nil {
				return nil
			}
			lastErr = err
		} else {
			// Non-final attempt - use ResponseRecorder
			recorder := httptest.NewRecorder()
			err := p.ServeHTTP(recorder, r, backend, timeout)
			if err == nil {
				// Success - copy the recorded response to the actual response
				for key, values := range recorder.Header() {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.WriteHeader(recorder.Code)
				if _, writeErr := w.Write(recorder.Body.Bytes()); writeErr != nil {
					p.logger.Error("failed to write response body",
						zap.Error(writeErr),
						zap.String("backend", backend.Name),
					)
				}
				return nil
			}
			lastErr = err
		}

		p.logger.Warn("proxy request failed",
			zap.Error(lastErr),
			zap.Int("attempt", attempt),
			zap.String("backend", backend.Name),
		)
	}

	return lastErr
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
		if clientIP := getClientIP(original); clientIP != "" {
			if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
				req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
			} else {
				req.Header.Set("X-Forwarded-For", clientIP)
			}
		}

		if original.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}

		req.Header.Set("X-Forwarded-Host", original.Host)
	}

	// Remove hop-by-hop headers
	removeHopByHopHeaders(req.Header)
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
		if _, writeErr := w.Write([]byte(`{"error": "Bad Gateway", "message": "Failed to connect to backend"}`)); writeErr != nil {
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
