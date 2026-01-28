package external

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// RetryConfig holds retry configuration for OPA requests.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts.
	MaxRetries int
	// InitialBackoff is the initial backoff duration.
	InitialBackoff time.Duration
	// MaxBackoff is the maximum backoff duration.
	MaxBackoff time.Duration
	// BackoffMultiplier is the multiplier for exponential backoff.
	BackoffMultiplier float64
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:        3,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// OPAClient is a client for OPA authorization.
type OPAClient interface {
	// Authorize sends an authorization request to OPA.
	Authorize(ctx context.Context, input *OPAInput) (*OPAResult, error)

	// Close closes the client.
	Close() error
}

// OPAInput represents the input to an OPA query.
type OPAInput struct {
	// Subject contains subject attributes.
	Subject map[string]interface{} `json:"subject,omitempty"`

	// Resource is the resource being accessed.
	Resource string `json:"resource,omitempty"`

	// Action is the action being performed.
	Action string `json:"action,omitempty"`

	// Request contains request attributes.
	Request map[string]interface{} `json:"request,omitempty"`

	// Context contains additional context.
	Context map[string]interface{} `json:"context,omitempty"`
}

// OPAResult represents the result of an OPA query.
type OPAResult struct {
	// Allow indicates if the request is allowed.
	Allow bool `json:"allow"`

	// Reason is the reason for the decision.
	Reason string `json:"reason,omitempty"`

	// DecisionID is the OPA decision ID.
	DecisionID string `json:"decision_id,omitempty"`
}

// opaClient implements OPAClient.
type opaClient struct {
	config      *OPAConfig
	httpClient  *http.Client
	logger      observability.Logger
	metrics     *Metrics
	retryConfig RetryConfig
}

// OPAClientOption is a functional option for the OPA client.
type OPAClientOption func(*opaClient)

// WithOPAHTTPClient sets the HTTP client.
func WithOPAHTTPClient(client *http.Client) OPAClientOption {
	return func(c *opaClient) {
		c.httpClient = client
	}
}

// WithOPALogger sets the logger.
func WithOPALogger(logger observability.Logger) OPAClientOption {
	return func(c *opaClient) {
		c.logger = logger
	}
}

// WithOPAMetrics sets the metrics.
func WithOPAMetrics(metrics *Metrics) OPAClientOption {
	return func(c *opaClient) {
		c.metrics = metrics
	}
}

// WithOPARetryConfig sets the retry configuration.
func WithOPARetryConfig(cfg RetryConfig) OPAClientOption {
	return func(c *opaClient) {
		c.retryConfig = cfg
	}
}

// NewOPAClient creates a new OPA client.
func NewOPAClient(config *OPAConfig, timeout time.Duration, opts ...OPAClientOption) (OPAClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	c := &opaClient{
		config: config,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger:      observability.NopLogger(),
		retryConfig: DefaultRetryConfig(),
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.metrics == nil {
		c.metrics = NewMetrics("gateway")
	}

	return c, nil
}

// Authorize sends an authorization request to OPA with retry and exponential backoff.
func (c *opaClient) Authorize(ctx context.Context, input *OPAInput) (*OPAResult, error) {
	start := time.Now()

	// Build the request URL
	url := c.config.URL
	if c.config.Policy != "" {
		url = fmt.Sprintf("%s/v1/data/%s", c.config.URL, c.config.Policy)
	}

	// Build the request body
	body := map[string]interface{}{
		"input": input,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		c.metrics.RecordRequest("opa", "error", time.Since(start))
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.retryConfig.MaxRetries; attempt++ {
		// Check context cancellation before each attempt
		select {
		case <-ctx.Done():
			c.metrics.RecordRequest("opa", "error", time.Since(start))
			return nil, ctx.Err()
		default:
		}

		// Apply backoff for retries (not on first attempt)
		if attempt > 0 {
			backoff := c.calculateBackoff(attempt)
			c.logger.Debug("retrying OPA request",
				observability.Int("attempt", attempt),
				observability.Duration("backoff", backoff),
			)

			select {
			case <-ctx.Done():
				c.metrics.RecordRequest("opa", "error", time.Since(start))
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		result, err := c.doAuthorizeRequest(ctx, url, bodyBytes)
		if err == nil {
			// Success
			status := "denied"
			if result.Allow {
				status = "allowed"
			}
			c.metrics.RecordRequest("opa", status, time.Since(start))
			c.logger.Debug("OPA authorization",
				observability.Bool("allowed", result.Allow),
				observability.String("decision_id", result.DecisionID),
				observability.Int("attempts", attempt+1),
			)
			return result, nil
		}

		lastErr = err

		// Don't retry on non-retryable errors
		if !c.isRetryableError(err) {
			break
		}

		c.logger.Warn("OPA request failed, will retry",
			observability.Int("attempt", attempt+1),
			observability.Int("max_retries", c.retryConfig.MaxRetries),
			observability.Error(err),
		)
	}

	c.metrics.RecordRequest("opa", "error", time.Since(start))
	return nil, fmt.Errorf("OPA request failed after %d attempts: %w", c.retryConfig.MaxRetries+1, lastErr)
}

// doAuthorizeRequest performs a single authorization request to OPA.
func (c *opaClient) doAuthorizeRequest(ctx context.Context, url string, bodyBytes []byte) (*OPAResult, error) {
	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(HeaderContentType, ContentTypeJSON)

	// Add custom headers
	for key, value := range c.config.Headers {
		req.Header.Set(key, value)
	}

	// Send the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &opaHTTPError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	// Parse the response
	var opaResp struct {
		Result     interface{} `json:"result"`
		DecisionID string      `json:"decision_id"`
	}

	if err := json.Unmarshal(respBody, &opaResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract the result
	result := &OPAResult{
		DecisionID: opaResp.DecisionID,
	}

	switch v := opaResp.Result.(type) {
	case bool:
		result.Allow = v
	case map[string]interface{}:
		if allow, ok := v["allow"].(bool); ok {
			result.Allow = allow
		}
		if reason, ok := v["reason"].(string); ok {
			result.Reason = reason
		}
	default:
		return nil, fmt.Errorf("unexpected result type: %T", opaResp.Result)
	}

	return result, nil
}

// opaHTTPError represents an HTTP error from OPA.
type opaHTTPError struct {
	StatusCode int
	Body       string
}

func (e *opaHTTPError) Error() string {
	return fmt.Sprintf("OPA returned status %d: %s", e.StatusCode, e.Body)
}

// calculateBackoff calculates the backoff duration for a given attempt using exponential backoff.
func (c *opaClient) calculateBackoff(attempt int) time.Duration {
	backoff := float64(c.retryConfig.InitialBackoff) * math.Pow(c.retryConfig.BackoffMultiplier, float64(attempt-1))
	if backoff > float64(c.retryConfig.MaxBackoff) {
		backoff = float64(c.retryConfig.MaxBackoff)
	}
	return time.Duration(backoff)
}

// isRetryableError determines if an error is retryable.
func (c *opaClient) isRetryableError(err error) bool {
	// Context errors are not retryable
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for HTTP errors - retry on 5xx and some 4xx
	var httpErr *opaHTTPError
	if errors.As(err, &httpErr) {
		// Retry on server errors (5xx)
		if httpErr.StatusCode >= 500 {
			return true
		}
		// Retry on rate limiting (429)
		if httpErr.StatusCode == http.StatusTooManyRequests {
			return true
		}
		// Don't retry on client errors (4xx except 429)
		return false
	}

	// Retry on network errors
	return true
}

// Close closes the client.
func (c *opaClient) Close() error {
	return nil
}

// Ensure opaClient implements OPAClient.
var _ OPAClient = (*opaClient)(nil)
