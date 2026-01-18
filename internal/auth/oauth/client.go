// Package oauth provides OAuth2 client credentials flow for the API Gateway.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/auth"
)

// Common errors for OAuth2 client.
var (
	ErrTokenRequestFailed   = errors.New("token request failed")
	ErrInvalidResponse      = errors.New("invalid token response")
	ErrTokenExpired         = errors.New("token expired")
	ErrMissingClientID      = errors.New("missing client ID")
	ErrMissingClientSecret  = errors.New("missing client secret")
	ErrMissingTokenEndpoint = errors.New("missing token endpoint")
)

// Metrics for OAuth2 client.
var (
	oauth2TokenRequestTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_oauth2_token_request_total",
			Help: "Total number of OAuth2 token requests",
		},
		[]string{"result"},
	)

	oauth2TokenRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "avapigw_oauth2_token_request_duration_seconds",
			Help:    "Duration of OAuth2 token requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	oauth2TokenCacheHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "avapigw_oauth2_token_cache_hits_total",
			Help: "Total number of OAuth2 token cache hits",
		},
	)

	oauth2TokenCacheMisses = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "avapigw_oauth2_token_cache_misses_total",
			Help: "Total number of OAuth2 token cache misses",
		},
	)
)

// TokenResponse represents an OAuth2 token response.
type TokenResponse struct {
	// AccessToken is the access token.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token (usually "Bearer").
	TokenType string `json:"token_type"`

	// ExpiresIn is the number of seconds until the token expires.
	ExpiresIn int64 `json:"expires_in"`

	// RefreshToken is the refresh token (optional).
	RefreshToken string `json:"refresh_token,omitempty"`

	// Scope is the scope of the token.
	Scope string `json:"scope,omitempty"`

	// ExpiresAt is the calculated expiration time.
	ExpiresAt time.Time `json:"-"`
}

// IsExpired checks if the token is expired.
func (t *TokenResponse) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsExpiredWithBuffer checks if the token is expired with a buffer.
func (t *TokenResponse) IsExpiredWithBuffer(buffer time.Duration) bool {
	return time.Now().Add(buffer).After(t.ExpiresAt)
}

// Config holds configuration for the OAuth2 client.
type Config struct {
	// TokenEndpoint is the OAuth2 token endpoint URL.
	TokenEndpoint string

	// ClientID is the OAuth2 client ID.
	ClientID string

	// ClientSecret is the OAuth2 client secret.
	ClientSecret string

	// Scopes is the list of scopes to request.
	Scopes []string

	// Timeout is the timeout for token requests.
	Timeout time.Duration

	// RefreshBuffer is the time before expiry to refresh the token.
	RefreshBuffer time.Duration

	// HTTPClient is the HTTP client to use (optional).
	HTTPClient *http.Client

	// Logger is the logger to use (optional).
	Logger *zap.Logger
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Timeout:       30 * time.Second,
		RefreshBuffer: 60 * time.Second,
	}
}

// Client is an OAuth2 client credentials flow client.
type Client struct {
	tokenEndpoint string
	clientID      string
	clientSecret  string
	scopes        []string
	timeout       time.Duration
	refreshBuffer time.Duration
	httpClient    *http.Client
	logger        *zap.Logger

	// Token cache
	token *TokenResponse
	mu    sync.RWMutex
}

// NewClient creates a new OAuth2 client.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}

	if config.TokenEndpoint == "" {
		return nil, ErrMissingTokenEndpoint
	}

	if config.ClientID == "" {
		return nil, ErrMissingClientID
	}

	if config.ClientSecret == "" {
		return nil, ErrMissingClientSecret
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	refreshBuffer := config.RefreshBuffer
	if refreshBuffer <= 0 {
		refreshBuffer = 60 * time.Second
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: timeout,
		}
	}

	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Client{
		tokenEndpoint: config.TokenEndpoint,
		clientID:      config.ClientID,
		clientSecret:  config.ClientSecret,
		scopes:        config.Scopes,
		timeout:       timeout,
		refreshBuffer: refreshBuffer,
		httpClient:    httpClient,
		logger:        logger,
	}, nil
}

// GetToken returns a valid access token, fetching a new one if necessary.
func (c *Client) GetToken(ctx context.Context) (*TokenResponse, error) {
	// Check cache first
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	if token != nil && !token.IsExpiredWithBuffer(c.refreshBuffer) {
		oauth2TokenCacheHits.Inc()
		return token, nil
	}

	oauth2TokenCacheMisses.Inc()

	// Fetch new token
	return c.FetchToken(ctx)
}

// FetchToken fetches a new access token from the token endpoint.
func (c *Client) FetchToken(ctx context.Context) (*TokenResponse, error) {
	start := time.Now()
	result := auth.MetricResultSuccess

	defer func() {
		duration := time.Since(start).Seconds()
		oauth2TokenRequestTotal.WithLabelValues(result).Inc()
		oauth2TokenRequestDuration.WithLabelValues(result).Observe(duration)
	}()

	req, result, err := c.buildTokenRequest(ctx)
	if err != nil {
		return nil, err
	}

	body, result, err := c.executeTokenRequest(req)
	if err != nil {
		return nil, err
	}

	tokenResp, result, err := c.parseTokenResponse(body)
	if err != nil {
		return nil, err
	}

	c.cacheToken(tokenResp)
	return tokenResp, nil
}

// buildTokenRequest creates the HTTP request for token fetch.
func (c *Client) buildTokenRequest(ctx context.Context) (*http.Request, string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	if len(c.scopes) > 0 {
		data.Set("scope", strings.Join(c.scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, "request_error", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	return req, auth.MetricResultSuccess, nil
}

// executeTokenRequest sends the token request and reads the response body.
func (c *Client) executeTokenRequest(req *http.Request) (body []byte, metricResult string, err error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "network_error", fmt.Errorf("%w: %w", ErrTokenRequestFailed, err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, "read_error", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		c.logger.Error("token request failed",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(body)),
		)
		return nil, "token_error", fmt.Errorf("%w: status %d", ErrTokenRequestFailed, resp.StatusCode)
	}

	return body, auth.MetricResultSuccess, nil
}

// parseTokenResponse parses the token response body and sets expiration.
func (c *Client) parseTokenResponse(body []byte) (*TokenResponse, string, error) {
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, "parse_error", fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	if tokenResp.ExpiresIn > 0 {
		tokenResp.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		tokenResp.ExpiresAt = time.Now().Add(time.Hour)
	}

	return &tokenResp, auth.MetricResultSuccess, nil
}

// cacheToken stores the token in the client cache.
func (c *Client) cacheToken(tokenResp *TokenResponse) {
	c.mu.Lock()
	c.token = tokenResp
	c.mu.Unlock()

	c.logger.Debug("fetched new OAuth2 token",
		zap.String("tokenType", tokenResp.TokenType),
		zap.Time("expiresAt", tokenResp.ExpiresAt),
	)
}

// GetAccessToken returns just the access token string.
func (c *Client) GetAccessToken(ctx context.Context) (string, error) {
	token, err := c.GetToken(ctx)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// InvalidateToken invalidates the cached token.
func (c *Client) InvalidateToken() {
	c.mu.Lock()
	c.token = nil
	c.mu.Unlock()
}

// StartAutoRefresh starts automatic token refresh.
func (c *Client) StartAutoRefresh(ctx context.Context) {
	go c.autoRefreshLoop(ctx)
}

// autoRefreshLoop is the main loop for automatic token refresh.
func (c *Client) autoRefreshLoop(ctx context.Context) {
	for {
		waitDuration := c.calculateRefreshWaitDuration()

		if !c.waitAndRefresh(ctx, waitDuration) {
			return
		}
	}
}

// calculateRefreshWaitDuration calculates how long to wait before the next token refresh.
func (c *Client) calculateRefreshWaitDuration() time.Duration {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	if token == nil || token.IsExpired() {
		return 0
	}

	waitDuration := time.Until(token.ExpiresAt) - c.refreshBuffer
	if waitDuration < 0 {
		return 0
	}
	return waitDuration
}

// waitAndRefresh waits for the specified duration and then refreshes the token.
// Returns false if the context is cancelled.
func (c *Client) waitAndRefresh(ctx context.Context, waitDuration time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(waitDuration):
		if _, err := c.FetchToken(ctx); err != nil {
			c.logger.Error("auto-refresh token failed", zap.Error(err))
			return c.waitForRetry(ctx)
		}
		return true
	}
}

// waitForRetry waits for a short delay before retrying token refresh.
// Returns false if the context is cancelled.
func (c *Client) waitForRetry(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(5 * time.Second):
		return true
	}
}

// RoundTripper returns an http.RoundTripper that adds the OAuth2 token to requests.
func (c *Client) RoundTripper(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &oauth2RoundTripper{
		client: c,
		base:   base,
	}
}

// oauth2RoundTripper is an http.RoundTripper that adds OAuth2 tokens to requests.
type oauth2RoundTripper struct {
	client *Client
	base   http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (rt *oauth2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := rt.client.GetAccessToken(req.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth2 token: %w", err)
	}

	// Clone the request to avoid modifying the original
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "Bearer "+token)

	return rt.base.RoundTrip(req2)
}

// TokenSource provides access tokens.
type TokenSource interface {
	// Token returns a valid access token.
	Token(ctx context.Context) (*TokenResponse, error)
}

// ClientTokenSource wraps a Client as a TokenSource.
type ClientTokenSource struct {
	client *Client
}

// NewClientTokenSource creates a new ClientTokenSource.
func NewClientTokenSource(client *Client) *ClientTokenSource {
	return &ClientTokenSource{client: client}
}

// Token implements TokenSource.
func (s *ClientTokenSource) Token(ctx context.Context) (*TokenResponse, error) {
	return s.client.GetToken(ctx)
}

// StaticTokenSource returns a static token.
type StaticTokenSource struct {
	token *TokenResponse
}

// NewStaticTokenSource creates a new StaticTokenSource.
func NewStaticTokenSource(accessToken string) *StaticTokenSource {
	return &StaticTokenSource{
		token: &TokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(100 * 365 * 24 * time.Hour), // Never expires
		},
	}
}

// Token implements TokenSource.
func (s *StaticTokenSource) Token(ctx context.Context) (*TokenResponse, error) {
	return s.token, nil
}

// TokenIntrospectionResponse represents an OAuth2 token introspection response.
type TokenIntrospectionResponse struct {
	// Active indicates whether the token is active.
	Active bool `json:"active"`

	// Scope is the scope of the token.
	Scope string `json:"scope,omitempty"`

	// ClientID is the client ID.
	ClientID string `json:"client_id,omitempty"`

	// Username is the username.
	Username string `json:"username,omitempty"`

	// TokenType is the type of token.
	TokenType string `json:"token_type,omitempty"`

	// Exp is the expiration time (Unix timestamp).
	Exp int64 `json:"exp,omitempty"`

	// Iat is the issued at time (Unix timestamp).
	Iat int64 `json:"iat,omitempty"`

	// Nbf is the not before time (Unix timestamp).
	Nbf int64 `json:"nbf,omitempty"`

	// Sub is the subject.
	Sub string `json:"sub,omitempty"`

	// Aud is the audience.
	Aud interface{} `json:"aud,omitempty"`

	// Iss is the issuer.
	Iss string `json:"iss,omitempty"`

	// Jti is the JWT ID.
	Jti string `json:"jti,omitempty"`
}

// IntrospectionClient is a client for OAuth2 token introspection.
type IntrospectionClient struct {
	introspectionEndpoint string
	clientID              string
	clientSecret          string
	httpClient            *http.Client
	logger                *zap.Logger
}

// IntrospectionConfig holds configuration for the introspection client.
type IntrospectionConfig struct {
	// IntrospectionEndpoint is the OAuth2 introspection endpoint URL.
	IntrospectionEndpoint string

	// ClientID is the OAuth2 client ID.
	ClientID string

	// ClientSecret is the OAuth2 client secret.
	ClientSecret string

	// Timeout is the timeout for introspection requests.
	Timeout time.Duration

	// HTTPClient is the HTTP client to use (optional).
	HTTPClient *http.Client

	// Logger is the logger to use (optional).
	Logger *zap.Logger
}

// NewIntrospectionClient creates a new introspection client.
func NewIntrospectionClient(config *IntrospectionConfig) (*IntrospectionClient, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}

	if config.IntrospectionEndpoint == "" {
		return nil, errors.New("introspection endpoint is required")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: timeout,
		}
	}

	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &IntrospectionClient{
		introspectionEndpoint: config.IntrospectionEndpoint,
		clientID:              config.ClientID,
		clientSecret:          config.ClientSecret,
		httpClient:            httpClient,
		logger:                logger,
	}, nil
}

// Introspect introspects a token.
func (c *IntrospectionClient) Introspect(ctx context.Context, token string) (*TokenIntrospectionResponse, error) {
	// Build request body
	data := url.Values{}
	data.Set("token", token)

	// Create request
	reqBody := strings.NewReader(data.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.introspectionEndpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Add client credentials if provided
	if c.clientID != "" && c.clientSecret != "" {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		c.logger.Error("introspection request failed",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(body)),
		)
		return nil, fmt.Errorf("introspection failed: status %d", resp.StatusCode)
	}

	// Parse response
	var introspectionResp TokenIntrospectionResponse
	if err := json.Unmarshal(body, &introspectionResp); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	return &introspectionResp, nil
}

// IsActive checks if a token is active.
func (c *IntrospectionClient) IsActive(ctx context.Context, token string) (bool, error) {
	resp, err := c.Introspect(ctx, token)
	if err != nil {
		return false, err
	}
	return resp.Active, nil
}
