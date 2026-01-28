package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// DiscoveryDocument represents an OIDC discovery document.
type DiscoveryDocument struct {
	// Issuer is the issuer identifier.
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is the authorization endpoint URL.
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// TokenEndpoint is the token endpoint URL.
	TokenEndpoint string `json:"token_endpoint"`

	// UserinfoEndpoint is the userinfo endpoint URL.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// JWKSUri is the JWKS endpoint URL.
	JWKSUri string `json:"jwks_uri"`

	// RegistrationEndpoint is the registration endpoint URL.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// ScopesSupported is the list of supported scopes.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ResponseTypesSupported is the list of supported response types.
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`

	// ResponseModesSupported is the list of supported response modes.
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// GrantTypesSupported is the list of supported grant types.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// SubjectTypesSupported is the list of supported subject types.
	SubjectTypesSupported []string `json:"subject_types_supported,omitempty"`

	// IDTokenSigningAlgValuesSupported is the list of supported ID token signing algorithms.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported is the list of supported token endpoint auth methods.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// ClaimsSupported is the list of supported claims.
	ClaimsSupported []string `json:"claims_supported,omitempty"`

	// IntrospectionEndpoint is the token introspection endpoint URL.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// RevocationEndpoint is the token revocation endpoint URL.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// EndSessionEndpoint is the end session endpoint URL.
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`

	// CodeChallengeMethodsSupported is the list of supported PKCE code challenge methods.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

// DiscoveryClient fetches and caches OIDC discovery documents.
type DiscoveryClient interface {
	// GetDiscovery returns the discovery document for a provider.
	GetDiscovery(ctx context.Context, providerName string) (*DiscoveryDocument, error)

	// Refresh refreshes the discovery document for a provider.
	Refresh(ctx context.Context, providerName string) error

	// Close closes the client.
	Close() error
}

// discoveryClient implements DiscoveryClient.
type discoveryClient struct {
	config     *Config
	httpClient *http.Client
	logger     observability.Logger
	metrics    *Metrics

	mu    sync.RWMutex
	cache map[string]*discoveryEntry
}

type discoveryEntry struct {
	document  *DiscoveryDocument
	expiresAt time.Time
}

// DiscoveryClientOption is a functional option for the discovery client.
type DiscoveryClientOption func(*discoveryClient)

// WithDiscoveryHTTPClient sets the HTTP client.
func WithDiscoveryHTTPClient(client *http.Client) DiscoveryClientOption {
	return func(c *discoveryClient) {
		c.httpClient = client
	}
}

// WithDiscoveryLogger sets the logger.
func WithDiscoveryLogger(logger observability.Logger) DiscoveryClientOption {
	return func(c *discoveryClient) {
		c.logger = logger
	}
}

// WithDiscoveryMetrics sets the metrics.
func WithDiscoveryMetrics(metrics *Metrics) DiscoveryClientOption {
	return func(c *discoveryClient) {
		c.metrics = metrics
	}
}

// NewDiscoveryClient creates a new discovery client.
func NewDiscoveryClient(config *Config, opts ...DiscoveryClientOption) (DiscoveryClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	c := &discoveryClient{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: observability.NopLogger(),
		cache:  make(map[string]*discoveryEntry),
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.metrics == nil {
		c.metrics = NewMetrics("gateway")
	}

	return c, nil
}

// GetDiscovery returns the discovery document for a provider.
func (c *discoveryClient) GetDiscovery(ctx context.Context, providerName string) (*DiscoveryDocument, error) {
	// Check cache first
	c.mu.RLock()
	entry, ok := c.cache[providerName]
	c.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		c.metrics.RecordDiscovery("cache_hit", providerName)
		return entry.document, nil
	}

	// Fetch discovery document
	return c.fetchDiscovery(ctx, providerName)
}

// Refresh refreshes the discovery document for a provider.
func (c *discoveryClient) Refresh(ctx context.Context, providerName string) error {
	_, err := c.fetchDiscovery(ctx, providerName)
	return err
}

// Close closes the client.
func (c *discoveryClient) Close() error {
	return nil
}

// fetchDiscovery fetches the discovery document for a provider.
func (c *discoveryClient) fetchDiscovery(ctx context.Context, providerName string) (*DiscoveryDocument, error) {
	start := time.Now()

	provider := c.config.GetProvider(providerName)
	if provider == nil {
		c.metrics.RecordDiscovery("error", providerName)
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	discoveryURL := provider.GetDiscoveryURL()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		c.metrics.RecordDiscovery("error", providerName)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.metrics.RecordDiscovery("error", providerName)
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.metrics.RecordDiscovery("error", providerName)
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.metrics.RecordDiscovery("error", providerName)
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var doc DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		c.metrics.RecordDiscovery("error", providerName)
		return nil, fmt.Errorf("failed to parse discovery document: %w", err)
	}

	// Validate issuer matches
	if doc.Issuer != provider.Issuer {
		c.metrics.RecordDiscovery("error", providerName)
		return nil, fmt.Errorf("issuer mismatch: expected %s, got %s", provider.Issuer, doc.Issuer)
	}

	// Cache the document
	ttl := c.config.DiscoveryCacheTTL
	if ttl == 0 {
		ttl = time.Hour
	}

	c.mu.Lock()
	c.cache[providerName] = &discoveryEntry{
		document:  &doc,
		expiresAt: time.Now().Add(ttl),
	}
	c.mu.Unlock()

	c.metrics.RecordDiscovery("success", providerName)
	c.logger.Debug("discovery document fetched",
		observability.String("provider", providerName),
		observability.String("issuer", doc.Issuer),
		observability.Duration("duration", time.Since(start)),
	)

	return &doc, nil
}

// Ensure discoveryClient implements DiscoveryClient.
var _ DiscoveryClient = (*discoveryClient)(nil)
