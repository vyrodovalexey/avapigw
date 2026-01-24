package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// JWKS timeout constants.
const (
	// DefaultJWKSRefreshTimeout is the default timeout for JWKS refresh operations.
	DefaultJWKSRefreshTimeout = 30 * time.Second

	// DefaultHTTPClientTimeout is the default timeout for HTTP client operations.
	DefaultHTTPClientTimeout = 30 * time.Second
)

// RetryConfig contains configuration for retry with exponential backoff.
type RetryConfig struct {
	MaxAttempts     int
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:     3,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
	}
}

// KeySet represents a set of cryptographic keys for JWT validation.
type KeySet interface {
	// GetKey returns a key by ID.
	GetKey(ctx context.Context, keyID string) (crypto.PublicKey, error)

	// GetKeyForAlgorithm returns a key suitable for the given algorithm.
	GetKeyForAlgorithm(ctx context.Context, keyID, algorithm string) (crypto.PublicKey, error)

	// Refresh refreshes the key set.
	Refresh(ctx context.Context) error

	// Close closes the key set.
	Close() error
}

// JWKSKeySet implements KeySet using a JWKS URL.
type JWKSKeySet struct {
	url         string
	httpClient  *http.Client
	logger      observability.Logger
	cacheTTL    time.Duration
	retryConfig RetryConfig

	mu          sync.RWMutex
	keys        jwk.Set
	lastRefresh time.Time

	// Background refresh
	stopCh    chan struct{}
	stoppedCh chan struct{}
	refreshes atomic.Int64
	errors    atomic.Int64
}

// JWKSKeySetOption is a functional option for JWKSKeySet.
type JWKSKeySetOption func(*JWKSKeySet)

// WithHTTPClient sets the HTTP client for JWKS fetching.
func WithHTTPClient(client *http.Client) JWKSKeySetOption {
	return func(ks *JWKSKeySet) {
		ks.httpClient = client
	}
}

// WithCacheTTL sets the cache TTL for JWKS.
func WithCacheTTL(ttl time.Duration) JWKSKeySetOption {
	return func(ks *JWKSKeySet) {
		ks.cacheTTL = ttl
	}
}

// WithJWKSLogger sets the logger for JWKS operations.
func WithJWKSLogger(logger observability.Logger) JWKSKeySetOption {
	return func(ks *JWKSKeySet) {
		ks.logger = logger
	}
}

// WithRetryConfig sets the retry configuration for JWKS fetching.
func WithRetryConfig(cfg RetryConfig) JWKSKeySetOption {
	return func(ks *JWKSKeySet) {
		ks.retryConfig = cfg
	}
}

// NewJWKSKeySet creates a new JWKS key set.
func NewJWKSKeySet(url string, opts ...JWKSKeySetOption) (*JWKSKeySet, error) {
	if url == "" {
		return nil, fmt.Errorf("JWKS URL is required")
	}

	ks := &JWKSKeySet{
		url: url,
		httpClient: &http.Client{
			Timeout: DefaultHTTPClientTimeout,
		},
		logger:      observability.NopLogger(),
		cacheTTL:    time.Hour,
		retryConfig: DefaultRetryConfig(),
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}

	for _, opt := range opts {
		opt(ks)
	}

	return ks, nil
}

// Start starts background refresh of the key set.
func (ks *JWKSKeySet) Start(ctx context.Context) error {
	// Initial fetch
	if err := ks.Refresh(ctx); err != nil {
		return fmt.Errorf("initial JWKS fetch failed: %w", err)
	}

	// Start background refresh
	go ks.refreshLoop()

	return nil
}

// GetKey returns a key by ID.
func (ks *JWKSKeySet) GetKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	ks.mu.RLock()
	keys := ks.keys
	ks.mu.RUnlock()

	if keys == nil {
		if err := ks.Refresh(ctx); err != nil {
			return nil, err
		}
		ks.mu.RLock()
		keys = ks.keys
		ks.mu.RUnlock()
	}

	if keys == nil {
		return nil, ErrKeyNotFound
	}

	key, found := keys.LookupKeyID(keyID)
	if !found {
		// Try refreshing and looking again
		if err := ks.Refresh(ctx); err != nil {
			return nil, err
		}
		ks.mu.RLock()
		keys = ks.keys
		ks.mu.RUnlock()

		key, found = keys.LookupKeyID(keyID)
		if !found {
			return nil, NewKeyError(keyID, "key not found", ErrKeyNotFound)
		}
	}

	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil, NewKeyError(keyID, "failed to extract raw key", err)
	}

	pubKey, ok := rawKey.(crypto.PublicKey)
	if !ok {
		return nil, NewKeyError(keyID, "key is not a public key", ErrInvalidKey)
	}

	return pubKey, nil
}

// GetKeyForAlgorithm returns a key suitable for the given algorithm.
func (ks *JWKSKeySet) GetKeyForAlgorithm(ctx context.Context, keyID, algorithm string) (crypto.PublicKey, error) {
	key, err := ks.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	// Validate key type matches algorithm
	if err := validateKeyAlgorithm(key, algorithm); err != nil {
		return nil, NewKeyError(keyID, err.Error(), ErrInvalidKey)
	}

	return key, nil
}

// Refresh refreshes the key set from the JWKS URL with retry and exponential backoff.
func (ks *JWKSKeySet) Refresh(ctx context.Context) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if refresh is needed
	if ks.keys != nil && time.Since(ks.lastRefresh) < ks.cacheTTL/2 {
		return nil
	}

	var lastErr error
	interval := ks.retryConfig.InitialInterval

	for attempt := 0; attempt < ks.retryConfig.MaxAttempts; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Attempt to fetch JWKS
		err := ks.fetchJWKS(ctx)
		if err == nil {
			return nil
		}

		lastErr = err
		ks.logger.Warn("JWKS fetch attempt failed",
			observability.String("url", ks.url),
			observability.Int("attempt", attempt+1),
			observability.Int("max_attempts", ks.retryConfig.MaxAttempts),
			observability.Error(err),
		)

		// Don't sleep after the last attempt
		if attempt < ks.retryConfig.MaxAttempts-1 {
			// Add jitter to prevent thundering herd
			jitter := time.Duration(float64(interval) * 0.25 * secureRandomFloat())
			sleepDuration := interval + jitter

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleepDuration):
			}

			// Calculate next interval with exponential backoff
			interval = time.Duration(float64(interval) * ks.retryConfig.Multiplier)
			if interval > ks.retryConfig.MaxInterval {
				interval = ks.retryConfig.MaxInterval
			}
		}
	}

	ks.errors.Add(1)
	return fmt.Errorf("%w after %d attempts: %v", ErrJWKSFetchFailed, ks.retryConfig.MaxAttempts, lastErr)
}

// fetchJWKS performs a single JWKS fetch attempt.
func (ks *JWKSKeySet) fetchJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ks.url, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	keys, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	ks.keys = keys
	ks.lastRefresh = time.Now()
	ks.refreshes.Add(1)

	ks.logger.Debug("JWKS refreshed",
		observability.String("url", ks.url),
		observability.Int("key_count", keys.Len()),
	)

	return nil
}

// secureRandomFloat returns a cryptographically secure random float64 between 0 and 1.
func secureRandomFloat() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5 // fallback to middle value
	}
	return float64(binary.LittleEndian.Uint64(b[:])) / float64(math.MaxUint64)
}

// Close closes the key set.
func (ks *JWKSKeySet) Close() error {
	close(ks.stopCh)
	<-ks.stoppedCh
	return nil
}

// refreshLoop periodically refreshes the key set.
func (ks *JWKSKeySet) refreshLoop() {
	defer close(ks.stoppedCh)

	ticker := time.NewTicker(ks.cacheTTL / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ks.stopCh:
			return
		case <-ticker.C:
			ks.performRefresh()
		}
	}
}

// performRefresh performs a single JWKS refresh operation with proper context management.
func (ks *JWKSKeySet) performRefresh() {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultJWKSRefreshTimeout)
	defer cancel()

	if err := ks.Refresh(ctx); err != nil {
		ks.logger.Error("failed to refresh JWKS",
			observability.Error(err),
			observability.String("url", ks.url),
		)
	} else {
		ks.logger.Debug("JWKS refresh completed successfully",
			observability.String("url", ks.url),
		)
	}
}

// Stats returns statistics about the key set.
func (ks *JWKSKeySet) Stats() JWKSStats {
	ks.mu.RLock()
	keyCount := 0
	if ks.keys != nil {
		keyCount = ks.keys.Len()
	}
	lastRefresh := ks.lastRefresh
	ks.mu.RUnlock()

	return JWKSStats{
		URL:         ks.url,
		KeyCount:    keyCount,
		LastRefresh: lastRefresh,
		Refreshes:   ks.refreshes.Load(),
		Errors:      ks.errors.Load(),
	}
}

// JWKSStats contains statistics about a JWKS key set.
type JWKSStats struct {
	URL         string
	KeyCount    int
	LastRefresh time.Time
	Refreshes   int64
	Errors      int64
}

// StaticKeySet implements KeySet using static keys.
type StaticKeySet struct {
	keys   map[string]crypto.PublicKey
	logger observability.Logger
}

// NewStaticKeySet creates a new static key set.
func NewStaticKeySet(keys []StaticKey, logger observability.Logger) (*StaticKeySet, error) {
	ks := &StaticKeySet{
		keys:   make(map[string]crypto.PublicKey),
		logger: logger,
	}

	for _, key := range keys {
		pubKey, err := parseStaticKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key %s: %w", key.KeyID, err)
		}
		ks.keys[key.KeyID] = pubKey
	}

	return ks, nil
}

// GetKey returns a key by ID.
func (ks *StaticKeySet) GetKey(_ context.Context, keyID string) (crypto.PublicKey, error) {
	key, ok := ks.keys[keyID]
	if !ok {
		return nil, NewKeyError(keyID, "key not found", ErrKeyNotFound)
	}
	return key, nil
}

// GetKeyForAlgorithm returns a key suitable for the given algorithm.
func (ks *StaticKeySet) GetKeyForAlgorithm(ctx context.Context, keyID, algorithm string) (crypto.PublicKey, error) {
	key, err := ks.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if err := validateKeyAlgorithm(key, algorithm); err != nil {
		return nil, NewKeyError(keyID, err.Error(), ErrInvalidKey)
	}

	return key, nil
}

// Refresh is a no-op for static keys.
func (ks *StaticKeySet) Refresh(_ context.Context) error {
	return nil
}

// Close is a no-op for static keys.
func (ks *StaticKeySet) Close() error {
	return nil
}

// parseStaticKey parses a static key configuration.
func parseStaticKey(key StaticKey) (crypto.PublicKey, error) {
	var keyData []byte
	var err error

	if key.Key != "" {
		keyData = []byte(key.Key)
	} else if key.KeyFile != "" {
		// Read from file - would need to implement file reading
		return nil, fmt.Errorf("keyFile not yet implemented")
	} else {
		return nil, fmt.Errorf("key or keyFile is required")
	}

	// Try to parse as JWK first
	jwkKey, err := jwk.ParseKey(keyData)
	if err == nil {
		var rawKey interface{}
		if err := jwkKey.Raw(&rawKey); err != nil {
			return nil, err
		}
		if pubKey, ok := rawKey.(crypto.PublicKey); ok {
			return pubKey, nil
		}
		return nil, fmt.Errorf("key is not a public key")
	}

	// Try to parse as PEM
	return parsePEMKey(keyData)
}

// parsePEMKey parses a PEM-encoded key.
func parsePEMKey(data []byte) (crypto.PublicKey, error) {
	// Try parsing as JWK JSON
	var jwkData map[string]interface{}
	if err := json.Unmarshal(data, &jwkData); err == nil {
		key, err := jwk.ParseKey(data)
		if err != nil {
			return nil, err
		}
		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, err
		}
		if pubKey, ok := rawKey.(crypto.PublicKey); ok {
			return pubKey, nil
		}
	}

	// Try parsing as PEM-encoded public key
	block, _ := pem.Decode(data)
	if block != nil {
		switch block.Type {
		case "PUBLIC KEY":
			// PKIX format (most common for public keys)
			pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
			}
			if pk, ok := pubKey.(crypto.PublicKey); ok {
				return pk, nil
			}
			return nil, fmt.Errorf("parsed key is not a public key")
		case "RSA PUBLIC KEY":
			// PKCS#1 format for RSA
			pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKCS1 public key: %w", err)
			}
			return pubKey, nil
		case "EC PUBLIC KEY":
			// EC public key
			pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse EC public key: %w", err)
			}
			if pk, ok := pubKey.(crypto.PublicKey); ok {
				return pk, nil
			}
			return nil, fmt.Errorf("parsed key is not a public key")
		case "CERTIFICATE":
			// X.509 certificate - extract public key
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			return cert.PublicKey, nil
		default:
			return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
		}
	}

	return nil, fmt.Errorf("unsupported key format")
}

// validateKeyAlgorithm validates that a key is suitable for an algorithm.
func validateKeyAlgorithm(key crypto.PublicKey, algorithm string) error {
	switch algorithm {
	case AlgRS256, AlgRS384, AlgRS512, AlgPS256, AlgPS384, AlgPS512:
		if _, ok := key.(*rsa.PublicKey); !ok {
			return fmt.Errorf("algorithm %s requires RSA key", algorithm)
		}
	case AlgES256, AlgES384, AlgES512:
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("algorithm %s requires ECDSA key", algorithm)
		}
	case AlgEdDSA, AlgEd25519:
		if _, ok := key.(ed25519.PublicKey); !ok {
			return fmt.Errorf("algorithm %s requires Ed25519 key", algorithm)
		}
	}
	return nil
}

// CompositeKeySet combines multiple key sets.
type CompositeKeySet struct {
	keySets []KeySet
	logger  observability.Logger
}

// NewCompositeKeySet creates a new composite key set.
func NewCompositeKeySet(keySets []KeySet, logger observability.Logger) *CompositeKeySet {
	return &CompositeKeySet{
		keySets: keySets,
		logger:  logger,
	}
}

// GetKey returns a key by ID from any of the key sets.
func (ks *CompositeKeySet) GetKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	for _, keySet := range ks.keySets {
		key, err := keySet.GetKey(ctx, keyID)
		if err == nil {
			return key, nil
		}
	}
	return nil, NewKeyError(keyID, "key not found in any key set", ErrKeyNotFound)
}

// GetKeyForAlgorithm returns a key suitable for the given algorithm.
func (ks *CompositeKeySet) GetKeyForAlgorithm(ctx context.Context, keyID, algorithm string) (crypto.PublicKey, error) {
	for _, keySet := range ks.keySets {
		key, err := keySet.GetKeyForAlgorithm(ctx, keyID, algorithm)
		if err == nil {
			return key, nil
		}
	}
	return nil, NewKeyError(keyID, "key not found in any key set", ErrKeyNotFound)
}

// Refresh refreshes all key sets.
func (ks *CompositeKeySet) Refresh(ctx context.Context) error {
	var lastErr error
	for _, keySet := range ks.keySets {
		if err := keySet.Refresh(ctx); err != nil {
			lastErr = err
			ks.logger.Error("failed to refresh key set", observability.Error(err))
		}
	}
	return lastErr
}

// Close closes all key sets.
func (ks *CompositeKeySet) Close() error {
	var lastErr error
	for _, keySet := range ks.keySets {
		if err := keySet.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
