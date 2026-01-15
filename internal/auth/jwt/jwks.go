package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// JWKSCache provides caching for JWKS (JSON Web Key Set) fetched from a remote URL.
type JWKSCache struct {
	url        string
	keys       *JSONWebKeySet
	mu         sync.RWMutex
	lastFetch  time.Time
	ttl        time.Duration
	httpClient *http.Client
	logger     *zap.Logger
	stopCh     chan struct{}
	stopped    bool
}

// JSONWebKeySet represents a JSON Web Key Set.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey represents a JSON Web Key.
type JSONWebKey struct {
	// Key type (e.g., "RSA", "EC")
	Kty string `json:"kty"`
	// Key ID
	Kid string `json:"kid,omitempty"`
	// Algorithm
	Alg string `json:"alg,omitempty"`
	// Use (e.g., "sig", "enc")
	Use string `json:"use,omitempty"`
	// Key operations
	KeyOps []string `json:"key_ops,omitempty"`

	// RSA public key components
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent

	// EC public key components
	Crv string `json:"crv,omitempty"` // Curve
	X   string `json:"x,omitempty"`   // X coordinate
	Y   string `json:"y,omitempty"`   // Y coordinate

	// Symmetric key
	K string `json:"k,omitempty"`

	// X.509 certificate chain
	X5c []string `json:"x5c,omitempty"`
	// X.509 certificate SHA-1 thumbprint
	X5t string `json:"x5t,omitempty"`
	// X.509 certificate SHA-256 thumbprint
	X5tS256 string `json:"x5t#S256,omitempty"`
	// X.509 URL
	X5u string `json:"x5u,omitempty"`
}

// NewJWKSCache creates a new JWKS cache.
func NewJWKSCache(url string, ttl time.Duration, logger *zap.Logger) *JWKSCache {
	if ttl <= 0 {
		ttl = time.Hour
	}

	return &JWKSCache{
		url: url,
		ttl: ttl,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// NewJWKSCacheWithClient creates a new JWKS cache with a custom HTTP client.
func NewJWKSCacheWithClient(url string, ttl time.Duration, client *http.Client, logger *zap.Logger) *JWKSCache {
	cache := NewJWKSCache(url, ttl, logger)
	if client != nil {
		cache.httpClient = client
	}
	return cache
}

// GetKey returns the key with the specified key ID.
func (c *JWKSCache) GetKey(kid string) (*JSONWebKey, error) {
	c.mu.RLock()
	keys := c.keys
	lastFetch := c.lastFetch
	c.mu.RUnlock()

	// Check if we need to refresh
	if keys == nil || time.Since(lastFetch) > c.ttl {
		if err := c.Refresh(context.Background()); err != nil {
			// If we have cached keys, use them even if refresh failed
			if keys == nil {
				return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
			}
			c.logger.Warn("failed to refresh JWKS, using cached keys",
				zap.Error(err),
				zap.Time("lastFetch", lastFetch),
			)
		}

		c.mu.RLock()
		keys = c.keys
		c.mu.RUnlock()
	}

	if keys == nil {
		return nil, errors.New("no JWKS available")
	}

	// Find the key
	for i := range keys.Keys {
		if keys.Keys[i].Kid == kid {
			return &keys.Keys[i], nil
		}
	}

	// If kid is empty, return the first key (for single-key JWKS)
	if kid == "" && len(keys.Keys) > 0 {
		return &keys.Keys[0], nil
	}

	return nil, fmt.Errorf("key with kid %q not found", kid)
}

// GetKeys returns all keys in the cache.
func (c *JWKSCache) GetKeys() ([]JSONWebKey, error) {
	c.mu.RLock()
	keys := c.keys
	lastFetch := c.lastFetch
	c.mu.RUnlock()

	// Check if we need to refresh
	if keys == nil || time.Since(lastFetch) > c.ttl {
		if err := c.Refresh(context.Background()); err != nil {
			if keys == nil {
				return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
			}
		}

		c.mu.RLock()
		keys = c.keys
		c.mu.RUnlock()
	}

	if keys == nil {
		return nil, errors.New("no JWKS available")
	}

	return keys.Keys, nil
}

// Refresh fetches the JWKS from the remote URL.
func (c *JWKSCache) Refresh(ctx context.Context) error {
	c.logger.Debug("refreshing JWKS", zap.String("url", c.url))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("JWKS endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	c.mu.Lock()
	c.keys = &jwks
	c.lastFetch = time.Now()
	c.mu.Unlock()

	c.logger.Info("JWKS refreshed successfully",
		zap.String("url", c.url),
		zap.Int("keyCount", len(jwks.Keys)),
	)

	return nil
}

// StartAutoRefresh starts automatic JWKS refresh at the specified interval.
func (c *JWKSCache) StartAutoRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = c.ttl / 2
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Initial fetch
		if err := c.Refresh(ctx); err != nil {
			c.logger.Error("initial JWKS fetch failed", zap.Error(err))
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-ticker.C:
				if err := c.Refresh(ctx); err != nil {
					c.logger.Error("JWKS refresh failed", zap.Error(err))
				}
			}
		}
	}()
}

// Stop stops the auto-refresh goroutine.
func (c *JWKSCache) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.stopped {
		close(c.stopCh)
		c.stopped = true
	}
}

// LastFetch returns the time of the last successful fetch.
func (c *JWKSCache) LastFetch() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastFetch
}

// URL returns the JWKS URL.
func (c *JWKSCache) URL() string {
	return c.url
}

// ToRSAPublicKey converts a JSONWebKey to an RSA public key.
func (jwk *JSONWebKey) ToRSAPublicKey() (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("key type is not RSA: %s", jwk.Kty)
	}

	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// ParseJWKSFromBytes parses a JWKS from bytes.
func ParseJWKSFromBytes(data []byte) (*JSONWebKeySet, error) {
	var jwks JSONWebKeySet
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}
	return &jwks, nil
}

// ParseJWKFromBytes parses a single JWK from bytes.
func ParseJWKFromBytes(data []byte) (*JSONWebKey, error) {
	var jwk JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}
	return &jwk, nil
}

// ParseRSAPublicKeyFromPEM parses an RSA public key from PEM-encoded data.
func ParseRSAPublicKeyFromPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS1
		rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		return rsaPub, nil
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

// LocalJWKS represents a locally configured JWKS.
type LocalJWKS struct {
	keys *JSONWebKeySet
	mu   sync.RWMutex
}

// NewLocalJWKS creates a new local JWKS from bytes.
func NewLocalJWKS(data []byte) (*LocalJWKS, error) {
	jwks, err := ParseJWKSFromBytes(data)
	if err != nil {
		return nil, err
	}
	return &LocalJWKS{keys: jwks}, nil
}

// GetKey returns the key with the specified key ID.
func (l *LocalJWKS) GetKey(kid string) (*JSONWebKey, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.keys == nil {
		return nil, errors.New("no JWKS configured")
	}

	for i := range l.keys.Keys {
		if l.keys.Keys[i].Kid == kid {
			return &l.keys.Keys[i], nil
		}
	}

	// If kid is empty, return the first key
	if kid == "" && len(l.keys.Keys) > 0 {
		return &l.keys.Keys[0], nil
	}

	return nil, fmt.Errorf("key with kid %q not found", kid)
}

// GetKeys returns all keys.
func (l *LocalJWKS) GetKeys() []JSONWebKey {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.keys == nil {
		return nil
	}

	return l.keys.Keys
}

// Update updates the JWKS.
func (l *LocalJWKS) Update(data []byte) error {
	jwks, err := ParseJWKSFromBytes(data)
	if err != nil {
		return err
	}

	l.mu.Lock()
	l.keys = jwks
	l.mu.Unlock()

	return nil
}
