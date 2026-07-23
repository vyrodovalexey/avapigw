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
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/sync/singleflight"

	"github.com/vyrodovalexey/avapigw/internal/httputil"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// JWKS timeout constants.
const (
	// DefaultJWKSRefreshTimeout is the default timeout for JWKS refresh operations.
	DefaultJWKSRefreshTimeout = 30 * time.Second

	// DefaultHTTPClientTimeout is the default timeout for HTTP client operations.
	DefaultHTTPClientTimeout = 30 * time.Second

	// backoffJitterFactor is the maximum fraction of the retry interval that is
	// added as random jitter to prevent thundering herd on the JWKS endpoint.
	backoffJitterFactor = 0.25

	// refreshFlightKey is the singleflight key used to coalesce concurrent
	// JWKS refreshes into a single in-flight fetch.
	refreshFlightKey = "jwks-refresh"

	// maxJWKSResponseBytes bounds JWKS document reads so a misbehaving or
	// compromised endpoint cannot inflate gateway memory.
	maxJWKSResponseBytes = httputil.DefaultMaxResponseBytes
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

	// mu guards keys and lastRefresh. The write lock is only taken to swap in
	// a freshly fetched key set; it is never held across network I/O, so key
	// lookups stay fast even while a refresh is in flight.
	mu          sync.RWMutex
	keys        jwk.Set
	lastRefresh time.Time

	// refreshGroup coalesces concurrent refresh requests into a single
	// in-flight JWKS fetch so an IdP outage cannot stall every caller.
	refreshGroup singleflight.Group

	// Background refresh lifecycle. lifecycleMu guards started/closed:
	// Close() must not block waiting for a refresh loop that was never
	// started (Start not called, or its initial fetch failed), and a second
	// Close() must be a safe no-op instead of a close-of-closed-channel
	// panic (mirrors the vault client renewalStarted pattern).
	lifecycleMu sync.Mutex
	started     bool
	closed      bool

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

// Start starts background refresh of the key set. It is idempotent: a
// second successful Start does not launch a duplicate refresh loop, and
// Start after Close is rejected.
func (ks *JWKSKeySet) Start(ctx context.Context) error {
	// Initial fetch
	if err := ks.Refresh(ctx); err != nil {
		return fmt.Errorf("initial JWKS fetch failed: %w", err)
	}

	ks.lifecycleMu.Lock()
	defer ks.lifecycleMu.Unlock()

	if ks.closed {
		return errors.New("JWKS key set is closed")
	}
	if ks.started {
		// Refresh loop already running; nothing to launch.
		return nil
	}
	ks.started = true

	// Start background refresh
	// The refresh loop runs independently with its own context management
	go ks.refreshLoop() //nolint:contextcheck // Background goroutine manages its own context lifecycle

	return nil
}

// GetKey returns a key by ID.
//
// The lookup runs under a read lock only. When the key set has not been
// loaded yet, or the key ID is unknown, a singleflight-coalesced refresh is
// triggered so concurrent callers share one fetch instead of serializing on
// the write mutex.
func (ks *JWKSKeySet) GetKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	if key, found := ks.lookupKey(keyID); found {
		return extractPublicKey(keyID, key)
	}

	// Key set not loaded or unknown kid: trigger a coalesced refresh. When
	// the cached key set is still fresh, Refresh is a no-op, which bounds
	// unknown-kid lookups to at most one fetch per refresh window.
	if err := ks.Refresh(ctx); err != nil {
		return nil, err
	}

	key, found := ks.lookupKey(keyID)
	if !found {
		return nil, NewKeyError(keyID, "key not found", ErrKeyNotFound)
	}

	return extractPublicKey(keyID, key)
}

// lookupKey returns the JWK with the given key ID from the cached key set.
// Only a read lock is taken.
func (ks *JWKSKeySet) lookupKey(keyID string) (jwk.Key, bool) {
	ks.mu.RLock()
	keys := ks.keys
	ks.mu.RUnlock()

	if keys == nil {
		return nil, false
	}

	return keys.LookupKeyID(keyID)
}

// extractPublicKey extracts the raw public key from a JWK.
func extractPublicKey(keyID string, key jwk.Key) (crypto.PublicKey, error) {
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
//
// The freshness check runs under a read lock and the HTTP fetch happens
// outside any lock; the write lock is only taken to swap in the new key set.
// Concurrent callers are coalesced into a single in-flight fetch, and each
// caller stops waiting as soon as its own context is done, even if the shared
// fetch is still in progress.
func (ks *JWKSKeySet) Refresh(ctx context.Context) error {
	// Fail fast if the caller is already canceled to avoid starting a flight.
	if err := ctx.Err(); err != nil {
		return err
	}

	if ks.isFresh() {
		return nil
	}

	resultCh := ks.refreshGroup.DoChan(refreshFlightKey, func() (interface{}, error) {
		return nil, ks.refreshFlight(ctx)
	})

	select {
	case res := <-resultCh:
		return res.Err
	case <-ctx.Done():
		// The shared fetch continues in the background for other callers;
		// this caller stops waiting to honor its own deadline.
		return ctx.Err()
	}
}

// isFresh reports whether the cached key set is recent enough to skip a
// refresh. Only a read lock is taken.
func (ks *JWKSKeySet) isFresh() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	return ks.keys != nil && time.Since(ks.lastRefresh) < ks.cacheTTL/2
}

// refreshFlight is the body of the singleflight-coalesced refresh. It is
// detached from the initiating caller's cancellation so one canceled caller
// cannot poison the shared fetch for the other coalesced waiters.
func (ks *JWKSKeySet) refreshFlight(callerCtx context.Context) error {
	// Double-check freshness: a previous flight may have refreshed the keys
	// between the caller's staleness check and this execution.
	if ks.isFresh() {
		return nil
	}

	// Detach from the initiating caller (context values such as trace
	// metadata are preserved) and bound the whole retry loop.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(callerCtx), DefaultJWKSRefreshTimeout)
	defer cancel()

	return ks.fetchWithRetry(ctx)
}

// fetchWithRetry fetches the JWKS with retry and exponential backoff. It runs
// entirely outside the key-set lock.
func (ks *JWKSKeySet) fetchWithRetry(ctx context.Context) error {
	var lastErr error
	interval := ks.retryConfig.InitialInterval

	for attempt := 0; attempt < ks.retryConfig.MaxAttempts; attempt++ {
		// Check context before each attempt
		if err := ctx.Err(); err != nil {
			ks.errors.Add(1)
			return fmt.Errorf("%w: %w", ErrJWKSFetchFailed, err)
		}

		// Attempt to fetch JWKS
		keys, err := ks.fetchJWKS(ctx)
		if err == nil {
			ks.storeKeys(keys)
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
			if err := sleepWithJitter(ctx, interval); err != nil {
				ks.errors.Add(1)
				return fmt.Errorf("%w: %w", ErrJWKSFetchFailed, err)
			}
			interval = ks.nextInterval(interval)
		}
	}

	ks.errors.Add(1)
	return fmt.Errorf("%w after %d attempts: %w", ErrJWKSFetchFailed, ks.retryConfig.MaxAttempts, lastErr)
}

// sleepWithJitter waits for the interval plus random jitter, honoring context
// cancellation. Jitter prevents thundering herd against the JWKS endpoint.
func sleepWithJitter(ctx context.Context, interval time.Duration) error {
	jitter := time.Duration(float64(interval) * backoffJitterFactor * secureRandomFloat())
	timer := time.NewTimer(interval + jitter)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// nextInterval computes the next exponential backoff interval, capped at the
// configured maximum.
func (ks *JWKSKeySet) nextInterval(interval time.Duration) time.Duration {
	next := time.Duration(float64(interval) * ks.retryConfig.Multiplier)
	if next > ks.retryConfig.MaxInterval {
		next = ks.retryConfig.MaxInterval
	}

	return next
}

// fetchJWKS performs a single JWKS fetch attempt and returns the parsed key
// set without mutating any shared state.
func (ks *JWKSKeySet) fetchJWKS(ctx context.Context) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ks.url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Bounded read: an over-limit JWKS document is rejected (counted through
	// the fetch-error path) instead of inflating memory.
	body, err := httputil.ReadAllLimited(resp.Body, maxJWKSResponseBytes)
	if err != nil {
		if errors.Is(err, httputil.ErrResponseTooLarge) {
			ks.logger.Warn("JWKS response exceeded size limit, rejecting",
				observability.String("url", ks.url),
				observability.Int64("limit_bytes", maxJWKSResponseBytes),
			)
		}
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	keys, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return keys, nil
}

// storeKeys swaps in a freshly fetched key set. This is the only place the
// write lock is taken, and it is never held across network I/O.
func (ks *JWKSKeySet) storeKeys(keys jwk.Set) {
	ks.mu.Lock()
	ks.keys = keys
	ks.lastRefresh = time.Now()
	ks.mu.Unlock()

	ks.refreshes.Add(1)
	ks.logger.Debug("JWKS refreshed",
		observability.String("url", ks.url),
		observability.Int("key_count", keys.Len()),
	)
}

// secureRandomFloat returns a cryptographically secure random float64 between 0 and 1.
func secureRandomFloat() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5 // fallback to middle value
	}
	return float64(binary.LittleEndian.Uint64(b[:])) / float64(math.MaxUint64)
}

// Close closes the key set. It returns immediately when Start was never
// called (or its initial fetch failed, so no refresh loop is running), and
// repeated Close calls are safe no-ops.
func (ks *JWKSKeySet) Close() error {
	ks.lifecycleMu.Lock()
	if ks.closed {
		ks.lifecycleMu.Unlock()
		return nil
	}
	ks.closed = true
	started := ks.started
	ks.lifecycleMu.Unlock()

	close(ks.stopCh)
	if started {
		// Wait for the refresh loop only when it is actually running,
		// otherwise Close would block forever on stoppedCh.
		<-ks.stoppedCh
	}
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
//
// Tokens signed with a single shared key (HMAC in particular) commonly omit
// the "kid" header. When no key ID is requested and exactly one static key
// is configured, that key is unambiguous and is returned. A non-empty
// unknown key ID still fails: an explicit kid mismatch must never silently
// fall back to a different key.
func (ks *StaticKeySet) GetKey(_ context.Context, keyID string) (crypto.PublicKey, error) {
	if key, ok := ks.keys[keyID]; ok {
		return key, nil
	}

	if keyID == "" && len(ks.keys) == 1 {
		for _, key := range ks.keys {
			return key, nil
		}
	}

	return nil, NewKeyError(keyID, "key not found", ErrKeyNotFound)
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

	switch {
	case key.Key != "":
		keyData = []byte(key.Key)
	case key.KeyFile != "":
		// Read from file - would need to implement file reading
		return nil, fmt.Errorf("keyFile not yet implemented")
	default:
		return nil, fmt.Errorf("key or keyFile is required")
	}

	// HMAC algorithms use symmetric secrets, not JWK/PEM public keys.
	if isHMACAlgorithm(key.Algorithm) {
		return parseHMACKey(key, keyData)
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
	pubKey, pemErr := parsePEMKey(keyData)
	if pemErr != nil {
		return nil, fmt.Errorf(
			"algorithm %s requires a JWK or PEM key: %w", key.Algorithm, pemErr,
		)
	}
	return pubKey, nil
}

// isHMACAlgorithm reports whether alg is a symmetric HMAC signing algorithm.
func isHMACAlgorithm(alg string) bool {
	return alg == AlgHS256 || alg == AlgHS384 || alg == AlgHS512
}

// parseHMACKey builds the symmetric key for HS256/HS384/HS512 static keys.
// The key material may be a JWK "oct" key or a raw shared secret (the common
// case for authentication.jwt.secret in gateway configuration). Raw secrets
// are normalized through jwk.FromRaw — mirroring how asymmetric keys flow
// through jwx — with the algorithm and key ID attached, then the raw bytes
// used by the HMAC verifier are extracted.
func parseHMACKey(key StaticKey, keyData []byte) (crypto.PublicKey, error) {
	// Accept JWK-formatted symmetric keys ({"kty":"oct","k":"..."}) so
	// explicitly provisioned oct keys keep working.
	if jwkKey, err := jwk.ParseKey(keyData); err == nil {
		var raw interface{}
		if rawErr := jwkKey.Raw(&raw); rawErr != nil {
			return nil, fmt.Errorf("failed to extract JWK key material: %w", rawErr)
		}
		if secret, ok := raw.([]byte); ok {
			return secret, nil
		}
		return nil, fmt.Errorf(
			"algorithm %s requires a symmetric (oct) key, got asymmetric JWK", key.Algorithm,
		)
	}

	// Raw shared secret: build a jwx symmetric key to validate the material
	// (rejects empty secrets) and carry alg/kid metadata consistently.
	symKey, err := jwk.FromRaw(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to construct symmetric key for %s: %w", key.Algorithm, err)
	}
	if err := symKey.Set(jwk.AlgorithmKey, key.Algorithm); err != nil {
		return nil, fmt.Errorf("failed to set algorithm on symmetric key: %w", err)
	}
	if key.KeyID != "" {
		if err := symKey.Set(jwk.KeyIDKey, key.KeyID); err != nil {
			return nil, fmt.Errorf("failed to set key ID on symmetric key: %w", err)
		}
	}

	var secret []byte
	if err := symKey.Raw(&secret); err != nil {
		return nil, fmt.Errorf("failed to extract symmetric key bytes: %w", err)
	}
	return secret, nil
}

// parsePEMKey parses a PEM-encoded key.
func parsePEMKey(data []byte) (crypto.PublicKey, error) {
	// Try parsing as JWK JSON first
	if key, err := parseAsJWK(data); err == nil {
		return key, nil
	}

	// Try parsing as PEM-encoded public key
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("unsupported key format")
	}

	return parsePEMBlock(block)
}

// parseAsJWK attempts to parse data as a JWK.
func parseAsJWK(data []byte) (crypto.PublicKey, error) {
	var jwkData map[string]interface{}
	if err := json.Unmarshal(data, &jwkData); err != nil {
		return nil, err
	}

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
	return nil, fmt.Errorf("key is not a public key")
}

// parsePEMBlock parses a PEM block into a public key.
func parsePEMBlock(block *pem.Block) (crypto.PublicKey, error) {
	switch block.Type {
	case "PUBLIC KEY":
		return parsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "EC PUBLIC KEY":
		return parsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		return parsePublicKeyFromCertificate(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// parsePKIXPublicKey parses a PKIX-encoded public key.
func parsePKIXPublicKey(data []byte) (crypto.PublicKey, error) {
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	if pk, ok := pubKey.(crypto.PublicKey); ok {
		return pk, nil
	}
	return nil, fmt.Errorf("parsed key is not a public key")
}

// parsePublicKeyFromCertificate extracts the public key from a certificate.
func parsePublicKeyFromCertificate(data []byte) (crypto.PublicKey, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert.PublicKey, nil
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
	case AlgHS256, AlgHS384, AlgHS512:
		// HMAC requires a symmetric secret. Rejecting asymmetric keys here
		// prevents algorithm-confusion attacks where a public key is abused
		// as an HMAC secret.
		if _, ok := key.([]byte); !ok {
			return fmt.Errorf("algorithm %s requires a symmetric key", algorithm)
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
