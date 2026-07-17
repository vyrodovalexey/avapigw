package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Hash algorithm constants.
const (
	HashAlgSHA256    = "sha256"
	HashAlgSHA512    = "sha512"
	HashAlgBcrypt    = "bcrypt"
	HashAlgPlaintext = "plaintext"
)

// dummyKeyBytes is the amount of random material used for the dummy key
// that equalizes validation timing on the not-found path.
const dummyKeyBytes = 32

// Common errors for API key validation.
var (
	// ErrInvalidAPIKey indicates that the API key is invalid.
	ErrInvalidAPIKey = errors.New("invalid API key")

	// ErrAPIKeyNotFound indicates that the API key was not found.
	ErrAPIKeyNotFound = errors.New("API key not found")

	// ErrAPIKeyExpired indicates that the API key has expired.
	ErrAPIKeyExpired = errors.New("API key expired")

	// ErrAPIKeyDisabled indicates that the API key is disabled.
	ErrAPIKeyDisabled = errors.New("API key disabled")

	// ErrAPIKeyRevoked indicates that the API key has been revoked.
	ErrAPIKeyRevoked = errors.New("API key revoked")

	// ErrEmptyAPIKey indicates that the API key is empty.
	ErrEmptyAPIKey = errors.New("API key is empty")
)

// KeyInfo contains information about a validated API key.
type KeyInfo struct {
	// ID is the unique identifier for the key.
	ID string `json:"id"`

	// Name is a human-readable name for the key.
	Name string `json:"name,omitempty"`

	// Scopes is a list of scopes granted to the key.
	Scopes []string `json:"scopes,omitempty"`

	// Roles is a list of roles granted to the key.
	Roles []string `json:"roles,omitempty"`

	// ExpiresAt is when the key expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Metadata contains additional metadata.
	Metadata map[string]string `json:"metadata,omitempty"`

	// RateLimit is the rate limit for this key.
	RateLimit *KeyRateLimit `json:"rate_limit,omitempty"`
}

// KeyRateLimit contains rate limit information for a key.
type KeyRateLimit struct {
	// RequestsPerSecond is the rate limit.
	RequestsPerSecond int `json:"requests_per_second"`

	// Burst is the burst size.
	Burst int `json:"burst"`
}

// IsExpired returns true if the key has expired.
func (k *KeyInfo) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// Validator validates API keys.
type Validator interface {
	// Validate validates an API key and returns key information.
	Validate(ctx context.Context, key string) (*KeyInfo, error)
}

// validator implements the Validator interface.
type validator struct {
	config  *Config
	store   Store
	logger  observability.Logger
	metrics *Metrics

	// dummyKey is a random key pre-computed at construction time. It is
	// compared against on the not-found path so that unknown keys cost the
	// same as known-but-wrong keys, preventing timing-based key discovery.
	dummyKey *StaticKey

	// dummyCompares counts dummy comparisons performed on the not-found
	// path. It exists for observability in tests and debugging.
	dummyCompares atomic.Int64
}

// ValidatorOption is a functional option for the validator.
type ValidatorOption func(*validator)

// WithValidatorLogger sets the logger for the validator.
func WithValidatorLogger(logger observability.Logger) ValidatorOption {
	return func(v *validator) {
		v.logger = logger
	}
}

// WithValidatorMetrics sets the metrics for the validator.
func WithValidatorMetrics(metrics *Metrics) ValidatorOption {
	return func(v *validator) {
		v.metrics = metrics
	}
}

// WithStore sets the store for the validator.
func WithStore(store Store) ValidatorOption {
	return func(v *validator) {
		v.store = store
	}
}

// NewValidator creates a new API key validator.
func NewValidator(config *Config, opts ...ValidatorOption) (Validator, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	v := &validator{
		config: config,
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(v)
	}

	// Initialize store if not provided
	if v.store == nil {
		store, err := NewStore(config, v.logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create store: %w", err)
		}
		v.store = store
	}

	// Initialize metrics if not provided. Default to the process-wide
	// shared singleton (the one cmd/gateway registers with the /metrics
	// registry): a fresh NewMetrics instance lives on its own private
	// registry, so recordings would be invisible on the metrics endpoint
	// (gateway_apikey_validation_total stuck at 0).
	if v.metrics == nil {
		v.metrics = GetSharedMetrics()
	}

	// Warn ONCE at construction time (not on every validation) when the
	// insecure plaintext comparison mode is configured.
	if config.GetEffectiveHashAlgorithm() == HashAlgPlaintext {
		v.logger.Warn("using plaintext API key comparison - not recommended for production")
	}

	// Pre-compute the random dummy key used to equalize not-found timing.
	v.dummyKey = newDummyKey(config.GetEffectiveHashAlgorithm())

	return v, nil
}

// newDummyKey generates a StaticKey with random material and a hash
// matching the given algorithm. The dummy is generated at init time (never
// a hard-coded constant) so it cannot collide with a real key, and it is
// used exclusively to make the not-found validation path cost the same as
// the found path.
func newDummyKey(algorithm string) *StaticKey {
	raw := make([]byte, dummyKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		// Extremely unlikely; fall back to a time-derived value rather than
		// failing construction. The dummy key only equalizes timing and is
		// never used to authenticate anything.
		raw = []byte(time.Now().Format(time.RFC3339Nano))
	}

	dummy := &StaticKey{Key: hex.EncodeToString(raw)}
	if hash, err := HashKey(dummy.Key, algorithm); err == nil {
		dummy.Hash = hash
	}
	return dummy
}

// Validate validates an API key and returns key information.
func (v *validator) Validate(ctx context.Context, key string) (*KeyInfo, error) {
	start := time.Now()

	if key == "" {
		v.metrics.RecordValidation(statusError, reasonEmptyKey, time.Since(start))
		return nil, ErrEmptyAPIKey
	}

	// Look up the key in the store
	storedKey, err := v.store.Get(ctx, key)
	if err != nil {
		return nil, v.handleLookupError(key, err, start)
	}

	// Validate the key
	if err := v.validateKey(key, storedKey); err != nil {
		v.metrics.RecordValidation(statusError, reasonInvalid, time.Since(start))
		return nil, err
	}

	// Check if key is enabled
	if !storedKey.Enabled {
		v.metrics.RecordValidation(statusError, reasonDisabled, time.Since(start))
		return nil, ErrAPIKeyDisabled
	}

	// Check expiration
	if storedKey.ExpiresAt != nil && time.Now().After(*storedKey.ExpiresAt) {
		v.metrics.RecordValidation(statusError, reasonExpired, time.Since(start))
		return nil, ErrAPIKeyExpired
	}

	keyInfo := &KeyInfo{
		ID:        storedKey.ID,
		Name:      storedKey.Name,
		Scopes:    storedKey.Scopes,
		Roles:     storedKey.Roles,
		ExpiresAt: storedKey.ExpiresAt,
		Metadata:  storedKey.Metadata,
	}

	v.metrics.RecordValidation(statusSuccess, reasonValid, time.Since(start))
	v.logger.Debug("API key validated",
		observability.String("key_id", storedKey.ID),
		observability.String("key_name", storedKey.Name),
	)

	return keyInfo, nil
}

// handleLookupError maps a store lookup failure to the outcome returned to
// the caller and records the matching metric. Genuine not-found results
// perform a dummy comparison so their timing matches a found-but-invalid
// key; any other store failure (for example ErrStoreUnavailable from a
// Vault outage) is surfaced with the "store_error" metric label instead of
// "not_found" so operators can distinguish outages from misses.
func (v *validator) handleLookupError(key string, err error, start time.Time) error {
	if errors.Is(err, ErrAPIKeyNotFound) {
		v.equalizeNotFoundTiming(key)
		v.metrics.RecordValidation(statusError, reasonNotFound, time.Since(start))
		return ErrAPIKeyNotFound
	}

	v.metrics.RecordValidation(statusError, reasonStoreError, time.Since(start))
	return fmt.Errorf("failed to look up API key: %w", err)
}

// equalizeNotFoundTiming performs a comparison against the pre-computed
// dummy key. The result is intentionally discarded: the sole purpose is to
// make the not-found path perform the same hashing work as the found path.
func (v *validator) equalizeNotFoundTiming(key string) {
	v.dummyCompares.Add(1)
	_ = v.validateKey(key, v.dummyKey)
}

// validateKey validates the provided key against the stored key.
func (v *validator) validateKey(providedKey string, storedKey *StaticKey) error {
	algorithm := v.config.GetEffectiveHashAlgorithm()

	switch algorithm {
	case HashAlgSHA256:
		return v.validateSHA256(providedKey, storedKey)
	case HashAlgSHA512:
		return v.validateSHA512(providedKey, storedKey)
	case HashAlgBcrypt:
		return v.validateBcrypt(providedKey, storedKey)
	case HashAlgPlaintext:
		return v.validatePlaintext(providedKey, storedKey)
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// validateSHA256 validates using SHA-256 hash comparison.
func (v *validator) validateSHA256(providedKey string, storedKey *StaticKey) error {
	storedHash := storedKey.Hash
	if storedHash == "" {
		// If no hash is stored, hash the stored key for comparison
		storedHash = sha256Hex(storedKey.Key)
	}
	return compareHexDigests(sha256Hex(providedKey), storedHash)
}

// validateSHA512 validates using SHA-512 hash comparison.
func (v *validator) validateSHA512(providedKey string, storedKey *StaticKey) error {
	storedHash := storedKey.Hash
	if storedHash == "" {
		storedHash = sha512Hex(storedKey.Key)
	}
	return compareHexDigests(sha512Hex(providedKey), storedHash)
}

// validateBcrypt validates using bcrypt hash comparison.
func (v *validator) validateBcrypt(providedKey string, storedKey *StaticKey) error {
	storedHash := storedKey.Hash
	if storedHash == "" {
		storedHash = storedKey.Key
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(providedKey)); err != nil {
		return ErrInvalidAPIKey
	}

	return nil
}

// validatePlaintext validates using plaintext comparison (dev only). The
// insecurity warning is logged once at validator construction, not here.
func (v *validator) validatePlaintext(providedKey string, storedKey *StaticKey) error {
	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(storedKey.Key)) != 1 {
		return ErrInvalidAPIKey
	}

	return nil
}

// compareHexDigests compares two hex-encoded digests in constant time.
// Comparison is case-insensitive because configured hashes may be
// upper-case while computed digests are always lower-case.
func compareHexDigests(providedHash, storedHash string) error {
	if subtle.ConstantTimeCompare([]byte(providedHash), []byte(strings.ToLower(storedHash))) != 1 {
		return ErrInvalidAPIKey
	}
	return nil
}

// sha256Hex returns the lower-case hex-encoded SHA-256 digest of value.
func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// sha512Hex returns the lower-case hex-encoded SHA-512 digest of value.
func sha512Hex(value string) string {
	digest := sha512.Sum512([]byte(value))
	return hex.EncodeToString(digest[:])
}

// HashKey hashes an API key using the configured algorithm.
func HashKey(key, algorithm string) (string, error) {
	switch algorithm {
	case HashAlgSHA256:
		return sha256Hex(key), nil
	case HashAlgSHA512:
		return sha512Hex(key), nil
	case HashAlgBcrypt:
		hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		return string(hash), nil
	case HashAlgPlaintext:
		return key, nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// Ensure validator implements Validator.
var _ Validator = (*validator)(nil)
