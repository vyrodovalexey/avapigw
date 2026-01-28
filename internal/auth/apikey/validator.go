package apikey

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
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

	// Initialize metrics if not provided
	if v.metrics == nil {
		v.metrics = NewMetrics("gateway")
	}

	return v, nil
}

// Validate validates an API key and returns key information.
func (v *validator) Validate(ctx context.Context, key string) (*KeyInfo, error) {
	start := time.Now()

	if key == "" {
		v.metrics.RecordValidation("error", "empty_key", time.Since(start))
		return nil, ErrEmptyAPIKey
	}

	// Look up the key in the store
	storedKey, err := v.store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrAPIKeyNotFound) {
			v.metrics.RecordValidation("error", "not_found", time.Since(start))
			return nil, ErrAPIKeyNotFound
		}
		v.metrics.RecordValidation("error", "store_error", time.Since(start))
		return nil, fmt.Errorf("failed to look up API key: %w", err)
	}

	// Validate the key
	if err := v.validateKey(key, storedKey); err != nil {
		v.metrics.RecordValidation("error", "invalid", time.Since(start))
		return nil, err
	}

	// Check if key is enabled
	if !storedKey.Enabled {
		v.metrics.RecordValidation("error", "disabled", time.Since(start))
		return nil, ErrAPIKeyDisabled
	}

	// Check expiration
	if storedKey.ExpiresAt != nil && time.Now().After(*storedKey.ExpiresAt) {
		v.metrics.RecordValidation("error", "expired", time.Since(start))
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

	v.metrics.RecordValidation("success", "valid", time.Since(start))
	v.logger.Debug("API key validated",
		observability.String("key_id", storedKey.ID),
		observability.String("key_name", storedKey.Name),
	)

	return keyInfo, nil
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
	hash := sha256.Sum256([]byte(providedKey))
	providedHash := hex.EncodeToString(hash[:])

	storedHash := storedKey.Hash
	if storedHash == "" {
		// If no hash is stored, hash the stored key for comparison
		storedHashBytes := sha256.Sum256([]byte(storedKey.Key))
		storedHash = hex.EncodeToString(storedHashBytes[:])
	}

	if subtle.ConstantTimeCompare([]byte(providedHash), []byte(storedHash)) != 1 {
		return ErrInvalidAPIKey
	}

	return nil
}

// validateSHA512 validates using SHA-512 hash comparison.
func (v *validator) validateSHA512(providedKey string, storedKey *StaticKey) error {
	hash := sha512.Sum512([]byte(providedKey))
	providedHash := hex.EncodeToString(hash[:])

	storedHash := storedKey.Hash
	if storedHash == "" {
		storedHashBytes := sha512.Sum512([]byte(storedKey.Key))
		storedHash = hex.EncodeToString(storedHashBytes[:])
	}

	if subtle.ConstantTimeCompare([]byte(providedHash), []byte(storedHash)) != 1 {
		return ErrInvalidAPIKey
	}

	return nil
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

// validatePlaintext validates using plaintext comparison (dev only).
func (v *validator) validatePlaintext(providedKey string, storedKey *StaticKey) error {
	v.logger.Warn("using plaintext API key comparison - not recommended for production")

	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(storedKey.Key)) != 1 {
		return ErrInvalidAPIKey
	}

	return nil
}

// HashKey hashes an API key using the configured algorithm.
func HashKey(key, algorithm string) (string, error) {
	switch algorithm {
	case HashAlgSHA256:
		hash := sha256.Sum256([]byte(key))
		return hex.EncodeToString(hash[:]), nil
	case HashAlgSHA512:
		hash := sha512.Sum512([]byte(key))
		return hex.EncodeToString(hash[:]), nil
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
