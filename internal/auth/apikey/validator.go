// Package apikey provides API key validation for the API Gateway.
package apikey

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// Common errors for API key validation.
var (
	ErrKeyNotFound       = errors.New("API key not found")
	ErrKeyExpired        = errors.New("API key has expired")
	ErrKeyDisabled       = errors.New("API key is disabled")
	ErrKeyInvalid        = errors.New("invalid API key")
	ErrInvalidHash       = errors.New("invalid key hash")
	ErrMissingKey        = errors.New("missing API key")
	ErrInsufficientScope = errors.New("insufficient scope")
)

// Metrics for API key validation.
var (
	apiKeyValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_apikey_validation_total",
			Help: "Total number of API key validation attempts",
		},
		[]string{"result"},
	)

	apiKeyValidationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "avapigw_apikey_validation_duration_seconds",
			Help:    "Duration of API key validation in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"result"},
	)
)

// Store defines the interface for API key storage.
type Store interface {
	// Get retrieves an API key by its hash.
	Get(ctx context.Context, keyHash string) (*APIKey, error)

	// List returns all API keys.
	List(ctx context.Context) ([]*APIKey, error)

	// Create creates a new API key.
	Create(ctx context.Context, key *APIKey) error

	// Delete deletes an API key by its hash.
	Delete(ctx context.Context, keyHash string) error

	// Validate validates an API key hash exists and is valid.
	Validate(ctx context.Context, keyHash string) (bool, error)
}

// Hasher defines the interface for hashing API keys.
type Hasher interface {
	// Hash hashes an API key.
	Hash(key string) string

	// Compare compares a key with a hash using constant-time comparison.
	Compare(key, hash string) bool
}

// APIKey represents an API key.
type APIKey struct {
	// ID is the unique identifier for the API key.
	ID string `json:"id"`

	// Name is a human-readable name for the API key.
	Name string `json:"name"`

	// KeyHash is the hashed API key.
	KeyHash string `json:"keyHash"`

	// Scopes is the list of scopes granted to this API key.
	Scopes []string `json:"scopes,omitempty"`

	// Metadata is additional metadata for the API key.
	Metadata map[string]string `json:"metadata,omitempty"`

	// CreatedAt is when the API key was created.
	CreatedAt time.Time `json:"createdAt"`

	// ExpiresAt is when the API key expires (nil means no expiry).
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`

	// LastUsedAt is when the API key was last used.
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`

	// Enabled indicates whether the API key is enabled.
	Enabled bool `json:"enabled"`
}

// IsExpired checks if the API key has expired.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// IsValid checks if the API key is valid (enabled and not expired).
func (k *APIKey) IsValid() bool {
	return k.Enabled && !k.IsExpired()
}

// HasScope checks if the API key has the specified scope.
func (k *APIKey) HasScope(scope string) bool {
	for _, s := range k.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the API key has any of the specified scopes.
func (k *APIKey) HasAnyScope(scopes ...string) bool {
	for _, scope := range scopes {
		if k.HasScope(scope) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the API key has all of the specified scopes.
func (k *APIKey) HasAllScopes(scopes ...string) bool {
	for _, scope := range scopes {
		if !k.HasScope(scope) {
			return false
		}
	}
	return true
}

// Validator validates API keys.
type Validator struct {
	store  Store
	hasher Hasher
	logger *zap.Logger
}

// ValidatorConfig holds configuration for the API key validator.
type ValidatorConfig struct {
	Store  Store
	Hasher Hasher
	Logger *zap.Logger
}

// NewValidator creates a new API key validator.
func NewValidator(store Store, logger *zap.Logger) *Validator {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Validator{
		store:  store,
		hasher: &SHA256Hasher{},
		logger: logger,
	}
}

// NewValidatorWithConfig creates a new API key validator with custom configuration.
func NewValidatorWithConfig(config *ValidatorConfig) *Validator {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	hasher := config.Hasher
	if hasher == nil {
		hasher = &SHA256Hasher{}
	}

	return &Validator{
		store:  config.Store,
		hasher: hasher,
		logger: config.Logger,
	}
}

// Validate validates an API key and returns the key details.
func (v *Validator) Validate(ctx context.Context, key string) (*APIKey, error) {
	start := time.Now()
	result := "success"

	defer func() {
		duration := time.Since(start).Seconds()
		apiKeyValidationTotal.WithLabelValues(result).Inc()
		apiKeyValidationDuration.WithLabelValues(result).Observe(duration)
	}()

	if key == "" {
		result = "missing_key"
		return nil, ErrMissingKey
	}

	// Hash the key
	keyHash := v.hasher.Hash(key)

	// Look up the key
	apiKey, err := v.store.Get(ctx, keyHash)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			result = "not_found"
			return nil, ErrKeyNotFound
		}
		result = "store_error"
		v.logger.Error("failed to get API key from store",
			zap.Error(err),
		)
		return nil, err
	}

	// Check if the key is enabled
	if !apiKey.Enabled {
		result = "disabled"
		return nil, ErrKeyDisabled
	}

	// Check if the key has expired
	if apiKey.IsExpired() {
		result = "expired"
		return nil, ErrKeyExpired
	}

	v.logger.Debug("API key validated successfully",
		zap.String("keyID", apiKey.ID),
		zap.String("keyName", apiKey.Name),
	)

	return apiKey, nil
}

// ValidateWithScopes validates an API key and checks for required scopes.
func (v *Validator) ValidateWithScopes(ctx context.Context, key string, requiredScopes ...string) (*APIKey, error) {
	apiKey, err := v.Validate(ctx, key)
	if err != nil {
		return nil, err
	}

	if len(requiredScopes) > 0 && !apiKey.HasAllScopes(requiredScopes...) {
		return nil, ErrInsufficientScope
	}

	return apiKey, nil
}

// SHA256Hasher implements Hasher using SHA256.
type SHA256Hasher struct{}

// Hash hashes an API key using SHA256.
func (h *SHA256Hasher) Hash(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// Compare compares a key with a hash using constant-time comparison.
func (h *SHA256Hasher) Compare(key, hash string) bool {
	keyHash := h.Hash(key)
	return subtle.ConstantTimeCompare([]byte(keyHash), []byte(hash)) == 1
}

// APIKeyContextKey is the context key for storing API key information.
type APIKeyContextKey struct{}

// GetAPIKeyFromContext retrieves the API key from the context.
func GetAPIKeyFromContext(ctx context.Context) (*APIKey, bool) {
	key, ok := ctx.Value(APIKeyContextKey{}).(*APIKey)
	return key, ok
}

// ContextWithAPIKey returns a new context with the API key.
func ContextWithAPIKey(ctx context.Context, key *APIKey) context.Context {
	return context.WithValue(ctx, APIKeyContextKey{}, key)
}
