package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/auth"
)

// Common validation errors.
var (
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenNotYetValid   = errors.New("token is not yet valid")
	ErrInvalidIssuer      = errors.New("invalid issuer")
	ErrInvalidAudience    = errors.New("invalid audience")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrInvalidAlgorithm   = errors.New("invalid algorithm")
	ErrMissingClaim       = errors.New("missing required claim")
	ErrInvalidClaimValue  = errors.New("invalid claim value")
	ErrKeyNotFound        = errors.New("signing key not found")
	ErrMalformedToken     = errors.New("malformed token")
	ErrUnsupportedKeyType = errors.New("unsupported key type")
)

// Metrics for JWT validation.
var (
	jwtValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_jwt_validation_total",
			Help: "Total number of JWT validation attempts",
		},
		[]string{"result"},
	)

	jwtValidationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "avapigw_jwt_validation_duration_seconds",
			Help:    "Duration of JWT validation in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"result"},
	)
)

// Config holds configuration for the JWT validator.
type Config struct {
	// Issuer is the expected issuer of the JWT.
	Issuer string

	// Audiences is the list of expected audiences.
	Audiences []string

	// JWKSURL is the URL to fetch the JWKS from.
	JWKSURL string

	// JWKSCacheTTL is the TTL for the JWKS cache.
	JWKSCacheTTL time.Duration

	// LocalJWKS is the local JWKS data (optional, used instead of JWKSURL).
	LocalJWKS []byte

	// Algorithms is the list of allowed algorithms.
	Algorithms []string

	// ClockSkew is the allowed clock skew for token validation.
	ClockSkew time.Duration

	// RequiredClaims is a map of claim names to allowed values.
	RequiredClaims map[string][]string

	// SkipExpiryCheck skips the expiry check (for testing only).
	SkipExpiryCheck bool
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		JWKSCacheTTL: time.Hour,
		Algorithms:   []string{"RS256", "RS384", "RS512"},
		ClockSkew:    time.Minute,
	}
}

// Validator validates JWT tokens.
type Validator struct {
	issuer         string
	audiences      []string
	jwksURL        string
	jwksCache      *JWKSCache
	localJWKS      *LocalJWKS
	algorithms     map[string]bool
	clockSkew      time.Duration
	requiredClaims map[string][]string
	skipExpiry     bool
	logger         *zap.Logger
	mu             sync.RWMutex
}

// NewValidator creates a new JWT validator.
func NewValidator(config *Config, logger *zap.Logger) (*Validator, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	v := &Validator{
		issuer:         config.Issuer,
		audiences:      config.Audiences,
		jwksURL:        config.JWKSURL,
		algorithms:     make(map[string]bool),
		clockSkew:      config.ClockSkew,
		requiredClaims: config.RequiredClaims,
		skipExpiry:     config.SkipExpiryCheck,
		logger:         logger,
	}

	// Set allowed algorithms
	if len(config.Algorithms) == 0 {
		config.Algorithms = []string{"RS256", "RS384", "RS512"}
	}
	for _, alg := range config.Algorithms {
		v.algorithms[alg] = true
	}

	// Initialize JWKS cache or local JWKS
	if config.JWKSURL != "" {
		v.jwksCache = NewJWKSCache(config.JWKSURL, config.JWKSCacheTTL, logger)
	}

	if len(config.LocalJWKS) > 0 {
		localJWKS, err := NewLocalJWKS(config.LocalJWKS)
		if err != nil {
			return nil, fmt.Errorf("failed to parse local JWKS: %w", err)
		}
		v.localJWKS = localJWKS
	}

	return v, nil
}

// Validate validates a JWT token and returns the claims.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	return v.ValidateWithClaims(ctx, tokenString, nil)
}

// ValidateWithClaims validates a JWT token with additional required claims.
func (v *Validator) ValidateWithClaims(
	ctx context.Context,
	tokenString string,
	requiredClaims map[string][]string,
) (*Claims, error) {
	start := time.Now()
	result := auth.MetricResultSuccess

	defer func() {
		duration := time.Since(start).Seconds()
		jwtValidationTotal.WithLabelValues(result).Inc()
		jwtValidationDuration.WithLabelValues(result).Observe(duration)
	}()

	// Parse and validate token structure
	header, payload, signature, result, err := v.parseAndValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Verify signature
	result, err = v.verifyTokenSignature(tokenString, header, signature)
	if err != nil {
		return nil, err
	}

	// Parse and validate claims
	claims, result, err := v.parseAndValidateClaims(payload, requiredClaims)
	if err != nil {
		return nil, err
	}

	v.logger.Debug("JWT validated successfully",
		zap.String("subject", claims.Subject),
		zap.String("issuer", claims.Issuer),
	)

	return claims, nil
}

// parseAndValidateToken parses the token and validates the algorithm.
func (v *Validator) parseAndValidateToken(
	tokenString string,
) (header map[string]interface{}, payload map[string]interface{}, signature []byte, metricResult string, err error) {
	header, payload, signature, err = v.parseToken(tokenString)
	if err != nil {
		return nil, nil, nil, "parse_error", err
	}

	alg, ok := header["alg"].(string)
	if !ok {
		return nil, nil, nil, "invalid_algorithm", ErrInvalidAlgorithm
	}

	if !v.algorithms[alg] {
		return nil, nil, nil, "unsupported_algorithm", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, alg)
	}

	return header, payload, signature, auth.MetricResultSuccess, nil
}

// verifyTokenSignature verifies the token signature using the appropriate key.
func (v *Validator) verifyTokenSignature(
	tokenString string,
	header map[string]interface{},
	signature []byte,
) (string, error) {
	kid, _ := header["kid"].(string)
	alg, _ := header["alg"].(string)

	key, err := v.getSigningKey(kid)
	if err != nil {
		return "key_not_found", err
	}

	if err := v.verifySignature(tokenString, signature, key, alg); err != nil {
		return "invalid_signature", err
	}

	return auth.MetricResultSuccess, nil
}

// parseAndValidateClaims parses claims and validates them against requirements.
func (v *Validator) parseAndValidateClaims(
	payload map[string]interface{},
	requiredClaims map[string][]string,
) (*Claims, string, error) {
	claims, err := ParseClaims(payload)
	if err != nil {
		return nil, "invalid_claims", fmt.Errorf("failed to parse claims: %w", err)
	}

	if err := v.validateClaims(claims); err != nil {
		return nil, "invalid_claims", err
	}

	mergedClaims := v.mergeRequiredClaims(requiredClaims)
	if err := v.validateRequiredClaims(claims, mergedClaims); err != nil {
		return nil, "missing_claims", err
	}

	return claims, auth.MetricResultSuccess, nil
}

// parseToken parses a JWT token into its components.
// Returns header claims, payload claims, signature bytes, and any error.
func (v *Validator) parseToken(
	tokenString string,
) (header map[string]interface{}, payload map[string]interface{}, signature []byte, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, nil, ErrMalformedToken
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid header encoding", ErrMalformedToken)
	}

	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid header JSON", ErrMalformedToken)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid payload encoding", ErrMalformedToken)
	}

	if err = json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid payload JSON", ErrMalformedToken)
	}

	// Decode signature
	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid signature encoding", ErrMalformedToken)
	}

	return header, payload, signature, nil
}

// getSigningKey retrieves the signing key for the given key ID.
func (v *Validator) getSigningKey(kid string) (*JSONWebKey, error) {
	// Try local JWKS first
	if v.localJWKS != nil {
		key, err := v.localJWKS.GetKey(kid)
		if err == nil {
			return key, nil
		}
	}

	// Try remote JWKS
	if v.jwksCache != nil {
		key, err := v.jwksCache.GetKey(kid)
		if err == nil {
			return key, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrKeyNotFound, err)
	}

	return nil, ErrKeyNotFound
}

// verifySignature verifies the token signature.
func (v *Validator) verifySignature(tokenString string, signature []byte, key *JSONWebKey, alg string) error {
	// Get the signing input (header.payload)
	parts := strings.Split(tokenString, ".")
	signingInput := parts[0] + "." + parts[1]

	switch alg {
	case "RS256", "RS384", "RS512":
		return v.verifyRSASignature(signingInput, signature, key, alg)
	default:
		return fmt.Errorf("%w: %s", ErrInvalidAlgorithm, alg)
	}
}

// verifyRSASignature verifies an RSA signature.
func (v *Validator) verifyRSASignature(signingInput string, signature []byte, key *JSONWebKey, alg string) error {
	rsaKey, err := key.ToRSAPublicKey()
	if err != nil {
		return fmt.Errorf("failed to convert key to RSA: %w", err)
	}

	return verifyRSAPKCS1v15(signingInput, signature, rsaKey, alg)
}

// validateClaims validates the standard claims.
func (v *Validator) validateClaims(claims *Claims) error {
	// Validate expiry
	if !v.skipExpiry && claims.ExpiresAt != nil {
		if claims.IsExpiredWithSkew(v.clockSkew) {
			return ErrTokenExpired
		}
	}

	// Validate not before
	if claims.NotBefore != nil {
		if claims.IsNotYetValidWithSkew(v.clockSkew) {
			return ErrTokenNotYetValid
		}
	}

	// Validate issuer
	if v.issuer != "" && claims.Issuer != v.issuer {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidIssuer, v.issuer, claims.Issuer)
	}

	// Validate audience
	if len(v.audiences) > 0 {
		found := false
		for _, aud := range v.audiences {
			if claims.Audience.Contains(aud) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: expected one of %v", ErrInvalidAudience, v.audiences)
		}
	}

	return nil
}

// validateRequiredClaims validates required claims.
func (v *Validator) validateRequiredClaims(claims *Claims, requiredClaims map[string][]string) error {
	for claimName, allowedValues := range requiredClaims {
		value, ok := claims.GetClaim(claimName)
		if !ok {
			return fmt.Errorf("%w: %s", ErrMissingClaim, claimName)
		}

		if len(allowedValues) > 0 {
			if !v.claimValueMatches(value, allowedValues) {
				return fmt.Errorf("%w: %s must be one of %v", ErrInvalidClaimValue, claimName, allowedValues)
			}
		}
	}

	return nil
}

// claimValueMatches checks if a claim value matches any of the allowed values.
func (v *Validator) claimValueMatches(value interface{}, allowedValues []string) bool {
	switch val := value.(type) {
	case string:
		return v.stringMatchesAny(val, allowedValues)
	case []interface{}:
		return v.interfaceSliceMatchesAny(val, allowedValues)
	case []string:
		return v.stringSliceMatchesAny(val, allowedValues)
	}
	return false
}

// stringMatchesAny checks if a string matches any of the allowed values using constant-time comparison.
func (v *Validator) stringMatchesAny(val string, allowedValues []string) bool {
	for _, allowed := range allowedValues {
		if subtle.ConstantTimeCompare([]byte(val), []byte(allowed)) == 1 {
			return true
		}
	}
	return false
}

// interfaceSliceMatchesAny checks if any string in an interface slice matches the allowed values.
func (v *Validator) interfaceSliceMatchesAny(val []interface{}, allowedValues []string) bool {
	for _, item := range val {
		if str, ok := item.(string); ok {
			if v.stringMatchesAny(str, allowedValues) {
				return true
			}
		}
	}
	return false
}

// stringSliceMatchesAny checks if any string in a slice matches the allowed values.
func (v *Validator) stringSliceMatchesAny(val []string, allowedValues []string) bool {
	for _, item := range val {
		if v.stringMatchesAny(item, allowedValues) {
			return true
		}
	}
	return false
}

// mergeRequiredClaims merges the validator's required claims with additional claims.
func (v *Validator) mergeRequiredClaims(additional map[string][]string) map[string][]string {
	if len(v.requiredClaims) == 0 && len(additional) == 0 {
		return nil
	}

	merged := make(map[string][]string)

	for k, vals := range v.requiredClaims {
		merged[k] = vals
	}

	for k, vals := range additional {
		if existing, ok := merged[k]; ok {
			// Merge values
			merged[k] = append(existing, vals...)
		} else {
			merged[k] = vals
		}
	}

	return merged
}

// StartAutoRefresh starts automatic JWKS refresh.
func (v *Validator) StartAutoRefresh(ctx context.Context, interval time.Duration) {
	if v.jwksCache != nil {
		v.jwksCache.StartAutoRefresh(ctx, interval)
	}
}

// Stop stops the validator and releases resources.
func (v *Validator) Stop() {
	if v.jwksCache != nil {
		v.jwksCache.Stop()
	}
}

// UpdateLocalJWKS updates the local JWKS.
func (v *Validator) UpdateLocalJWKS(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.localJWKS == nil {
		localJWKS, err := NewLocalJWKS(data)
		if err != nil {
			return err
		}
		v.localJWKS = localJWKS
		return nil
	}

	return v.localJWKS.Update(data)
}

// verifyRSAPKCS1v15 verifies an RSA PKCS#1 v1.5 signature.
func verifyRSAPKCS1v15(signingInput string, signature []byte, key *rsa.PublicKey, alg string) error {
	var hashFunc string
	switch alg {
	case "RS256":
		hashFunc = "SHA256"
	case "RS384":
		hashFunc = "SHA384"
	case "RS512":
		hashFunc = "SHA512"
	default:
		return fmt.Errorf("%w: %s", ErrInvalidAlgorithm, alg)
	}

	// Use crypto/rsa for verification
	return verifyRSASignatureWithHash(signingInput, signature, key, hashFunc)
}

// verifyRSASignatureWithHash verifies an RSA signature with the specified hash.
func verifyRSASignatureWithHash(signingInput string, signature []byte, key *rsa.PublicKey, hashFunc string) error {
	var hash []byte
	var cryptoHash interface{}

	switch hashFunc {
	case "SHA256":
		h := newSHA256()
		h.Write([]byte(signingInput))
		hash = h.Sum(nil)
		cryptoHash = cryptoSHA256
	case "SHA384":
		h := newSHA384()
		h.Write([]byte(signingInput))
		hash = h.Sum(nil)
		cryptoHash = cryptoSHA384
	case "SHA512":
		h := newSHA512()
		h.Write([]byte(signingInput))
		hash = h.Sum(nil)
		cryptoHash = cryptoSHA512
	default:
		return fmt.Errorf("unsupported hash function: %s", hashFunc)
	}

	return rsaVerifyPKCS1v15(key, cryptoHash, hash, signature)
}
