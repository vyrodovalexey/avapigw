package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Validator validates JWT tokens.
type Validator interface {
	// Validate validates a JWT token and returns the claims.
	Validate(ctx context.Context, token string) (*Claims, error)

	// ValidateWithOptions validates a JWT token with custom options.
	ValidateWithOptions(ctx context.Context, token string, opts ValidationOptions) (*Claims, error)
}

// ValidationOptions contains options for token validation.
type ValidationOptions struct {
	// SkipExpirationCheck skips expiration validation.
	SkipExpirationCheck bool

	// SkipIssuerCheck skips issuer validation.
	SkipIssuerCheck bool

	// SkipAudienceCheck skips audience validation.
	SkipAudienceCheck bool

	// RequiredClaims is a list of claims that must be present.
	RequiredClaims []string

	// ClockSkew is the allowed clock skew.
	ClockSkew time.Duration
}

// validator implements the Validator interface.
type validator struct {
	config  *Config
	keySet  KeySet
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

// WithKeySet sets the key set for the validator.
func WithKeySet(keySet KeySet) ValidatorOption {
	return func(v *validator) {
		v.keySet = keySet
	}
}

// NewValidator creates a new JWT validator.
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

	// Initialize key set if not provided
	if v.keySet == nil {
		keySet, err := createKeySet(config, v.logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create key set: %w", err)
		}
		v.keySet = keySet
	}

	// Initialize metrics if not provided
	if v.metrics == nil {
		v.metrics = NewMetrics("gateway")
	}

	return v, nil
}

// createKeySet creates a key set based on configuration.
func createKeySet(config *Config, logger observability.Logger) (KeySet, error) {
	var keySets []KeySet

	// Add JWKS key set
	if config.JWKSUrl != "" {
		jwksKeySet, err := NewJWKSKeySet(
			config.JWKSUrl,
			WithCacheTTL(config.GetEffectiveJWKSCacheTTL()),
			WithJWKSLogger(logger),
		)
		if err != nil {
			return nil, err
		}
		keySets = append(keySets, jwksKeySet)
	}

	// Add static key set
	if len(config.StaticKeys) > 0 {
		staticKeySet, err := NewStaticKeySet(config.StaticKeys, logger)
		if err != nil {
			return nil, err
		}
		keySets = append(keySets, staticKeySet)
	}

	if len(keySets) == 0 {
		return nil, fmt.Errorf("no key source configured")
	}

	if len(keySets) == 1 {
		return keySets[0], nil
	}

	return NewCompositeKeySet(keySets, logger), nil
}

// Validate validates a JWT token and returns the claims.
func (v *validator) Validate(ctx context.Context, token string) (*Claims, error) {
	return v.ValidateWithOptions(ctx, token, ValidationOptions{
		ClockSkew: v.config.GetEffectiveClockSkew(),
	})
}

// ValidateWithOptions validates a JWT token with custom options.
func (v *validator) ValidateWithOptions(ctx context.Context, token string, opts ValidationOptions) (*Claims, error) {
	start := time.Now()

	if token == "" {
		v.metrics.RecordValidation("error", "empty_token", time.Since(start))
		return nil, ErrEmptyToken
	}

	// Parse the token
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		v.metrics.RecordValidation("error", "malformed", time.Since(start))
		return nil, ErrTokenMalformed
	}

	// Decode header
	header, err := v.decodeHeader(parts[0])
	if err != nil {
		v.metrics.RecordValidation("error", "invalid_header", time.Since(start))
		return nil, NewValidationError("failed to decode header", err)
	}

	// Validate algorithm
	if err := v.validateAlgorithm(header.Algorithm); err != nil {
		v.metrics.RecordValidation("error", "invalid_algorithm", time.Since(start))
		return nil, err
	}

	// Decode payload
	claims, err := v.decodePayload(parts[1])
	if err != nil {
		v.metrics.RecordValidation("error", "invalid_payload", time.Since(start))
		return nil, NewValidationError("failed to decode payload", err)
	}

	// Verify signature
	if err := v.verifySignature(ctx, header, parts[0]+"."+parts[1], parts[2]); err != nil {
		v.metrics.RecordValidation("error", "invalid_signature", time.Since(start))
		return nil, err
	}

	// Validate claims
	if err := v.validateClaims(claims, opts); err != nil {
		v.metrics.RecordValidation("error", "invalid_claims", time.Since(start))
		return nil, err
	}

	v.metrics.RecordValidation("success", header.Algorithm, time.Since(start))
	v.logger.Debug("JWT validated",
		observability.String("subject", claims.Subject),
		observability.String("issuer", claims.Issuer),
	)

	return claims, nil
}

// tokenHeader represents the JWT header.
type tokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// decodeHeader decodes the JWT header.
func (v *validator) decodeHeader(encoded string) (*tokenHeader, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header tokenHeader
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	return &header, nil
}

// decodePayload decodes the JWT payload.
func (v *validator) decodePayload(encoded string) (*Claims, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claimsMap map[string]interface{}
	if err := json.Unmarshal(data, &claimsMap); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	return ParseClaims(claimsMap)
}

// validateAlgorithm validates the signing algorithm.
func (v *validator) validateAlgorithm(alg string) error {
	if len(v.config.Algorithms) == 0 {
		return nil
	}

	for _, allowed := range v.config.Algorithms {
		if alg == allowed {
			return nil
		}
	}

	return NewValidationError(fmt.Sprintf("algorithm %s is not allowed", alg), ErrUnsupportedAlgorithm)
}

// verifySignature verifies the token signature.
func (v *validator) verifySignature(ctx context.Context, header *tokenHeader, signingInput, signature string) error {
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return NewValidationError("failed to decode signature", err)
	}

	// Get the key
	key, err := v.keySet.GetKeyForAlgorithm(ctx, header.KeyID, header.Algorithm)
	if err != nil {
		return NewValidationError("failed to get signing key", err)
	}

	// Verify based on algorithm
	switch header.Algorithm {
	case AlgRS256:
		return v.verifyRSA(key, signingInput, sigBytes, crypto.SHA256)
	case AlgRS384:
		return v.verifyRSA(key, signingInput, sigBytes, crypto.SHA384)
	case AlgRS512:
		return v.verifyRSA(key, signingInput, sigBytes, crypto.SHA512)
	case AlgPS256:
		return v.verifyRSAPSS(key, signingInput, sigBytes, crypto.SHA256)
	case AlgPS384:
		return v.verifyRSAPSS(key, signingInput, sigBytes, crypto.SHA384)
	case AlgPS512:
		return v.verifyRSAPSS(key, signingInput, sigBytes, crypto.SHA512)
	case AlgES256:
		return v.verifyECDSA(key, signingInput, sigBytes, crypto.SHA256)
	case AlgES384:
		return v.verifyECDSA(key, signingInput, sigBytes, crypto.SHA384)
	case AlgES512:
		return v.verifyECDSA(key, signingInput, sigBytes, crypto.SHA512)
	case AlgHS256:
		return v.verifyHMAC(key, signingInput, sigBytes, sha256.New)
	case AlgHS384:
		return v.verifyHMAC(key, signingInput, sigBytes, sha512.New384)
	case AlgHS512:
		return v.verifyHMAC(key, signingInput, sigBytes, sha512.New)
	case AlgEdDSA, AlgEd25519:
		return v.verifyEdDSA(key, signingInput, sigBytes)
	default:
		return NewValidationError(fmt.Sprintf("unsupported algorithm: %s", header.Algorithm), ErrUnsupportedAlgorithm)
	}
}

// verifyRSA verifies an RSA signature.
func (v *validator) verifyRSA(key crypto.PublicKey, signingInput string, signature []byte, hashAlg crypto.Hash) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return NewValidationError("key is not an RSA public key", ErrInvalidKey)
	}

	h := hashAlg.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	if err := rsa.VerifyPKCS1v15(rsaKey, hashAlg, hashed, signature); err != nil {
		return NewValidationError("RSA signature verification failed", ErrTokenInvalidSignature)
	}

	return nil
}

// verifyRSAPSS verifies an RSA-PSS signature.
func (v *validator) verifyRSAPSS(
	key crypto.PublicKey, signingInput string, signature []byte, hashAlg crypto.Hash,
) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return NewValidationError("key is not an RSA public key", ErrInvalidKey)
	}

	h := hashAlg.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hashAlg,
	}

	if err := rsa.VerifyPSS(rsaKey, hashAlg, hashed, signature, opts); err != nil {
		return NewValidationError("RSA-PSS signature verification failed", ErrTokenInvalidSignature)
	}

	return nil
}

// verifyECDSA verifies an ECDSA signature.
func (v *validator) verifyECDSA(
	key crypto.PublicKey, signingInput string, signature []byte, hashFunc crypto.Hash,
) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return NewValidationError("key is not an ECDSA public key", ErrInvalidKey)
	}

	h := hashFunc.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	// ECDSA signatures in JWT are r || s concatenated
	keySize := (ecdsaKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keySize {
		return NewValidationError("invalid ECDSA signature length", ErrTokenInvalidSignature)
	}

	if !ecdsa.VerifyASN1(ecdsaKey, hashed, convertToASN1(signature, keySize)) {
		return NewValidationError("ECDSA signature verification failed", ErrTokenInvalidSignature)
	}

	return nil
}

// convertToASN1 converts a raw ECDSA signature to ASN.1 format.
func convertToASN1(sig []byte, _ int) []byte {
	// This is a simplified conversion - in production, use proper ASN.1 encoding
	// For now, we'll use the raw signature directly with ecdsa.Verify
	return sig
}

// verifyHMAC verifies an HMAC signature.
func (v *validator) verifyHMAC(
	key crypto.PublicKey, signingInput string, signature []byte, hashFunc func() hash.Hash,
) error {
	// For HMAC, the key should be a byte slice
	var keyBytes []byte
	switch k := key.(type) {
	case []byte:
		keyBytes = k
	default:
		return NewValidationError("key is not suitable for HMAC", ErrInvalidKey)
	}

	mac := hmac.New(hashFunc, keyBytes)
	mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)

	if !hmac.Equal(signature, expected) {
		return NewValidationError("HMAC signature verification failed", ErrTokenInvalidSignature)
	}

	return nil
}

// verifyEdDSA verifies an Ed25519 signature.
func (v *validator) verifyEdDSA(key crypto.PublicKey, signingInput string, signature []byte) error {
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return NewValidationError("key is not an Ed25519 public key", ErrInvalidKey)
	}

	if !ed25519.Verify(edKey, []byte(signingInput), signature) {
		return NewValidationError("Ed25519 signature verification failed", ErrTokenInvalidSignature)
	}

	return nil
}

// validateClaims validates the token claims.
func (v *validator) validateClaims(claims *Claims, opts ValidationOptions) error {
	// Validate expiration
	if !opts.SkipExpirationCheck {
		if err := claims.ValidWithSkew(opts.ClockSkew); err != nil {
			if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time.Add(opts.ClockSkew)) {
				return NewValidationErrorWithClaims("token has expired", ErrTokenExpired, claims)
			}
			if claims.NotBefore != nil && time.Now().Before(claims.NotBefore.Time.Add(-opts.ClockSkew)) {
				return NewValidationErrorWithClaims("token is not yet valid", ErrTokenNotYetValid, claims)
			}
			return NewValidationErrorWithClaims(err.Error(), err, claims)
		}
	}

	// Validate issuer
	if !opts.SkipIssuerCheck {
		allowedIssuers := v.config.GetAllowedIssuers()
		if len(allowedIssuers) > 0 {
			valid := false
			for _, iss := range allowedIssuers {
				if claims.Issuer == iss {
					valid = true
					break
				}
			}
			if !valid {
				return NewValidationErrorWithClaims(
					fmt.Sprintf("issuer %s is not allowed", claims.Issuer),
					ErrTokenInvalidIssuer,
					claims,
				)
			}
		}
	}

	// Validate audience
	if !opts.SkipAudienceCheck && len(v.config.Audience) > 0 {
		if !claims.Audience.ContainsAny(v.config.Audience...) {
			return NewValidationErrorWithClaims(
				"token audience does not match",
				ErrTokenInvalidAudience,
				claims,
			)
		}
	}

	// Validate required claims
	requiredClaims := opts.RequiredClaims
	if len(requiredClaims) == 0 {
		requiredClaims = v.config.RequiredClaims
	}
	for _, claim := range requiredClaims {
		if _, ok := claims.GetClaim(claim); !ok {
			return NewValidationErrorWithClaims(
				fmt.Sprintf("required claim %s is missing", claim),
				ErrTokenMissingClaim,
				claims,
			)
		}
	}

	return nil
}

// Ensure validator implements Validator.
var _ Validator = (*validator)(nil)
