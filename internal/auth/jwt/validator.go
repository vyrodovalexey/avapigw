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

	return v.verifyWithAlgorithm(key, header.Algorithm, signingInput, sigBytes)
}

// verifyWithAlgorithm verifies the signature using the specified algorithm.
func (v *validator) verifyWithAlgorithm(key crypto.PublicKey, alg, signingInput string, sigBytes []byte) error {
	switch alg {
	case AlgRS256, AlgRS384, AlgRS512:
		return v.verifyRSA(key, signingInput, sigBytes, rsaHashAlgorithm(alg))
	case AlgPS256, AlgPS384, AlgPS512:
		return v.verifyRSAPSS(key, signingInput, sigBytes, rsaHashAlgorithm(alg))
	case AlgES256, AlgES384, AlgES512:
		return v.verifyECDSA(key, signingInput, sigBytes, ecdsaHashAlgorithm(alg))
	case AlgHS256, AlgHS384, AlgHS512:
		return v.verifyHMAC(key, signingInput, sigBytes, hmacHashFunc(alg))
	case AlgEdDSA, AlgEd25519:
		return v.verifyEdDSA(key, signingInput, sigBytes)
	default:
		return NewValidationError(fmt.Sprintf("unsupported algorithm: %s", alg), ErrUnsupportedAlgorithm)
	}
}

// rsaHashAlgorithm returns the hash algorithm for RSA/RSA-PSS algorithms.
func rsaHashAlgorithm(alg string) crypto.Hash {
	switch alg {
	case AlgRS256, AlgPS256:
		return crypto.SHA256
	case AlgRS384, AlgPS384:
		return crypto.SHA384
	default:
		return crypto.SHA512
	}
}

// ecdsaHashAlgorithm returns the hash algorithm for ECDSA algorithms.
func ecdsaHashAlgorithm(alg string) crypto.Hash {
	switch alg {
	case AlgES256:
		return crypto.SHA256
	case AlgES384:
		return crypto.SHA384
	default:
		return crypto.SHA512
	}
}

// hmacHashFunc returns the hash function for HMAC algorithms.
func hmacHashFunc(alg string) func() hash.Hash {
	switch alg {
	case AlgHS256:
		return sha256.New
	case AlgHS384:
		return sha512.New384
	default:
		return sha512.New
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

// convertToASN1 converts a raw ECDSA signature (r || s format) to ASN.1 DER format.
// The raw signature consists of two big-endian integers r and s, each of keySize bytes.
// ASN.1 DER format: SEQUENCE { INTEGER r, INTEGER s }
func convertToASN1(sig []byte, keySize int) []byte {
	// Extract r and s from the raw signature
	r := sig[:keySize]
	s := sig[keySize:]

	// Remove leading zeros but keep at least one byte
	r = trimLeadingZeros(r)
	s = trimLeadingZeros(s)

	// If the high bit is set, prepend a zero byte to indicate positive integer
	if len(r) > 0 && r[0]&0x80 != 0 {
		r = append([]byte{0x00}, r...)
	}
	if len(s) > 0 && s[0]&0x80 != 0 {
		s = append([]byte{0x00}, s...)
	}

	// Build ASN.1 DER encoding
	// INTEGER tag = 0x02
	rEncoded := make([]byte, 0, 2+len(r))
	rEncoded = append(rEncoded, 0x02, byte(len(r)))
	rEncoded = append(rEncoded, r...)

	sEncoded := make([]byte, 0, 2+len(s))
	sEncoded = append(sEncoded, 0x02, byte(len(s)))
	sEncoded = append(sEncoded, s...)

	// SEQUENCE tag = 0x30
	content := make([]byte, 0, len(rEncoded)+len(sEncoded))
	content = append(content, rEncoded...)
	content = append(content, sEncoded...)

	result := make([]byte, 0, 2+len(content))
	result = append(result, 0x30, byte(len(content)))
	result = append(result, content...)
	return result
}

// trimLeadingZeros removes leading zero bytes from a byte slice,
// but ensures at least one byte remains.
func trimLeadingZeros(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
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
	if err := v.validateExpiration(claims, opts); err != nil {
		return err
	}
	if err := v.validateIssuer(claims, opts); err != nil {
		return err
	}
	if err := v.validateAudience(claims, opts); err != nil {
		return err
	}
	return v.validateRequiredClaims(claims, opts)
}

// validateExpiration validates the token expiration.
func (v *validator) validateExpiration(claims *Claims, opts ValidationOptions) error {
	if opts.SkipExpirationCheck {
		return nil
	}
	if err := claims.ValidWithSkew(opts.ClockSkew); err != nil {
		return v.createExpirationError(claims, opts.ClockSkew, err)
	}
	return nil
}

// createExpirationError creates an appropriate expiration error.
func (v *validator) createExpirationError(claims *Claims, clockSkew time.Duration, err error) error {
	now := time.Now()
	if claims.ExpiresAt != nil && now.After(claims.ExpiresAt.Time.Add(clockSkew)) {
		return NewValidationErrorWithClaims("token has expired", ErrTokenExpired, claims)
	}
	if claims.NotBefore != nil && now.Before(claims.NotBefore.Time.Add(-clockSkew)) {
		return NewValidationErrorWithClaims("token is not yet valid", ErrTokenNotYetValid, claims)
	}
	return NewValidationErrorWithClaims(err.Error(), err, claims)
}

// validateIssuer validates the token issuer.
func (v *validator) validateIssuer(claims *Claims, opts ValidationOptions) error {
	if opts.SkipIssuerCheck {
		return nil
	}
	allowedIssuers := v.config.GetAllowedIssuers()
	if len(allowedIssuers) == 0 {
		return nil
	}
	if !v.isIssuerAllowed(claims.Issuer, allowedIssuers) {
		return NewValidationErrorWithClaims(
			fmt.Sprintf("issuer %s is not allowed", claims.Issuer),
			ErrTokenInvalidIssuer,
			claims,
		)
	}
	return nil
}

// isIssuerAllowed checks if the issuer is in the allowed list.
func (v *validator) isIssuerAllowed(issuer string, allowedIssuers []string) bool {
	for _, iss := range allowedIssuers {
		if issuer == iss {
			return true
		}
	}
	return false
}

// validateAudience validates the token audience.
func (v *validator) validateAudience(claims *Claims, opts ValidationOptions) error {
	if opts.SkipAudienceCheck || len(v.config.Audience) == 0 {
		return nil
	}
	if !claims.Audience.ContainsAny(v.config.Audience...) {
		return NewValidationErrorWithClaims(
			"token audience does not match",
			ErrTokenInvalidAudience,
			claims,
		)
	}
	return nil
}

// validateRequiredClaims validates that all required claims are present.
func (v *validator) validateRequiredClaims(claims *Claims, opts ValidationOptions) error {
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
