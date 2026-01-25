package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"time"

	"github.com/google/uuid"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Signer signs JWT tokens.
type Signer interface {
	// Sign creates a signed JWT token.
	Sign(ctx context.Context, claims *Claims) (string, error)

	// SignWithOptions creates a signed JWT token with custom options.
	SignWithOptions(ctx context.Context, claims *Claims, opts SigningOptions) (string, error)
}

// SigningOptions contains options for token signing.
type SigningOptions struct {
	// Algorithm is the signing algorithm.
	Algorithm string

	// KeyID is the key identifier.
	KeyID string

	// ExpiresIn is the token expiration duration.
	ExpiresIn time.Duration

	// NotBefore is when the token becomes valid.
	NotBefore time.Time

	// Issuer overrides the default issuer.
	Issuer string

	// Audience overrides the default audience.
	Audience []string

	// GenerateJTI generates a unique token ID.
	GenerateJTI bool
}

// signer implements the Signer interface.
type signer struct {
	config      *Config
	privateKey  crypto.PrivateKey
	keyID       string
	algorithm   string
	vaultClient vault.Client
	logger      observability.Logger
	metrics     *Metrics
}

// SignerOption is a functional option for the signer.
type SignerOption func(*signer)

// WithSignerLogger sets the logger for the signer.
func WithSignerLogger(logger observability.Logger) SignerOption {
	return func(s *signer) {
		s.logger = logger
	}
}

// WithSignerMetrics sets the metrics for the signer.
func WithSignerMetrics(metrics *Metrics) SignerOption {
	return func(s *signer) {
		s.metrics = metrics
	}
}

// WithPrivateKey sets the private key for signing.
func WithPrivateKey(key crypto.PrivateKey, keyID, algorithm string) SignerOption {
	return func(s *signer) {
		s.privateKey = key
		s.keyID = keyID
		s.algorithm = algorithm
	}
}

// WithVaultClient sets the Vault client for signing.
func WithVaultClient(client vault.Client) SignerOption {
	return func(s *signer) {
		s.vaultClient = client
	}
}

// NewSigner creates a new JWT signer.
func NewSigner(config *Config, opts ...SignerOption) (Signer, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	s := &signer{
		config: config,
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Initialize metrics if not provided
	if s.metrics == nil {
		s.metrics = NewMetrics("gateway")
	}

	// Validate configuration
	if s.privateKey == nil && (s.vaultClient == nil || !s.config.Vault.Enabled) {
		return nil, fmt.Errorf("either privateKey or Vault must be configured for signing")
	}

	return s, nil
}

// Sign creates a signed JWT token.
func (s *signer) Sign(ctx context.Context, claims *Claims) (string, error) {
	return s.SignWithOptions(ctx, claims, SigningOptions{
		Algorithm:   s.algorithm,
		KeyID:       s.keyID,
		GenerateJTI: true,
	})
}

// SignWithOptions creates a signed JWT token with custom options.
func (s *signer) SignWithOptions(ctx context.Context, claims *Claims, opts SigningOptions) (string, error) {
	start := time.Now()

	algorithm := s.resolveAlgorithm(opts.Algorithm)
	keyID := s.resolveKeyID(opts.KeyID)

	// Prepare claims with defaults
	s.prepareClaims(claims, opts)

	// Build and sign the token
	token, err := s.buildAndSignToken(ctx, claims, algorithm, keyID)
	if err != nil {
		s.metrics.RecordSigning("error", algorithm, time.Since(start))
		return "", err
	}

	s.metrics.RecordSigning("success", algorithm, time.Since(start))
	s.logger.Debug("JWT signed",
		observability.String("subject", claims.Subject),
		observability.String("algorithm", algorithm),
	)

	return token, nil
}

// resolveAlgorithm resolves the signing algorithm from options or defaults.
func (s *signer) resolveAlgorithm(optAlgorithm string) string {
	if optAlgorithm != "" {
		return optAlgorithm
	}
	if s.algorithm != "" {
		return s.algorithm
	}
	return "RS256"
}

// resolveKeyID resolves the key ID from options or defaults.
func (s *signer) resolveKeyID(optKeyID string) string {
	if optKeyID != "" {
		return optKeyID
	}
	return s.keyID
}

// prepareClaims prepares claims with default values from options and config.
func (s *signer) prepareClaims(claims *Claims, opts SigningOptions) {
	now := time.Now()

	if claims.IssuedAt == nil {
		claims.IssuedAt = &Time{Time: now}
	}
	if opts.ExpiresIn > 0 && claims.ExpiresAt == nil {
		claims.ExpiresAt = &Time{Time: now.Add(opts.ExpiresIn)}
	}
	if !opts.NotBefore.IsZero() && claims.NotBefore == nil {
		claims.NotBefore = &Time{Time: opts.NotBefore}
	}

	s.setIssuer(claims, opts.Issuer)
	s.setAudience(claims, opts.Audience)

	if opts.GenerateJTI && claims.JWTID == "" {
		claims.JWTID = uuid.New().String()
	}
}

// setIssuer sets the issuer claim from options or config.
func (s *signer) setIssuer(claims *Claims, optIssuer string) {
	if claims.Issuer != "" {
		return
	}
	if optIssuer != "" {
		claims.Issuer = optIssuer
	} else if s.config.Issuer != "" {
		claims.Issuer = s.config.Issuer
	}
}

// setAudience sets the audience claim from options or config.
func (s *signer) setAudience(claims *Claims, optAudience Audience) {
	if len(claims.Audience) > 0 {
		return
	}
	if len(optAudience) > 0 {
		claims.Audience = optAudience
	} else if len(s.config.Audience) > 0 {
		claims.Audience = s.config.Audience
	}
}

// buildAndSignToken builds the JWT header and payload, then signs it.
func (s *signer) buildAndSignToken(
	ctx context.Context, claims *Claims, algorithm, keyID string,
) (string, error) {
	// Create header
	header := map[string]interface{}{
		"alg": algorithm,
		"typ": "JWT",
	}
	if keyID != "" {
		header["kid"] = keyID
	}

	// Encode header
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", NewSigningError("failed to encode header", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode payload
	payloadJSON, err := json.Marshal(claims.ToMap())
	if err != nil {
		return "", NewSigningError("failed to encode payload", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signing input
	signingInput := headerEncoded + "." + payloadEncoded

	// Sign
	signature, err := s.createSignature(ctx, signingInput, algorithm)
	if err != nil {
		return "", err
	}

	// Encode signature and build token
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + signatureEncoded, nil
}

// createSignature creates the signature using Vault or local key.
func (s *signer) createSignature(ctx context.Context, signingInput, algorithm string) ([]byte, error) {
	if s.vaultClient != nil && s.config.Vault != nil && s.config.Vault.Enabled {
		return s.signWithVault(ctx, signingInput, algorithm)
	}
	return s.signWithKey(signingInput, algorithm)
}

// signWithKey signs using a local private key.
func (s *signer) signWithKey(signingInput, algorithm string) ([]byte, error) {
	switch algorithm {
	case "RS256":
		return s.signRSA(signingInput, crypto.SHA256)
	case "RS384":
		return s.signRSA(signingInput, crypto.SHA384)
	case "RS512":
		return s.signRSA(signingInput, crypto.SHA512)
	case "PS256":
		return s.signRSAPSS(signingInput, crypto.SHA256)
	case "PS384":
		return s.signRSAPSS(signingInput, crypto.SHA384)
	case "PS512":
		return s.signRSAPSS(signingInput, crypto.SHA512)
	case "ES256":
		return s.signECDSA(signingInput, crypto.SHA256)
	case "ES384":
		return s.signECDSA(signingInput, crypto.SHA384)
	case "ES512":
		return s.signECDSA(signingInput, crypto.SHA512)
	case "HS256":
		return s.signHMAC(signingInput, sha256.New)
	case "HS384":
		return s.signHMAC(signingInput, sha512.New384)
	case "HS512":
		return s.signHMAC(signingInput, sha512.New)
	case "EdDSA", "Ed25519":
		return s.signEdDSA(signingInput)
	default:
		return nil, NewSigningError(fmt.Sprintf("unsupported algorithm: %s", algorithm), ErrUnsupportedAlgorithm)
	}
}

// signRSA signs using RSA PKCS#1 v1.5.
func (s *signer) signRSA(signingInput string, hashFunc crypto.Hash) ([]byte, error) {
	rsaKey, ok := s.privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, NewSigningError("key is not an RSA private key", ErrInvalidKey)
	}

	h := hashFunc.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, hashFunc, hashed)
	if err != nil {
		return nil, NewSigningError("RSA signing failed", err)
	}

	return signature, nil
}

// signRSAPSS signs using RSA-PSS.
func (s *signer) signRSAPSS(signingInput string, hashFunc crypto.Hash) ([]byte, error) {
	rsaKey, ok := s.privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, NewSigningError("key is not an RSA private key", ErrInvalidKey)
	}

	h := hashFunc.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hashFunc,
	}

	signature, err := rsa.SignPSS(rand.Reader, rsaKey, hashFunc, hashed, opts)
	if err != nil {
		return nil, NewSigningError("RSA-PSS signing failed", err)
	}

	return signature, nil
}

// signECDSA signs using ECDSA.
func (s *signer) signECDSA(signingInput string, hashFunc crypto.Hash) ([]byte, error) {
	ecdsaKey, ok := s.privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, NewSigningError("key is not an ECDSA private key", ErrInvalidKey)
	}

	h := hashFunc.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, hashed)
	if err != nil {
		return nil, NewSigningError("ECDSA signing failed", err)
	}

	return signature, nil
}

// signHMAC signs using HMAC.
func (s *signer) signHMAC(signingInput string, hashFunc func() hash.Hash) ([]byte, error) {
	var keyBytes []byte
	switch k := s.privateKey.(type) {
	case []byte:
		keyBytes = k
	default:
		return nil, NewSigningError("key is not suitable for HMAC", ErrInvalidKey)
	}

	mac := hmac.New(hashFunc, keyBytes)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil), nil
}

// signEdDSA signs using Ed25519.
func (s *signer) signEdDSA(signingInput string) ([]byte, error) {
	edKey, ok := s.privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, NewSigningError("key is not an Ed25519 private key", ErrInvalidKey)
	}

	return ed25519.Sign(edKey, []byte(signingInput)), nil
}

// signWithVault signs using Vault Transit.
func (s *signer) signWithVault(ctx context.Context, signingInput, _ string) ([]byte, error) {
	if s.vaultClient == nil || !s.vaultClient.IsEnabled() {
		return nil, NewSigningError("Vault client is not available", nil)
	}

	transit := s.vaultClient.Transit()
	signature, err := transit.Sign(
		ctx,
		s.config.Vault.TransitMount,
		s.config.Vault.KeyName,
		[]byte(signingInput),
	)
	if err != nil {
		return nil, NewSigningError("Vault signing failed", err)
	}

	return signature, nil
}

// Ensure signer implements Signer.
var _ Signer = (*signer)(nil)
