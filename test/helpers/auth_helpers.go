// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
)

// Note: Redis helpers are defined in transform_helpers.go
// Use GetRedisURL(), IsRedisAvailable(), SkipIfRedisUnavailable() from there

// TestJWTConfig creates a test JWT configuration.
func TestJWTConfig() *jwt.Config {
	return &jwt.Config{
		Enabled:    true,
		Algorithms: []string{"RS256", "ES256", "HS256"},
		ClockSkew:  5 * time.Minute,
		ClaimMapping: &jwt.ClaimMapping{
			Subject: "sub",
			Roles:   "roles",
			Email:   "email",
			Name:    "name",
		},
	}
}

// TestJWTConfigWithJWKS creates a test JWT configuration with JWKS URL.
func TestJWTConfigWithJWKS(jwksURL string) *jwt.Config {
	cfg := TestJWTConfig()
	cfg.JWKSUrl = jwksURL
	cfg.JWKSCacheTTL = 5 * time.Minute
	return cfg
}

// TestJWTConfigWithStaticKey creates a test JWT configuration with a static key.
func TestJWTConfigWithStaticKey(keyID, algorithm, key string) *jwt.Config {
	cfg := TestJWTConfig()
	cfg.StaticKeys = []jwt.StaticKey{
		{
			KeyID:     keyID,
			Algorithm: algorithm,
			Key:       key,
		},
	}
	return cfg
}

// TestAPIKeyConfig creates a test API Key configuration.
func TestAPIKeyConfig() *apikey.Config {
	return &apikey.Config{
		Enabled:       true,
		HashAlgorithm: "sha256",
		Extraction: []apikey.ExtractionSource{
			{
				Type: "header",
				Name: "X-API-Key",
			},
		},
		Cache: &apikey.CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 1000,
		},
	}
}

// TestAPIKeyConfigWithKeys creates a test API Key configuration with static keys.
func TestAPIKeyConfigWithKeys(keys []apikey.StaticKey) *apikey.Config {
	cfg := TestAPIKeyConfig()
	cfg.Store = &apikey.StoreConfig{
		Type: "memory",
		Keys: keys,
	}
	return cfg
}

// TestMTLSConfig creates a test mTLS configuration.
func TestMTLSConfig() *mtls.Config {
	return &mtls.Config{
		Enabled:           true,
		RequireClientCert: true,
		ExtractIdentity: &mtls.IdentityExtractionConfig{
			SubjectDN: true,
			SPIFFE:    true,
		},
	}
}

// TestMTLSConfigWithCA creates a test mTLS configuration with CA certificate.
func TestMTLSConfigWithCA(caCert string) *mtls.Config {
	cfg := TestMTLSConfig()
	cfg.CACert = caCert
	return cfg
}

// TestOIDCConfig creates a test OIDC configuration.
func TestOIDCConfig(issuer, clientID, clientSecret string) *oidc.Config {
	return &oidc.Config{
		Enabled:           true,
		DiscoveryCacheTTL: 5 * time.Minute,
		Providers: []oidc.ProviderConfig{
			{
				Name:         "test",
				Issuer:       issuer,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Type:         "generic",
				ClaimMapping: &oidc.ClaimMapping{
					Subject: "sub",
					Roles:   "roles",
					Email:   "email",
					Name:    "name",
				},
			},
		},
		DefaultProvider: "test",
		TokenValidation: &oidc.TokenValidationConfig{
			ClockSkew: 5 * time.Minute,
		},
	}
}

// TestOIDCConfigKeycloak creates a test OIDC configuration for Keycloak.
func TestOIDCConfigKeycloak(baseURL, realm, clientID, clientSecret string) *oidc.Config {
	issuer := fmt.Sprintf("%s/realms/%s", baseURL, realm)
	cfg := TestOIDCConfig(issuer, clientID, clientSecret)
	cfg.Providers[0].Type = "keycloak"
	cfg.Providers[0].Keycloak = &oidc.KeycloakConfig{
		Realm:         realm,
		UseRealmRoles: true,
	}
	return cfg
}

// TestAuthConfig creates a test authentication configuration.
func TestAuthConfig() *auth.Config {
	return &auth.Config{
		Enabled:               true,
		RequireAuthentication: true,
		Extraction: &auth.ExtractionConfig{
			JWT: []auth.ExtractionSource{
				{
					Type:   auth.ExtractionTypeHeader,
					Name:   "Authorization",
					Prefix: "Bearer ",
				},
			},
			APIKey: []auth.ExtractionSource{
				{
					Type: auth.ExtractionTypeHeader,
					Name: "X-API-Key",
				},
			},
		},
		Cache: &auth.AuthCacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 10000,
			Type:    "memory",
		},
	}
}

// GenerateRSAKeyPair generates an RSA key pair for testing.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// GenerateECDSAKeyPair generates an ECDSA key pair for testing.
func GenerateECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// GenerateHMACKey generates an HMAC key for testing.
func GenerateHMACKey(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	return key, err
}

// EncodeRSAPrivateKeyPEM encodes an RSA private key to PEM format.
func EncodeRSAPrivateKeyPEM(key *rsa.PrivateKey) string {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}

// EncodeRSAPublicKeyPEM encodes an RSA public key to PEM format.
func EncodeRSAPublicKeyPEM(key *rsa.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// EncodeECDSAPrivateKeyPEM encodes an ECDSA private key to PEM format.
func EncodeECDSAPrivateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// CreateTestJWT creates a test JWT token.
func CreateTestJWT(claims map[string]interface{}, privateKey interface{}, algorithm, keyID string) (string, error) {
	header := map[string]interface{}{
		"alg": algorithm,
		"typ": "JWT",
	}
	if keyID != "" {
		header["kid"] = keyID
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	var signature []byte
	switch algorithm {
	case "HS256":
		key, ok := privateKey.([]byte)
		if !ok {
			return "", fmt.Errorf("invalid key type for HS256")
		}
		signature, err = signHS256([]byte(signingInput), key)
	case "RS256":
		key, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid key type for RS256")
		}
		signature, err = signRS256([]byte(signingInput), key)
	case "ES256":
		key, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid key type for ES256")
		}
		signature, err = signES256([]byte(signingInput), key)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		return "", err
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + signatureB64, nil
}

// signHS256 signs data using HMAC-SHA256.
func signHS256(data, key []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil), nil
}

// signRS256 signs data using RSA-SHA256.
func signRS256(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
}

// signES256 signs data using ECDSA-SHA256.
func signES256(data []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return nil, err
	}
	// Concatenate r and s (each 32 bytes for P-256)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, nil
}

// CreateTestIdentity creates a test identity.
func CreateTestIdentity(subject string, authType auth.AuthType) *auth.Identity {
	return &auth.Identity{
		Subject:  subject,
		AuthType: authType,
		AuthTime: time.Now(),
		Roles:    []string{"user"},
		Claims:   make(map[string]interface{}),
	}
}

// CreateTestIdentityWithRoles creates a test identity with specific roles.
func CreateTestIdentityWithRoles(subject string, authType auth.AuthType, roles []string) *auth.Identity {
	identity := CreateTestIdentity(subject, authType)
	identity.Roles = roles
	return identity
}

// CreateTestIdentityWithClaims creates a test identity with specific claims.
func CreateTestIdentityWithClaims(subject string, authType auth.AuthType, claims map[string]interface{}) *auth.Identity {
	identity := CreateTestIdentity(subject, authType)
	identity.Claims = claims
	return identity
}

// HashAPIKey hashes an API key using SHA-256.
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// CreateTestAPIKey creates a test API key configuration.
func CreateTestAPIKey(id, key string, scopes, roles []string) apikey.StaticKey {
	return apikey.StaticKey{
		ID:      id,
		Key:     key,
		Scopes:  scopes,
		Roles:   roles,
		Enabled: true,
	}
}

// GenerateTestCertificate generates a test X.509 certificate.
func GenerateTestCertificate(commonName string, isCA bool) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              []string{"localhost", commonName},
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

// EncodeCertificatePEM encodes a certificate to PEM format.
func EncodeCertificatePEM(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block))
}

// AuthTestSetup contains authentication test setup information.
type AuthTestSetup struct {
	RSAPrivateKey   *rsa.PrivateKey
	RSAPublicKey    *rsa.PublicKey
	ECDSAPrivateKey *ecdsa.PrivateKey
	ECDSAPublicKey  *ecdsa.PublicKey
	HMACKey         []byte
	CACert          *x509.Certificate
	CAKey           *rsa.PrivateKey
}

// SetupAuthForTesting sets up authentication resources for testing.
func SetupAuthForTesting(t *testing.T) *AuthTestSetup {
	rsaPriv, rsaPub, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	ecdsaPriv, ecdsaPub, err := GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	hmacKey, err := GenerateHMACKey(32)
	if err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}

	caCert, caKey, err := GenerateTestCertificate("Test CA", true)
	if err != nil {
		t.Fatalf("Failed to generate CA certificate: %v", err)
	}

	return &AuthTestSetup{
		RSAPrivateKey:   rsaPriv,
		RSAPublicKey:    rsaPub,
		ECDSAPrivateKey: ecdsaPriv,
		ECDSAPublicKey:  ecdsaPub,
		HMACKey:         hmacKey,
		CACert:          caCert,
		CAKey:           caKey,
	}
}

// CreateJWTClaims creates standard JWT claims for testing.
func CreateJWTClaims(subject, issuer string, audience []string, roles []string, expiry time.Duration) map[string]interface{} {
	now := time.Now()
	claims := map[string]interface{}{
		"sub": subject,
		"iss": issuer,
		"iat": now.Unix(),
		"exp": now.Add(expiry).Unix(),
		"nbf": now.Unix(),
	}
	if len(audience) > 0 {
		claims["aud"] = audience
	}
	if len(roles) > 0 {
		claims["roles"] = roles
	}
	return claims
}

// CreateExpiredJWTClaims creates expired JWT claims for testing.
func CreateExpiredJWTClaims(subject, issuer string) map[string]interface{} {
	past := time.Now().Add(-1 * time.Hour)
	return map[string]interface{}{
		"sub": subject,
		"iss": issuer,
		"iat": past.Add(-1 * time.Hour).Unix(),
		"exp": past.Unix(),
		"nbf": past.Add(-1 * time.Hour).Unix(),
	}
}

// CreateFutureJWTClaims creates JWT claims that are not yet valid.
func CreateFutureJWTClaims(subject, issuer string) map[string]interface{} {
	future := time.Now().Add(1 * time.Hour)
	return map[string]interface{}{
		"sub": subject,
		"iss": issuer,
		"iat": future.Unix(),
		"exp": future.Add(1 * time.Hour).Unix(),
		"nbf": future.Unix(),
	}
}

// MockJWKS creates a mock JWKS response for testing.
func MockJWKS(publicKey *rsa.PublicKey, keyID string) map[string]interface{} {
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": keyID,
				"n":   n,
				"e":   e,
			},
		},
	}
}

// ContextWithTimeout creates a context with timeout for testing.
func ContextWithTimeout(t *testing.T, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx, cancel
}
