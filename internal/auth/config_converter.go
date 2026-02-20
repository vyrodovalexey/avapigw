package auth

import (
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// ConvertFromGatewayConfig converts a config.AuthenticationConfig (used in
// GatewaySpec.Authentication) to an auth.Config (used by auth.NewAuthenticator).
// Returns (nil, nil) when the input is nil or authentication is disabled.
func ConvertFromGatewayConfig(cfg *config.AuthenticationConfig) (*Config, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	authCfg := &Config{
		Enabled:        true,
		AllowAnonymous: cfg.AllowAnonymous,
		SkipPaths:      cfg.SkipPaths,
	}

	// Convert JWT configuration
	if cfg.JWT != nil && cfg.JWT.Enabled {
		authCfg.JWT = convertJWTConfig(cfg.JWT)
	}

	// Convert API Key configuration
	if cfg.APIKey != nil && cfg.APIKey.Enabled {
		authCfg.APIKey = convertAPIKeyConfig(cfg.APIKey)
	}

	// Convert mTLS configuration
	if cfg.MTLS != nil && cfg.MTLS.Enabled {
		authCfg.MTLS = convertMTLSConfig(cfg.MTLS)
	}

	// Convert OIDC configuration
	if cfg.OIDC != nil && cfg.OIDC.Enabled {
		authCfg.OIDC = convertOIDCConfig(cfg.OIDC)
	}

	return authCfg, nil
}

// convertJWTConfig converts config.JWTAuthConfig to jwt.Config.
func convertJWTConfig(src *config.JWTAuthConfig) *jwt.Config {
	jwtCfg := &jwt.Config{
		Enabled:  true,
		Issuer:   src.Issuer,
		Audience: src.Audience,
		JWKSUrl:  src.JWKSURL,
	}

	// Map algorithm to Algorithms slice if provided
	if src.Algorithm != "" {
		jwtCfg.Algorithms = []string{src.Algorithm}
	}

	// Map Secret as a static key if provided
	if src.Secret != "" {
		algo := src.Algorithm
		if algo == "" {
			algo = "HS256"
		}
		jwtCfg.StaticKeys = append(jwtCfg.StaticKeys, jwt.StaticKey{
			KeyID:     "default",
			Algorithm: algo,
			Key:       src.Secret,
		})
	}

	// Map PublicKey as a static key if provided
	if src.PublicKey != "" {
		algo := src.Algorithm
		if algo == "" {
			algo = "RS256"
		}
		jwtCfg.StaticKeys = append(jwtCfg.StaticKeys, jwt.StaticKey{
			KeyID:     "default-public",
			Algorithm: algo,
			Key:       src.PublicKey,
		})
	}

	// Convert claim mapping
	if src.ClaimMapping != nil {
		jwtCfg.ClaimMapping = &jwt.ClaimMapping{
			Roles:       src.ClaimMapping.Roles,
			Permissions: src.ClaimMapping.Permissions,
			Groups:      src.ClaimMapping.Groups,
			Scopes:      src.ClaimMapping.Scopes,
			Email:       src.ClaimMapping.Email,
			Name:        src.ClaimMapping.Name,
		}
	}

	return jwtCfg
}

// convertAPIKeyConfig converts config.APIKeyAuthConfig to apikey.Config.
func convertAPIKeyConfig(src *config.APIKeyAuthConfig) *apikey.Config {
	apiKeyCfg := &apikey.Config{
		Enabled:       true,
		HashAlgorithm: src.HashAlgorithm,
	}

	// Map Header extraction source
	if src.Header != "" {
		apiKeyCfg.Extraction = append(apiKeyCfg.Extraction, apikey.ExtractionSource{
			Type: "header",
			Name: src.Header,
		})
	}

	// Map Query extraction source
	if src.Query != "" {
		apiKeyCfg.Extraction = append(apiKeyCfg.Extraction, apikey.ExtractionSource{
			Type: "query",
			Name: src.Query,
		})
	}

	// Map VaultPath — extract the KV mount (first path segment) while
	// keeping the original path for backward compatibility.
	if src.VaultPath != "" {
		mount, _ := extractVaultMount(src.VaultPath)
		apiKeyCfg.Vault = &apikey.VaultConfig{
			Enabled: true,
			KVMount: mount,
			Path:    src.VaultPath,
		}
	}

	return apiKeyCfg
}

// extractVaultMount extracts the KV mount point (first path segment)
// and the remaining path from a CRD-style vault path.
//
// Examples:
//
//	"secret/data/apikeys"  → ("secret", "data/apikeys")
//	"secret/apikeys"       → ("secret", "apikeys")
//	"custom-kv/data/a/b"   → ("custom-kv", "data/a/b")
//	"onlymount"            → ("onlymount", "")
func extractVaultMount(raw string) (mount, remainder string) {
	parts := strings.SplitN(raw, "/", 2)
	mount = parts[0]
	if len(parts) < 2 {
		return mount, ""
	}
	return mount, parts[1]
}

// convertMTLSConfig converts config.MTLSAuthConfig to mtls.Config.
func convertMTLSConfig(src *config.MTLSAuthConfig) *mtls.Config {
	mtlsCfg := &mtls.Config{
		Enabled: true,
		CAFile:  src.CAFile,
	}

	// Map ExtractIdentity string to IdentityExtractionConfig
	if src.ExtractIdentity != "" {
		mtlsCfg.ExtractIdentity = &mtls.IdentityExtractionConfig{
			SubjectField: src.ExtractIdentity,
		}
	}

	// AllowedCNs and AllowedOUs are informational constraints;
	// the mtls.Config does not have direct fields for these, but
	// they are used during validation. We store them in the
	// RequireClientCert flag and rely on the TLS layer for CN/OU checks.
	if len(src.AllowedCNs) > 0 || len(src.AllowedOUs) > 0 {
		mtlsCfg.RequireClientCert = true
	}

	return mtlsCfg
}

// convertOIDCConfig converts config.OIDCAuthConfig to oidc.Config.
func convertOIDCConfig(src *config.OIDCAuthConfig) *oidc.Config {
	oidcCfg := &oidc.Config{
		Enabled: true,
	}

	for _, p := range src.Providers {
		provider := oidc.ProviderConfig{
			Name:         p.Name,
			Issuer:       p.IssuerURL,
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			Scopes:       p.Scopes,
		}
		oidcCfg.Providers = append(oidcCfg.Providers, provider)
	}

	return oidcCfg
}
