package auth

import (
	"time"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
)

// claimsToIdentity converts JWT claims to an identity using the provided config
// for claim mapping. This is a package-level function shared by both the HTTP
// authenticator and the gRPC authenticator.
func claimsToIdentity(claims *jwt.Claims, authType AuthType, cfg *Config) *Identity {
	identity := &Identity{
		Subject:  claims.Subject,
		Issuer:   claims.Issuer,
		Audience: []string(claims.Audience),
		AuthType: authType,
		AuthTime: time.Now(),
		Claims:   claims.ToMap(),
	}

	if claims.ExpiresAt != nil {
		identity.ExpiresAt = claims.ExpiresAt.Time
	}

	// Extract additional fields from claims
	if cfg.JWT != nil && cfg.JWT.ClaimMapping != nil {
		mapping := cfg.JWT.ClaimMapping
		if mapping.Roles != "" {
			identity.Roles = claims.GetNestedStringSliceClaim(mapping.Roles)
		}
		if mapping.Permissions != "" {
			identity.Permissions = claims.GetNestedStringSliceClaim(mapping.Permissions)
		}
		if mapping.Groups != "" {
			identity.Groups = claims.GetNestedStringSliceClaim(mapping.Groups)
		}
		if mapping.Scopes != "" {
			identity.Scopes = claims.GetNestedStringSliceClaim(mapping.Scopes)
		}
		if mapping.Email != "" {
			identity.Email = claims.GetStringClaim(mapping.Email)
		}
		if mapping.Name != "" {
			identity.Name = claims.GetStringClaim(mapping.Name)
		}
	}

	return identity
}

// keyInfoToIdentity converts API key info to an identity.
// This is a package-level function shared by both the HTTP authenticator
// and the gRPC authenticator.
func keyInfoToIdentity(keyInfo *apikey.KeyInfo) *Identity {
	identity := &Identity{
		Subject:  keyInfo.ID,
		AuthType: AuthTypeAPIKey,
		AuthTime: time.Now(),
		Roles:    keyInfo.Roles,
		Scopes:   keyInfo.Scopes,
		Metadata: keyInfo.Metadata,
		ClientID: keyInfo.ID,
	}

	if keyInfo.ExpiresAt != nil {
		identity.ExpiresAt = *keyInfo.ExpiresAt
	}

	return identity
}
