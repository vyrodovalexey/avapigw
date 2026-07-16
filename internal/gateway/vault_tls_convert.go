package gateway

import (
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// convertVaultTLSConfig maps a listener-level Vault TLS config into the TLS
// package's representation, shared by the HTTP and gRPC listeners.
//
// The documented `vault.ttl` duration string is parsed into the provider's
// TTL (it flows through the Vault provider factory into the PKI issue
// request); previously it was silently dropped, so issued certificates
// always used the PKI role's default TTL. An unparsable or non-positive TTL
// is logged and skipped — the provider falls back to the role default —
// rather than failing listener construction.
func convertVaultTLSConfig(
	v *config.VaultTLSConfig,
	logger observability.Logger,
) *tlspkg.VaultTLSConfig {
	if v == nil || !v.Enabled {
		return nil
	}

	out := &tlspkg.VaultTLSConfig{
		Enabled:    true,
		PKIMount:   v.PKIMount,
		Role:       v.Role,
		CommonName: v.CommonName,
		AltNames:   v.AltNames,
	}

	if v.TTL == "" {
		return out
	}

	ttl, err := time.ParseDuration(v.TTL)
	switch {
	case err != nil:
		logger.Warn("invalid listener vault.ttl, using PKI role default TTL",
			observability.String("ttl", v.TTL),
			observability.Error(err),
		)
	case ttl <= 0:
		logger.Warn("non-positive listener vault.ttl, using PKI role default TTL",
			observability.String("ttl", v.TTL),
		)
	default:
		out.TTL = ttl
	}

	return out
}
