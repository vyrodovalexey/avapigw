// Package authz provides authorization functionality.
package authz

import (
	"time"

	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// ConvertFromGatewayConfig converts a config.AuthorizationConfig (used in
// GatewaySpec.Authorization and Route.Authorization) to an authz.Config
// (used by authz.New). Returns (nil, nil) when the input is nil or
// authorization is disabled.
func ConvertFromGatewayConfig(cfg *config.AuthorizationConfig) (*Config, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	authzCfg := &Config{
		Enabled:       true,
		DefaultPolicy: Policy(cfg.DefaultPolicy),
		SkipPaths:     cfg.SkipPaths,
	}

	// Convert RBAC configuration
	if cfg.RBAC != nil && cfg.RBAC.Enabled {
		authzCfg.RBAC = convertRBACConfig(cfg.RBAC)
	}

	// Convert ABAC configuration
	if cfg.ABAC != nil && cfg.ABAC.Enabled {
		authzCfg.ABAC = convertABACConfig(cfg.ABAC)
	}

	// Convert External authorization configuration
	if cfg.External != nil && cfg.External.Enabled {
		authzCfg.External = convertExternalConfig(cfg.External)
	}

	// Convert cache configuration
	if cfg.Cache != nil && cfg.Cache.Enabled {
		authzCfg.Cache = convertCacheConfig(cfg.Cache)
	}

	return authzCfg, nil
}

// convertRBACConfig converts config.RBACConfig to rbac.Config.
func convertRBACConfig(src *config.RBACConfig) *rbac.Config {
	rbacCfg := &rbac.Config{
		Enabled:       true,
		RoleHierarchy: src.RoleHierarchy,
	}

	for _, p := range src.Policies {
		policy := rbac.Policy{
			Name:      p.Name,
			Roles:     p.Roles,
			Resources: p.Resources,
			Actions:   p.Actions,
			Effect:    rbac.PolicyEffect(p.Effect),
			Priority:  p.Priority,
		}
		rbacCfg.Policies = append(rbacCfg.Policies, policy)
	}

	return rbacCfg
}

// convertABACConfig converts config.ABACConfig to abac.Config.
func convertABACConfig(src *config.ABACConfig) *abac.Config {
	abacCfg := &abac.Config{
		Enabled: true,
		Engine:  "cel",
	}

	for _, p := range src.Policies {
		policy := abac.Policy{
			Name:       p.Name,
			Expression: p.Expression,
			Resources:  p.Resources,
			Actions:    p.Actions,
			Effect:     abac.PolicyEffect(p.Effect),
			Priority:   p.Priority,
		}
		abacCfg.Policies = append(abacCfg.Policies, policy)
	}

	return abacCfg
}

// convertExternalConfig converts config.ExternalAuthzConfig to external.Config.
func convertExternalConfig(src *config.ExternalAuthzConfig) *external.Config {
	extCfg := &external.Config{
		Enabled:  true,
		Type:     "opa",
		Timeout:  time.Duration(src.Timeout),
		FailOpen: src.FailOpen,
	}

	if src.OPA != nil {
		extCfg.OPA = &external.OPAConfig{
			URL:     src.OPA.URL,
			Policy:  src.OPA.Policy,
			Headers: src.OPA.Headers,
		}
	}

	return extCfg
}

// convertCacheConfig converts config.AuthzCacheConfig to authz.CacheConfig.
func convertCacheConfig(src *config.AuthzCacheConfig) *CacheConfig {
	return &CacheConfig{
		Enabled: true,
		TTL:     time.Duration(src.TTL),
		MaxSize: src.MaxSize,
		Type:    src.Type,
	}
}
