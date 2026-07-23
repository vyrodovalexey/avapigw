// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"strconv"
	"strings"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// This file contains spec normalizations applied by the route controllers
// before the CRD spec is serialized for the gateway. The normalizations
// rewrite deprecated CRD field shapes into the exact JSON shape the gateway
// configuration types deserialize, so no configuration is silently dropped
// at the CRD -> data-plane boundary. The in-memory resource copy fetched by
// the reconciler is mutated; the change is never written back to Kubernetes
// (same pattern as the ConfigMap validation resolvers).

// hstsMaxAgeDirective is the prefix of the HSTS max-age directive.
const hstsMaxAgeDirective = "max-age="

// normalizeRouteSpecShared applies the normalizations shared by all route
// kinds (APIRoute, GRPCRoute, GraphQLRoute): the authorization decision
// cache legacy sentinel shape and the legacy security CSP/HSTS header
// fields. It returns the number of legacy fields converted so callers can
// surface the conversions in logs/metrics.
func normalizeRouteSpecShared(
	authz *avapigwv1alpha1.AuthorizationConfig,
	security *avapigwv1alpha1.SecurityConfig,
) int {
	converted := normalizeAuthorizationConfig(authz)
	converted += normalizeSecurityConfig(security)
	return converted
}

// normalizeAuthorizationConfig rewrites the deprecated
// authorization.cache.sentinel field into the authorization.cache.redis
// shape consumed by the gateway (config.AuthzCacheConfig has a "redis" key
// and no "sentinel" key, so the legacy field would otherwise be dropped at
// JSON unmarshal on the gateway side). The preferred redis block always
// wins when both are set; the legacy field is cleared either way so the
// serialized spec only ever contains the gateway-consumable shape.
// It returns the number of converted legacy fields (0 or 1).
//
//nolint:staticcheck // SA1019: this converter is the one place that must read/clear the deprecated field
func normalizeAuthorizationConfig(authz *avapigwv1alpha1.AuthorizationConfig) int {
	if authz == nil || authz.Cache == nil || authz.Cache.Sentinel == nil {
		return 0
	}

	cache := authz.Cache
	converted := 0
	if cache.Redis == nil {
		cache.Redis = &avapigwv1alpha1.RedisCacheSpec{Sentinel: cache.Sentinel}
		converted = 1
	}
	cache.Sentinel = nil
	return converted
}

// normalizeSecurityConfig rewrites the deprecated
// security.headers.contentSecurityPolicy and
// security.headers.strictTransportSecurity fields into the structured
// security.csp / security.hsts blocks consumed by the gateway
// (config.SecurityHeadersConfig has neither key, so the legacy fields would
// otherwise be dropped at JSON unmarshal on the gateway side). Structured
// blocks always win when both are set; the legacy fields are cleared either
// way. It returns the number of converted legacy fields (0..2).
//
//nolint:staticcheck // SA1019: this converter is the one place that must read/clear the deprecated fields
func normalizeSecurityConfig(security *avapigwv1alpha1.SecurityConfig) int {
	if security == nil || security.Headers == nil {
		return 0
	}

	converted := 0

	if csp := security.Headers.ContentSecurityPolicy; csp != "" {
		if security.CSP == nil {
			security.CSP = &avapigwv1alpha1.SecurityCSPConfig{Enabled: true, Policy: csp}
			converted++
		}
		security.Headers.ContentSecurityPolicy = ""
	}

	if hsts := security.Headers.StrictTransportSecurity; hsts != "" {
		if security.HSTS == nil {
			security.HSTS = parseHSTSHeaderValue(hsts)
			converted++
		}
		security.Headers.StrictTransportSecurity = ""
	}

	return converted
}

// parseHSTSHeaderValue parses a raw Strict-Transport-Security header value
// (e.g. "max-age=31536000; includeSubDomains; preload") into the structured
// HSTS configuration consumed by the gateway. Unknown directives are
// ignored; a missing or malformed max-age leaves MaxAge at zero (the
// gateway then applies its own default).
func parseHSTSHeaderValue(value string) *avapigwv1alpha1.SecurityHSTSConfig {
	hsts := &avapigwv1alpha1.SecurityHSTSConfig{Enabled: true}

	for _, part := range strings.Split(value, ";") {
		directive := strings.ToLower(strings.TrimSpace(part))
		switch {
		case strings.HasPrefix(directive, hstsMaxAgeDirective):
			seconds, err := strconv.Atoi(strings.TrimPrefix(directive, hstsMaxAgeDirective))
			if err == nil && seconds >= 0 {
				hsts.MaxAge = seconds
			}
		case directive == "includesubdomains":
			hsts.IncludeSubDomains = true
		case directive == "preload":
			hsts.Preload = true
		}
	}

	return hsts
}
