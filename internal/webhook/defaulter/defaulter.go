// Package defaulter provides defaulting logic for CRD webhooks.
package defaulter

import (
	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// Defaulter interface for all CRD defaulters
type Defaulter interface {
	// Default applies default values to the object
	Default(obj interface{})
}

// GatewayDefaulter provides defaulting for Gateway resources
type GatewayDefaulter struct{}

// NewGatewayDefaulter creates a new GatewayDefaulter
func NewGatewayDefaulter() *GatewayDefaulter {
	return &GatewayDefaulter{}
}

// Default applies default values to a Gateway
func (d *GatewayDefaulter) Default(gateway *avapigwv1alpha1.Gateway) {
	for i := range gateway.Spec.Listeners {
		listener := &gateway.Spec.Listeners[i]

		// Default TLS mode to Terminate for HTTPS/GRPCS listeners
		if listener.TLS != nil && listener.TLS.Mode == nil {
			mode := avapigwv1alpha1.TLSModeTerminate
			listener.TLS.Mode = &mode
		}

		// Default allowed routes
		if listener.AllowedRoutes == nil {
			listener.AllowedRoutes = &avapigwv1alpha1.AllowedRoutes{}
		}

		if listener.AllowedRoutes.Namespaces == nil {
			listener.AllowedRoutes.Namespaces = &avapigwv1alpha1.RouteNamespaces{}
		}

		if listener.AllowedRoutes.Namespaces.From == nil {
			from := avapigwv1alpha1.NamespacesFromSame
			listener.AllowedRoutes.Namespaces.From = &from
		}

		// Default allowed kinds based on protocol
		if len(listener.AllowedRoutes.Kinds) == 0 {
			group := avapigwv1alpha1.GroupVersion.Group
			switch listener.Protocol {
			case avapigwv1alpha1.ProtocolHTTP, avapigwv1alpha1.ProtocolHTTPS:
				listener.AllowedRoutes.Kinds = []avapigwv1alpha1.RouteGroupKind{
					{Group: &group, Kind: "HTTPRoute"},
				}
			case avapigwv1alpha1.ProtocolGRPC, avapigwv1alpha1.ProtocolGRPCS:
				listener.AllowedRoutes.Kinds = []avapigwv1alpha1.RouteGroupKind{
					{Group: &group, Kind: "GRPCRoute"},
				}
			case avapigwv1alpha1.ProtocolTCP:
				listener.AllowedRoutes.Kinds = []avapigwv1alpha1.RouteGroupKind{
					{Group: &group, Kind: "TCPRoute"},
				}
			case avapigwv1alpha1.ProtocolTLS:
				listener.AllowedRoutes.Kinds = []avapigwv1alpha1.RouteGroupKind{
					{Group: &group, Kind: "TLSRoute"},
				}
			}
		}
	}
}

// HTTPRouteDefaulter provides defaulting for HTTPRoute resources
type HTTPRouteDefaulter struct{}

// NewHTTPRouteDefaulter creates a new HTTPRouteDefaulter
func NewHTTPRouteDefaulter() *HTTPRouteDefaulter {
	return &HTTPRouteDefaulter{}
}

// Default applies default values to an HTTPRoute
func (d *HTTPRouteDefaulter) Default(route *avapigwv1alpha1.HTTPRoute) {
	// Default parent refs
	for i := range route.Spec.ParentRefs {
		parentRef := &route.Spec.ParentRefs[i]
		if parentRef.Group == nil {
			group := avapigwv1alpha1.GroupVersion.Group
			parentRef.Group = &group
		}
		if parentRef.Kind == nil {
			kind := "Gateway"
			parentRef.Kind = &kind
		}
	}

	// Default rules
	for i := range route.Spec.Rules {
		rule := &route.Spec.Rules[i]

		// Default matches
		for j := range rule.Matches {
			match := &rule.Matches[j]

			// Default path match
			if match.Path == nil {
				match.Path = &avapigwv1alpha1.HTTPPathMatch{}
			}
			if match.Path.Type == nil {
				pathType := avapigwv1alpha1.PathMatchPathPrefix
				match.Path.Type = &pathType
			}
			if match.Path.Value == nil {
				value := "/"
				match.Path.Value = &value
			}
		}

		// Default backend refs
		for j := range rule.BackendRefs {
			backendRef := &rule.BackendRefs[j]
			if backendRef.Group == nil {
				group := ""
				backendRef.Group = &group
			}
			if backendRef.Kind == nil {
				kind := "Service"
				backendRef.Kind = &kind
			}
			if backendRef.Weight == nil {
				weight := int32(1)
				backendRef.Weight = &weight
			}
		}
	}
}

// GRPCRouteDefaulter provides defaulting for GRPCRoute resources
type GRPCRouteDefaulter struct{}

// NewGRPCRouteDefaulter creates a new GRPCRouteDefaulter
func NewGRPCRouteDefaulter() *GRPCRouteDefaulter {
	return &GRPCRouteDefaulter{}
}

// Default applies default values to a GRPCRoute
func (d *GRPCRouteDefaulter) Default(route *avapigwv1alpha1.GRPCRoute) {
	// Default parent refs
	for i := range route.Spec.ParentRefs {
		parentRef := &route.Spec.ParentRefs[i]
		if parentRef.Group == nil {
			group := avapigwv1alpha1.GroupVersion.Group
			parentRef.Group = &group
		}
		if parentRef.Kind == nil {
			kind := "Gateway"
			parentRef.Kind = &kind
		}
	}

	// Default rules
	for i := range route.Spec.Rules {
		rule := &route.Spec.Rules[i]

		// Default method match type
		for j := range rule.Matches {
			match := &rule.Matches[j]
			if match.Method != nil && match.Method.Type == nil {
				matchType := avapigwv1alpha1.GRPCMethodMatchExact
				match.Method.Type = &matchType
			}
		}

		// Default retry policy
		if rule.RetryPolicy != nil {
			if rule.RetryPolicy.NumRetries == nil {
				numRetries := int32(1)
				rule.RetryPolicy.NumRetries = &numRetries
			}
			if rule.RetryPolicy.Backoff == nil {
				rule.RetryPolicy.Backoff = &avapigwv1alpha1.RetryBackoff{}
			}
			if rule.RetryPolicy.Backoff.BaseInterval == nil {
				baseInterval := "100ms"
				rule.RetryPolicy.Backoff.BaseInterval = &baseInterval
			}
			if rule.RetryPolicy.Backoff.MaxInterval == nil {
				maxInterval := "10s"
				rule.RetryPolicy.Backoff.MaxInterval = &maxInterval
			}
		}

		// Default backend refs
		for j := range rule.BackendRefs {
			backendRef := &rule.BackendRefs[j]
			if backendRef.Group == nil {
				group := ""
				backendRef.Group = &group
			}
			if backendRef.Kind == nil {
				kind := "Service"
				backendRef.Kind = &kind
			}
			if backendRef.Weight == nil {
				weight := int32(1)
				backendRef.Weight = &weight
			}
		}
	}
}

// TCPRouteDefaulter provides defaulting for TCPRoute resources
type TCPRouteDefaulter struct{}

// NewTCPRouteDefaulter creates a new TCPRouteDefaulter
func NewTCPRouteDefaulter() *TCPRouteDefaulter {
	return &TCPRouteDefaulter{}
}

// Default applies default values to a TCPRoute
func (d *TCPRouteDefaulter) Default(route *avapigwv1alpha1.TCPRoute) {
	// Default parent refs
	for i := range route.Spec.ParentRefs {
		parentRef := &route.Spec.ParentRefs[i]
		if parentRef.Group == nil {
			group := avapigwv1alpha1.GroupVersion.Group
			parentRef.Group = &group
		}
		if parentRef.Kind == nil {
			kind := "Gateway"
			parentRef.Kind = &kind
		}
	}

	// Default rules
	for i := range route.Spec.Rules {
		rule := &route.Spec.Rules[i]

		// Default timeouts
		if rule.IdleTimeout == nil {
			timeout := avapigwv1alpha1.Duration("3600s")
			rule.IdleTimeout = &timeout
		}
		if rule.ConnectTimeout == nil {
			timeout := avapigwv1alpha1.Duration("10s")
			rule.ConnectTimeout = &timeout
		}

		// Default backend refs
		for j := range rule.BackendRefs {
			backendRef := &rule.BackendRefs[j]
			if backendRef.Group == nil {
				group := ""
				backendRef.Group = &group
			}
			if backendRef.Kind == nil {
				kind := "Service"
				backendRef.Kind = &kind
			}
			if backendRef.Weight == nil {
				weight := int32(1)
				backendRef.Weight = &weight
			}
		}
	}
}

// TLSRouteDefaulter provides defaulting for TLSRoute resources
type TLSRouteDefaulter struct{}

// NewTLSRouteDefaulter creates a new TLSRouteDefaulter
func NewTLSRouteDefaulter() *TLSRouteDefaulter {
	return &TLSRouteDefaulter{}
}

// Default applies default values to a TLSRoute
func (d *TLSRouteDefaulter) Default(route *avapigwv1alpha1.TLSRoute) {
	// Default parent refs
	for i := range route.Spec.ParentRefs {
		parentRef := &route.Spec.ParentRefs[i]
		if parentRef.Group == nil {
			group := avapigwv1alpha1.GroupVersion.Group
			parentRef.Group = &group
		}
		if parentRef.Kind == nil {
			kind := "Gateway"
			parentRef.Kind = &kind
		}
	}

	// Default rules
	for i := range route.Spec.Rules {
		rule := &route.Spec.Rules[i]

		// Default backend refs
		for j := range rule.BackendRefs {
			backendRef := &rule.BackendRefs[j]
			if backendRef.Group == nil {
				group := ""
				backendRef.Group = &group
			}
			if backendRef.Kind == nil {
				kind := "Service"
				backendRef.Kind = &kind
			}
			if backendRef.Weight == nil {
				weight := int32(1)
				backendRef.Weight = &weight
			}
		}
	}
}

// BackendDefaulter provides defaulting for Backend resources
type BackendDefaulter struct{}

// NewBackendDefaulter creates a new BackendDefaulter
func NewBackendDefaulter() *BackendDefaulter {
	return &BackendDefaulter{}
}

// Default applies default values to a Backend
func (d *BackendDefaulter) Default(backend *avapigwv1alpha1.Backend) {
	// Default load balancing
	if backend.Spec.LoadBalancing == nil {
		backend.Spec.LoadBalancing = &avapigwv1alpha1.LoadBalancingConfig{}
	}
	if backend.Spec.LoadBalancing.Algorithm == nil {
		algorithm := avapigwv1alpha1.LoadBalancingRoundRobin
		backend.Spec.LoadBalancing.Algorithm = &algorithm
	}

	// Default health check
	if backend.Spec.HealthCheck == nil {
		backend.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{}
	}
	if backend.Spec.HealthCheck.Enabled == nil {
		enabled := true
		backend.Spec.HealthCheck.Enabled = &enabled
	}
	if backend.Spec.HealthCheck.Interval == nil {
		interval := avapigwv1alpha1.Duration("10s")
		backend.Spec.HealthCheck.Interval = &interval
	}
	if backend.Spec.HealthCheck.Timeout == nil {
		timeout := avapigwv1alpha1.Duration("5s")
		backend.Spec.HealthCheck.Timeout = &timeout
	}
	if backend.Spec.HealthCheck.HealthyThreshold == nil {
		threshold := int32(2)
		backend.Spec.HealthCheck.HealthyThreshold = &threshold
	}
	if backend.Spec.HealthCheck.UnhealthyThreshold == nil {
		threshold := int32(3)
		backend.Spec.HealthCheck.UnhealthyThreshold = &threshold
	}

	// Default connection pool
	if backend.Spec.ConnectionPool == nil {
		backend.Spec.ConnectionPool = &avapigwv1alpha1.ConnectionPoolConfig{}
	}
	if backend.Spec.ConnectionPool.HTTP == nil {
		backend.Spec.ConnectionPool.HTTP = &avapigwv1alpha1.HTTPConnectionPoolConfig{}
	}
	if backend.Spec.ConnectionPool.HTTP.MaxConnections == nil {
		maxConn := int32(100)
		backend.Spec.ConnectionPool.HTTP.MaxConnections = &maxConn
	}
	if backend.Spec.ConnectionPool.HTTP.MaxPendingRequests == nil {
		maxPending := int32(100)
		backend.Spec.ConnectionPool.HTTP.MaxPendingRequests = &maxPending
	}
	if backend.Spec.ConnectionPool.HTTP.IdleTimeout == nil {
		timeout := avapigwv1alpha1.Duration("60s")
		backend.Spec.ConnectionPool.HTTP.IdleTimeout = &timeout
	}
}

// RateLimitPolicyDefaulter provides defaulting for RateLimitPolicy resources
type RateLimitPolicyDefaulter struct{}

// NewRateLimitPolicyDefaulter creates a new RateLimitPolicyDefaulter
func NewRateLimitPolicyDefaulter() *RateLimitPolicyDefaulter {
	return &RateLimitPolicyDefaulter{}
}

// Default applies default values to a RateLimitPolicy
func (d *RateLimitPolicyDefaulter) Default(policy *avapigwv1alpha1.RateLimitPolicy) {
	// Default rules
	for i := range policy.Spec.Rules {
		rule := &policy.Spec.Rules[i]

		// Default algorithm
		if rule.Algorithm == nil {
			algorithm := avapigwv1alpha1.RateLimitAlgorithmTokenBucket
			rule.Algorithm = &algorithm
		}
	}

	// Default response
	if policy.Spec.RateLimitResponse == nil {
		policy.Spec.RateLimitResponse = &avapigwv1alpha1.RateLimitResponseConfig{}
	}
	if policy.Spec.RateLimitResponse.StatusCode == nil {
		statusCode := int32(429)
		policy.Spec.RateLimitResponse.StatusCode = &statusCode
	}
	if policy.Spec.RateLimitResponse.IncludeRateLimitHeaders == nil {
		include := true
		policy.Spec.RateLimitResponse.IncludeRateLimitHeaders = &include
	}

	// Default storage
	if policy.Spec.Storage == nil {
		policy.Spec.Storage = &avapigwv1alpha1.RateLimitStorageConfig{
			Type: avapigwv1alpha1.RateLimitStorageMemory,
		}
	}
}

// AuthPolicyDefaulter provides defaulting for AuthPolicy resources
type AuthPolicyDefaulter struct{}

// NewAuthPolicyDefaulter creates a new AuthPolicyDefaulter
func NewAuthPolicyDefaulter() *AuthPolicyDefaulter {
	return &AuthPolicyDefaulter{}
}

// Default applies default values to an AuthPolicy
func (d *AuthPolicyDefaulter) Default(policy *avapigwv1alpha1.AuthPolicy) {
	// Default authorization
	if policy.Spec.Authorization == nil {
		policy.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{}
	}
	if policy.Spec.Authorization.DefaultAction == nil {
		action := avapigwv1alpha1.AuthorizationActionDeny
		policy.Spec.Authorization.DefaultAction = &action
	}

	// Default JWT token location
	if policy.Spec.Authentication != nil && policy.Spec.Authentication.JWT != nil {
		jwt := policy.Spec.Authentication.JWT
		if jwt.TokenLocation == nil {
			jwt.TokenLocation = &avapigwv1alpha1.TokenLocationConfig{}
		}
		if jwt.TokenLocation.Header == nil {
			header := "Authorization"
			jwt.TokenLocation.Header = &header
		}
		if jwt.TokenLocation.Prefix == nil {
			prefix := "Bearer "
			jwt.TokenLocation.Prefix = &prefix
		}
	}

	// Default security headers
	if policy.Spec.SecurityHeaders != nil {
		if policy.Spec.SecurityHeaders.CORS != nil && policy.Spec.SecurityHeaders.CORS.MaxAge == nil {
			maxAge := avapigwv1alpha1.Duration("86400s")
			policy.Spec.SecurityHeaders.CORS.MaxAge = &maxAge
		}
		if policy.Spec.SecurityHeaders.HSTS != nil {
			if policy.Spec.SecurityHeaders.HSTS.MaxAge == nil {
				maxAge := int32(31536000)
				policy.Spec.SecurityHeaders.HSTS.MaxAge = &maxAge
			}
		}
	}
}

// TLSConfigDefaulter provides defaulting for TLSConfig resources
type TLSConfigDefaulter struct{}

// NewTLSConfigDefaulter creates a new TLSConfigDefaulter
func NewTLSConfigDefaulter() *TLSConfigDefaulter {
	return &TLSConfigDefaulter{}
}

// Default applies default values to a TLSConfig
func (d *TLSConfigDefaulter) Default(config *avapigwv1alpha1.TLSConfig) {
	// Default TLS versions
	if config.Spec.MinVersion == nil {
		minVersion := avapigwv1alpha1.TLSVersion12
		config.Spec.MinVersion = &minVersion
	}
	if config.Spec.MaxVersion == nil {
		maxVersion := avapigwv1alpha1.TLSVersion13
		config.Spec.MaxVersion = &maxVersion
	}

	// Default cipher suites for TLS 1.2
	if len(config.Spec.CipherSuites) == 0 {
		config.Spec.CipherSuites = []string{
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		}
	}

	// Default ALPN protocols
	if len(config.Spec.ALPNProtocols) == 0 {
		config.Spec.ALPNProtocols = []string{"h2", "http/1.1"}
	}

	// Default rotation
	if config.Spec.Rotation == nil {
		config.Spec.Rotation = &avapigwv1alpha1.CertificateRotationConfig{}
	}
	if config.Spec.Rotation.Enabled == nil {
		enabled := true
		config.Spec.Rotation.Enabled = &enabled
	}
	if config.Spec.Rotation.CheckInterval == nil {
		interval := avapigwv1alpha1.Duration("1h")
		config.Spec.Rotation.CheckInterval = &interval
	}
	if config.Spec.Rotation.RenewBefore == nil {
		renewBefore := "720h"
		config.Spec.Rotation.RenewBefore = &renewBefore
	}
}

// VaultSecretDefaulter provides defaulting for VaultSecret resources
type VaultSecretDefaulter struct{}

// NewVaultSecretDefaulter creates a new VaultSecretDefaulter
func NewVaultSecretDefaulter() *VaultSecretDefaulter {
	return &VaultSecretDefaulter{}
}

// Default applies default values to a VaultSecret
func (d *VaultSecretDefaulter) Default(secret *avapigwv1alpha1.VaultSecret) {
	// Default mount point
	if secret.Spec.MountPoint == nil {
		mountPoint := "secret"
		secret.Spec.MountPoint = &mountPoint
	}

	// Default refresh
	if secret.Spec.Refresh == nil {
		secret.Spec.Refresh = &avapigwv1alpha1.VaultRefreshConfig{}
	}
	if secret.Spec.Refresh.Enabled == nil {
		enabled := true
		secret.Spec.Refresh.Enabled = &enabled
	}
	if secret.Spec.Refresh.Interval == nil {
		interval := avapigwv1alpha1.Duration("5m")
		secret.Spec.Refresh.Interval = &interval
	}
	if secret.Spec.Refresh.JitterPercent == nil {
		jitter := int32(10)
		secret.Spec.Refresh.JitterPercent = &jitter
	}

	// Default target
	if secret.Spec.Target != nil {
		if secret.Spec.Target.Type == nil {
			secretType := "Opaque"
			secret.Spec.Target.Type = &secretType
		}
		if secret.Spec.Target.CreationPolicy == nil {
			policy := avapigwv1alpha1.SecretCreationPolicyOwner
			secret.Spec.Target.CreationPolicy = &policy
		}
		if secret.Spec.Target.DeletionPolicy == nil {
			policy := avapigwv1alpha1.SecretDeletionPolicyDelete
			secret.Spec.Target.DeletionPolicy = &policy
		}
	}

	// Default Kubernetes auth mount path
	if secret.Spec.VaultConnection.Auth.Kubernetes != nil {
		if secret.Spec.VaultConnection.Auth.Kubernetes.MountPath == nil {
			mountPath := "kubernetes"
			secret.Spec.VaultConnection.Auth.Kubernetes.MountPath = &mountPath
		}
	}
}
