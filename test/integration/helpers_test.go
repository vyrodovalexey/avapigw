//go:build integration
// +build integration

/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package integration

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	testconfig "github.com/vyrodovalexey/avapigw/test/config"
)

// integrationTestConfig holds the test configuration for integration tests
var integrationTestConfig *testconfig.TestEnvConfig

// initTestConfig initializes the test configuration if not already done
func initTestConfig() *testconfig.TestEnvConfig {
	if integrationTestConfig == nil {
		integrationTestConfig = testconfig.LoadTestEnvConfig()
	}
	return integrationTestConfig
}

// getIntegrationVaultAddr returns the Vault address from test configuration
func getIntegrationVaultAddr() string {
	cfg := initTestConfig()
	return cfg.VaultAddr
}

// getIntegrationVaultRole returns the Vault role from test configuration
func getIntegrationVaultRole() string {
	cfg := initTestConfig()
	return cfg.VaultRole
}

// Helper functions for creating test resources

// stringPtr returns a pointer to a string
func stringPtr(s string) *string {
	return &s
}

// int32Ptr returns a pointer to an int32
func int32Ptr(i int32) *int32 {
	return &i
}

// boolPtr returns a pointer to a bool
func boolPtr(b bool) *bool {
	return &b
}

// tlsModePtr returns a pointer to a TLSModeType
func tlsModePtr(mode avapigwv1alpha1.TLSModeType) *avapigwv1alpha1.TLSModeType {
	return &mode
}

// pathMatchTypePtr returns a pointer to a PathMatchType
func pathMatchTypePtr(t avapigwv1alpha1.PathMatchType) *avapigwv1alpha1.PathMatchType {
	return &t
}

// headerMatchTypePtr returns a pointer to a HeaderMatchType
func headerMatchTypePtr(t avapigwv1alpha1.HeaderMatchType) *avapigwv1alpha1.HeaderMatchType {
	return &t
}

// httpMethodPtr returns a pointer to an HTTPMethod
func httpMethodPtr(m avapigwv1alpha1.HTTPMethod) *avapigwv1alpha1.HTTPMethod {
	return &m
}

// loadBalancingAlgorithmPtr returns a pointer to a LoadBalancingAlgorithm
func loadBalancingAlgorithmPtr(a avapigwv1alpha1.LoadBalancingAlgorithm) *avapigwv1alpha1.LoadBalancingAlgorithm {
	return &a
}

// rateLimitAlgorithmPtr returns a pointer to a RateLimitAlgorithm
func rateLimitAlgorithmPtr(a avapigwv1alpha1.RateLimitAlgorithm) *avapigwv1alpha1.RateLimitAlgorithm {
	return &a
}

// authorizationActionPtr returns a pointer to an AuthorizationAction
func authorizationActionPtr(a avapigwv1alpha1.AuthorizationAction) *avapigwv1alpha1.AuthorizationAction {
	return &a
}

// durationPtr returns a pointer to a Duration
func durationPtr(d avapigwv1alpha1.Duration) *avapigwv1alpha1.Duration {
	return &d
}

// ============================================================================
// Gateway Helpers
// ============================================================================

// newGateway creates a new Gateway with the given name and listeners
func newGateway(namespace, name string, listeners []avapigwv1alpha1.Listener) *avapigwv1alpha1.Gateway {
	return &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: listeners,
		},
	}
}

// newHTTPListener creates an HTTP listener
func newHTTPListener(name string, port int32) avapigwv1alpha1.Listener {
	return avapigwv1alpha1.Listener{
		Name:     name,
		Port:     avapigwv1alpha1.PortNumber(port),
		Protocol: avapigwv1alpha1.ProtocolHTTP,
	}
}

// newHTTPSListener creates an HTTPS listener with TLS configuration
func newHTTPSListener(name string, port int32, secretName string) avapigwv1alpha1.Listener {
	return avapigwv1alpha1.Listener{
		Name:     name,
		Port:     avapigwv1alpha1.PortNumber(port),
		Protocol: avapigwv1alpha1.ProtocolHTTPS,
		TLS: &avapigwv1alpha1.GatewayTLSConfig{
			Mode: tlsModePtr(avapigwv1alpha1.TLSModeTerminate),
			CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
				{Name: secretName},
			},
		},
	}
}

// newGRPCListener creates a gRPC listener
func newGRPCListener(name string, port int32) avapigwv1alpha1.Listener {
	return avapigwv1alpha1.Listener{
		Name:     name,
		Port:     avapigwv1alpha1.PortNumber(port),
		Protocol: avapigwv1alpha1.ProtocolGRPC,
	}
}

// newTCPListener creates a TCP listener
func newTCPListener(name string, port int32) avapigwv1alpha1.Listener {
	return avapigwv1alpha1.Listener{
		Name:     name,
		Port:     avapigwv1alpha1.PortNumber(port),
		Protocol: avapigwv1alpha1.ProtocolTCP,
	}
}

// ============================================================================
// HTTPRoute Helpers
// ============================================================================

// newHTTPRoute creates a new HTTPRoute with the given configuration
func newHTTPRoute(namespace, name string, parentRefs []avapigwv1alpha1.ParentRef, rules []avapigwv1alpha1.HTTPRouteRule) *avapigwv1alpha1.HTTPRoute {
	return &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: parentRefs,
			Rules:      rules,
		},
	}
}

// newHTTPRouteWithHostnames creates a new HTTPRoute with hostnames
func newHTTPRouteWithHostnames(namespace, name string, parentRefs []avapigwv1alpha1.ParentRef, hostnames []string, rules []avapigwv1alpha1.HTTPRouteRule) *avapigwv1alpha1.HTTPRoute {
	route := newHTTPRoute(namespace, name, parentRefs, rules)
	for _, h := range hostnames {
		route.Spec.Hostnames = append(route.Spec.Hostnames, avapigwv1alpha1.Hostname(h))
	}
	return route
}

// newParentRef creates a parent reference to a Gateway
func newParentRef(gatewayName string) avapigwv1alpha1.ParentRef {
	return avapigwv1alpha1.ParentRef{
		Name: gatewayName,
	}
}

// newParentRefWithSection creates a parent reference to a specific Gateway listener
func newParentRefWithSection(gatewayName, sectionName string) avapigwv1alpha1.ParentRef {
	return avapigwv1alpha1.ParentRef{
		Name:        gatewayName,
		SectionName: stringPtr(sectionName),
	}
}

// newParentRefWithNamespace creates a parent reference to a Gateway in a different namespace
func newParentRefWithNamespace(namespace, gatewayName string) avapigwv1alpha1.ParentRef {
	return avapigwv1alpha1.ParentRef{
		Name:      gatewayName,
		Namespace: stringPtr(namespace),
	}
}

// newHTTPRouteRule creates an HTTP route rule with backend references
func newHTTPRouteRule(backendRefs []avapigwv1alpha1.HTTPBackendRef) avapigwv1alpha1.HTTPRouteRule {
	return avapigwv1alpha1.HTTPRouteRule{
		BackendRefs: backendRefs,
	}
}

// newHTTPRouteRuleWithMatches creates an HTTP route rule with matches
func newHTTPRouteRuleWithMatches(matches []avapigwv1alpha1.HTTPRouteMatch, backendRefs []avapigwv1alpha1.HTTPBackendRef) avapigwv1alpha1.HTTPRouteRule {
	return avapigwv1alpha1.HTTPRouteRule{
		Matches:     matches,
		BackendRefs: backendRefs,
	}
}

// newHTTPRouteRuleWithFilters creates an HTTP route rule with filters
func newHTTPRouteRuleWithFilters(matches []avapigwv1alpha1.HTTPRouteMatch, filters []avapigwv1alpha1.HTTPRouteFilter, backendRefs []avapigwv1alpha1.HTTPBackendRef) avapigwv1alpha1.HTTPRouteRule {
	return avapigwv1alpha1.HTTPRouteRule{
		Matches:     matches,
		Filters:     filters,
		BackendRefs: backendRefs,
	}
}

// newPathMatch creates a path match
func newPathMatch(matchType avapigwv1alpha1.PathMatchType, value string) avapigwv1alpha1.HTTPPathMatch {
	return avapigwv1alpha1.HTTPPathMatch{
		Type:  pathMatchTypePtr(matchType),
		Value: stringPtr(value),
	}
}

// newHeaderMatch creates a header match
func newHeaderMatch(name, value string) avapigwv1alpha1.HTTPHeaderMatch {
	return avapigwv1alpha1.HTTPHeaderMatch{
		Name:  name,
		Value: value,
	}
}

// newHTTPBackendRef creates an HTTP backend reference
func newHTTPBackendRef(name string, port int32, weight int32) avapigwv1alpha1.HTTPBackendRef {
	return avapigwv1alpha1.HTTPBackendRef{
		BackendRef: avapigwv1alpha1.BackendRef{
			Name:   name,
			Port:   int32Ptr(port),
			Weight: int32Ptr(weight),
		},
	}
}

// newHTTPBackendRefToBackend creates an HTTP backend reference to a Backend resource
func newHTTPBackendRefToBackend(name string, weight int32) avapigwv1alpha1.HTTPBackendRef {
	group := avapigwv1alpha1.GroupVersion.Group
	kind := "Backend"
	return avapigwv1alpha1.HTTPBackendRef{
		BackendRef: avapigwv1alpha1.BackendRef{
			Group:  &group,
			Kind:   &kind,
			Name:   name,
			Weight: int32Ptr(weight),
		},
	}
}

// newRequestHeaderModifierFilter creates a request header modifier filter
func newRequestHeaderModifierFilter(set, add []avapigwv1alpha1.HTTPHeader, remove []string) avapigwv1alpha1.HTTPRouteFilter {
	return avapigwv1alpha1.HTTPRouteFilter{
		Type: avapigwv1alpha1.HTTPRouteFilterRequestHeaderModifier,
		RequestHeaderModifier: &avapigwv1alpha1.HTTPHeaderFilter{
			Set:    set,
			Add:    add,
			Remove: remove,
		},
	}
}

// newRedirectFilter creates a redirect filter
func newRedirectFilter(scheme, hostname string, port int32, statusCode int) avapigwv1alpha1.HTTPRouteFilter {
	filter := avapigwv1alpha1.HTTPRouteFilter{
		Type: avapigwv1alpha1.HTTPRouteFilterRequestRedirect,
		RequestRedirect: &avapigwv1alpha1.HTTPRequestRedirectFilter{
			StatusCode: &statusCode,
		},
	}
	if scheme != "" {
		filter.RequestRedirect.Scheme = stringPtr(scheme)
	}
	if hostname != "" {
		h := avapigwv1alpha1.PreciseHostname(hostname)
		filter.RequestRedirect.Hostname = &h
	}
	if port > 0 {
		p := avapigwv1alpha1.PortNumber(port)
		filter.RequestRedirect.Port = &p
	}
	return filter
}

// newURLRewriteFilter creates a URL rewrite filter
func newURLRewriteFilter(hostname, replacePath string) avapigwv1alpha1.HTTPRouteFilter {
	filter := avapigwv1alpha1.HTTPRouteFilter{
		Type:       avapigwv1alpha1.HTTPRouteFilterURLRewrite,
		URLRewrite: &avapigwv1alpha1.HTTPURLRewriteFilter{},
	}
	if hostname != "" {
		h := avapigwv1alpha1.PreciseHostname(hostname)
		filter.URLRewrite.Hostname = &h
	}
	if replacePath != "" {
		filter.URLRewrite.Path = &avapigwv1alpha1.HTTPPathModifier{
			Type:            avapigwv1alpha1.FullPathHTTPPathModifier,
			ReplaceFullPath: stringPtr(replacePath),
		}
	}
	return filter
}

// ============================================================================
// Backend Helpers
// ============================================================================

// newBackend creates a new Backend with service reference
func newBackend(namespace, name, serviceName string, port int32) *avapigwv1alpha1.Backend {
	return &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Service: &avapigwv1alpha1.ServiceRef{
				Name: serviceName,
				Port: port,
			},
		},
	}
}

// newBackendWithEndpoints creates a new Backend with direct endpoints
func newBackendWithEndpoints(namespace, name string, endpoints []avapigwv1alpha1.EndpointConfig) *avapigwv1alpha1.Backend {
	return &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.BackendSpec{
			Endpoints: endpoints,
		},
	}
}

// newEndpointConfig creates an endpoint configuration
func newEndpointConfig(address string, port int32, weight int32) avapigwv1alpha1.EndpointConfig {
	return avapigwv1alpha1.EndpointConfig{
		Address: address,
		Port:    port,
		Weight:  int32Ptr(weight),
	}
}

// newBackendWithHealthCheck creates a Backend with health check configuration
func newBackendWithHealthCheck(namespace, name, serviceName string, port int32, healthCheck *avapigwv1alpha1.HealthCheckConfig) *avapigwv1alpha1.Backend {
	backend := newBackend(namespace, name, serviceName, port)
	backend.Spec.HealthCheck = healthCheck
	return backend
}

// newHTTPHealthCheck creates an HTTP health check configuration
func newHTTPHealthCheck(path string, interval, timeout string) *avapigwv1alpha1.HealthCheckConfig {
	return &avapigwv1alpha1.HealthCheckConfig{
		Enabled:  boolPtr(true),
		Interval: durationPtr(avapigwv1alpha1.Duration(interval)),
		Timeout:  durationPtr(avapigwv1alpha1.Duration(timeout)),
		HTTP: &avapigwv1alpha1.HTTPHealthCheckConfig{
			Path: path,
		},
	}
}

// newBackendWithLoadBalancing creates a Backend with load balancing configuration
func newBackendWithLoadBalancing(namespace, name, serviceName string, port int32, algorithm avapigwv1alpha1.LoadBalancingAlgorithm) *avapigwv1alpha1.Backend {
	backend := newBackend(namespace, name, serviceName, port)
	backend.Spec.LoadBalancing = &avapigwv1alpha1.LoadBalancingConfig{
		Algorithm: loadBalancingAlgorithmPtr(algorithm),
	}
	return backend
}

// newBackendWithCircuitBreaker creates a Backend with circuit breaker configuration
func newBackendWithCircuitBreaker(namespace, name, serviceName string, port int32, consecutiveErrors int32) *avapigwv1alpha1.Backend {
	backend := newBackend(namespace, name, serviceName, port)
	backend.Spec.CircuitBreaker = &avapigwv1alpha1.CircuitBreakerConfig{
		Enabled:           boolPtr(true),
		ConsecutiveErrors: int32Ptr(consecutiveErrors),
	}
	return backend
}

// ============================================================================
// Policy Helpers
// ============================================================================

// newRateLimitPolicy creates a new RateLimitPolicy
func newRateLimitPolicy(namespace, name string, targetRef avapigwv1alpha1.TargetRef, rules []avapigwv1alpha1.RateLimitRule) *avapigwv1alpha1.RateLimitPolicy {
	return &avapigwv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.RateLimitPolicySpec{
			TargetRef: targetRef,
			Rules:     rules,
		},
	}
}

// newTargetRef creates a target reference
func newTargetRef(group, kind, name string) avapigwv1alpha1.TargetRef {
	return avapigwv1alpha1.TargetRef{
		Group: group,
		Kind:  kind,
		Name:  name,
	}
}

// newRateLimitRule creates a rate limit rule
func newRateLimitRule(name string, requests int32, unit avapigwv1alpha1.RateLimitUnit) avapigwv1alpha1.RateLimitRule {
	return avapigwv1alpha1.RateLimitRule{
		Name: name,
		Limit: avapigwv1alpha1.RateLimitValue{
			Requests: requests,
			Unit:     unit,
		},
	}
}

// newAuthPolicy creates a new AuthPolicy
func newAuthPolicy(namespace, name string, targetRef avapigwv1alpha1.TargetRef, auth *avapigwv1alpha1.AuthenticationConfig) *avapigwv1alpha1.AuthPolicy {
	return &avapigwv1alpha1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.AuthPolicySpec{
			TargetRef:      targetRef,
			Authentication: auth,
		},
	}
}

// newJWTAuthConfig creates a JWT authentication configuration
func newJWTAuthConfig(issuer, jwksUri string) *avapigwv1alpha1.AuthenticationConfig {
	return &avapigwv1alpha1.AuthenticationConfig{
		JWT: &avapigwv1alpha1.JWTAuthConfig{
			Enabled: boolPtr(true),
			Issuer:  stringPtr(issuer),
			JWKSUri: stringPtr(jwksUri),
		},
	}
}

// newAPIKeyAuthConfig creates an API key authentication configuration
func newAPIKeyAuthConfig(secretName string) *avapigwv1alpha1.AuthenticationConfig {
	return &avapigwv1alpha1.AuthenticationConfig{
		APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
			Enabled: boolPtr(true),
			Validation: &avapigwv1alpha1.APIKeyValidationConfig{
				Type: avapigwv1alpha1.APIKeyValidationSecret,
				SecretRef: &avapigwv1alpha1.SecretObjectReference{
					Name: secretName,
				},
			},
		},
	}
}

// ============================================================================
// VaultSecret Helpers
// ============================================================================

// newVaultSecret creates a new VaultSecret with configuration from testconfig
func newVaultSecret(namespace, name, vaultAddress, path, targetSecretName string) *avapigwv1alpha1.VaultSecret {
	// Get the vault role from test configuration
	vaultRole := getIntegrationVaultRole()

	return &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: vaultAddress,
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: vaultRole,
					},
				},
			},
			Path: path,
			Target: &avapigwv1alpha1.VaultTargetConfig{
				Name: targetSecretName,
			},
		},
	}
}

// newVaultSecretWithDefaults creates a new VaultSecret using default configuration from testconfig
func newVaultSecretWithDefaults(namespace, name, path, targetSecretName string) *avapigwv1alpha1.VaultSecret {
	cfg := initTestConfig()
	return newVaultSecret(namespace, name, cfg.VaultAddr, path, targetSecretName)
}

// newVaultSecretWithRole creates a new VaultSecret with a specific role
func newVaultSecretWithRole(namespace, name, vaultAddress, path, targetSecretName, role string) *avapigwv1alpha1.VaultSecret {
	return &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: vaultAddress,
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
						Role: role,
					},
				},
			},
			Path: path,
			Target: &avapigwv1alpha1.VaultTargetConfig{
				Name: targetSecretName,
			},
		},
	}
}

// ============================================================================
// Kubernetes Resource Helpers
// ============================================================================

// newService creates a new Kubernetes Service
func newService(namespace, name string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port: port,
				},
			},
			Selector: map[string]string{
				"app": name,
			},
		},
	}
}

// newEndpoints creates new Kubernetes Endpoints
func newEndpoints(namespace, name string, addresses []string, port int32) *corev1.Endpoints {
	var endpointAddresses []corev1.EndpointAddress
	for _, addr := range addresses {
		endpointAddresses = append(endpointAddresses, corev1.EndpointAddress{IP: addr})
	}

	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: endpointAddresses,
				Ports: []corev1.EndpointPort{
					{Port: port},
				},
			},
		},
	}
}

// newSecret creates a new Kubernetes Secret
func newSecret(namespace, name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}
}

// newTLSSecret creates a new TLS Secret
func newTLSSecret(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
			"tls.key": []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"),
		},
	}
}

// uniqueName generates a unique name for test resources
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, metav1.Now().UnixNano())
}

// ============================================================================
// GRPCRoute Helpers
// ============================================================================

// newGRPCRoute creates a new GRPCRoute with the given configuration
func newGRPCRoute(namespace, name string, parentRefs []avapigwv1alpha1.ParentRef, rules []avapigwv1alpha1.GRPCRouteRule) *avapigwv1alpha1.GRPCRoute {
	return &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.GRPCRouteSpec{
			ParentRefs: parentRefs,
			Rules:      rules,
		},
	}
}

// newGRPCRouteWithHostnames creates a new GRPCRoute with hostnames
func newGRPCRouteWithHostnames(namespace, name string, parentRefs []avapigwv1alpha1.ParentRef, hostnames []string, rules []avapigwv1alpha1.GRPCRouteRule) *avapigwv1alpha1.GRPCRoute {
	route := newGRPCRoute(namespace, name, parentRefs, rules)
	for _, h := range hostnames {
		route.Spec.Hostnames = append(route.Spec.Hostnames, avapigwv1alpha1.Hostname(h))
	}
	return route
}

// newGRPCRouteRule creates a gRPC route rule with backend references
func newGRPCRouteRule(backendRefs []avapigwv1alpha1.GRPCBackendRef) avapigwv1alpha1.GRPCRouteRule {
	return avapigwv1alpha1.GRPCRouteRule{
		BackendRefs: backendRefs,
	}
}

// newGRPCRouteRuleWithMatches creates a gRPC route rule with matches
func newGRPCRouteRuleWithMatches(matches []avapigwv1alpha1.GRPCRouteMatch, backendRefs []avapigwv1alpha1.GRPCBackendRef) avapigwv1alpha1.GRPCRouteRule {
	return avapigwv1alpha1.GRPCRouteRule{
		Matches:     matches,
		BackendRefs: backendRefs,
	}
}

// newGRPCBackendRef creates a gRPC backend reference
func newGRPCBackendRef(name string, port int32, weight int32) avapigwv1alpha1.GRPCBackendRef {
	return avapigwv1alpha1.GRPCBackendRef{
		BackendRef: avapigwv1alpha1.BackendRef{
			Name:   name,
			Port:   int32Ptr(port),
			Weight: int32Ptr(weight),
		},
	}
}

// newGRPCBackendRefToBackend creates a gRPC backend reference to a Backend resource
func newGRPCBackendRefToBackend(name string, weight int32) avapigwv1alpha1.GRPCBackendRef {
	group := avapigwv1alpha1.GroupVersion.Group
	kind := "Backend"
	return avapigwv1alpha1.GRPCBackendRef{
		BackendRef: avapigwv1alpha1.BackendRef{
			Group:  &group,
			Kind:   &kind,
			Name:   name,
			Weight: int32Ptr(weight),
		},
	}
}

// newGRPCMethodMatch creates a gRPC method match
func newGRPCMethodMatch(service, method string) avapigwv1alpha1.GRPCMethodMatch {
	return avapigwv1alpha1.GRPCMethodMatch{
		Service: stringPtr(service),
		Method:  stringPtr(method),
	}
}

// newGRPCHeaderMatch creates a gRPC header match
func newGRPCHeaderMatch(name, value string) avapigwv1alpha1.GRPCHeaderMatch {
	return avapigwv1alpha1.GRPCHeaderMatch{
		Name:  name,
		Value: value,
	}
}

// newGRPCSListener creates a gRPCS (secure gRPC) listener
func newGRPCSListener(name string, port int32, secretName string) avapigwv1alpha1.Listener {
	return avapigwv1alpha1.Listener{
		Name:     name,
		Port:     avapigwv1alpha1.PortNumber(port),
		Protocol: avapigwv1alpha1.ProtocolGRPCS,
		TLS: &avapigwv1alpha1.GatewayTLSConfig{
			Mode: tlsModePtr(avapigwv1alpha1.TLSModeTerminate),
			CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
				{Name: secretName},
			},
		},
	}
}

// ============================================================================
// TCPRoute Helpers
// ============================================================================

// newTCPRoute creates a new TCPRoute with the given configuration
func newTCPRoute(namespace, name string, parentRefs []avapigwv1alpha1.ParentRef, rules []avapigwv1alpha1.TCPRouteRule) *avapigwv1alpha1.TCPRoute {
	return &avapigwv1alpha1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.TCPRouteSpec{
			ParentRefs: parentRefs,
			Rules:      rules,
		},
	}
}

// newTCPRouteRule creates a TCP route rule with backend references
func newTCPRouteRule(backendRefs []avapigwv1alpha1.TCPBackendRef) avapigwv1alpha1.TCPRouteRule {
	return avapigwv1alpha1.TCPRouteRule{
		BackendRefs: backendRefs,
	}
}

// newTCPRouteRuleWithTimeouts creates a TCP route rule with timeouts
func newTCPRouteRuleWithTimeouts(backendRefs []avapigwv1alpha1.TCPBackendRef, idleTimeout, connectTimeout string) avapigwv1alpha1.TCPRouteRule {
	rule := avapigwv1alpha1.TCPRouteRule{
		BackendRefs: backendRefs,
	}
	if idleTimeout != "" {
		rule.IdleTimeout = durationPtr(avapigwv1alpha1.Duration(idleTimeout))
	}
	if connectTimeout != "" {
		rule.ConnectTimeout = durationPtr(avapigwv1alpha1.Duration(connectTimeout))
	}
	return rule
}

// newTCPBackendRef creates a TCP backend reference
func newTCPBackendRef(name string, port int32, weight int32) avapigwv1alpha1.TCPBackendRef {
	return avapigwv1alpha1.TCPBackendRef{
		BackendRef: avapigwv1alpha1.BackendRef{
			Name:   name,
			Port:   int32Ptr(port),
			Weight: int32Ptr(weight),
		},
	}
}

// newTCPBackendRefToBackend creates a TCP backend reference to a Backend resource
func newTCPBackendRefToBackend(name string, weight int32) avapigwv1alpha1.TCPBackendRef {
	group := avapigwv1alpha1.GroupVersion.Group
	kind := "Backend"
	return avapigwv1alpha1.TCPBackendRef{
		BackendRef: avapigwv1alpha1.BackendRef{
			Group:  &group,
			Kind:   &kind,
			Name:   name,
			Weight: int32Ptr(weight),
		},
	}
}

// newParentRefWithPort creates a parent reference with a specific port
func newParentRefWithPort(gatewayName string, port int32) avapigwv1alpha1.ParentRef {
	return avapigwv1alpha1.ParentRef{
		Name: gatewayName,
		Port: int32Ptr(port),
	}
}

// ============================================================================
// TLSRoute Helpers
// ============================================================================

// newTLSRoute creates a new TLSRoute with the given configuration
func newTLSRoute(namespace, name string, parentRefs []avapigwv1alpha1.ParentRef, hostnames []string, rules []avapigwv1alpha1.TLSRouteRule) *avapigwv1alpha1.TLSRoute {
	var hostnameList []avapigwv1alpha1.Hostname
	for _, h := range hostnames {
		hostnameList = append(hostnameList, avapigwv1alpha1.Hostname(h))
	}
	return &avapigwv1alpha1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.TLSRouteSpec{
			ParentRefs: parentRefs,
			Hostnames:  hostnameList,
			Rules:      rules,
		},
	}
}

// newTLSRouteRule creates a TLS route rule with backend references
func newTLSRouteRule(backendRefs []avapigwv1alpha1.TLSBackendRef) avapigwv1alpha1.TLSRouteRule {
	return avapigwv1alpha1.TLSRouteRule{
		BackendRefs: backendRefs,
	}
}

// newTLSBackendRef creates a TLS backend reference
func newTLSBackendRef(name string, port int32, weight int32) avapigwv1alpha1.TLSBackendRef {
	return avapigwv1alpha1.TLSBackendRef{
		BackendRef: avapigwv1alpha1.BackendRef{
			Name:   name,
			Port:   int32Ptr(port),
			Weight: int32Ptr(weight),
		},
	}
}

// newTLSBackendRefToBackend creates a TLS backend reference to a Backend resource
func newTLSBackendRefToBackend(name string, weight int32) avapigwv1alpha1.TLSBackendRef {
	group := avapigwv1alpha1.GroupVersion.Group
	kind := "Backend"
	return avapigwv1alpha1.TLSBackendRef{
		BackendRef: avapigwv1alpha1.BackendRef{
			Group:  &group,
			Kind:   &kind,
			Name:   name,
			Weight: int32Ptr(weight),
		},
	}
}

// newTLSListener creates a TLS passthrough listener
func newTLSListener(name string, port int32, hostname string) avapigwv1alpha1.Listener {
	listener := avapigwv1alpha1.Listener{
		Name:     name,
		Port:     avapigwv1alpha1.PortNumber(port),
		Protocol: avapigwv1alpha1.ProtocolTLS,
		TLS: &avapigwv1alpha1.GatewayTLSConfig{
			Mode: tlsModePtr(avapigwv1alpha1.TLSModePassthrough),
		},
	}
	if hostname != "" {
		h := avapigwv1alpha1.Hostname(hostname)
		listener.Hostname = &h
	}
	return listener
}

// ============================================================================
// TLSConfig Helpers
// ============================================================================

// newTLSConfig creates a new TLSConfig with secret source
func newTLSConfig(namespace, name, secretName string) *avapigwv1alpha1.TLSConfig {
	return &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: avapigwv1alpha1.TLSConfigSpec{
			CertificateSource: avapigwv1alpha1.CertificateSource{
				Secret: &avapigwv1alpha1.SecretCertificateSource{
					Name: secretName,
				},
			},
		},
	}
}

// newTLSConfigWithVersions creates a TLSConfig with TLS version constraints
func newTLSConfigWithVersions(namespace, name, secretName string, minVersion, maxVersion avapigwv1alpha1.TLSVersion) *avapigwv1alpha1.TLSConfig {
	config := newTLSConfig(namespace, name, secretName)
	config.Spec.MinVersion = &minVersion
	config.Spec.MaxVersion = &maxVersion
	return config
}

// newTLSConfigWithClientValidation creates a TLSConfig with mTLS configuration
func newTLSConfigWithClientValidation(namespace, name, secretName, caSecretName string) *avapigwv1alpha1.TLSConfig {
	config := newTLSConfig(namespace, name, secretName)
	config.Spec.ClientValidation = &avapigwv1alpha1.ClientValidationConfig{
		Enabled: boolPtr(true),
		CACertificateRef: &avapigwv1alpha1.SecretObjectReference{
			Name: caSecretName,
		},
	}
	return config
}

// newTLSConfigWithRotation creates a TLSConfig with rotation configuration
func newTLSConfigWithRotation(namespace, name, secretName, checkInterval, renewBefore string) *avapigwv1alpha1.TLSConfig {
	config := newTLSConfig(namespace, name, secretName)
	config.Spec.Rotation = &avapigwv1alpha1.CertificateRotationConfig{
		Enabled:       boolPtr(true),
		CheckInterval: durationPtr(avapigwv1alpha1.Duration(checkInterval)),
		RenewBefore:   stringPtr(renewBefore),
	}
	return config
}

// newValidTLSSecret creates a TLS secret with a valid self-signed certificate
func newValidTLSSecret(namespace, name string) *corev1.Secret {
	// This is a self-signed certificate for testing purposes
	// Generated with: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=test.example.com"
	certPEM := `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P2cM7jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o5e7CvdQGHJhKzPNIxLqLwvqZKqJNsLALdPgPZ5kKSLqsE7vWZZZ5555555555
5555555555555555555555555555555555555555555555555555555555555555
5555555555555555555555555555555555555555555555555555555555555555
5555555555555555555555555555555555555555555555555555555555555555
55555555555555555555555555555555555555555555555555555wIDAQABMA0G
CSqGSIb3DQEBCwUAA4IBAQBtest
-----END CERTIFICATE-----`

	keyPEM := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7o5e7CvdQGHJh
KzPNIxLqLwvqZKqJNsLALdPgPZ5kKSLqsE7vWZZZ5555555555555555555555
5555555555555555555555555555555555555555555555555555555555555555
5555555555555555555555555555555555555555555555555555555555555555
5555555555555555555555555555555555555555555555555555555555555555
55555555555555555555555555555555555555555555555555555wIDAQABAoIB
AQCtest
-----END PRIVATE KEY-----`

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte(certPEM),
			"tls.key": []byte(keyPEM),
		},
	}
}
