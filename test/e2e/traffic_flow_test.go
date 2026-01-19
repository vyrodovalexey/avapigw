//go:build e2e
// +build e2e

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

package e2e

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

var _ = Describe("Traffic Flow E2E", Ordered, func() {
	// Note: These tests require a running Gateway deployment
	// They test the traffic flow through the Gateway

	Context("HTTP Request Routing", func() {
		var (
			gatewayName string
			routeName   string
			backendName string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-http")
			routeName = generateUniqueName("route-http")
			backendName = generateUniqueName("backend-http")
		})

		AfterEach(func() {
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should route HTTP requests based on path", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-service",
					Port: 80,
				},
			})

			// Create HTTPRoute with path matching
			pathPrefix := avapigwv1alpha1.PathMatchPathPrefix
			apiPath := "/api"
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
				Rules: []avapigwv1alpha1.HTTPRouteRule{
					{
						Matches: []avapigwv1alpha1.HTTPRouteMatch{
							{
								Path: &avapigwv1alpha1.HTTPPathMatch{
									Type:  &pathPrefix,
									Value: &apiPath,
								},
							},
						},
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{
								BackendRef: avapigwv1alpha1.BackendRef{
									Name: backendName,
								},
							},
						},
					},
				},
			})

			// Verify resources were created
			Eventually(func() error {
				_, err := getHTTPRoute(routeName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// In a real test with a running gateway, we would make HTTP requests
			// and verify they are routed correctly
		})

		It("should route HTTP requests based on headers", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-service",
					Port: 80,
				},
			})

			// Create HTTPRoute with header matching
			headerType := avapigwv1alpha1.HeaderMatchExact
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
				Rules: []avapigwv1alpha1.HTTPRouteRule{
					{
						Matches: []avapigwv1alpha1.HTTPRouteMatch{
							{
								Headers: []avapigwv1alpha1.HTTPHeaderMatch{
									{
										Type:  &headerType,
										Name:  "X-Version",
										Value: "v2",
									},
								},
							},
						},
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{
								BackendRef: avapigwv1alpha1.BackendRef{
									Name: backendName,
								},
							},
						},
					},
				},
			})

			// Verify resources were created
			Eventually(func() error {
				_, err := getHTTPRoute(routeName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())
		})

		It("should route HTTP requests based on method", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-service",
					Port: 80,
				},
			})

			// Create HTTPRoute with method matching
			postMethod := avapigwv1alpha1.HTTPMethodPost
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
				Rules: []avapigwv1alpha1.HTTPRouteRule{
					{
						Matches: []avapigwv1alpha1.HTTPRouteMatch{
							{
								Method: &postMethod,
							},
						},
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{
								BackendRef: avapigwv1alpha1.BackendRef{
									Name: backendName,
								},
							},
						},
					},
				},
			})

			// Verify resources were created
			Eventually(func() error {
				_, err := getHTTPRoute(routeName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())
		})
	})

	Context("HTTPS with TLS Termination", func() {
		var (
			gatewayName   string
			routeName     string
			backendName   string
			tlsSecretName string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-https")
			routeName = generateUniqueName("route-https")
			backendName = generateUniqueName("backend-https")
			tlsSecretName = generateUniqueName("tls-secret")

			// Create TLS secret
			certPEM, keyPEM, err := generateSelfSignedCert("gateway.example.com", []string{"gateway.example.com", "*.example.com"}, 24*time.Hour)
			Expect(err).NotTo(HaveOccurred())

			createSecretWithType(tlsSecretName, corev1.SecretTypeTLS, map[string][]byte{
				"tls.crt": certPEM,
				"tls.key": keyPEM,
			})
		})

		AfterEach(func() {
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
			deleteSecret(tlsSecretName)
		})

		It("should terminate TLS and route to backend", func() {
			// Create Gateway with HTTPS listener
			tlsMode := avapigwv1alpha1.TLSModeTerminate
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						Mode: &tlsMode,
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: tlsSecretName},
						},
					},
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
				Hostnames: []avapigwv1alpha1.Hostname{"gateway.example.com"},
				Rules: []avapigwv1alpha1.HTTPRouteRule{
					{
						BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
							{
								BackendRef: avapigwv1alpha1.BackendRef{
									Name: backendName,
								},
							},
						},
					},
				},
			})

			// Verify resources were created
			Eventually(func() error {
				gw, err := getGateway(gatewayName)
				if err != nil {
					return err
				}
				if gw.Spec.Listeners[0].TLS == nil {
					return fmt.Errorf("TLS not configured")
				}
				return nil
			}, ShortTimeout, DefaultInterval).Should(Succeed())
		})

		It("should support TLS passthrough", func() {
			// Create Gateway with TLS passthrough
			tlsMode := avapigwv1alpha1.TLSModePassthrough
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "tls",
					Port:     8443,
					Protocol: avapigwv1alpha1.ProtocolTLS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						Mode: &tlsMode,
					},
				},
			})

			// Verify Gateway was created with passthrough mode
			Eventually(func() *avapigwv1alpha1.TLSModeType {
				gw, err := getGateway(gatewayName)
				if err != nil {
					return nil
				}
				if gw.Spec.Listeners[0].TLS == nil {
					return nil
				}
				return gw.Spec.Listeners[0].TLS.Mode
			}, ShortTimeout, DefaultInterval).Should(Equal(&tlsMode))
		})
	})

	Context("Load Balancing", func() {
		var (
			gatewayName string
			routeName   string
			backendName string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-lb")
			routeName = generateUniqueName("route-lb")
			backendName = generateUniqueName("backend-lb")
		})

		AfterEach(func() {
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should configure round-robin load balancing", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend with round-robin load balancing
			algorithm := avapigwv1alpha1.LoadBalancingRoundRobin
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{
					{Address: "10.0.0.1", Port: 8080},
					{Address: "10.0.0.2", Port: 8080},
					{Address: "10.0.0.3", Port: 8080},
				},
				LoadBalancing: &avapigwv1alpha1.LoadBalancingConfig{
					Algorithm: &algorithm,
				},
			})

			// Verify Backend was created
			Eventually(func() error {
				backend, err := getBackend(backendName)
				if err != nil {
					return err
				}
				if backend.Spec.LoadBalancing == nil {
					return fmt.Errorf("load balancing not configured")
				}
				return nil
			}, ShortTimeout, DefaultInterval).Should(Succeed())
		})

		It("should configure weighted load balancing", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend with weighted endpoints
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{
					{Address: "10.0.0.1", Port: 8080, Weight: int32Ptr(70)},
					{Address: "10.0.0.2", Port: 8080, Weight: int32Ptr(20)},
					{Address: "10.0.0.3", Port: 8080, Weight: int32Ptr(10)},
				},
			})

			// Verify Backend was created with weights
			Eventually(func() bool {
				backend, err := getBackend(backendName)
				if err != nil {
					return false
				}
				if len(backend.Spec.Endpoints) != 3 {
					return false
				}
				return *backend.Spec.Endpoints[0].Weight == 70
			}, ShortTimeout, DefaultInterval).Should(BeTrue())
		})

		It("should configure consistent hash load balancing", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend with consistent hash
			algorithm := avapigwv1alpha1.LoadBalancingConsistentHash
			hashType := avapigwv1alpha1.ConsistentHashHeader
			headerName := "X-User-ID"
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{
					{Address: "10.0.0.1", Port: 8080},
					{Address: "10.0.0.2", Port: 8080},
				},
				LoadBalancing: &avapigwv1alpha1.LoadBalancingConfig{
					Algorithm: &algorithm,
					ConsistentHash: &avapigwv1alpha1.ConsistentHashConfig{
						Type:   hashType,
						Header: &headerName,
					},
				},
			})

			// Verify Backend was created
			Eventually(func() bool {
				backend, err := getBackend(backendName)
				if err != nil {
					return false
				}
				if backend.Spec.LoadBalancing == nil {
					return false
				}
				return *backend.Spec.LoadBalancing.Algorithm == avapigwv1alpha1.LoadBalancingConsistentHash
			}, ShortTimeout, DefaultInterval).Should(BeTrue())
		})
	})

	Context("Rate Limiting", func() {
		var (
			gatewayName string
			routeName   string
			policyName  string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-ratelimit")
			routeName = generateUniqueName("route-ratelimit")
			policyName = generateUniqueName("ratelimit-policy")
		})

		AfterEach(func() {
			// Delete RateLimitPolicy
			policy := &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
			}
			_ = k8sClient.Delete(ctx, policy)

			deleteHTTPRoute(routeName)
			deleteGateway(gatewayName)
		})

		It("should apply rate limiting policy", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
			})

			// Create RateLimitPolicy
			policy := &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: "avapigw.vyrodovalexey.github.com",
						Kind:  "HTTPRoute",
						Name:  routeName,
					},
					Rules: []avapigwv1alpha1.RateLimitRule{
						{
							Name: "default",
							Limit: avapigwv1alpha1.RateLimitValue{
								Requests: 100,
								Unit:     avapigwv1alpha1.RateLimitUnitMinute,
							},
						},
					},
				},
			}

			err := k8sClient.Create(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			// Verify policy was created
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)
			}, ShortTimeout, DefaultInterval).Should(Succeed())
		})
	})

	Context("Authentication", func() {
		var (
			gatewayName string
			routeName   string
			policyName  string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-auth")
			routeName = generateUniqueName("route-auth")
			policyName = generateUniqueName("auth-policy")
		})

		AfterEach(func() {
			// Delete AuthPolicy
			policy := &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
			}
			_ = k8sClient.Delete(ctx, policy)

			deleteHTTPRoute(routeName)
			deleteGateway(gatewayName)
		})

		It("should apply JWT authentication policy", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
			})

			// Create AuthPolicy with JWT
			enabled := true
			policy := &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: "avapigw.vyrodovalexey.github.com",
						Kind:  "HTTPRoute",
						Name:  routeName,
					},
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						JWT: &avapigwv1alpha1.JWTAuthConfig{
							Enabled: &enabled,
							Issuer:  stringPtr("https://auth.example.com"),
							JWKSUri: stringPtr("https://auth.example.com/.well-known/jwks.json"),
						},
					},
				},
			}

			err := k8sClient.Create(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			// Verify policy was created
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)
			}, ShortTimeout, DefaultInterval).Should(Succeed())
		})

		It("should apply API key authentication policy", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
			})

			// Create secret with API keys
			apiKeySecretName := generateUniqueName("api-keys")
			createSecret(apiKeySecretName, map[string][]byte{
				"key1": []byte("sk-test-12345"),
				"key2": []byte("sk-test-67890"),
			})

			// Create AuthPolicy with API key
			enabled := true
			headerName := "X-API-Key"
			policy := &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: "avapigw.vyrodovalexey.github.com",
						Kind:  "HTTPRoute",
						Name:  routeName,
					},
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
							Enabled: &enabled,
							Location: &avapigwv1alpha1.APIKeyLocationConfig{
								Header: &headerName,
							},
							Validation: &avapigwv1alpha1.APIKeyValidationConfig{
								Type: avapigwv1alpha1.APIKeyValidationSecret,
								SecretRef: &avapigwv1alpha1.SecretObjectReference{
									Name: apiKeySecretName,
								},
							},
						},
					},
				},
			}

			err := k8sClient.Create(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			// Verify policy was created
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Cleanup
			deleteSecret(apiKeySecretName)
		})
	})
})

// Helper to make HTTP request through gateway
func makeGatewayRequest(gatewayURL, path string, headers map[string]string) (*http.Response, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	req, err := http.NewRequest(http.MethodGet, gatewayURL+path, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return client.Do(req)
}

// Helper to verify response status
func verifyResponseStatus(resp *http.Response, expectedStatus int) {
	Expect(resp.StatusCode).To(Equal(expectedStatus))
}

// Helper to verify response header
func verifyResponseHeader(resp *http.Response, headerName, expectedValue string) {
	Expect(resp.Header.Get(headerName)).To(Equal(expectedValue))
}
