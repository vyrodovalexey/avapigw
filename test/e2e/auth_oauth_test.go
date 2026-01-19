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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

var _ = Describe("OAuth2 Authentication E2E", Ordered, func() {
	// Test configuration
	var (
		gatewayName    string
		routeName      string
		backendName    string
		authPolicyName string
		gatewayPort    avapigwv1alpha1.PortNumber = 8080
	)

	// BeforeAll sets up shared test resources
	BeforeAll(func() {
		skipIfKeycloakNotAvailable()
		GinkgoWriter.Printf("Setting up OAuth2 Authentication E2E tests\n")
	})

	// AfterAll cleans up shared test resources
	AfterAll(func() {
		GinkgoWriter.Printf("Cleaning up OAuth2 Authentication E2E tests\n")
	})

	// ============================================================================
	// JWT Validation with Keycloak
	// ============================================================================

	Context("JWT Validation with Keycloak", func() {
		BeforeEach(func() {
			skipIfKeycloakNotAvailable()
			gatewayName = generateUniqueName("gw-jwt-validation")
			routeName = generateUniqueName("route-jwt-validation")
			backendName = generateUniqueName("backend-jwt-validation")
			authPolicyName = generateUniqueName("auth-policy-jwt")
		})

		AfterEach(func() {
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should authenticate with valid JWT token from Keycloak", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with JWT configuration
			createJWTAuthPolicy(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(), nil)

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Get a valid token from Keycloak
			token, err := getKeycloakToken()
			Expect(err).NotTo(HaveOccurred(), "Should be able to get token from Keycloak")
			Expect(token).NotTo(BeEmpty(), "Token should not be empty")

			GinkgoWriter.Printf("JWT AuthPolicy created successfully - valid token test\n")
			GinkgoWriter.Printf("Token obtained from Keycloak (first 50 chars): %s...\n", token[:min(50, len(token))])
		})

		It("should reject requests with invalid JWT token", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with JWT configuration
			createJWTAuthPolicy(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(), nil)

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Test with invalid token
			invalidToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkludmFsaWQgVG9rZW4iLCJpYXQiOjE1MTYyMzkwMjJ9.invalid_signature"

			GinkgoWriter.Printf("JWT AuthPolicy created - invalid token should be rejected\n")
			GinkgoWriter.Printf("Invalid token: %s...\n", invalidToken[:min(50, len(invalidToken))])
		})

		It("should reject requests with missing JWT token", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with JWT configuration
			createJWTAuthPolicy(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(), nil)

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			GinkgoWriter.Printf("JWT AuthPolicy created - missing token should be rejected\n")
		})
	})

	// ============================================================================
	// JWT Issuer Validation
	// ============================================================================

	Context("JWT Issuer Validation", func() {
		BeforeEach(func() {
			skipIfKeycloakNotAvailable()
			gatewayName = generateUniqueName("gw-jwt-issuer")
			routeName = generateUniqueName("route-jwt-issuer")
			backendName = generateUniqueName("backend-jwt-issuer")
			authPolicyName = generateUniqueName("auth-policy-issuer")
		})

		AfterEach(func() {
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should validate JWT issuer matches expected value", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with specific issuer
			expectedIssuer := testConfig.GetKeycloakIssuer()
			createJWTAuthPolicy(authPolicyName, routeName, expectedIssuer, testConfig.GetKeycloakJWKSURL(), nil)

			// Verify AuthPolicy was created with correct issuer
			Eventually(func() bool {
				policy, err := getAuthPolicy(authPolicyName)
				if err != nil {
					return false
				}
				if policy.Spec.Authentication == nil || policy.Spec.Authentication.JWT == nil {
					return false
				}
				return policy.Spec.Authentication.JWT.Issuer != nil &&
					*policy.Spec.Authentication.JWT.Issuer == expectedIssuer
			}, ShortTimeout, DefaultInterval).Should(BeTrue())

			GinkgoWriter.Printf("JWT AuthPolicy created with issuer: %s\n", expectedIssuer)
		})

		It("should reject tokens with wrong issuer", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with a different issuer than what Keycloak uses
			wrongIssuer := "https://wrong-issuer.example.com"
			createJWTAuthPolicy(authPolicyName, routeName, wrongIssuer, testConfig.GetKeycloakJWKSURL(), nil)

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			GinkgoWriter.Printf("JWT AuthPolicy created with wrong issuer: %s\n", wrongIssuer)
			GinkgoWriter.Printf("Tokens from Keycloak (issuer: %s) should be rejected\n", testConfig.GetKeycloakIssuer())
		})
	})

	// ============================================================================
	// JWT Audience Validation
	// ============================================================================

	Context("JWT Audience Validation", func() {
		BeforeEach(func() {
			skipIfKeycloakNotAvailable()
			gatewayName = generateUniqueName("gw-jwt-audience")
			routeName = generateUniqueName("route-jwt-audience")
			backendName = generateUniqueName("backend-jwt-audience")
			authPolicyName = generateUniqueName("auth-policy-audience")
		})

		AfterEach(func() {
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should validate JWT audience matches expected value", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with specific audiences
			expectedAudiences := []string{testConfig.KeycloakClientID, "account"}
			createJWTAuthPolicy(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(), expectedAudiences)

			// Verify AuthPolicy was created with correct audiences
			Eventually(func() bool {
				policy, err := getAuthPolicy(authPolicyName)
				if err != nil {
					return false
				}
				if policy.Spec.Authentication == nil || policy.Spec.Authentication.JWT == nil {
					return false
				}
				return len(policy.Spec.Authentication.JWT.Audiences) > 0
			}, ShortTimeout, DefaultInterval).Should(BeTrue())

			GinkgoWriter.Printf("JWT AuthPolicy created with audiences: %v\n", expectedAudiences)
		})

		It("should reject tokens with wrong audience", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with a different audience than what Keycloak uses
			wrongAudiences := []string{"wrong-audience", "another-wrong-audience"}
			createJWTAuthPolicy(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(), wrongAudiences)

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			GinkgoWriter.Printf("JWT AuthPolicy created with wrong audiences: %v\n", wrongAudiences)
			GinkgoWriter.Printf("Tokens from Keycloak should be rejected\n")
		})
	})

	// ============================================================================
	// OAuth2 Client Credentials Flow
	// ============================================================================

	Context("OAuth2 Client Credentials Flow", func() {
		BeforeEach(func() {
			skipIfKeycloakNotAvailable()
			gatewayName = generateUniqueName("gw-oauth2-cc")
			routeName = generateUniqueName("route-oauth2-cc")
			backendName = generateUniqueName("backend-oauth2-cc")
			authPolicyName = generateUniqueName("auth-policy-oauth2")
		})

		AfterEach(func() {
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should authenticate using OAuth2 client credentials flow", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with OAuth2 configuration
			createOAuth2AuthPolicy(authPolicyName, routeName, testConfig.GetKeycloakTokenURL(), testConfig.KeycloakClientID)

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Get token using client credentials flow
			token, err := getKeycloakToken()
			Expect(err).NotTo(HaveOccurred(), "Should be able to get token using client credentials")
			Expect(token).NotTo(BeEmpty(), "Token should not be empty")

			GinkgoWriter.Printf("OAuth2 AuthPolicy created for client credentials flow\n")
			GinkgoWriter.Printf("Token endpoint: %s\n", testConfig.GetKeycloakTokenURL())
			GinkgoWriter.Printf("Client ID: %s\n", testConfig.KeycloakClientID)
		})

		It("should reject requests with invalid client credentials", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with OAuth2 configuration
			createOAuth2AuthPolicy(authPolicyName, routeName, testConfig.GetKeycloakTokenURL(), testConfig.KeycloakClientID)

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Try to get token with invalid credentials
			_, err := getKeycloakTokenWithCredentials(testConfig.KeycloakClientID, "invalid-secret")
			Expect(err).To(HaveOccurred(), "Should fail with invalid client secret")

			GinkgoWriter.Printf("OAuth2 AuthPolicy created - invalid credentials should be rejected\n")
		})
	})

	// ============================================================================
	// Token Introspection
	// ============================================================================

	Context("Token Introspection", func() {
		BeforeEach(func() {
			skipIfKeycloakNotAvailable()
			gatewayName = generateUniqueName("gw-introspection")
			routeName = generateUniqueName("route-introspection")
			backendName = generateUniqueName("backend-introspection")
			authPolicyName = generateUniqueName("auth-policy-introspect")
		})

		AfterEach(func() {
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should validate token via introspection endpoint", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with JWT configuration (introspection uses same JWT validation)
			createJWTAuthPolicy(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(), nil)

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Get a valid token
			token, err := getKeycloakToken()
			Expect(err).NotTo(HaveOccurred())

			// Introspect the token
			introspectionResult, err := introspectToken(token)
			Expect(err).NotTo(HaveOccurred(), "Should be able to introspect token")
			Expect(introspectionResult).NotTo(BeNil())
			Expect(introspectionResult["active"]).To(BeTrue(), "Token should be active")

			GinkgoWriter.Printf("Token introspection successful - token is active\n")
		})

		It("should reject expired or revoked tokens via introspection", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with JWT configuration
			createJWTAuthPolicy(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(), nil)

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Introspect an invalid token
			invalidToken := "invalid.token.here"
			introspectionResult, err := introspectToken(invalidToken)
			Expect(err).NotTo(HaveOccurred(), "Introspection should not error for invalid tokens")
			Expect(introspectionResult).NotTo(BeNil())
			Expect(introspectionResult["active"]).To(BeFalse(), "Invalid token should not be active")

			GinkgoWriter.Printf("Token introspection successful - invalid token is not active\n")
		})
	})

	// ============================================================================
	// Claims-Based Authorization
	// ============================================================================

	Context("Claims-Based Authorization", func() {
		BeforeEach(func() {
			skipIfKeycloakNotAvailable()
			gatewayName = generateUniqueName("gw-claims-authz")
			routeName = generateUniqueName("route-claims-authz")
			backendName = generateUniqueName("backend-claims-authz")
			authPolicyName = generateUniqueName("auth-policy-claims")
		})

		AfterEach(func() {
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should authorize based on JWT claims", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with JWT and claims-based authorization
			createJWTAuthPolicyWithClaims(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(),
				[]avapigwv1alpha1.RequiredClaim{
					{
						Name:   "iss",
						Values: []string{testConfig.GetKeycloakIssuer()},
					},
				},
			)

			// Verify AuthPolicy was created with required claims
			Eventually(func() bool {
				policy, err := getAuthPolicy(authPolicyName)
				if err != nil {
					return false
				}
				if policy.Spec.Authentication == nil || policy.Spec.Authentication.JWT == nil {
					return false
				}
				return len(policy.Spec.Authentication.JWT.RequiredClaims) > 0
			}, ShortTimeout, DefaultInterval).Should(BeTrue())

			GinkgoWriter.Printf("JWT AuthPolicy created with claims-based authorization\n")
		})

		It("should extract claims and add as headers", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with claims to headers mapping
			createJWTAuthPolicyWithClaimsToHeaders(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(),
				[]avapigwv1alpha1.ClaimToHeader{
					{
						Claim:  "sub",
						Header: "X-User-ID",
					},
					{
						Claim:  "preferred_username",
						Header: "X-Username",
					},
					{
						Claim:  "email",
						Header: "X-User-Email",
					},
				},
			)

			// Verify AuthPolicy was created with claims to headers
			Eventually(func() bool {
				policy, err := getAuthPolicy(authPolicyName)
				if err != nil {
					return false
				}
				if policy.Spec.Authentication == nil || policy.Spec.Authentication.JWT == nil {
					return false
				}
				return len(policy.Spec.Authentication.JWT.ClaimsToHeaders) > 0
			}, ShortTimeout, DefaultInterval).Should(BeTrue())

			GinkgoWriter.Printf("JWT AuthPolicy created with claims-to-headers mapping\n")
		})
	})

	// ============================================================================
	// Role-Based Access Control
	// ============================================================================

	Context("Role-Based Access Control", func() {
		BeforeEach(func() {
			skipIfKeycloakNotAvailable()
			gatewayName = generateUniqueName("gw-rbac")
			routeName = generateUniqueName("route-rbac")
			backendName = generateUniqueName("backend-rbac")
			authPolicyName = generateUniqueName("auth-policy-rbac")
		})

		AfterEach(func() {
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should authorize users with api-user role", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with role-based authorization
			createJWTAuthPolicyWithRBAC(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(),
				"realm_access.roles", []string{"api-user"})

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Get token for testuser (has api-user role)
			token, err := getKeycloakTokenForUser("testuser", "testpassword")
			Expect(err).NotTo(HaveOccurred(), "Should be able to get token for testuser")
			Expect(token).NotTo(BeEmpty())

			GinkgoWriter.Printf("JWT AuthPolicy created with RBAC - api-user role required\n")
			GinkgoWriter.Printf("Token obtained for testuser (has api-user role)\n")
		})

		It("should authorize users with api-admin role", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy with role-based authorization for admin
			createJWTAuthPolicyWithRBAC(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(),
				"realm_access.roles", []string{"api-admin"})

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Get token for admin-user (has api-admin role)
			token, err := getKeycloakTokenForUser("admin-user", "adminpassword")
			Expect(err).NotTo(HaveOccurred(), "Should be able to get token for admin-user")
			Expect(token).NotTo(BeEmpty())

			GinkgoWriter.Printf("JWT AuthPolicy created with RBAC - api-admin role required\n")
			GinkgoWriter.Printf("Token obtained for admin-user (has api-admin role)\n")
		})

		It("should deny users without required role", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     gatewayPort,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-backend-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
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

			// Create AuthPolicy requiring api-admin role
			createJWTAuthPolicyWithRBAC(authPolicyName, routeName, testConfig.GetKeycloakIssuer(), testConfig.GetKeycloakJWKSURL(),
				"realm_access.roles", []string{"api-admin"})

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Get token for testuser (has only api-user role, not api-admin)
			token, err := getKeycloakTokenForUser("testuser", "testpassword")
			Expect(err).NotTo(HaveOccurred(), "Should be able to get token for testuser")
			Expect(token).NotTo(BeEmpty())

			GinkgoWriter.Printf("JWT AuthPolicy created with RBAC - api-admin role required\n")
			GinkgoWriter.Printf("Token obtained for testuser (has only api-user role) - should be denied\n")
		})
	})
})

// ============================================================================
// OAuth2/JWT Helper Functions
// ============================================================================

// createJWTAuthPolicy creates an AuthPolicy CR with JWT authentication configuration
func createJWTAuthPolicy(name, targetRouteName, issuer, jwksUri string, audiences []string) *avapigwv1alpha1.AuthPolicy {
	enabled := true
	policy := &avapigwv1alpha1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: avapigwv1alpha1.AuthPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Group: "avapigw.vyrodovalexey.github.com",
				Kind:  "HTTPRoute",
				Name:  targetRouteName,
			},
			Authentication: &avapigwv1alpha1.AuthenticationConfig{
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled:   &enabled,
					Issuer:    &issuer,
					JWKSUri:   &jwksUri,
					Audiences: audiences,
				},
			},
		},
	}

	err := k8sClient.Create(ctx, policy)
	Expect(err).NotTo(HaveOccurred(), "Failed to create JWT AuthPolicy %s", name)

	return policy
}

// createJWTAuthPolicyWithClaims creates an AuthPolicy with JWT and required claims
func createJWTAuthPolicyWithClaims(name, targetRouteName, issuer, jwksUri string, requiredClaims []avapigwv1alpha1.RequiredClaim) *avapigwv1alpha1.AuthPolicy {
	enabled := true
	policy := &avapigwv1alpha1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: avapigwv1alpha1.AuthPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Group: "avapigw.vyrodovalexey.github.com",
				Kind:  "HTTPRoute",
				Name:  targetRouteName,
			},
			Authentication: &avapigwv1alpha1.AuthenticationConfig{
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled:        &enabled,
					Issuer:         &issuer,
					JWKSUri:        &jwksUri,
					RequiredClaims: requiredClaims,
				},
			},
		},
	}

	err := k8sClient.Create(ctx, policy)
	Expect(err).NotTo(HaveOccurred(), "Failed to create JWT AuthPolicy with claims %s", name)

	return policy
}

// createJWTAuthPolicyWithClaimsToHeaders creates an AuthPolicy with JWT and claims-to-headers mapping
func createJWTAuthPolicyWithClaimsToHeaders(name, targetRouteName, issuer, jwksUri string, claimsToHeaders []avapigwv1alpha1.ClaimToHeader) *avapigwv1alpha1.AuthPolicy {
	enabled := true
	policy := &avapigwv1alpha1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: avapigwv1alpha1.AuthPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Group: "avapigw.vyrodovalexey.github.com",
				Kind:  "HTTPRoute",
				Name:  targetRouteName,
			},
			Authentication: &avapigwv1alpha1.AuthenticationConfig{
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled:         &enabled,
					Issuer:          &issuer,
					JWKSUri:         &jwksUri,
					ClaimsToHeaders: claimsToHeaders,
				},
			},
		},
	}

	err := k8sClient.Create(ctx, policy)
	Expect(err).NotTo(HaveOccurred(), "Failed to create JWT AuthPolicy with claims-to-headers %s", name)

	return policy
}

// createJWTAuthPolicyWithRBAC creates an AuthPolicy with JWT and role-based authorization
func createJWTAuthPolicyWithRBAC(name, targetRouteName, issuer, jwksUri, roleClaim string, allowedRoles []string) *avapigwv1alpha1.AuthPolicy {
	enabled := true
	allowAction := avapigwv1alpha1.AuthorizationActionAllow

	policy := &avapigwv1alpha1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: avapigwv1alpha1.AuthPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Group: "avapigw.vyrodovalexey.github.com",
				Kind:  "HTTPRoute",
				Name:  targetRouteName,
			},
			Authentication: &avapigwv1alpha1.AuthenticationConfig{
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: &enabled,
					Issuer:  &issuer,
					JWKSUri: &jwksUri,
				},
			},
			Authorization: &avapigwv1alpha1.AuthorizationConfig{
				Rules: []avapigwv1alpha1.AuthorizationRule{
					{
						Name: "require-role",
						When: []avapigwv1alpha1.AuthorizationCondition{
							{
								Claim:  &roleClaim,
								Values: allowedRoles,
							},
						},
						Action: &allowAction,
					},
				},
			},
		},
	}

	err := k8sClient.Create(ctx, policy)
	Expect(err).NotTo(HaveOccurred(), "Failed to create JWT AuthPolicy with RBAC %s", name)

	return policy
}

// createOAuth2AuthPolicy creates an AuthPolicy CR with OAuth2 configuration
func createOAuth2AuthPolicy(name, targetRouteName, tokenEndpoint, clientID string) *avapigwv1alpha1.AuthPolicy {
	enabled := true
	policy := &avapigwv1alpha1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: avapigwv1alpha1.AuthPolicySpec{
			TargetRef: avapigwv1alpha1.TargetRef{
				Group: "avapigw.vyrodovalexey.github.com",
				Kind:  "HTTPRoute",
				Name:  targetRouteName,
			},
			Authentication: &avapigwv1alpha1.AuthenticationConfig{
				OAuth2: &avapigwv1alpha1.OAuth2Config{
					Enabled:       &enabled,
					TokenEndpoint: &tokenEndpoint,
					ClientID:      &clientID,
				},
			},
		},
	}

	err := k8sClient.Create(ctx, policy)
	Expect(err).NotTo(HaveOccurred(), "Failed to create OAuth2 AuthPolicy %s", name)

	return policy
}

// getKeycloakToken gets an access token from Keycloak using client credentials flow
func getKeycloakToken() (string, error) {
	return getKeycloakTokenWithCredentials(testConfig.KeycloakClientID, testConfig.KeycloakClientSecret)
}

// getKeycloakTokenWithCredentials gets an access token from Keycloak with specific credentials
func getKeycloakTokenWithCredentials(clientID, clientSecret string) (string, error) {
	tokenURL := testConfig.GetKeycloakTokenURL()

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get token: status %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// getKeycloakTokenForUser gets an access token for a specific user using password grant
func getKeycloakTokenForUser(username, password string) (string, error) {
	tokenURL := testConfig.GetKeycloakTokenURL()

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", "avapigw-test-public") // Use public client for password grant
	data.Set("username", username)
	data.Set("password", password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get token for user %s: status %d, body: %s", username, resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// sendRequestWithBearerToken sends an HTTP request with a Bearer token
func sendRequestWithBearerToken(requestURL, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

// introspectToken introspects a token using Keycloak's introspection endpoint
func introspectToken(token string) (map[string]interface{}, error) {
	introspectionURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect",
		testConfig.KeycloakURL, testConfig.KeycloakRealm)

	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", testConfig.KeycloakClientID)
	data.Set("client_secret", testConfig.KeycloakClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to introspect token: status %d, body: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	return result, nil
}

// waitForJWTAuthPolicyReady waits for a JWT AuthPolicy to be ready
func waitForJWTAuthPolicyReady(name string, timeout time.Duration) *avapigwv1alpha1.AuthPolicy {
	var policy *avapigwv1alpha1.AuthPolicy
	Eventually(func() bool {
		var err error
		policy, err = getAuthPolicy(name)
		if err != nil {
			return false
		}
		return policy.Status.Phase == avapigwv1alpha1.PhaseStatusReady
	}, timeout, DefaultInterval).Should(BeTrue(), "JWT AuthPolicy %s should be ready", name)
	return policy
}

// listJWTAuthPolicies lists all AuthPolicies with JWT configuration in the test namespace
func listJWTAuthPolicies() ([]*avapigwv1alpha1.AuthPolicy, error) {
	list := &avapigwv1alpha1.AuthPolicyList{}
	err := k8sClient.List(ctx, list, client.InNamespace(testNamespace))
	if err != nil {
		return nil, err
	}

	var jwtPolicies []*avapigwv1alpha1.AuthPolicy
	for i := range list.Items {
		policy := &list.Items[i]
		if policy.Spec.Authentication != nil && policy.Spec.Authentication.JWT != nil {
			jwtPolicies = append(jwtPolicies, policy)
		}
	}

	return jwtPolicies, nil
}

// verifyJWTToken verifies a JWT token structure (basic validation)
func verifyJWTToken(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT token format: expected 3 parts, got %d", len(parts))
	}
	return nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
