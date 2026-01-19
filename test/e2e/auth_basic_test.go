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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

var _ = Describe("Basic Authentication E2E", Ordered, func() {
	// Test configuration
	var (
		gatewayName     string
		routeName       string
		backendName     string
		authPolicyName  string
		basicSecretName string
		gatewayPort     int32 = 8080
	)

	// BeforeAll sets up shared test resources
	BeforeAll(func() {
		GinkgoWriter.Printf("Setting up Basic Authentication E2E tests\n")
	})

	// AfterAll cleans up shared test resources
	AfterAll(func() {
		GinkgoWriter.Printf("Cleaning up Basic Authentication E2E tests\n")
	})

	Context("Basic Auth with K8s Secret", func() {
		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-basic-auth")
			routeName = generateUniqueName("route-basic-auth")
			backendName = generateUniqueName("backend-basic-auth")
			authPolicyName = generateUniqueName("auth-policy-basic")
			basicSecretName = generateUniqueName("basic-auth-secret")
		})

		AfterEach(func() {
			// Clean up resources in reverse order of creation
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
			deleteSecret(basicSecretName)
		})

		It("should authenticate with valid credentials", func() {
			// Create K8s Secret with basic auth credentials
			users := map[string]string{
				"testuser": "testpassword",
			}
			createBasicAuthSecret(basicSecretName, users)

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

			// Create AuthPolicy with Basic Auth
			createBasicAuthPolicy(authPolicyName, routeName, basicSecretName, "")

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			GinkgoWriter.Printf("Basic Auth policy created successfully with valid credentials test\n")
		})

		It("should reject requests with invalid credentials", func() {
			// Create K8s Secret with basic auth credentials
			users := map[string]string{
				"validuser": "validpassword",
			}
			createBasicAuthSecret(basicSecretName, users)

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

			// Create AuthPolicy with Basic Auth
			createBasicAuthPolicy(authPolicyName, routeName, basicSecretName, "")

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			GinkgoWriter.Printf("Basic Auth policy created - invalid credentials should be rejected\n")
		})

		It("should reject requests with missing credentials", func() {
			// Create K8s Secret with basic auth credentials
			users := map[string]string{
				"user1": "password1",
			}
			createBasicAuthSecret(basicSecretName, users)

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

			// Create AuthPolicy with Basic Auth
			createBasicAuthPolicy(authPolicyName, routeName, basicSecretName, "")

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			GinkgoWriter.Printf("Basic Auth policy created - missing credentials should be rejected\n")
		})

		It("should reject requests with malformed Authorization header", func() {
			// Create K8s Secret with basic auth credentials
			users := map[string]string{
				"user1": "password1",
			}
			createBasicAuthSecret(basicSecretName, users)

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

			// Create AuthPolicy with Basic Auth
			createBasicAuthPolicy(authPolicyName, routeName, basicSecretName, "")

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			GinkgoWriter.Printf("Basic Auth policy created - malformed header should be rejected\n")
		})

		It("should use custom realm in WWW-Authenticate header", func() {
			customRealm := "MyCustomRealm"

			// Create K8s Secret with basic auth credentials
			users := map[string]string{
				"user1": "password1",
			}
			createBasicAuthSecret(basicSecretName, users)

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

			// Create AuthPolicy with Basic Auth and custom realm
			createBasicAuthPolicy(authPolicyName, routeName, basicSecretName, customRealm)

			// Verify AuthPolicy was created with custom realm
			Eventually(func() bool {
				policy, err := getAuthPolicy(authPolicyName)
				if err != nil {
					return false
				}
				if policy.Spec.Authentication == nil || policy.Spec.Authentication.Basic == nil {
					return false
				}
				return policy.Spec.Authentication.Basic.Realm != nil &&
					*policy.Spec.Authentication.Basic.Realm == customRealm
			}, ShortTimeout, DefaultInterval).Should(BeTrue())

			GinkgoWriter.Printf("Basic Auth policy created with custom realm: %s\n", customRealm)
		})

		It("should authenticate multiple users from the same secret", func() {
			// Create K8s Secret with multiple users
			users := map[string]string{
				"user1": "password1",
				"user2": "password2",
				"admin": "adminpass",
			}
			createBasicAuthSecret(basicSecretName, users)

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

			// Create AuthPolicy with Basic Auth
			createBasicAuthPolicy(authPolicyName, routeName, basicSecretName, "")

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Verify the secret has all users
			secret, err := getSecret(basicSecretName)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data).To(HaveLen(3))
			Expect(secret.Data).To(HaveKey("user1"))
			Expect(secret.Data).To(HaveKey("user2"))
			Expect(secret.Data).To(HaveKey("admin"))

			GinkgoWriter.Printf("Basic Auth policy created with multiple users\n")
		})
	})

	Context("Basic Auth with Vault Secret", func() {
		var (
			vaultSecretName  string
			targetSecretName string
			vaultPath        string
			tokenSecretName  string
		)

		BeforeEach(func() {
			skipIfVaultNotAvailable()

			gatewayName = generateUniqueName("gw-basic-vault")
			routeName = generateUniqueName("route-basic-vault")
			backendName = generateUniqueName("backend-basic-vault")
			authPolicyName = generateUniqueName("auth-policy-vault")
			vaultSecretName = generateUniqueName("vs-basic-auth")
			targetSecretName = generateUniqueName("target-basic-auth")
			tokenSecretName = generateUniqueName("vault-token-basic")
			vaultPath = fmt.Sprintf("avapigw/e2e/basic-auth-%d", time.Now().UnixNano())

			// Create token secret for Vault authentication
			createSecret(tokenSecretName, map[string][]byte{
				"token": []byte(testConfig.VaultToken),
			})

			// Create basic auth credentials in Vault
			createVaultKV2Secret(vaultPath, map[string]interface{}{
				"vaultuser":  "vaultpassword",
				"vaultadmin": "vaultadminpass",
			})
		})

		AfterEach(func() {
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
			deleteVaultSecret(vaultSecretName)
			deleteSecret(targetSecretName)
			deleteSecret(tokenSecretName)
			deleteVaultKV2Secret(vaultPath)
		})

		It("should authenticate with credentials from Vault", func() {
			// Create VaultSecret to sync credentials from Vault
			createVaultSecret(vaultSecretName, avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: testConfig.VaultAddr,
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Token: &avapigwv1alpha1.TokenAuthConfig{
							SecretRef: avapigwv1alpha1.SecretObjectReference{
								Name: tokenSecretName,
							},
						},
					},
				},
				Path:       vaultPath,
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			// Wait for VaultSecret to be ready and target secret to be created
			waitForVaultSecretReady(vaultSecretName, DefaultTimeout)
			waitForSecretWithData(targetSecretName, []string{"vaultuser", "vaultadmin"}, ShortTimeout)

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

			// Create AuthPolicy referencing the synced secret
			createBasicAuthPolicy(authPolicyName, routeName, targetSecretName, "VaultRealm")

			// Verify AuthPolicy was created
			Eventually(func() error {
				_, err := getAuthPolicy(authPolicyName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Verify the target secret has the expected credentials
			secret, err := getSecret(targetSecretName)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(secret.Data["vaultuser"])).To(Equal("vaultpassword"))
			Expect(string(secret.Data["vaultadmin"])).To(Equal("vaultadminpass"))

			GinkgoWriter.Printf("Basic Auth policy created with Vault-sourced credentials\n")
		})
	})

	Context("Basic Auth Policy Validation", func() {
		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-basic-validation")
			routeName = generateUniqueName("route-basic-validation")
			backendName = generateUniqueName("backend-basic-validation")
			authPolicyName = generateUniqueName("auth-policy-validation")
			basicSecretName = generateUniqueName("basic-auth-validation")
		})

		AfterEach(func() {
			deleteAuthPolicy(authPolicyName)
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
			deleteSecret(basicSecretName)
		})

		It("should create AuthPolicy with Basic Auth enabled", func() {
			// Create K8s Secret with basic auth credentials
			users := map[string]string{
				"testuser": "testpassword",
			}
			createBasicAuthSecret(basicSecretName, users)

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

			// Create AuthPolicy with Basic Auth
			createBasicAuthPolicy(authPolicyName, routeName, basicSecretName, "")

			// Verify AuthPolicy was created with correct configuration
			Eventually(func() bool {
				policy, err := getAuthPolicy(authPolicyName)
				if err != nil {
					return false
				}
				if policy.Spec.Authentication == nil || policy.Spec.Authentication.Basic == nil {
					return false
				}
				return policy.Spec.Authentication.Basic.Enabled != nil &&
					*policy.Spec.Authentication.Basic.Enabled == true
			}, ShortTimeout, DefaultInterval).Should(BeTrue())

			GinkgoWriter.Printf("AuthPolicy validation passed - Basic Auth is enabled\n")
		})

		It("should reference correct secret in AuthPolicy", func() {
			// Create K8s Secret with basic auth credentials
			users := map[string]string{
				"testuser": "testpassword",
			}
			createBasicAuthSecret(basicSecretName, users)

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

			// Create AuthPolicy with Basic Auth
			createBasicAuthPolicy(authPolicyName, routeName, basicSecretName, "")

			// Verify AuthPolicy references the correct secret
			Eventually(func() bool {
				policy, err := getAuthPolicy(authPolicyName)
				if err != nil {
					return false
				}
				if policy.Spec.Authentication == nil || policy.Spec.Authentication.Basic == nil {
					return false
				}
				if policy.Spec.Authentication.Basic.SecretRef == nil {
					return false
				}
				return policy.Spec.Authentication.Basic.SecretRef.Name == basicSecretName
			}, ShortTimeout, DefaultInterval).Should(BeTrue())

			GinkgoWriter.Printf("AuthPolicy validation passed - correct secret reference\n")
		})
	})
})

// ============================================================================
// Basic Auth Helper Functions
// ============================================================================

// createBasicAuthPolicy creates an AuthPolicy CR with Basic Auth configuration
func createBasicAuthPolicy(name, targetRouteName, secretRef, realm string) *avapigwv1alpha1.AuthPolicy {
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
				Basic: &avapigwv1alpha1.BasicAuthConfig{
					Enabled: &enabled,
					SecretRef: &avapigwv1alpha1.SecretObjectReference{
						Name: secretRef,
					},
				},
			},
		},
	}

	// Set custom realm if provided
	if realm != "" {
		policy.Spec.Authentication.Basic.Realm = &realm
	}

	err := k8sClient.Create(ctx, policy)
	Expect(err).NotTo(HaveOccurred(), "Failed to create AuthPolicy %s", name)

	return policy
}

// createBasicAuthSecret creates a Kubernetes Secret with username:password pairs
// The secret data format is: username -> password (plaintext)
func createBasicAuthSecret(name string, users map[string]string) *corev1.Secret {
	data := make(map[string][]byte)
	for username, password := range users {
		data[username] = []byte(password)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "basic-auth-credentials",
				"app.kubernetes.io/managed-by": "e2e-tests",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}

	err := k8sClient.Create(ctx, secret)
	Expect(err).NotTo(HaveOccurred(), "Failed to create basic auth secret %s", name)

	return secret
}

// createBasicAuthVaultSecret creates a VaultSecret CR for basic auth credentials
func createBasicAuthVaultSecret(name, vaultPath, targetSecretName, tokenSecretName string) *avapigwv1alpha1.VaultSecret {
	vs := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: avapigwv1alpha1.VaultSecretSpec{
			VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
				Address: testConfig.VaultAddr,
				Auth: avapigwv1alpha1.VaultAuthConfig{
					Token: &avapigwv1alpha1.TokenAuthConfig{
						SecretRef: avapigwv1alpha1.SecretObjectReference{
							Name: tokenSecretName,
						},
					},
				},
			},
			Path:       vaultPath,
			MountPoint: stringPtr("secret"),
			Target: &avapigwv1alpha1.VaultTargetConfig{
				Name: targetSecretName,
			},
		},
	}

	err := k8sClient.Create(ctx, vs)
	Expect(err).NotTo(HaveOccurred(), "Failed to create VaultSecret %s", name)

	return vs
}

// getAuthPolicy retrieves an AuthPolicy resource
func getAuthPolicy(name string) (*avapigwv1alpha1.AuthPolicy, error) {
	policy := &avapigwv1alpha1.AuthPolicy{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: testNamespace,
	}, policy)
	return policy, err
}

// deleteAuthPolicy deletes an AuthPolicy resource
func deleteAuthPolicy(name string) {
	policy := &avapigwv1alpha1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
	}
	_ = k8sClient.Delete(ctx, policy)
}

// sendRequestWithBasicAuth sends an HTTP request with Basic Auth header
func sendRequestWithBasicAuth(url, username, password string) (*http.Response, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Set Basic Auth header
	req.Header.Set("Authorization", encodeBasicAuth(username, password))

	return client.Do(req)
}

// sendRequestWithoutAuth sends an HTTP request without any authentication
func sendRequestWithoutAuth(url string) (*http.Response, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	return client.Do(req)
}

// sendRequestWithMalformedAuth sends an HTTP request with a malformed Authorization header
func sendRequestWithMalformedAuth(url, malformedHeader string) (*http.Response, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Set malformed Authorization header
	req.Header.Set("Authorization", malformedHeader)

	return client.Do(req)
}

// encodeBasicAuth encodes username and password to Base64 for Basic Auth
func encodeBasicAuth(username, password string) string {
	credentials := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}

// verifyWWWAuthenticateHeader checks if the WWW-Authenticate header contains the expected realm
func verifyWWWAuthenticateHeader(resp *http.Response, expectedRealm string) bool {
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		return false
	}

	// Check if it starts with "Basic" and contains the realm
	if !strings.HasPrefix(wwwAuth, "Basic") {
		return false
	}

	if expectedRealm != "" {
		return strings.Contains(wwwAuth, fmt.Sprintf("realm=\"%s\"", expectedRealm))
	}

	return true
}

// waitForAuthPolicyReady waits for an AuthPolicy to be ready
func waitForAuthPolicyReady(name string, timeout time.Duration) *avapigwv1alpha1.AuthPolicy {
	var policy *avapigwv1alpha1.AuthPolicy
	Eventually(func() bool {
		var err error
		policy, err = getAuthPolicy(name)
		if err != nil {
			return false
		}
		return policy.Status.Phase == avapigwv1alpha1.PhaseStatusReady
	}, timeout, DefaultInterval).Should(BeTrue(), "AuthPolicy %s should be ready", name)
	return policy
}

// listAuthPolicies lists all AuthPolicies in the test namespace
func listAuthPolicies() (*avapigwv1alpha1.AuthPolicyList, error) {
	list := &avapigwv1alpha1.AuthPolicyList{}
	err := k8sClient.List(ctx, list, client.InNamespace(testNamespace))
	return list, err
}
