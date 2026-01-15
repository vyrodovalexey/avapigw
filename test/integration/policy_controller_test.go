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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

var _ = Describe("Policy Controller Integration Tests", func() {
	var gateway *avapigwv1alpha1.Gateway
	var httpRoute *avapigwv1alpha1.HTTPRoute

	BeforeEach(func() {
		// Create Gateway for policy tests
		gateway = newGateway(TestNamespace, uniqueName("gw-policy"), []avapigwv1alpha1.Listener{
			newHTTPListener("http", 8080),
		})
		Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
		waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

		// Create HTTPRoute for policy attachment
		httpRoute = newHTTPRoute(TestNamespace, uniqueName("route-policy"), []avapigwv1alpha1.ParentRef{
			newParentRef(gateway.Name),
		}, []avapigwv1alpha1.HTTPRouteRule{
			newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
				newHTTPBackendRef("backend-svc", 8080, 1),
			}),
		})
		Expect(k8sClient.Create(ctx, httpRoute)).Should(Succeed())
	})

	AfterEach(func() {
		cleanupResource(httpRoute)
		cleanupResource(gateway)
	})

	Context("RateLimitPolicy Creation and Attachment", func() {
		It("should create RateLimitPolicy targeting HTTPRoute", func() {
			policy := newRateLimitPolicy(TestNamespace, uniqueName("rlp-route"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("default", 100, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify conditions
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).Should(Succeed())
			cond := policy.Status.GetCondition(avapigwv1alpha1.ConditionTypeAccepted)
			Expect(cond).ShouldNot(BeNil())
			Expect(cond.Status).Should(Equal(metav1.ConditionTrue))
		})

		It("should create RateLimitPolicy targeting Gateway", func() {
			policy := newRateLimitPolicy(TestNamespace, uniqueName("rlp-gateway"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "Gateway", gateway.Name),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("global", 1000, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)
		})

		It("should reject RateLimitPolicy with non-existent target", func() {
			policy := newRateLimitPolicy(TestNamespace, uniqueName("rlp-invalid"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", "non-existent-route"),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("default", 100, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to report error
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusError, Timeout)

			// Verify condition
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).Should(Succeed())
			cond := policy.Status.GetCondition(avapigwv1alpha1.ConditionTypeAccepted)
			Expect(cond).ShouldNot(BeNil())
			Expect(cond.Status).Should(Equal(metav1.ConditionFalse))
		})
	})

	Context("RateLimitPolicy Update", func() {
		It("should update RateLimitPolicy when rules change", func() {
			policy := newRateLimitPolicy(TestNamespace, uniqueName("rlp-update"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("default", 100, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Update the rate limit
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).Should(Succeed())
			policy.Spec.Rules[0].Limit.Requests = 200
			Expect(k8sClient.Update(ctx, policy)).Should(Succeed())

			// Verify update
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
					return 0
				}
				return policy.Spec.Rules[0].Limit.Requests
			}, Timeout, Interval).Should(Equal(int32(200)))
		})

		It("should update RateLimitPolicy when adding new rules", func() {
			policy := newRateLimitPolicy(TestNamespace, uniqueName("rlp-add-rule"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("default", 100, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Add a new rule
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).Should(Succeed())
			policy.Spec.Rules = append(policy.Spec.Rules,
				newRateLimitRule("burst", 1000, avapigwv1alpha1.RateLimitUnitSecond))
			Expect(k8sClient.Update(ctx, policy)).Should(Succeed())

			// Verify update
			Eventually(func() int {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
					return 0
				}
				return len(policy.Spec.Rules)
			}, Timeout, Interval).Should(Equal(2))
		})
	})

	Context("RateLimitPolicy with Different Algorithms", func() {
		It("should create RateLimitPolicy with TokenBucket algorithm", func() {
			policy := &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("rlp-token-bucket"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
					Rules: []avapigwv1alpha1.RateLimitRule{
						{
							Name: "token-bucket",
							Limit: avapigwv1alpha1.RateLimitValue{
								Requests: 100,
								Unit:     avapigwv1alpha1.RateLimitUnitMinute,
							},
							Algorithm: rateLimitAlgorithmPtr(avapigwv1alpha1.RateLimitAlgorithmTokenBucket),
							TokenBucket: &avapigwv1alpha1.TokenBucketConfig{
								Tokens:        100,
								FillInterval:  stringPtr("1s"),
								TokensPerFill: int32Ptr(10),
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify token bucket configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).Should(Succeed())
			Expect(policy.Spec.Rules[0].TokenBucket).ShouldNot(BeNil())
			Expect(policy.Spec.Rules[0].TokenBucket.Tokens).Should(Equal(int32(100)))
		})

		It("should create RateLimitPolicy with SlidingWindow algorithm", func() {
			policy := &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("rlp-sliding-window"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
					Rules: []avapigwv1alpha1.RateLimitRule{
						{
							Name: "sliding-window",
							Limit: avapigwv1alpha1.RateLimitValue{
								Requests: 100,
								Unit:     avapigwv1alpha1.RateLimitUnitMinute,
							},
							Algorithm: rateLimitAlgorithmPtr(avapigwv1alpha1.RateLimitAlgorithmSlidingWindow),
							SlidingWindow: &avapigwv1alpha1.SlidingWindowConfig{
								WindowSize: stringPtr("1m"),
								Precision:  int32Ptr(10),
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)
		})
	})

	Context("AuthPolicy with JWT Configuration", func() {
		It("should create AuthPolicy with JWT authentication using JWKS URI", func() {
			policy := newAuthPolicy(TestNamespace, uniqueName("ap-jwt-uri"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				newJWTAuthConfig("https://auth.example.com", "https://auth.example.com/.well-known/jwks.json"),
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify JWT configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).Should(Succeed())
			Expect(policy.Spec.Authentication).ShouldNot(BeNil())
			Expect(policy.Spec.Authentication.JWT).ShouldNot(BeNil())
			Expect(*policy.Spec.Authentication.JWT.Enabled).Should(BeTrue())
		})

		It("should create AuthPolicy with JWT authentication using JWKS secret", func() {
			// Create JWKS secret
			jwksSecret := newSecret(TestNamespace, uniqueName("jwks-secret"), map[string][]byte{
				"jwks.json": []byte(`{"keys":[]}`),
			})
			Expect(k8sClient.Create(ctx, jwksSecret)).Should(Succeed())
			defer cleanupResource(jwksSecret)

			policy := &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("ap-jwt-secret"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						JWT: &avapigwv1alpha1.JWTAuthConfig{
							Enabled: boolPtr(true),
							Issuer:  stringPtr("https://auth.example.com"),
							JWKS: &avapigwv1alpha1.SecretObjectReference{
								Name: jwksSecret.Name,
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)
		})

		It("should reject AuthPolicy with missing JWKS configuration", func() {
			policy := &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("ap-jwt-invalid"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						JWT: &avapigwv1alpha1.JWTAuthConfig{
							Enabled: boolPtr(true),
							Issuer:  stringPtr("https://auth.example.com"),
							// Missing both JWKSUri and JWKS
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to report error
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusError, Timeout)
		})
	})

	Context("AuthPolicy with API Key Configuration", func() {
		It("should create AuthPolicy with API Key authentication", func() {
			// Create API keys secret
			apiKeySecret := newSecret(TestNamespace, uniqueName("api-keys"), map[string][]byte{
				"key1": []byte("secret-key-1"),
				"key2": []byte("secret-key-2"),
			})
			Expect(k8sClient.Create(ctx, apiKeySecret)).Should(Succeed())
			defer cleanupResource(apiKeySecret)

			policy := newAuthPolicy(TestNamespace, uniqueName("ap-apikey"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				newAPIKeyAuthConfig(apiKeySecret.Name),
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify API Key configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).Should(Succeed())
			Expect(policy.Spec.Authentication.APIKey).ShouldNot(BeNil())
			Expect(*policy.Spec.Authentication.APIKey.Enabled).Should(BeTrue())
		})

		It("should reject AuthPolicy with missing API Key secret", func() {
			policy := newAuthPolicy(TestNamespace, uniqueName("ap-apikey-invalid"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				newAPIKeyAuthConfig("non-existent-secret"),
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to report error
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusError, Timeout)
		})
	})

	Context("AuthPolicy with Authorization Rules", func() {
		It("should create AuthPolicy with authorization rules", func() {
			policy := &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("ap-authz"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						JWT: &avapigwv1alpha1.JWTAuthConfig{
							Enabled: boolPtr(true),
							Issuer:  stringPtr("https://auth.example.com"),
							JWKSUri: stringPtr("https://auth.example.com/.well-known/jwks.json"),
						},
					},
					Authorization: &avapigwv1alpha1.AuthorizationConfig{
						DefaultAction: authorizationActionPtr(avapigwv1alpha1.AuthorizationActionDeny),
						Rules: []avapigwv1alpha1.AuthorizationRule{
							{
								Name: "allow-admin",
								When: []avapigwv1alpha1.AuthorizationCondition{
									{
										Claim:  stringPtr("role"),
										Values: []string{"admin"},
									},
								},
								Action: authorizationActionPtr(avapigwv1alpha1.AuthorizationActionAllow),
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify authorization configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).Should(Succeed())
			Expect(policy.Spec.Authorization).ShouldNot(BeNil())
			Expect(policy.Spec.Authorization.Rules).Should(HaveLen(1))
		})
	})

	Context("Policy Conflict Resolution", func() {
		It("should handle multiple policies targeting the same resource", func() {
			// Create first policy
			policy1 := newRateLimitPolicy(TestNamespace, uniqueName("rlp-conflict-1"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("rule1", 100, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)
			Expect(k8sClient.Create(ctx, policy1)).Should(Succeed())
			defer cleanupResource(policy1)

			// Create second policy targeting the same route
			policy2 := newRateLimitPolicy(TestNamespace, uniqueName("rlp-conflict-2"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("rule2", 200, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)
			Expect(k8sClient.Create(ctx, policy2)).Should(Succeed())
			defer cleanupResource(policy2)

			// Both policies should be accepted (conflict resolution is implementation-specific)
			waitForPhase(policy1, avapigwv1alpha1.PhaseStatusReady, Timeout)
			waitForPhase(policy2, avapigwv1alpha1.PhaseStatusReady, Timeout)
		})
	})

	Context("Policy Deletion", func() {
		It("should delete RateLimitPolicy cleanly", func() {
			policy := newRateLimitPolicy(TestNamespace, uniqueName("rlp-delete"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("default", 100, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Delete policy
			Expect(k8sClient.Delete(ctx, policy)).Should(Succeed())

			// Wait for deletion
			waitForDeletion(policy, Timeout)
		})

		It("should delete AuthPolicy cleanly", func() {
			policy := newAuthPolicy(TestNamespace, uniqueName("ap-delete"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", httpRoute.Name),
				newJWTAuthConfig("https://auth.example.com", "https://auth.example.com/.well-known/jwks.json"),
			)

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			// Wait for policy to be ready
			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Delete policy
			Expect(k8sClient.Delete(ctx, policy)).Should(Succeed())

			// Wait for deletion
			waitForDeletion(policy, Timeout)
		})
	})
})
