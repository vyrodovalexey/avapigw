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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

var _ = Describe("Cross-Resource Integration Tests", func() {
	Context("Gateway with Attached HTTPRoutes", func() {
		It("should properly track attached routes on Gateway", func() {
			// Create Gateway
			gateway := newGateway(TestNamespace, uniqueName("gw-cross"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
				newHTTPListener("http-alt", 8081),
			})
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to be ready
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create multiple HTTPRoutes
			route1 := newHTTPRoute(TestNamespace, uniqueName("route-cross-1"), []avapigwv1alpha1.ParentRef{
				newParentRefWithSection(gateway.Name, "http"),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-1", 8080, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route1)).Should(Succeed())
			defer cleanupResource(route1)

			route2 := newHTTPRoute(TestNamespace, uniqueName("route-cross-2"), []avapigwv1alpha1.ParentRef{
				newParentRefWithSection(gateway.Name, "http"),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-2", 8080, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route2)).Should(Succeed())
			defer cleanupResource(route2)

			route3 := newHTTPRoute(TestNamespace, uniqueName("route-cross-3"), []avapigwv1alpha1.ParentRef{
				newParentRefWithSection(gateway.Name, "http-alt"),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-3", 8080, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route3)).Should(Succeed())
			defer cleanupResource(route3)

			// Wait for Gateway to update attached routes count
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway); err != nil {
					return -1
				}
				// Find the "http" listener
				for _, l := range gateway.Status.Listeners {
					if l.Name == "http" {
						return l.AttachedRoutes
					}
				}
				return -1
			}, Timeout, Interval).Should(BeNumerically(">=", int32(2)))

			// Verify http-alt listener has 1 attached route
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			for _, l := range gateway.Status.Listeners {
				if l.Name == "http-alt" {
					Expect(l.AttachedRoutes).Should(BeNumerically(">=", int32(1)))
				}
			}
		})

		It("should update Gateway when HTTPRoute is deleted", func() {
			// Create Gateway
			gateway := newGateway(TestNamespace, uniqueName("gw-route-delete"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create HTTPRoute
			route := newHTTPRoute(TestNamespace, uniqueName("route-to-delete"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend", 8080, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route)).Should(Succeed())

			// Wait for route to be attached
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway); err != nil {
					return -1
				}
				if len(gateway.Status.Listeners) == 0 {
					return -1
				}
				return gateway.Status.Listeners[0].AttachedRoutes
			}, Timeout, Interval).Should(BeNumerically(">=", int32(1)))

			// Delete the route
			Expect(k8sClient.Delete(ctx, route)).Should(Succeed())
			waitForDeletion(route, Timeout)

			// Wait for Gateway to update (attached routes should decrease)
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway); err != nil {
					return -1
				}
				if len(gateway.Status.Listeners) == 0 {
					return -1
				}
				return gateway.Status.Listeners[0].AttachedRoutes
			}, Timeout, Interval).Should(Equal(int32(0)))
		})
	})

	Context("HTTPRoute with Backend References", func() {
		It("should create HTTPRoute referencing Backend resource", func() {
			// Create Service and Endpoints for Backend
			svc := newService(TestNamespace, uniqueName("backend-svc-cross"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1", "10.0.0.2"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			// Create Backend
			backend := newBackend(TestNamespace, uniqueName("backend-cross"), svc.Name, 8080)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			waitForPhase(backend, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create Gateway
			gateway := newGateway(TestNamespace, uniqueName("gw-backend-ref"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create HTTPRoute referencing the Backend
			route := newHTTPRoute(TestNamespace, uniqueName("route-backend-ref"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRefToBackend(backend.Name, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify route is accepted
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return false
				}
				for _, parent := range route.Status.Parents {
					for _, cond := range parent.Conditions {
						if cond.Type == avapigwv1alpha1.ConditionTypeAccepted && cond.Status == metav1.ConditionTrue {
							return true
						}
					}
				}
				return false
			}, Timeout, Interval).Should(BeTrue())
		})
	})

	Context("Route with Attached Policies", func() {
		It("should create full configuration with Gateway, HTTPRoute, and Policies", func() {
			// Create Gateway
			gateway := newGateway(TestNamespace, uniqueName("gw-full-config"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create HTTPRoute
			route := newHTTPRoute(TestNamespace, uniqueName("route-full-config"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend", 8080, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Create RateLimitPolicy targeting the route
			rateLimitPolicy := newRateLimitPolicy(TestNamespace, uniqueName("rlp-full-config"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", route.Name),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("default", 100, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)
			Expect(k8sClient.Create(ctx, rateLimitPolicy)).Should(Succeed())
			defer cleanupResource(rateLimitPolicy)

			// Create AuthPolicy targeting the route
			authPolicy := newAuthPolicy(TestNamespace, uniqueName("ap-full-config"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", route.Name),
				newJWTAuthConfig("https://auth.example.com", "https://auth.example.com/.well-known/jwks.json"),
			)
			Expect(k8sClient.Create(ctx, authPolicy)).Should(Succeed())
			defer cleanupResource(authPolicy)

			// Wait for all resources to be ready
			waitForPhase(rateLimitPolicy, avapigwv1alpha1.PhaseStatusReady, Timeout)
			waitForPhase(authPolicy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify all resources are in ready state
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			Expect(gateway.Status.Phase).Should(Equal(avapigwv1alpha1.PhaseStatusReady))

			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rateLimitPolicy), rateLimitPolicy)).Should(Succeed())
			Expect(rateLimitPolicy.Status.Phase).Should(Equal(avapigwv1alpha1.PhaseStatusReady))

			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(authPolicy), authPolicy)).Should(Succeed())
			Expect(authPolicy.Status.Phase).Should(Equal(avapigwv1alpha1.PhaseStatusReady))
		})
	})

	Context("Full Configuration Flow", func() {
		It("should handle complete API Gateway configuration", func() {
			// Step 1: Create TLS Secret
			tlsSecret := newTLSSecret(TestNamespace, uniqueName("tls-full"))
			Expect(k8sClient.Create(ctx, tlsSecret)).Should(Succeed())
			defer cleanupResource(tlsSecret)

			// Step 2: Create Gateway with HTTP and HTTPS listeners
			gateway := &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("gw-full"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						newHTTPListener("http", 8080),
						newHTTPSListener("https", 8443, tlsSecret.Name),
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Step 3: Create Backend Service and Endpoints
			svc := newService(TestNamespace, uniqueName("api-svc"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			// Step 4: Create Backend with health check and load balancing
			backend := &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("api-backend"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: svc.Name,
						Port: 8080,
					},
					LoadBalancing: &avapigwv1alpha1.LoadBalancingConfig{
						Algorithm: loadBalancingAlgorithmPtr(avapigwv1alpha1.LoadBalancingRoundRobin),
					},
					HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
						Enabled:  boolPtr(true),
						Interval: durationPtr("10s"),
						HTTP: &avapigwv1alpha1.HTTPHealthCheckConfig{
							Path: "/health",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			waitForPhase(backend, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Step 5: Create HTTPRoute with path-based routing
			route := &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("api-route"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						newParentRef(gateway.Name),
					},
					Hostnames: []avapigwv1alpha1.Hostname{"api.example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							Matches: []avapigwv1alpha1.HTTPRouteMatch{
								{
									Path: &avapigwv1alpha1.HTTPPathMatch{
										Type:  pathMatchTypePtr(avapigwv1alpha1.PathMatchPathPrefix),
										Value: stringPtr("/api/v1"),
									},
								},
							},
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
								newHTTPBackendRefToBackend(backend.Name, 1),
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Step 6: Create RateLimitPolicy
			rateLimitPolicy := &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("api-ratelimit"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", route.Name),
					Rules: []avapigwv1alpha1.RateLimitRule{
						{
							Name: "default",
							Limit: avapigwv1alpha1.RateLimitValue{
								Requests: 100,
								Unit:     avapigwv1alpha1.RateLimitUnitMinute,
							},
							ClientIdentifier: &avapigwv1alpha1.ClientIdentifierConfig{
								Type: avapigwv1alpha1.ClientIdentifierRemoteAddress,
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rateLimitPolicy)).Should(Succeed())
			defer cleanupResource(rateLimitPolicy)

			waitForPhase(rateLimitPolicy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Step 7: Create AuthPolicy with JWT
			authPolicy := &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("api-auth"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", route.Name),
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						JWT: &avapigwv1alpha1.JWTAuthConfig{
							Enabled:   boolPtr(true),
							Issuer:    stringPtr("https://auth.example.com"),
							JWKSUri:   stringPtr("https://auth.example.com/.well-known/jwks.json"),
							Audiences: []string{"api.example.com"},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, authPolicy)).Should(Succeed())
			defer cleanupResource(authPolicy)

			waitForPhase(authPolicy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify final state
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			Expect(gateway.Status.Phase).Should(Equal(avapigwv1alpha1.PhaseStatusReady))
			Expect(gateway.Status.ListenersCount).Should(Equal(int32(2)))

			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(backend.Status.Phase).Should(Equal(avapigwv1alpha1.PhaseStatusReady))
			Expect(backend.Status.TotalEndpoints).Should(Equal(int32(3)))
		})
	})

	Context("Resource Dependency Updates", func() {
		It("should update HTTPRoute status when Gateway is deleted", func() {
			// Create Gateway
			gateway := newGateway(TestNamespace, uniqueName("gw-dep-delete"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create HTTPRoute
			route := newHTTPRoute(TestNamespace, uniqueName("route-dep-delete"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend", 8080, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Wait for route to be accepted
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return false
				}
				for _, parent := range route.Status.Parents {
					for _, cond := range parent.Conditions {
						if cond.Type == avapigwv1alpha1.ConditionTypeAccepted && cond.Status == metav1.ConditionTrue {
							return true
						}
					}
				}
				return false
			}, Timeout, Interval).Should(BeTrue())

			// Delete Gateway
			Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())
			waitForDeletion(gateway, Timeout)

			// Route should update status to reflect missing parent
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return false
				}
				for _, parent := range route.Status.Parents {
					for _, cond := range parent.Conditions {
						if cond.Type == avapigwv1alpha1.ConditionTypeAccepted && cond.Status == metav1.ConditionFalse {
							return true
						}
					}
				}
				return false
			}, Timeout, Interval).Should(BeTrue())
		})

		It("should update Policy status when target HTTPRoute is deleted", func() {
			// Create Gateway
			gateway := newGateway(TestNamespace, uniqueName("gw-policy-dep"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create HTTPRoute
			route := newHTTPRoute(TestNamespace, uniqueName("route-policy-dep"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend", 8080, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route)).Should(Succeed())

			// Create Policy targeting the route
			policy := newRateLimitPolicy(TestNamespace, uniqueName("rlp-dep"),
				newTargetRef(avapigwv1alpha1.GroupVersion.Group, "HTTPRoute", route.Name),
				[]avapigwv1alpha1.RateLimitRule{
					newRateLimitRule("default", 100, avapigwv1alpha1.RateLimitUnitMinute),
				},
			)
			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())
			defer cleanupResource(policy)

			waitForPhase(policy, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Delete HTTPRoute
			Expect(k8sClient.Delete(ctx, route)).Should(Succeed())
			waitForDeletion(route, Timeout)

			// Policy should update status to reflect missing target
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
					return ""
				}
				return policy.Status.Phase
			}, Timeout, Interval).Should(Equal(avapigwv1alpha1.PhaseStatusError))
		})
	})

	Context("Multi-Namespace Scenarios", func() {
		var testNs2 string

		BeforeEach(func() {
			// Create a second namespace for cross-namespace tests
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "avapigw-test-2-",
				},
			}
			Expect(k8sClient.Create(ctx, ns)).Should(Succeed())
			testNs2 = ns.Name
		})

		AfterEach(func() {
			deleteTestNamespace(testNs2)
		})

		It("should handle HTTPRoute referencing Gateway in different namespace", func() {
			// Create Gateway in first namespace
			gateway := newGateway(TestNamespace, uniqueName("gw-cross-ns"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create HTTPRoute in second namespace referencing Gateway in first namespace
			route := &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("route-cross-ns"),
					Namespace: testNs2,
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						newParentRefWithNamespace(TestNamespace, gateway.Name),
					},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
							newHTTPBackendRef("backend", 8080, 1),
						}),
					},
				},
			}
			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Route should be created (acceptance depends on Gateway's AllowedRoutes configuration)
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
		})
	})
})
