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

var _ = Describe("HTTPRoute Controller Integration Tests", func() {
	var gateway *avapigwv1alpha1.Gateway

	BeforeEach(func() {
		// Create a Gateway for HTTPRoute tests
		gateway = newGateway(TestNamespace, uniqueName("gw-httproute"), []avapigwv1alpha1.Listener{
			newHTTPListener("http", 8080),
		})
		Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
		waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)
	})

	AfterEach(func() {
		cleanupResource(gateway)
	})

	Context("HTTPRoute Creation with Parent Gateway", func() {
		It("should create HTTPRoute with valid parent Gateway reference", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-basic"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-svc", 8080, 1),
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
		})

		It("should create HTTPRoute with specific listener section", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-section"), []avapigwv1alpha1.ParentRef{
				newParentRefWithSection(gateway.Name, "http"),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-svc", 8080, 1),
				}),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Wait for route to be accepted
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return false
				}
				return len(route.Status.Parents) > 0
			}, Timeout, Interval).Should(BeTrue())

			// Verify parent ref in status
			Expect(route.Status.Parents[0].ParentRef.SectionName).ShouldNot(BeNil())
			Expect(*route.Status.Parents[0].ParentRef.SectionName).Should(Equal("http"))
		})

		It("should reject HTTPRoute with non-existent parent Gateway", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-no-parent"), []avapigwv1alpha1.ParentRef{
				newParentRef("non-existent-gateway"),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-svc", 8080, 1),
				}),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Wait for route to report not accepted
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
	})

	Context("HTTPRoute with Path Matching", func() {
		It("should create HTTPRoute with exact path match", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-exact-path"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRuleWithMatches(
					[]avapigwv1alpha1.HTTPRouteMatch{
						{
							Path: &avapigwv1alpha1.HTTPPathMatch{
								Type:  pathMatchTypePtr(avapigwv1alpha1.PathMatchExact),
								Value: stringPtr("/api/v1/users"),
							},
						},
					},
					[]avapigwv1alpha1.HTTPBackendRef{
						newHTTPBackendRef("users-svc", 8080, 1),
					},
				),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify route is created with correct path match
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			Expect(route.Spec.Rules[0].Matches[0].Path.Type).ShouldNot(BeNil())
			Expect(*route.Spec.Rules[0].Matches[0].Path.Type).Should(Equal(avapigwv1alpha1.PathMatchExact))
		})

		It("should create HTTPRoute with prefix path match", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-prefix-path"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRuleWithMatches(
					[]avapigwv1alpha1.HTTPRouteMatch{
						{
							Path: &avapigwv1alpha1.HTTPPathMatch{
								Type:  pathMatchTypePtr(avapigwv1alpha1.PathMatchPathPrefix),
								Value: stringPtr("/api/"),
							},
						},
					},
					[]avapigwv1alpha1.HTTPBackendRef{
						newHTTPBackendRef("api-svc", 8080, 1),
					},
				),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Wait for route to be accepted
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return false
				}
				return len(route.Status.Parents) > 0
			}, Timeout, Interval).Should(BeTrue())
		})

		It("should create HTTPRoute with regex path match", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-regex-path"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRuleWithMatches(
					[]avapigwv1alpha1.HTTPRouteMatch{
						{
							Path: &avapigwv1alpha1.HTTPPathMatch{
								Type:  pathMatchTypePtr(avapigwv1alpha1.PathMatchRegularExpression),
								Value: stringPtr("/api/v[0-9]+/.*"),
							},
						},
					},
					[]avapigwv1alpha1.HTTPBackendRef{
						newHTTPBackendRef("api-svc", 8080, 1),
					},
				),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify route is created
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
		})
	})

	Context("HTTPRoute with Header Matching", func() {
		It("should create HTTPRoute with header match", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-header"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRuleWithMatches(
					[]avapigwv1alpha1.HTTPRouteMatch{
						{
							Headers: []avapigwv1alpha1.HTTPHeaderMatch{
								newHeaderMatch("X-Custom-Header", "custom-value"),
							},
						},
					},
					[]avapigwv1alpha1.HTTPBackendRef{
						newHTTPBackendRef("backend-svc", 8080, 1),
					},
				),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify route is created with header match
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			Expect(route.Spec.Rules[0].Matches[0].Headers).Should(HaveLen(1))
			Expect(route.Spec.Rules[0].Matches[0].Headers[0].Name).Should(Equal("X-Custom-Header"))
		})

		It("should create HTTPRoute with multiple header matches", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-multi-header"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRuleWithMatches(
					[]avapigwv1alpha1.HTTPRouteMatch{
						{
							Headers: []avapigwv1alpha1.HTTPHeaderMatch{
								newHeaderMatch("X-Header-1", "value1"),
								newHeaderMatch("X-Header-2", "value2"),
							},
						},
					},
					[]avapigwv1alpha1.HTTPBackendRef{
						newHTTPBackendRef("backend-svc", 8080, 1),
					},
				),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify route is created with multiple header matches
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			Expect(route.Spec.Rules[0].Matches[0].Headers).Should(HaveLen(2))
		})
	})

	Context("HTTPRoute with Multiple Backends (Weighted)", func() {
		It("should create HTTPRoute with weighted backends", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-weighted"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-v1", 8080, 80),
					newHTTPBackendRef("backend-v2", 8080, 20),
				}),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify route is created with weighted backends
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			Expect(route.Spec.Rules[0].BackendRefs).Should(HaveLen(2))
			Expect(*route.Spec.Rules[0].BackendRefs[0].Weight).Should(Equal(int32(80)))
			Expect(*route.Spec.Rules[0].BackendRefs[1].Weight).Should(Equal(int32(20)))
		})

		It("should create HTTPRoute with canary deployment pattern", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-canary"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("stable", 8080, 90),
					newHTTPBackendRef("canary", 8080, 10),
				}),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify canary weights
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			totalWeight := *route.Spec.Rules[0].BackendRefs[0].Weight + *route.Spec.Rules[0].BackendRefs[1].Weight
			Expect(totalWeight).Should(Equal(int32(100)))
		})
	})

	Context("HTTPRoute Filters", func() {
		It("should create HTTPRoute with request header modifier filter", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-header-mod"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRuleWithFilters(
					[]avapigwv1alpha1.HTTPRouteMatch{
						{
							Path: &avapigwv1alpha1.HTTPPathMatch{
								Type:  pathMatchTypePtr(avapigwv1alpha1.PathMatchPathPrefix),
								Value: stringPtr("/"),
							},
						},
					},
					[]avapigwv1alpha1.HTTPRouteFilter{
						newRequestHeaderModifierFilter(
							[]avapigwv1alpha1.HTTPHeader{{Name: "X-Set-Header", Value: "set-value"}},
							[]avapigwv1alpha1.HTTPHeader{{Name: "X-Add-Header", Value: "add-value"}},
							[]string{"X-Remove-Header"},
						),
					},
					[]avapigwv1alpha1.HTTPBackendRef{
						newHTTPBackendRef("backend-svc", 8080, 1),
					},
				),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify filter configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			Expect(route.Spec.Rules[0].Filters).Should(HaveLen(1))
			Expect(route.Spec.Rules[0].Filters[0].Type).Should(Equal(avapigwv1alpha1.HTTPRouteFilterRequestHeaderModifier))
		})

		It("should create HTTPRoute with redirect filter", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-redirect"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRuleWithFilters(
					[]avapigwv1alpha1.HTTPRouteMatch{
						{
							Path: &avapigwv1alpha1.HTTPPathMatch{
								Type:  pathMatchTypePtr(avapigwv1alpha1.PathMatchExact),
								Value: stringPtr("/old-path"),
							},
						},
					},
					[]avapigwv1alpha1.HTTPRouteFilter{
						newRedirectFilter("https", "new.example.com", 443, 301),
					},
					[]avapigwv1alpha1.HTTPBackendRef{},
				),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify redirect filter
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			Expect(route.Spec.Rules[0].Filters[0].Type).Should(Equal(avapigwv1alpha1.HTTPRouteFilterRequestRedirect))
			Expect(*route.Spec.Rules[0].Filters[0].RequestRedirect.StatusCode).Should(Equal(301))
		})

		It("should create HTTPRoute with URL rewrite filter", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-rewrite"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRuleWithFilters(
					[]avapigwv1alpha1.HTTPRouteMatch{
						{
							Path: &avapigwv1alpha1.HTTPPathMatch{
								Type:  pathMatchTypePtr(avapigwv1alpha1.PathMatchPathPrefix),
								Value: stringPtr("/api/v1"),
							},
						},
					},
					[]avapigwv1alpha1.HTTPRouteFilter{
						newURLRewriteFilter("internal.example.com", "/internal/api"),
					},
					[]avapigwv1alpha1.HTTPBackendRef{
						newHTTPBackendRef("backend-svc", 8080, 1),
					},
				),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify URL rewrite filter
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			Expect(route.Spec.Rules[0].Filters[0].Type).Should(Equal(avapigwv1alpha1.HTTPRouteFilterURLRewrite))
		})
	})

	Context("HTTPRoute Update and Reconciliation", func() {
		It("should update HTTPRoute when adding new rules", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-update"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-svc", 8080, 1),
				}),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Wait for initial reconciliation
			Eventually(func() int {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return 0
				}
				return len(route.Status.Parents)
			}, Timeout, Interval).Should(BeNumerically(">=", 1))

			// Add a new rule
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			route.Spec.Rules = append(route.Spec.Rules, newHTTPRouteRuleWithMatches(
				[]avapigwv1alpha1.HTTPRouteMatch{
					{
						Path: &avapigwv1alpha1.HTTPPathMatch{
							Type:  pathMatchTypePtr(avapigwv1alpha1.PathMatchPathPrefix),
							Value: stringPtr("/new-path"),
						},
					},
				},
				[]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("new-backend", 8080, 1),
				},
			))
			Expect(k8sClient.Update(ctx, route)).Should(Succeed())

			// Verify update
			Eventually(func() int {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return 0
				}
				return len(route.Spec.Rules)
			}, Timeout, Interval).Should(Equal(2))
		})

		It("should update HTTPRoute when changing backend weights", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-weight-update"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-v1", 8080, 100),
				}),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Wait for initial reconciliation
			Eventually(func() int {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return 0
				}
				return len(route.Status.Parents)
			}, Timeout, Interval).Should(BeNumerically(">=", 1))

			// Update weights for canary deployment
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			route.Spec.Rules[0].BackendRefs = []avapigwv1alpha1.HTTPBackendRef{
				newHTTPBackendRef("backend-v1", 8080, 50),
				newHTTPBackendRef("backend-v2", 8080, 50),
			}
			Expect(k8sClient.Update(ctx, route)).Should(Succeed())

			// Verify update
			Eventually(func() int {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return 0
				}
				return len(route.Spec.Rules[0].BackendRefs)
			}, Timeout, Interval).Should(Equal(2))
		})
	})

	Context("HTTPRoute Deletion", func() {
		It("should delete HTTPRoute and update Gateway status", func() {
			route := newHTTPRoute(TestNamespace, uniqueName("route-delete"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-svc", 8080, 1),
				}),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())

			// Wait for route to be accepted
			Eventually(func() int {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route); err != nil {
					return 0
				}
				return len(route.Status.Parents)
			}, Timeout, Interval).Should(BeNumerically(">=", 1))

			// Delete the route
			Expect(k8sClient.Delete(ctx, route)).Should(Succeed())

			// Wait for deletion
			waitForDeletion(route, Timeout)
		})
	})

	Context("HTTPRoute with Hostnames", func() {
		It("should create HTTPRoute with hostnames", func() {
			route := newHTTPRouteWithHostnames(TestNamespace, uniqueName("route-hostnames"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []string{"api.example.com", "www.example.com"}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-svc", 8080, 1),
				}),
			})

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Verify hostnames
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
			Expect(route.Spec.Hostnames).Should(HaveLen(2))
			Expect(string(route.Spec.Hostnames[0])).Should(Equal("api.example.com"))
		})
	})
})
