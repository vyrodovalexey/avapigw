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

var _ = Describe("TLSRoute Controller Integration", func() {
	var testNs string

	BeforeEach(func() {
		testNs = createTestNamespace("tlsroute-test")
	})

	AfterEach(func() {
		deleteTestNamespace(testNs)
	})

	Context("when creating a TLSRoute", func() {
		It("should reconcile with a valid parent Gateway", func() {
			By("creating a Gateway with TLS passthrough listener")
			gateway := newGateway(testNs, "tls-gateway", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())

			By("waiting for Gateway to be ready")
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute referencing the Gateway")
			tlsRoute := newTLSRoute(testNs, "test-tlsroute",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway")},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway)
		})

		It("should handle TLSRoute with wildcard hostname", func() {
			By("creating a Gateway with TLS listener and wildcard hostname")
			gateway := newGateway(testNs, "tls-gateway-wildcard", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, "*.example.com"),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute with matching hostname")
			tlsRoute := newTLSRoute(testNs, "tlsroute-wildcard",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway-wildcard")},
				[]string{"api.example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway)
		})

		It("should reject TLSRoute with non-matching hostname", func() {
			By("creating a Gateway with TLS listener and specific hostname")
			gateway := newGateway(testNs, "tls-gateway-specific", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, "api.example.com"),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute with non-matching hostname")
			tlsRoute := newTLSRoute(testNs, "tlsroute-nomatch",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway-specific")},
				[]string{"other.example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is not accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway)
		})

		It("should handle TLSRoute with multiple hostnames", func() {
			By("creating a Gateway with TLS listener")
			gateway := newGateway(testNs, "tls-gateway-multi-host", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute with multiple hostnames")
			tlsRoute := newTLSRoute(testNs, "tlsroute-multi-host",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway-multi-host")},
				[]string{"api.example.com", "www.example.com", "admin.example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway)
		})

		It("should handle TLSRoute with specific listener section", func() {
			By("creating a Gateway with multiple listeners")
			gateway := newGateway(testNs, "tls-gateway-section", []avapigwv1alpha1.Listener{
				newHTTPListener("http", 80),
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute targeting specific listener")
			tlsRoute := newTLSRoute(testNs, "tlsroute-section",
				[]avapigwv1alpha1.ParentRef{newParentRefWithSection("tls-gateway-section", "tls")},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway)
		})

		It("should reject TLSRoute targeting HTTP listener", func() {
			By("creating a Gateway with HTTP listener only")
			gateway := newGateway(testNs, "http-only-gateway", []avapigwv1alpha1.Listener{
				newHTTPListener("http", 80),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute targeting HTTP listener")
			tlsRoute := newTLSRoute(testNs, "tlsroute-http",
				[]avapigwv1alpha1.ParentRef{newParentRefWithSection("http-only-gateway", "http")},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is not accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway)
		})

		It("should handle TLSRoute referencing a Backend resource", func() {
			By("creating a Gateway with TLS listener")
			gateway := newGateway(testNs, "tls-gateway-backend", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a Backend resource")
			backend := newBackend(testNs, "tls-backend", "tls-svc", 443)
			Expect(k8sClient.Create(ctx, backend)).To(Succeed())

			By("creating a TLSRoute referencing the Backend")
			tlsRoute := newTLSRoute(testNs, "tlsroute-backend",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway-backend")},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRefToBackend("tls-backend", 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(backend)
			cleanupResource(gateway)
		})

		It("should handle TLSRoute with weighted backends", func() {
			By("creating a Gateway with TLS listener")
			gateway := newGateway(testNs, "tls-gateway-weighted", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute with weighted backends")
			tlsRoute := newTLSRoute(testNs, "tlsroute-weighted",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway-weighted")},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc-1", 443, 70),
						newTLSBackendRef("backend-svc-2", 443, 30),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway)
		})

		It("should handle TLSRoute with missing parent Gateway", func() {
			By("creating a TLSRoute referencing non-existent Gateway")
			tlsRoute := newTLSRoute(testNs, "tlsroute-missing-gw",
				[]avapigwv1alpha1.ParentRef{newParentRef("non-existent-gateway")},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is not accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
		})
	})

	Context("when updating a TLSRoute", func() {
		It("should reconcile after adding new hostnames", func() {
			By("creating a Gateway with TLS listener")
			gateway := newGateway(testNs, "tls-gateway-update", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute with one hostname")
			tlsRoute := newTLSRoute(testNs, "tlsroute-update",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway-update")},
				[]string{"api.example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("updating the TLSRoute with additional hostname")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsRoute), tlsRoute)).To(Succeed())
			tlsRoute.Spec.Hostnames = append(tlsRoute.Spec.Hostnames, avapigwv1alpha1.Hostname("www.example.com"))
			Expect(k8sClient.Update(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is still accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway)
		})

		It("should reconcile after changing backends", func() {
			By("creating a Gateway with TLS listener")
			gateway := newGateway(testNs, "tls-gateway-backend-update", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute with one backend")
			tlsRoute := newTLSRoute(testNs, "tlsroute-backend-update",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway-backend-update")},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc-1", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("updating the TLSRoute with different backend")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsRoute), tlsRoute)).To(Succeed())
			tlsRoute.Spec.Rules[0].BackendRefs = []avapigwv1alpha1.TLSBackendRef{
				newTLSBackendRef("backend-svc-2", 443, 100),
			}
			Expect(k8sClient.Update(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is still accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway)
		})
	})

	Context("when deleting a TLSRoute", func() {
		It("should clean up properly", func() {
			By("creating a Gateway with TLS listener")
			gateway := newGateway(testNs, "tls-gateway-delete", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute")
			tlsRoute := newTLSRoute(testNs, "tlsroute-delete",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway-delete")},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("deleting the TLSRoute")
			Expect(k8sClient.Delete(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is deleted")
			waitForDeletion(tlsRoute, Timeout)

			By("cleaning up")
			cleanupResource(gateway)
		})
	})

	Context("when Gateway is deleted", func() {
		It("should update TLSRoute status", func() {
			By("creating a Gateway with TLS listener")
			gateway := newGateway(testNs, "tls-gateway-gw-delete", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute referencing the Gateway")
			tlsRoute := newTLSRoute(testNs, "tlsroute-gw-delete",
				[]avapigwv1alpha1.ParentRef{newParentRef("tls-gateway-gw-delete")},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("deleting the Gateway")
			Expect(k8sClient.Delete(ctx, gateway)).To(Succeed())
			waitForDeletion(gateway, Timeout)

			By("verifying the TLSRoute status is updated")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tlsRoute)
		})
	})

	Context("when using multiple parent Gateways", func() {
		It("should handle TLSRoute attached to multiple Gateways", func() {
			By("creating two Gateways with TLS listeners")
			gateway1 := newGateway(testNs, "tls-gateway-1", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway1)).To(Succeed())
			waitForPhase(gateway1, avapigwv1alpha1.PhaseStatusReady, Timeout)

			gateway2 := newGateway(testNs, "tls-gateway-2", []avapigwv1alpha1.Listener{
				newTLSListener("tls", 8443, ""),
			})
			Expect(k8sClient.Create(ctx, gateway2)).To(Succeed())
			waitForPhase(gateway2, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TLSRoute referencing both Gateways")
			tlsRoute := newTLSRoute(testNs, "tlsroute-multi-gw",
				[]avapigwv1alpha1.ParentRef{
					newParentRef("tls-gateway-1"),
					newParentRef("tls-gateway-2"),
				},
				[]string{"example.com"},
				[]avapigwv1alpha1.TLSRouteRule{
					newTLSRouteRule([]avapigwv1alpha1.TLSBackendRef{
						newTLSBackendRef("backend-svc", 443, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tlsRoute)).To(Succeed())

			By("verifying the TLSRoute is accepted")
			waitForCondition(tlsRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("verifying the TLSRoute has status for both parents")
			Eventually(func() int {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsRoute), tlsRoute); err != nil {
					return 0
				}
				return len(tlsRoute.Status.Parents)
			}, Timeout, Interval).Should(Equal(2))

			By("cleaning up")
			cleanupResource(tlsRoute)
			cleanupResource(gateway1)
			cleanupResource(gateway2)
		})
	})
})
