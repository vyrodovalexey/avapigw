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

var _ = Describe("TCPRoute Controller Integration", func() {
	var testNs string

	BeforeEach(func() {
		testNs = createTestNamespace("tcproute-test")
	})

	AfterEach(func() {
		deleteTestNamespace(testNs)
	})

	Context("when creating a TCPRoute", func() {
		It("should reconcile with a valid parent Gateway", func() {
			By("creating a Gateway with TCP listener")
			gateway := newGateway(testNs, "tcp-gateway", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())

			By("waiting for Gateway to be ready")
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute referencing the Gateway")
			tcpRoute := newTCPRoute(testNs, "test-tcproute",
				[]avapigwv1alpha1.ParentRef{newParentRef("tcp-gateway")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc", 9000, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(gateway)
		})

		It("should handle TCPRoute with port matching", func() {
			By("creating a Gateway with multiple TCP listeners")
			gateway := newGateway(testNs, "tcp-gateway-multi", []avapigwv1alpha1.Listener{
				newTCPListener("tcp-9000", 9000),
				newTCPListener("tcp-9001", 9001),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute targeting specific port")
			tcpRoute := newTCPRoute(testNs, "tcproute-port",
				[]avapigwv1alpha1.ParentRef{newParentRefWithPort("tcp-gateway-multi", 9001)},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc", 9001, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(gateway)
		})

		It("should handle TCPRoute with specific listener section", func() {
			By("creating a Gateway with multiple listeners")
			gateway := newGateway(testNs, "tcp-gateway-section", []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute targeting specific listener")
			tcpRoute := newTCPRoute(testNs, "tcproute-section",
				[]avapigwv1alpha1.ParentRef{newParentRefWithSection("tcp-gateway-section", "tcp")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc", 9000, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(gateway)
		})

		It("should reject TCPRoute targeting HTTP listener", func() {
			By("creating a Gateway with HTTP listener only")
			gateway := newGateway(testNs, "http-only-gateway", []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute targeting HTTP listener")
			tcpRoute := newTCPRoute(testNs, "tcproute-http",
				[]avapigwv1alpha1.ParentRef{newParentRefWithSection("http-only-gateway", "http")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc", 9000, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is not accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(gateway)
		})

		It("should handle TCPRoute with timeouts", func() {
			By("creating a Gateway with TCP listener")
			gateway := newGateway(testNs, "tcp-gateway-timeout", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute with timeouts")
			tcpRoute := newTCPRoute(testNs, "tcproute-timeout",
				[]avapigwv1alpha1.ParentRef{newParentRef("tcp-gateway-timeout")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRuleWithTimeouts(
						[]avapigwv1alpha1.TCPBackendRef{
							newTCPBackendRef("backend-svc", 9000, 100),
						},
						"1h",  // idle timeout
						"30s", // connect timeout
					),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(gateway)
		})

		It("should handle TCPRoute referencing a Backend resource", func() {
			By("creating a Gateway with TCP listener")
			gateway := newGateway(testNs, "tcp-gateway-backend", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a Backend resource")
			backend := newBackend(testNs, "tcp-backend", "tcp-svc", 9000)
			Expect(k8sClient.Create(ctx, backend)).To(Succeed())

			By("creating a TCPRoute referencing the Backend")
			tcpRoute := newTCPRoute(testNs, "tcproute-backend",
				[]avapigwv1alpha1.ParentRef{newParentRef("tcp-gateway-backend")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRefToBackend("tcp-backend", 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(backend)
			cleanupResource(gateway)
		})

		It("should handle TCPRoute with weighted backends", func() {
			By("creating a Gateway with TCP listener")
			gateway := newGateway(testNs, "tcp-gateway-weighted", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute with weighted backends")
			tcpRoute := newTCPRoute(testNs, "tcproute-weighted",
				[]avapigwv1alpha1.ParentRef{newParentRef("tcp-gateway-weighted")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc-1", 9000, 80),
						newTCPBackendRef("backend-svc-2", 9000, 20),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(gateway)
		})

		It("should handle TCPRoute with missing parent Gateway", func() {
			By("creating a TCPRoute referencing non-existent Gateway")
			tcpRoute := newTCPRoute(testNs, "tcproute-missing-gw",
				[]avapigwv1alpha1.ParentRef{newParentRef("non-existent-gateway")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc", 9000, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is not accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
		})

		It("should reject TCPRoute with non-matching port", func() {
			By("creating a Gateway with TCP listener on specific port")
			gateway := newGateway(testNs, "tcp-gateway-port", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute targeting different port")
			tcpRoute := newTCPRoute(testNs, "tcproute-wrong-port",
				[]avapigwv1alpha1.ParentRef{newParentRefWithPort("tcp-gateway-port", 9999)},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc", 9000, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is not accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(gateway)
		})
	})

	Context("when updating a TCPRoute", func() {
		It("should reconcile after adding new backends", func() {
			By("creating a Gateway with TCP listener")
			gateway := newGateway(testNs, "tcp-gateway-update", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute with one backend")
			tcpRoute := newTCPRoute(testNs, "tcproute-update",
				[]avapigwv1alpha1.ParentRef{newParentRef("tcp-gateway-update")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc-1", 9000, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("updating the TCPRoute with additional backend")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tcpRoute), tcpRoute)).To(Succeed())
			tcpRoute.Spec.Rules[0].BackendRefs = append(tcpRoute.Spec.Rules[0].BackendRefs,
				newTCPBackendRef("backend-svc-2", 9000, 50),
			)
			// Adjust weights
			tcpRoute.Spec.Rules[0].BackendRefs[0].Weight = int32Ptr(50)
			Expect(k8sClient.Update(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is still accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(gateway)
		})

		It("should reconcile after changing parent reference", func() {
			By("creating two Gateways with TCP listeners")
			gateway1 := newGateway(testNs, "tcp-gateway-1", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway1)).To(Succeed())
			waitForPhase(gateway1, avapigwv1alpha1.PhaseStatusReady, Timeout)

			gateway2 := newGateway(testNs, "tcp-gateway-2", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9001),
			})
			Expect(k8sClient.Create(ctx, gateway2)).To(Succeed())
			waitForPhase(gateway2, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute referencing first Gateway")
			tcpRoute := newTCPRoute(testNs, "tcproute-switch",
				[]avapigwv1alpha1.ParentRef{newParentRef("tcp-gateway-1")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc", 9000, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("updating the TCPRoute to reference second Gateway")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tcpRoute), tcpRoute)).To(Succeed())
			tcpRoute.Spec.ParentRefs = []avapigwv1alpha1.ParentRef{newParentRef("tcp-gateway-2")}
			Expect(k8sClient.Update(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is still accepted")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
			cleanupResource(gateway1)
			cleanupResource(gateway2)
		})
	})

	Context("when deleting a TCPRoute", func() {
		It("should clean up properly", func() {
			By("creating a Gateway with TCP listener")
			gateway := newGateway(testNs, "tcp-gateway-delete", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute")
			tcpRoute := newTCPRoute(testNs, "tcproute-delete",
				[]avapigwv1alpha1.ParentRef{newParentRef("tcp-gateway-delete")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc", 9000, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("deleting the TCPRoute")
			Expect(k8sClient.Delete(ctx, tcpRoute)).To(Succeed())

			By("verifying the TCPRoute is deleted")
			waitForDeletion(tcpRoute, Timeout)

			By("cleaning up")
			cleanupResource(gateway)
		})
	})

	Context("when Gateway is deleted", func() {
		It("should update TCPRoute status", func() {
			By("creating a Gateway with TCP listener")
			gateway := newGateway(testNs, "tcp-gateway-gw-delete", []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a TCPRoute referencing the Gateway")
			tcpRoute := newTCPRoute(testNs, "tcproute-gw-delete",
				[]avapigwv1alpha1.ParentRef{newParentRef("tcp-gateway-gw-delete")},
				[]avapigwv1alpha1.TCPRouteRule{
					newTCPRouteRule([]avapigwv1alpha1.TCPBackendRef{
						newTCPBackendRef("backend-svc", 9000, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, tcpRoute)).To(Succeed())
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("deleting the Gateway")
			Expect(k8sClient.Delete(ctx, gateway)).To(Succeed())
			waitForDeletion(gateway, Timeout)

			By("verifying the TCPRoute status is updated")
			waitForCondition(tcpRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tcpRoute)
		})
	})
})
