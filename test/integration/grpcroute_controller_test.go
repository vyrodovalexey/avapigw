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

var _ = Describe("GRPCRoute Controller Integration", func() {
	var testNs string

	BeforeEach(func() {
		testNs = createTestNamespace("grpcroute-test")
	})

	AfterEach(func() {
		deleteTestNamespace(testNs)
	})

	Context("when creating a GRPCRoute", func() {
		It("should reconcile with a valid parent Gateway", func() {
			By("creating a Gateway with gRPC listener")
			gateway := newGateway(testNs, "grpc-gateway", []avapigwv1alpha1.Listener{
				newGRPCListener("grpc", 50051),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())

			By("waiting for Gateway to be ready")
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute referencing the Gateway")
			grpcRoute := newGRPCRoute(testNs, "test-grpcroute",
				[]avapigwv1alpha1.ParentRef{newParentRef("grpc-gateway")},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRef("backend-svc", 50051, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(gateway)
		})

		It("should handle GRPCRoute with hostnames", func() {
			By("creating a Gateway with gRPC listener and hostname")
			hostname := avapigwv1alpha1.Hostname("*.example.com")
			gateway := &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-gateway-hostname",
					Namespace: testNs,
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "grpc",
							Port:     50051,
							Protocol: avapigwv1alpha1.ProtocolGRPC,
							Hostname: &hostname,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute with matching hostname")
			grpcRoute := newGRPCRouteWithHostnames(testNs, "grpcroute-hostname",
				[]avapigwv1alpha1.ParentRef{newParentRef("grpc-gateway-hostname")},
				[]string{"api.example.com"},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRef("backend-svc", 50051, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(gateway)
		})

		It("should reject GRPCRoute with non-matching hostname", func() {
			By("creating a Gateway with gRPC listener and specific hostname")
			hostname := avapigwv1alpha1.Hostname("api.example.com")
			gateway := &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-gateway-specific",
					Namespace: testNs,
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "grpc",
							Port:     50051,
							Protocol: avapigwv1alpha1.ProtocolGRPC,
							Hostname: &hostname,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute with non-matching hostname")
			grpcRoute := newGRPCRouteWithHostnames(testNs, "grpcroute-nomatch",
				[]avapigwv1alpha1.ParentRef{newParentRef("grpc-gateway-specific")},
				[]string{"other.example.com"},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRef("backend-svc", 50051, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is not accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(gateway)
		})

		It("should handle GRPCRoute with method matching", func() {
			By("creating a Gateway with gRPC listener")
			gateway := newGateway(testNs, "grpc-gateway-method", []avapigwv1alpha1.Listener{
				newGRPCListener("grpc", 50051),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute with method matching")
			grpcRoute := &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpcroute-method",
					Namespace: testNs,
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{newParentRef("grpc-gateway-method")},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Method: &avapigwv1alpha1.GRPCMethodMatch{
										Service: stringPtr("myservice.v1.MyService"),
										Method:  stringPtr("GetResource"),
									},
								},
							},
							BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
								newGRPCBackendRef("backend-svc", 50051, 100),
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(gateway)
		})

		It("should handle GRPCRoute with header matching", func() {
			By("creating a Gateway with gRPC listener")
			gateway := newGateway(testNs, "grpc-gateway-header", []avapigwv1alpha1.Listener{
				newGRPCListener("grpc", 50051),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute with header matching")
			grpcRoute := &avapigwv1alpha1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpcroute-header",
					Namespace: testNs,
				},
				Spec: avapigwv1alpha1.GRPCRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{newParentRef("grpc-gateway-header")},
					Rules: []avapigwv1alpha1.GRPCRouteRule{
						{
							Matches: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Headers: []avapigwv1alpha1.GRPCHeaderMatch{
										newGRPCHeaderMatch("x-tenant-id", "tenant-123"),
									},
								},
							},
							BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
								newGRPCBackendRef("backend-svc", 50051, 100),
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(gateway)
		})

		It("should handle GRPCRoute referencing a Backend resource", func() {
			By("creating a Gateway with gRPC listener")
			gateway := newGateway(testNs, "grpc-gateway-backend", []avapigwv1alpha1.Listener{
				newGRPCListener("grpc", 50051),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a Backend resource")
			backend := newBackend(testNs, "grpc-backend", "grpc-svc", 50051)
			Expect(k8sClient.Create(ctx, backend)).To(Succeed())

			By("creating a GRPCRoute referencing the Backend")
			grpcRoute := newGRPCRoute(testNs, "grpcroute-backend",
				[]avapigwv1alpha1.ParentRef{newParentRef("grpc-gateway-backend")},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRefToBackend("grpc-backend", 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(backend)
			cleanupResource(gateway)
		})

		It("should handle GRPCRoute with specific listener section", func() {
			By("creating a Gateway with multiple listeners")
			gateway := newGateway(testNs, "grpc-gateway-multi", []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
				newGRPCListener("grpc", 50051),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute targeting specific listener")
			grpcRoute := newGRPCRoute(testNs, "grpcroute-section",
				[]avapigwv1alpha1.ParentRef{newParentRefWithSection("grpc-gateway-multi", "grpc")},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRef("backend-svc", 50051, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(gateway)
		})

		It("should reject GRPCRoute targeting HTTP listener", func() {
			By("creating a Gateway with HTTP listener only")
			gateway := newGateway(testNs, "http-only-gateway", []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute targeting HTTP listener")
			grpcRoute := newGRPCRoute(testNs, "grpcroute-http",
				[]avapigwv1alpha1.ParentRef{newParentRefWithSection("http-only-gateway", "http")},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRef("backend-svc", 50051, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is not accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(gateway)
		})

		It("should handle GRPCRoute with missing parent Gateway", func() {
			By("creating a GRPCRoute referencing non-existent Gateway")
			grpcRoute := newGRPCRoute(testNs, "grpcroute-missing-gw",
				[]avapigwv1alpha1.ParentRef{newParentRef("non-existent-gateway")},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRef("backend-svc", 50051, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is not accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
		})
	})

	Context("when updating a GRPCRoute", func() {
		It("should reconcile after adding new rules", func() {
			By("creating a Gateway with gRPC listener")
			gateway := newGateway(testNs, "grpc-gateway-update", []avapigwv1alpha1.Listener{
				newGRPCListener("grpc", 50051),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute with one rule")
			grpcRoute := newGRPCRoute(testNs, "grpcroute-update",
				[]avapigwv1alpha1.ParentRef{newParentRef("grpc-gateway-update")},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRef("backend-svc-1", 50051, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("updating the GRPCRoute with additional rule")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(grpcRoute), grpcRoute)).To(Succeed())
			grpcRoute.Spec.Rules = append(grpcRoute.Spec.Rules, avapigwv1alpha1.GRPCRouteRule{
				Matches: []avapigwv1alpha1.GRPCRouteMatch{
					{
						Method: &avapigwv1alpha1.GRPCMethodMatch{
							Service: stringPtr("myservice.v2.MyService"),
						},
					},
				},
				BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
					newGRPCBackendRef("backend-svc-2", 50052, 100),
				},
			})
			Expect(k8sClient.Update(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is still accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(gateway)
		})
	})

	Context("when deleting a GRPCRoute", func() {
		It("should clean up properly", func() {
			By("creating a Gateway with gRPC listener")
			gateway := newGateway(testNs, "grpc-gateway-delete", []avapigwv1alpha1.Listener{
				newGRPCListener("grpc", 50051),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute")
			grpcRoute := newGRPCRoute(testNs, "grpcroute-delete",
				[]avapigwv1alpha1.ParentRef{newParentRef("grpc-gateway-delete")},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRef("backend-svc", 50051, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("deleting the GRPCRoute")
			Expect(k8sClient.Delete(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is deleted")
			waitForDeletion(grpcRoute, Timeout)

			By("cleaning up")
			cleanupResource(gateway)
		})
	})

	Context("when using secure gRPC (gRPCS)", func() {
		It("should handle GRPCRoute with gRPCS listener", func() {
			By("creating a TLS secret")
			tlsSecret := newTLSSecret(testNs, "grpcs-tls-secret")
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a Gateway with gRPCS listener")
			gateway := newGateway(testNs, "grpcs-gateway", []avapigwv1alpha1.Listener{
				newGRPCSListener("grpcs", 50051, "grpcs-tls-secret"),
			})
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("creating a GRPCRoute referencing the gRPCS Gateway")
			grpcRoute := newGRPCRoute(testNs, "grpcroute-secure",
				[]avapigwv1alpha1.ParentRef{newParentRef("grpcs-gateway")},
				[]avapigwv1alpha1.GRPCRouteRule{
					newGRPCRouteRule([]avapigwv1alpha1.GRPCBackendRef{
						newGRPCBackendRef("backend-svc", 50051, 100),
					}),
				},
			)
			Expect(k8sClient.Create(ctx, grpcRoute)).To(Succeed())

			By("verifying the GRPCRoute is accepted")
			waitForCondition(grpcRoute, avapigwv1alpha1.ConditionTypeAccepted, metav1.ConditionTrue, Timeout)

			By("cleaning up")
			cleanupResource(grpcRoute)
			cleanupResource(gateway)
			cleanupResource(tlsSecret)
		})
	})
})
