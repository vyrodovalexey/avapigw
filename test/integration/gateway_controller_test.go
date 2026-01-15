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

var _ = Describe("Gateway Controller Integration Tests", func() {
	Context("Gateway Creation", func() {
		It("should create Gateway with single HTTP listener and become Ready", func() {
			gateway := newGateway(TestNamespace, uniqueName("gw-single"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to become Ready
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify status
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			Expect(gateway.Status.ListenersCount).Should(Equal(int32(1)))
			Expect(gateway.Status.Listeners).Should(HaveLen(1))
			Expect(gateway.Status.Listeners[0].Name).Should(Equal("http"))

			// Verify conditions
			cond := gateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeAccepted)
			Expect(cond).ShouldNot(BeNil())
			Expect(cond.Status).Should(Equal(metav1.ConditionTrue))

			cond = gateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeProgrammed)
			Expect(cond).ShouldNot(BeNil())
			Expect(cond.Status).Should(Equal(metav1.ConditionTrue))
		})

		It("should create Gateway with multiple listeners", func() {
			gateway := newGateway(TestNamespace, uniqueName("gw-multi"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
				newHTTPListener("http-alt", 8081),
				newGRPCListener("grpc", 9090),
			})

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to become Ready
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify status
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			Expect(gateway.Status.ListenersCount).Should(Equal(int32(3)))
			Expect(gateway.Status.Listeners).Should(HaveLen(3))

			// Verify each listener has correct supported kinds
			listenerMap := make(map[string]avapigwv1alpha1.ListenerStatus)
			for _, l := range gateway.Status.Listeners {
				listenerMap[l.Name] = l
			}

			Expect(listenerMap["http"].SupportedKinds).Should(ContainElement(
				HaveField("Kind", "HTTPRoute"),
			))
			Expect(listenerMap["grpc"].SupportedKinds).Should(ContainElement(
				HaveField("Kind", "GRPCRoute"),
			))
		})

		It("should create Gateway with HTTPS listener and TLS secret reference", func() {
			// Create TLS secret first
			tlsSecret := newTLSSecret(TestNamespace, uniqueName("tls-secret"))
			Expect(k8sClient.Create(ctx, tlsSecret)).Should(Succeed())
			defer cleanupResource(tlsSecret)

			gateway := newGateway(TestNamespace, uniqueName("gw-https"), []avapigwv1alpha1.Listener{
				newHTTPSListener("https", 8443, tlsSecret.Name),
			})

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to become Ready
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify status
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			Expect(gateway.Status.Phase).Should(Equal(avapigwv1alpha1.PhaseStatusReady))
		})

		It("should create Gateway with TCP listener", func() {
			gateway := newGateway(TestNamespace, uniqueName("gw-tcp"), []avapigwv1alpha1.Listener{
				newTCPListener("tcp", 9000),
			})

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to become Ready
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify listener supports TCPRoute
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			Expect(gateway.Status.Listeners[0].SupportedKinds).Should(ContainElement(
				HaveField("Kind", "TCPRoute"),
			))
		})
	})

	Context("Gateway Update", func() {
		It("should update Gateway when adding a new listener", func() {
			gateway := newGateway(TestNamespace, uniqueName("gw-update-add"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for initial Ready state
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Add a new listener
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			gateway.Spec.Listeners = append(gateway.Spec.Listeners, newHTTPListener("http-new", 8081))
			Expect(k8sClient.Update(ctx, gateway)).Should(Succeed())

			// Wait for reconciliation
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway); err != nil {
					return 0
				}
				return gateway.Status.ListenersCount
			}, Timeout, Interval).Should(Equal(int32(2)))
		})

		It("should update Gateway when removing a listener", func() {
			gateway := newGateway(TestNamespace, uniqueName("gw-update-remove"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
				newHTTPListener("http-alt", 8081),
			})

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for initial Ready state
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Remove a listener
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			gateway.Spec.Listeners = gateway.Spec.Listeners[:1]
			Expect(k8sClient.Update(ctx, gateway)).Should(Succeed())

			// Wait for reconciliation
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway); err != nil {
					return 0
				}
				return gateway.Status.ListenersCount
			}, Timeout, Interval).Should(Equal(int32(1)))
		})

		It("should update Gateway when modifying listener port", func() {
			gateway := newGateway(TestNamespace, uniqueName("gw-update-port"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for initial Ready state
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Modify listener port
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			gateway.Spec.Listeners[0].Port = 8090
			Expect(k8sClient.Update(ctx, gateway)).Should(Succeed())

			// Wait for reconciliation and verify
			Eventually(func() avapigwv1alpha1.PortNumber {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway); err != nil {
					return 0
				}
				return gateway.Spec.Listeners[0].Port
			}, Timeout, Interval).Should(Equal(avapigwv1alpha1.PortNumber(8090)))
		})
	})

	Context("Gateway Deletion", func() {
		It("should delete Gateway and clean up resources", func() {
			gateway := newGateway(TestNamespace, uniqueName("gw-delete"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			// Wait for Ready state
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Delete the Gateway
			Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())

			// Wait for deletion
			waitForDeletion(gateway, Timeout)
		})

		It("should handle deletion with attached routes gracefully", func() {
			// Create Gateway
			gateway := newGateway(TestNamespace, uniqueName("gw-delete-routes"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to be Ready
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create HTTPRoute attached to Gateway
			route := newHTTPRoute(TestNamespace, uniqueName("route-attached"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-svc", 8080, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Delete the Gateway
			Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())

			// Wait for Gateway deletion
			waitForDeletion(gateway, Timeout)

			// Route should still exist but with updated status
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(route), route)).Should(Succeed())
		})
	})

	Context("Gateway Status Updates", func() {
		It("should update attached routes count when routes are added", func() {
			// Create Gateway
			gateway := newGateway(TestNamespace, uniqueName("gw-routes-count"), []avapigwv1alpha1.Listener{
				newHTTPListener("http", 8080),
			})
			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to be Ready
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Create HTTPRoute
			route := newHTTPRoute(TestNamespace, uniqueName("route-count"), []avapigwv1alpha1.ParentRef{
				newParentRef(gateway.Name),
			}, []avapigwv1alpha1.HTTPRouteRule{
				newHTTPRouteRule([]avapigwv1alpha1.HTTPBackendRef{
					newHTTPBackendRef("backend-svc", 8080, 1),
				}),
			})
			Expect(k8sClient.Create(ctx, route)).Should(Succeed())
			defer cleanupResource(route)

			// Wait for Gateway to update attached routes count
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway); err != nil {
					return -1
				}
				if len(gateway.Status.Listeners) == 0 {
					return -1
				}
				return gateway.Status.Listeners[0].AttachedRoutes
			}, Timeout, Interval).Should(BeNumerically(">=", int32(1)))
		})

		It("should update addresses in status when specified in spec", func() {
			gateway := &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("gw-addresses"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						newHTTPListener("http", 8080),
					},
					Addresses: []avapigwv1alpha1.GatewayAddress{
						{
							Value: "192.168.1.100",
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to be Ready
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify addresses in status
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			Expect(gateway.Status.Addresses).Should(HaveLen(1))
			Expect(gateway.Status.Addresses[0].Value).Should(Equal("192.168.1.100"))
		})
	})

	Context("Gateway Error Handling", func() {
		It("should handle missing TLS secret reference gracefully", func() {
			gateway := newGateway(TestNamespace, uniqueName("gw-missing-tls"), []avapigwv1alpha1.Listener{
				newHTTPSListener("https", 8443, "non-existent-secret"),
			})

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to report error condition
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway); err != nil {
					return false
				}
				cond := gateway.Status.GetCondition(avapigwv1alpha1.ConditionTypeAccepted)
				return cond != nil && cond.Status == metav1.ConditionFalse
			}, Timeout, Interval).Should(BeTrue())

			// Verify error phase
			Expect(gateway.Status.Phase).Should(Equal(avapigwv1alpha1.PhaseStatusError))
		})
	})

	Context("Gateway with Hostname", func() {
		It("should create Gateway with listener hostname", func() {
			hostname := avapigwv1alpha1.Hostname("example.com")
			gateway := &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("gw-hostname"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
							Hostname: &hostname,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())
			defer cleanupResource(gateway)

			// Wait for Gateway to be Ready
			waitForPhase(gateway, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify hostname is preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gateway), gateway)).Should(Succeed())
			Expect(gateway.Spec.Listeners[0].Hostname).ShouldNot(BeNil())
			Expect(string(*gateway.Spec.Listeners[0].Hostname)).Should(Equal("example.com"))
		})
	})
})
