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

var _ = Describe("Backend Controller Integration Tests", func() {
	Context("Backend Creation with Service Reference", func() {
		It("should create Backend with service reference and discover endpoints", func() {
			// Create a Service first
			svc := newService(TestNamespace, uniqueName("backend-svc"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			// Create Endpoints for the Service
			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1", "10.0.0.2"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			// Create Backend
			backend := newBackend(TestNamespace, uniqueName("backend"), svc.Name, 8080)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Wait for Backend to discover endpoints
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend); err != nil {
					return 0
				}
				return backend.Status.TotalEndpoints
			}, Timeout, Interval).Should(Equal(int32(2)))

			// Verify status
			Expect(backend.Status.HealthyEndpoints).Should(Equal(int32(2)))
			Expect(backend.Status.Phase).Should(Equal(avapigwv1alpha1.PhaseStatusReady))
		})

		It("should handle Backend with non-existent service", func() {
			backend := newBackend(TestNamespace, uniqueName("backend-no-svc"), "non-existent-service", 8080)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Wait for Backend to report error
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend); err != nil {
					return ""
				}
				return backend.Status.Phase
			}, Timeout, Interval).Should(Equal(avapigwv1alpha1.PhaseStatusError))

			// Verify condition
			cond := backend.Status.GetCondition(avapigwv1alpha1.ConditionTypeResolvedRefs)
			Expect(cond).ShouldNot(BeNil())
			Expect(cond.Status).Should(Equal(metav1.ConditionFalse))
		})

		It("should update Backend when service endpoints change", func() {
			// Create Service
			svc := newService(TestNamespace, uniqueName("backend-svc-update"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			// Create initial Endpoints
			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			// Create Backend
			backend := newBackend(TestNamespace, uniqueName("backend-update"), svc.Name, 8080)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Wait for initial endpoint discovery
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend); err != nil {
					return 0
				}
				return backend.Status.TotalEndpoints
			}, Timeout, Interval).Should(Equal(int32(1)))

			// Update Endpoints
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(endpoints), endpoints)).Should(Succeed())
			endpoints.Subsets[0].Addresses = append(endpoints.Subsets[0].Addresses,
				corev1.EndpointAddress{IP: "10.0.0.2"},
				corev1.EndpointAddress{IP: "10.0.0.3"},
			)
			Expect(k8sClient.Update(ctx, endpoints)).Should(Succeed())

			// Wait for Backend to update
			Eventually(func() int32 {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend); err != nil {
					return 0
				}
				return backend.Status.TotalEndpoints
			}, Timeout, Interval).Should(Equal(int32(3)))
		})
	})

	Context("Backend Creation with Direct Endpoints", func() {
		It("should create Backend with direct endpoints", func() {
			backend := newBackendWithEndpoints(TestNamespace, uniqueName("backend-direct"), []avapigwv1alpha1.EndpointConfig{
				newEndpointConfig("10.0.0.1", 8080, 1),
				newEndpointConfig("10.0.0.2", 8080, 1),
			})
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Wait for Backend to be ready
			waitForPhase(backend, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify endpoints
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(backend.Status.TotalEndpoints).Should(Equal(int32(2)))
			Expect(backend.Status.Endpoints).Should(HaveLen(2))
		})

		It("should create Backend with weighted endpoints", func() {
			backend := newBackendWithEndpoints(TestNamespace, uniqueName("backend-weighted"), []avapigwv1alpha1.EndpointConfig{
				newEndpointConfig("10.0.0.1", 8080, 3),
				newEndpointConfig("10.0.0.2", 8080, 1),
			})
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Wait for Backend to be ready
			waitForPhase(backend, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Verify weights are preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(backend.Spec.Endpoints[0].Weight).ShouldNot(BeNil())
			Expect(*backend.Spec.Endpoints[0].Weight).Should(Equal(int32(3)))
		})
	})

	Context("Backend Health Check Configuration", func() {
		It("should create Backend with HTTP health check", func() {
			// Create Service and Endpoints
			svc := newService(TestNamespace, uniqueName("backend-svc-hc"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			// Create Backend with health check
			backend := newBackendWithHealthCheck(TestNamespace, uniqueName("backend-hc"), svc.Name, 8080,
				newHTTPHealthCheck("/health", "10s", "5s"))
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Verify health check configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(backend.Spec.HealthCheck).ShouldNot(BeNil())
			Expect(backend.Spec.HealthCheck.HTTP).ShouldNot(BeNil())
			Expect(backend.Spec.HealthCheck.HTTP.Path).Should(Equal("/health"))
		})

		It("should create Backend with TCP health check", func() {
			svc := newService(TestNamespace, uniqueName("backend-svc-tcp-hc"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			backend := &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("backend-tcp-hc"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: svc.Name,
						Port: 8080,
					},
					HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
						Enabled:  boolPtr(true),
						Interval: durationPtr("10s"),
						Timeout:  durationPtr("5s"),
						TCP:      &avapigwv1alpha1.TCPHealthCheckConfig{},
					},
				},
			}
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Verify TCP health check configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(backend.Spec.HealthCheck.TCP).ShouldNot(BeNil())
		})
	})

	Context("Backend Load Balancing Configuration", func() {
		It("should create Backend with RoundRobin load balancing", func() {
			svc := newService(TestNamespace, uniqueName("backend-svc-rr"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1", "10.0.0.2"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			backend := newBackendWithLoadBalancing(TestNamespace, uniqueName("backend-rr"), svc.Name, 8080,
				avapigwv1alpha1.LoadBalancingRoundRobin)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Verify load balancing configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(backend.Spec.LoadBalancing).ShouldNot(BeNil())
			Expect(*backend.Spec.LoadBalancing.Algorithm).Should(Equal(avapigwv1alpha1.LoadBalancingRoundRobin))
		})

		It("should create Backend with LeastConnections load balancing", func() {
			svc := newService(TestNamespace, uniqueName("backend-svc-lc"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1", "10.0.0.2"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			backend := newBackendWithLoadBalancing(TestNamespace, uniqueName("backend-lc"), svc.Name, 8080,
				avapigwv1alpha1.LoadBalancingLeastConnections)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Verify load balancing configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(*backend.Spec.LoadBalancing.Algorithm).Should(Equal(avapigwv1alpha1.LoadBalancingLeastConnections))
		})

		It("should create Backend with ConsistentHash load balancing", func() {
			svc := newService(TestNamespace, uniqueName("backend-svc-ch"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1", "10.0.0.2"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			backend := &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("backend-ch"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: svc.Name,
						Port: 8080,
					},
					LoadBalancing: &avapigwv1alpha1.LoadBalancingConfig{
						Algorithm: loadBalancingAlgorithmPtr(avapigwv1alpha1.LoadBalancingConsistentHash),
						ConsistentHash: &avapigwv1alpha1.ConsistentHashConfig{
							Type:   avapigwv1alpha1.ConsistentHashHeader,
							Header: stringPtr("X-User-ID"),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Verify consistent hash configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(backend.Spec.LoadBalancing.ConsistentHash).ShouldNot(BeNil())
			Expect(backend.Spec.LoadBalancing.ConsistentHash.Type).Should(Equal(avapigwv1alpha1.ConsistentHashHeader))
		})
	})

	Context("Backend Circuit Breaker Configuration", func() {
		It("should create Backend with circuit breaker enabled", func() {
			svc := newService(TestNamespace, uniqueName("backend-svc-cb"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			backend := newBackendWithCircuitBreaker(TestNamespace, uniqueName("backend-cb"), svc.Name, 8080, 5)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Verify circuit breaker configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(backend.Spec.CircuitBreaker).ShouldNot(BeNil())
			Expect(*backend.Spec.CircuitBreaker.Enabled).Should(BeTrue())
			Expect(*backend.Spec.CircuitBreaker.ConsecutiveErrors).Should(Equal(int32(5)))
		})

		It("should create Backend with full circuit breaker configuration", func() {
			svc := newService(TestNamespace, uniqueName("backend-svc-cb-full"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			backend := &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("backend-cb-full"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: svc.Name,
						Port: 8080,
					},
					CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
						Enabled:            boolPtr(true),
						ConsecutiveErrors:  int32Ptr(5),
						Interval:           durationPtr("30s"),
						BaseEjectionTime:   durationPtr("30s"),
						MaxEjectionPercent: int32Ptr(50),
					},
				},
			}
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Verify full circuit breaker configuration
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend)).Should(Succeed())
			Expect(*backend.Spec.CircuitBreaker.MaxEjectionPercent).Should(Equal(int32(50)))
		})
	})

	Context("Backend Status Updates", func() {
		It("should update Backend status when endpoints become unhealthy", func() {
			svc := newService(TestNamespace, uniqueName("backend-svc-status"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			// Create Endpoints with ready and not-ready addresses
			endpoints := &corev1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      svc.Name,
					Namespace: TestNamespace,
				},
				Subsets: []corev1.EndpointSubset{
					{
						Addresses: []corev1.EndpointAddress{
							{IP: "10.0.0.1"},
						},
						NotReadyAddresses: []corev1.EndpointAddress{
							{IP: "10.0.0.2"},
						},
						Ports: []corev1.EndpointPort{
							{Port: 8080},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			backend := newBackend(TestNamespace, uniqueName("backend-status"), svc.Name, 8080)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Wait for Backend to report degraded status
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend); err != nil {
					return ""
				}
				return backend.Status.Phase
			}, Timeout, Interval).Should(Equal(avapigwv1alpha1.PhaseStatusDegraded))

			// Verify endpoint counts
			Expect(backend.Status.TotalEndpoints).Should(Equal(int32(2)))
			Expect(backend.Status.HealthyEndpoints).Should(Equal(int32(1)))
		})

		It("should report no endpoints when service has no endpoints", func() {
			svc := newService(TestNamespace, uniqueName("backend-svc-empty"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			// Create empty Endpoints
			endpoints := &corev1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      svc.Name,
					Namespace: TestNamespace,
				},
				Subsets: []corev1.EndpointSubset{},
			}
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			backend := newBackend(TestNamespace, uniqueName("backend-empty"), svc.Name, 8080)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())
			defer cleanupResource(backend)

			// Wait for Backend to report error (no endpoints)
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(backend), backend); err != nil {
					return ""
				}
				return backend.Status.Phase
			}, Timeout, Interval).Should(Equal(avapigwv1alpha1.PhaseStatusError))

			// Verify condition
			cond := backend.Status.GetCondition(avapigwv1alpha1.ConditionTypeReady)
			Expect(cond).ShouldNot(BeNil())
			Expect(cond.Status).Should(Equal(metav1.ConditionFalse))
		})
	})

	Context("Backend Deletion", func() {
		It("should delete Backend and clean up resources", func() {
			svc := newService(TestNamespace, uniqueName("backend-svc-delete"), 8080)
			Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
			defer cleanupResource(svc)

			endpoints := newEndpoints(TestNamespace, svc.Name, []string{"10.0.0.1"}, 8080)
			Expect(k8sClient.Create(ctx, endpoints)).Should(Succeed())
			defer cleanupResource(endpoints)

			backend := newBackend(TestNamespace, uniqueName("backend-delete"), svc.Name, 8080)
			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())

			// Wait for Backend to be ready
			waitForPhase(backend, avapigwv1alpha1.PhaseStatusReady, Timeout)

			// Delete Backend
			Expect(k8sClient.Delete(ctx, backend)).Should(Succeed())

			// Wait for deletion
			waitForDeletion(backend, Timeout)
		})
	})
})
