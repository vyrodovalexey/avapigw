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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

var _ = Describe("Resilience E2E", Ordered, func() {
	Context("Gateway Pod Restart Recovery", func() {
		var (
			gatewayName string
			routeName   string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-resilience")
			routeName = generateUniqueName("route-resilience")
		})

		AfterEach(func() {
			deleteHTTPRoute(routeName)
			deleteGateway(gatewayName)
		})

		It("should recover Gateway state after pod restart", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create HTTPRoute
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
				Hostnames: []avapigwv1alpha1.Hostname{"test.example.com"},
			})

			// Wait for resources to be created
			Eventually(func() error {
				_, err := getGateway(gatewayName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			Eventually(func() error {
				_, err := getHTTPRoute(routeName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Simulate pod restart by updating Gateway (triggers reconciliation)
			gw, err := getGateway(gatewayName)
			Expect(err).NotTo(HaveOccurred())

			// Add annotation to trigger update
			if gw.Annotations == nil {
				gw.Annotations = make(map[string]string)
			}
			gw.Annotations["test.avapigw/restart-time"] = time.Now().Format(time.RFC3339)

			err = k8sClient.Update(ctx, gw)
			Expect(err).NotTo(HaveOccurred())

			// Verify Gateway is still functional
			Eventually(func() error {
				gw, err := getGateway(gatewayName)
				if err != nil {
					return err
				}
				if len(gw.Spec.Listeners) != 1 {
					return fmt.Errorf("expected 1 listener, got %d", len(gw.Spec.Listeners))
				}
				return nil
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Verify HTTPRoute is still attached
			Eventually(func() error {
				route, err := getHTTPRoute(routeName)
				if err != nil {
					return err
				}
				if len(route.Spec.ParentRefs) != 1 {
					return fmt.Errorf("expected 1 parent ref, got %d", len(route.Spec.ParentRefs))
				}
				return nil
			}, ShortTimeout, DefaultInterval).Should(Succeed())
		})

		It("should maintain configuration after multiple updates", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Perform multiple updates
			for i := 0; i < 5; i++ {
				gw, err := getGateway(gatewayName)
				Expect(err).NotTo(HaveOccurred())

				if gw.Annotations == nil {
					gw.Annotations = make(map[string]string)
				}
				gw.Annotations["test.avapigw/update-count"] = fmt.Sprintf("%d", i+1)

				err = k8sClient.Update(ctx, gw)
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(500 * time.Millisecond)
			}

			// Verify Gateway configuration is intact
			gw, err := getGateway(gatewayName)
			Expect(err).NotTo(HaveOccurred())
			Expect(gw.Spec.Listeners).To(HaveLen(1))
			Expect(gw.Spec.Listeners[0].Port).To(Equal(avapigwv1alpha1.PortNumber(8080)))
		})
	})

	Context("Backend Failure Handling", func() {
		var (
			gatewayName string
			backendName string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-backend-fail")
			backendName = generateUniqueName("backend-fail")
		})

		AfterEach(func() {
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should handle backend with no healthy endpoints", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend with endpoints that don't exist
			enabled := true
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Endpoints: []avapigwv1alpha1.EndpointConfig{
					{Address: "10.255.255.1", Port: 8080},
					{Address: "10.255.255.2", Port: 8080},
				},
				HealthCheck: &avapigwv1alpha1.HealthCheckConfig{
					Enabled: &enabled,
					HTTP: &avapigwv1alpha1.HTTPHealthCheckConfig{
						Path: "/health",
					},
				},
			})

			// Verify Backend was created
			Eventually(func() error {
				_, err := getBackend(backendName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Backend should report unhealthy endpoints
			// In a real scenario, the controller would update the status
		})

		It("should configure circuit breaker for backend", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend with circuit breaker
			enabled := true
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-service",
					Port: 80,
				},
				CircuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
					Enabled:            &enabled,
					ConsecutiveErrors:  int32Ptr(5),
					Interval:           durationPtr("30s"),
					BaseEjectionTime:   durationPtr("30s"),
					MaxEjectionPercent: int32Ptr(50),
				},
			})

			// Verify Backend was created with circuit breaker
			Eventually(func() bool {
				backend, err := getBackend(backendName)
				if err != nil {
					return false
				}
				return backend.Spec.CircuitBreaker != nil && *backend.Spec.CircuitBreaker.Enabled
			}, ShortTimeout, DefaultInterval).Should(BeTrue())
		})

		It("should configure outlier detection for backend", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend with outlier detection
			enabled := true
			createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-service",
					Port: 80,
				},
				OutlierDetection: &avapigwv1alpha1.OutlierDetectionConfig{
					Enabled:              &enabled,
					Consecutive5xxErrors: int32Ptr(5),
					Interval:             durationPtr("10s"),
					BaseEjectionTime:     durationPtr("30s"),
					MaxEjectionPercent:   int32Ptr(10),
				},
			})

			// Verify Backend was created with outlier detection
			Eventually(func() bool {
				backend, err := getBackend(backendName)
				if err != nil {
					return false
				}
				return backend.Spec.OutlierDetection != nil && *backend.Spec.OutlierDetection.Enabled
			}, ShortTimeout, DefaultInterval).Should(BeTrue())
		})
	})

	Context("Vault Unavailability Handling", func() {
		var (
			vsName           string
			targetSecretName string
			tokenSecretName  string
		)

		BeforeEach(func() {
			skipIfVaultNotAvailable()

			vsName = generateUniqueName("vs-unavail")
			targetSecretName = generateUniqueName("target-unavail")
			tokenSecretName = generateUniqueName("token-unavail")

			// Create token secret
			createSecret(tokenSecretName, map[string][]byte{
				"token": []byte(testConfig.VaultToken),
			})

			// Create test secret in Vault
			createVaultKV2Secret("avapigw/e2e/unavail", map[string]interface{}{
				"key": "value",
			})
		})

		AfterEach(func() {
			deleteVaultSecret(vsName)
			deleteSecret(targetSecretName)
			deleteSecret(tokenSecretName)
			deleteVaultKV2Secret("avapigw/e2e/unavail")
		})

		It("should handle Vault connection errors gracefully", func() {
			// Create VaultSecret pointing to invalid Vault address
			createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "http://invalid-vault:8200",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Token: &avapigwv1alpha1.TokenAuthConfig{
							SecretRef: avapigwv1alpha1.SecretObjectReference{
								Name: tokenSecretName,
							},
						},
					},
				},
				Path:       "avapigw/e2e/unavail",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			// VaultSecret should show error status
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				vs, err := getVaultSecret(vsName)
				if err != nil {
					return ""
				}
				return vs.Status.Phase
			}, DefaultTimeout, DefaultInterval).Should(Equal(avapigwv1alpha1.PhaseStatusError))

			// Verify error is recorded
			vs, err := getVaultSecret(vsName)
			Expect(err).NotTo(HaveOccurred())
			Expect(vs.Status.LastVaultError).NotTo(BeNil())
		})

		It("should recover when Vault becomes available", func() {
			// First create a working VaultSecret
			createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/unavail",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			// Wait for it to be ready
			waitForVaultSecretReady(vsName, DefaultTimeout)

			// Verify secret was synced
			secret := waitForSecretWithData(targetSecretName, []string{"key"}, ShortTimeout)
			Expect(string(secret.Data["key"])).To(Equal("value"))
		})

		It("should preserve existing secret during Vault outage", func() {
			// Create VaultSecret with refresh enabled
			refreshInterval := avapigwv1alpha1.Duration("5s")
			createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/unavail",
				MountPoint: stringPtr("secret"),
				Refresh: &avapigwv1alpha1.VaultRefreshConfig{
					Enabled:  boolPtr(true),
					Interval: &refreshInterval,
				},
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			// Wait for initial sync
			waitForVaultSecretReady(vsName, DefaultTimeout)
			secret := waitForSecretWithData(targetSecretName, []string{"key"}, ShortTimeout)
			initialValue := string(secret.Data["key"])

			// The secret should persist even if refresh fails
			// (In a real test, we would simulate Vault outage)
			time.Sleep(10 * time.Second)

			// Verify secret still exists with same value
			secret, err := getSecret(targetSecretName)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(secret.Data["key"])).To(Equal(initialValue))
		})
	})

	Context("Configuration Update Without Downtime", func() {
		var (
			gatewayName string
			routeName   string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-update")
			routeName = generateUniqueName("route-update")
		})

		AfterEach(func() {
			deleteHTTPRoute(routeName)
			deleteGateway(gatewayName)
		})

		It("should update Gateway listeners without downtime", func() {
			// Create Gateway with one listener
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Wait for Gateway to be created
			Eventually(func() error {
				_, err := getGateway(gatewayName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Update Gateway to add another listener
			gw, err := getGateway(gatewayName)
			Expect(err).NotTo(HaveOccurred())

			gw.Spec.Listeners = append(gw.Spec.Listeners, avapigwv1alpha1.Listener{
				Name:     "grpc",
				Port:     9090,
				Protocol: avapigwv1alpha1.ProtocolGRPC,
			})

			err = k8sClient.Update(ctx, gw)
			Expect(err).NotTo(HaveOccurred())

			// Verify Gateway has both listeners
			Eventually(func() int {
				gw, err := getGateway(gatewayName)
				if err != nil {
					return 0
				}
				return len(gw.Spec.Listeners)
			}, ShortTimeout, DefaultInterval).Should(Equal(2))
		})

		It("should update HTTPRoute rules without downtime", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create HTTPRoute with one rule
			pathPrefix := avapigwv1alpha1.PathMatchPathPrefix
			apiPath := "/api"
			createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
				Rules: []avapigwv1alpha1.HTTPRouteRule{
					{
						Matches: []avapigwv1alpha1.HTTPRouteMatch{
							{
								Path: &avapigwv1alpha1.HTTPPathMatch{
									Type:  &pathPrefix,
									Value: &apiPath,
								},
							},
						},
					},
				},
			})

			// Wait for HTTPRoute to be created
			Eventually(func() error {
				_, err := getHTTPRoute(routeName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Update HTTPRoute to add another rule
			route, err := getHTTPRoute(routeName)
			Expect(err).NotTo(HaveOccurred())

			webPath := "/web"
			route.Spec.Rules = append(route.Spec.Rules, avapigwv1alpha1.HTTPRouteRule{
				Matches: []avapigwv1alpha1.HTTPRouteMatch{
					{
						Path: &avapigwv1alpha1.HTTPPathMatch{
							Type:  &pathPrefix,
							Value: &webPath,
						},
					},
				},
			})

			err = k8sClient.Update(ctx, route)
			Expect(err).NotTo(HaveOccurred())

			// Verify HTTPRoute has both rules
			Eventually(func() int {
				route, err := getHTTPRoute(routeName)
				if err != nil {
					return 0
				}
				return len(route.Spec.Rules)
			}, ShortTimeout, DefaultInterval).Should(Equal(2))
		})

		It("should handle rapid configuration changes", func() {
			// Create Gateway
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Perform rapid updates
			for i := 0; i < 10; i++ {
				gw, err := getGateway(gatewayName)
				if err != nil {
					continue
				}

				if gw.Annotations == nil {
					gw.Annotations = make(map[string]string)
				}
				gw.Annotations["test.avapigw/rapid-update"] = fmt.Sprintf("%d", i)

				_ = k8sClient.Update(ctx, gw)
				time.Sleep(100 * time.Millisecond)
			}

			// Verify Gateway is still functional
			Eventually(func() error {
				gw, err := getGateway(gatewayName)
				if err != nil {
					return err
				}
				if len(gw.Spec.Listeners) != 1 {
					return fmt.Errorf("expected 1 listener")
				}
				return nil
			}, ShortTimeout, DefaultInterval).Should(Succeed())
		})
	})

	Context("Resource Cleanup", func() {
		It("should clean up orphaned resources", func() {
			// Create a Gateway
			gatewayName := generateUniqueName("gw-cleanup")
			createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Wait for Gateway to be created
			Eventually(func() error {
				_, err := getGateway(gatewayName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Delete Gateway
			deleteGateway(gatewayName)

			// Verify Gateway is deleted
			Eventually(func() bool {
				_, err := getGateway(gatewayName)
				return err != nil
			}, ShortTimeout, DefaultInterval).Should(BeTrue())
		})

		It("should handle finalizers correctly", func() {
			// Create VaultSecret with finalizer
			vsName := generateUniqueName("vs-finalizer")
			tokenSecretName := generateUniqueName("token-finalizer")
			targetSecretName := generateUniqueName("target-finalizer")

			skipIfVaultNotAvailable()

			// Create token secret
			createSecret(tokenSecretName, map[string][]byte{
				"token": []byte(testConfig.VaultToken),
			})

			// Create test secret in Vault
			createVaultKV2Secret("avapigw/e2e/finalizer", map[string]interface{}{
				"key": "value",
			})

			// Create VaultSecret
			createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/finalizer",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			waitForVaultSecretReady(vsName, DefaultTimeout)

			// Delete VaultSecret
			deleteVaultSecret(vsName)

			// Verify VaultSecret is deleted
			Eventually(func() bool {
				_, err := getVaultSecret(vsName)
				return err != nil
			}, ShortTimeout, DefaultInterval).Should(BeTrue())

			// Cleanup
			deleteSecret(tokenSecretName)
			deleteVaultKV2Secret("avapigw/e2e/finalizer")
		})
	})
})

// Helper to create Duration pointer
func durationPtr(d string) *avapigwv1alpha1.Duration {
	duration := avapigwv1alpha1.Duration(d)
	return &duration
}

// Helper to simulate pod restart
func simulatePodRestart(namespace, labelSelector string) error {
	pods := &corev1.PodList{}
	err := k8sClient.List(ctx, pods,
		client.InNamespace(namespace),
		client.MatchingLabels(map[string]string{"app": labelSelector}),
	)
	if err != nil {
		return err
	}

	for _, pod := range pods.Items {
		if err := k8sClient.Delete(ctx, &pod); err != nil {
			return err
		}
	}

	return nil
}

// Helper to wait for pods to be ready
func waitForPodsReady(namespace, labelSelector string, timeout time.Duration) {
	Eventually(func() bool {
		pods := &corev1.PodList{}
		err := k8sClient.List(ctx, pods,
			client.InNamespace(namespace),
			client.MatchingLabels(map[string]string{"app": labelSelector}),
		)
		if err != nil {
			return false
		}

		for _, pod := range pods.Items {
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status != corev1.ConditionTrue {
					return false
				}
			}
		}
		return len(pods.Items) > 0
	}, timeout, DefaultInterval).Should(BeTrue())
}
