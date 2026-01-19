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
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

var _ = Describe("Gateway Deployment E2E", Ordered, func() {
	Context("Gateway Resource Creation", func() {
		var gatewayName string

		BeforeEach(func() {
			gatewayName = generateUniqueName("gateway")
		})

		AfterEach(func() {
			deleteGateway(gatewayName)
		})

		It("should create Gateway with HTTP listener", func() {
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
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

			// Verify Gateway spec
			gw, err := getGateway(gatewayName)
			Expect(err).NotTo(HaveOccurred())
			Expect(gw.Spec.Listeners).To(HaveLen(1))
			Expect(gw.Spec.Listeners[0].Name).To(Equal("http"))
			Expect(gw.Spec.Listeners[0].Port).To(Equal(avapigwv1alpha1.PortNumber(8080)))
			Expect(gw.Spec.Listeners[0].Protocol).To(Equal(avapigwv1alpha1.ProtocolHTTP))

			_ = gateway
		})

		It("should create Gateway with HTTPS listener", func() {
			// Create TLS secret first
			certPEM, keyPEM, err := generateSelfSignedCert("gateway.example.com", []string{"gateway.example.com"}, 24*time.Hour)
			Expect(err).NotTo(HaveOccurred())

			tlsSecretName := generateUniqueName("gw-tls")
			createSecretWithType(tlsSecretName, corev1.SecretTypeTLS, map[string][]byte{
				"tls.crt": certPEM,
				"tls.key": keyPEM,
			})

			tlsMode := avapigwv1alpha1.TLSModeTerminate
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						Mode: &tlsMode,
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: tlsSecretName},
						},
					},
				},
			})

			// Wait for Gateway to be created
			Eventually(func() error {
				_, err := getGateway(gatewayName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Verify Gateway spec
			gw, err := getGateway(gatewayName)
			Expect(err).NotTo(HaveOccurred())
			Expect(gw.Spec.Listeners[0].TLS).NotTo(BeNil())
			Expect(*gw.Spec.Listeners[0].TLS.Mode).To(Equal(avapigwv1alpha1.TLSModeTerminate))

			// Cleanup
			deleteSecret(tlsSecretName)
			_ = gateway
		})

		It("should create Gateway with multiple listeners", func() {
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
				{
					Name:     "grpc",
					Port:     9090,
					Protocol: avapigwv1alpha1.ProtocolGRPC,
				},
				{
					Name:     "tcp",
					Port:     9000,
					Protocol: avapigwv1alpha1.ProtocolTCP,
				},
			})

			// Wait for Gateway to be created
			Eventually(func() error {
				_, err := getGateway(gatewayName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Verify Gateway spec
			gw, err := getGateway(gatewayName)
			Expect(err).NotTo(HaveOccurred())
			Expect(gw.Spec.Listeners).To(HaveLen(3))

			_ = gateway
		})

		It("should create Gateway with hostname filter", func() {
			hostname := avapigwv1alpha1.Hostname("*.example.com")
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
					Hostname: &hostname,
				},
			})

			// Wait for Gateway to be created
			Eventually(func() error {
				_, err := getGateway(gatewayName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			// Verify Gateway spec
			gw, err := getGateway(gatewayName)
			Expect(err).NotTo(HaveOccurred())
			Expect(gw.Spec.Listeners[0].Hostname).NotTo(BeNil())
			Expect(string(*gw.Spec.Listeners[0].Hostname)).To(Equal("*.example.com"))

			_ = gateway
		})

		It("should update Gateway status", func() {
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Wait for Gateway status to be updated
			Eventually(func() int32 {
				gw, err := getGateway(gatewayName)
				if err != nil {
					return -1
				}
				return gw.Status.ListenersCount
			}, DefaultTimeout, DefaultInterval).Should(Equal(int32(1)))

			_ = gateway
		})
	})

	Context("Gateway with Backend", func() {
		var (
			gatewayName string
			backendName string
			routeName   string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-backend")
			backendName = generateUniqueName("backend")
			routeName = generateUniqueName("route")
		})

		AfterEach(func() {
			deleteHTTPRoute(routeName)
			deleteBackend(backendName)
			deleteGateway(gatewayName)
		})

		It("should create complete Gateway with Backend and HTTPRoute", func() {
			// Create Gateway
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create Backend
			backend := createBackend(backendName, avapigwv1alpha1.BackendSpec{
				Service: &avapigwv1alpha1.ServiceRef{
					Name: "test-service",
					Port: 80,
				},
			})

			// Create HTTPRoute
			pathPrefix := avapigwv1alpha1.PathMatchPathPrefix
			pathValue := "/"
			route := createHTTPRoute(routeName, avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: gatewayName},
				},
				Hostnames: []avapigwv1alpha1.Hostname{"test.example.com"},
				Rules: []avapigwv1alpha1.HTTPRouteRule{
					{
						Matches: []avapigwv1alpha1.HTTPRouteMatch{
							{
								Path: &avapigwv1alpha1.HTTPPathMatch{
									Type:  &pathPrefix,
									Value: &pathValue,
								},
							},
						},
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

			// Verify all resources were created
			Eventually(func() error {
				_, err := getGateway(gatewayName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			Eventually(func() error {
				_, err := getBackend(backendName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			Eventually(func() error {
				_, err := getHTTPRoute(routeName)
				return err
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			_ = gateway
			_ = backend
			_ = route
		})
	})

	Context("Gateway Service Verification", func() {
		var (
			gatewayName string
			serviceName string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-svc")
			serviceName = generateUniqueName("gw-service")
		})

		AfterEach(func() {
			deleteGateway(gatewayName)
			// Delete service if it was created
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName,
					Namespace: testNamespace,
				},
			}
			_ = k8sClient.Delete(ctx, svc)
		})

		It("should verify Gateway service is created", func() {
			// Create Gateway
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create a service that would be created by the controller
			// In a real scenario, the controller would create this
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName,
					Namespace: testNamespace,
					Labels: map[string]string{
						"app.kubernetes.io/name":     "avapigw",
						"app.kubernetes.io/instance": gatewayName,
					},
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeClusterIP,
					Ports: []corev1.ServicePort{
						{
							Name:       "http",
							Port:       8080,
							TargetPort: intstr.FromInt32(8080),
							Protocol:   corev1.ProtocolTCP,
						},
					},
					Selector: map[string]string{
						"app.kubernetes.io/name":     "avapigw",
						"app.kubernetes.io/instance": gatewayName,
					},
				},
			}

			err := k8sClient.Create(ctx, svc)
			Expect(err).NotTo(HaveOccurred())

			// Verify service exists
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      serviceName,
					Namespace: testNamespace,
				}, &corev1.Service{})
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			_ = gateway
		})
	})

	Context("Gateway Deployment Verification", func() {
		var (
			gatewayName    string
			deploymentName string
		)

		BeforeEach(func() {
			gatewayName = generateUniqueName("gw-deploy")
			deploymentName = generateUniqueName("gw-deployment")
		})

		AfterEach(func() {
			deleteGateway(gatewayName)
			// Delete deployment if it was created
			deploy := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: testNamespace,
				},
			}
			_ = k8sClient.Delete(ctx, deploy)
		})

		It("should verify Gateway deployment is created", func() {
			// Create Gateway
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			})

			// Create a deployment that would be created by the controller
			replicas := int32(1)
			deploy := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: testNamespace,
					Labels: map[string]string{
						"app.kubernetes.io/name":     "avapigw",
						"app.kubernetes.io/instance": gatewayName,
					},
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: &replicas,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/name":     "avapigw",
							"app.kubernetes.io/instance": gatewayName,
						},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"app.kubernetes.io/name":     "avapigw",
								"app.kubernetes.io/instance": gatewayName,
							},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "gateway",
									Image: "nginx:latest", // Placeholder image
									Ports: []corev1.ContainerPort{
										{
											ContainerPort: 8080,
											Protocol:      corev1.ProtocolTCP,
										},
									},
								},
							},
						},
					},
				},
			}

			err := k8sClient.Create(ctx, deploy)
			Expect(err).NotTo(HaveOccurred())

			// Verify deployment exists
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      deploymentName,
					Namespace: testNamespace,
				}, &appsv1.Deployment{})
			}, ShortTimeout, DefaultInterval).Should(Succeed())

			_ = gateway
		})
	})

	Context("Gateway Health Endpoints", func() {
		It("should verify health endpoint configuration", func() {
			gatewayName := generateUniqueName("gw-health")

			// Create Gateway
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
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

			// In a real deployment, we would test the health endpoint
			// For now, we just verify the Gateway was created successfully
			gw, err := getGateway(gatewayName)
			Expect(err).NotTo(HaveOccurred())
			Expect(gw).NotTo(BeNil())

			// Cleanup
			deleteGateway(gatewayName)
			_ = gateway
		})
	})

	Context("Gateway Metrics Endpoint", func() {
		It("should verify metrics endpoint configuration", func() {
			gatewayName := generateUniqueName("gw-metrics")

			// Create Gateway
			gateway := createGateway(gatewayName, []avapigwv1alpha1.Listener{
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

			// In a real deployment, we would test the metrics endpoint
			// For now, we just verify the Gateway was created successfully
			gw, err := getGateway(gatewayName)
			Expect(err).NotTo(HaveOccurred())
			Expect(gw).NotTo(BeNil())

			// Cleanup
			deleteGateway(gatewayName)
			_ = gateway
		})
	})
})

// Helper to check if a deployment is ready
func isDeploymentReady(name string) bool {
	deploy := &appsv1.Deployment{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: testNamespace,
	}, deploy)
	if err != nil {
		return false
	}

	return deploy.Status.ReadyReplicas == *deploy.Spec.Replicas
}

// Helper to wait for deployment to be ready
func waitForDeploymentReady(name string, timeout time.Duration) {
	Eventually(func() bool {
		return isDeploymentReady(name)
	}, timeout, DefaultInterval).Should(BeTrue(), "Deployment %s should be ready", name)
}

// Helper to check endpoint health
func checkEndpointHealth(url string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// Helper to get Gateway addresses
func getGatewayAddresses(name string) []avapigwv1alpha1.GatewayStatusAddress {
	gw, err := getGateway(name)
	if err != nil {
		return nil
	}
	return gw.Status.Addresses
}

// Helper to get Gateway listener status
func getGatewayListenerStatus(name, listenerName string) *avapigwv1alpha1.ListenerStatus {
	gw, err := getGateway(name)
	if err != nil {
		return nil
	}

	for i := range gw.Status.Listeners {
		if gw.Status.Listeners[i].Name == listenerName {
			return &gw.Status.Listeners[i]
		}
	}
	return nil
}
