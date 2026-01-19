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

var _ = Describe("Gateway Controller", func() {
	Context("When creating a Gateway", func() {
		It("Should create successfully with valid spec", func() {
			gateway := &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway",
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: avapigwv1alpha1.ProtocolHTTP,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			// Verify the gateway was created
			createdGateway := &avapigwv1alpha1.Gateway{}
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      "test-gateway",
					Namespace: TestNamespace,
				}, createdGateway)
			}, Timeout, Interval).Should(Succeed())

			Expect(createdGateway.Spec.Listeners).Should(HaveLen(1))
			Expect(createdGateway.Spec.Listeners[0].Name).Should(Equal("http"))
			Expect(createdGateway.Spec.Listeners[0].Port).Should(Equal(avapigwv1alpha1.PortNumber(8080)))

			// Cleanup
			Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())
		})

		It("Should create Gateway with HTTPS listener", func() {
			tlsMode := avapigwv1alpha1.TLSModeTerminate
			gateway := &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway-https",
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "https",
							Port:     8443,
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
							TLS: &avapigwv1alpha1.GatewayTLSConfig{
								Mode: &tlsMode,
								CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
									{
										Name: "tls-secret",
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			// Verify the gateway was created
			createdGateway := &avapigwv1alpha1.Gateway{}
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      "test-gateway-https",
					Namespace: TestNamespace,
				}, createdGateway)
			}, Timeout, Interval).Should(Succeed())

			Expect(createdGateway.Spec.Listeners[0].TLS).ShouldNot(BeNil())
			Expect(*createdGateway.Spec.Listeners[0].TLS.Mode).Should(Equal(avapigwv1alpha1.TLSModeTerminate))

			// Cleanup
			Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())
		})

		It("Should create Gateway with multiple listeners", func() {
			gateway := &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gateway-multi",
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
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
					},
				},
			}

			Expect(k8sClient.Create(ctx, gateway)).Should(Succeed())

			// Verify the gateway was created
			createdGateway := &avapigwv1alpha1.Gateway{}
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      "test-gateway-multi",
					Namespace: TestNamespace,
				}, createdGateway)
			}, Timeout, Interval).Should(Succeed())

			Expect(createdGateway.Spec.Listeners).Should(HaveLen(2))

			// Cleanup
			Expect(k8sClient.Delete(ctx, gateway)).Should(Succeed())
		})
	})
})

var _ = Describe("HTTPRoute Controller", func() {
	Context("When creating an HTTPRoute", func() {
		It("Should create successfully with valid spec", func() {
			route := &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-httproute",
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.HTTPRouteSpec{
					ParentRefs: []avapigwv1alpha1.ParentRef{
						{
							Name: "test-gateway",
						},
					},
					Hostnames: []avapigwv1alpha1.Hostname{"example.com"},
					Rules: []avapigwv1alpha1.HTTPRouteRule{
						{
							BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
								{
									BackendRef: avapigwv1alpha1.BackendRef{
										Name: "backend-service",
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, route)).Should(Succeed())

			// Verify the route was created
			createdRoute := &avapigwv1alpha1.HTTPRoute{}
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      "test-httproute",
					Namespace: TestNamespace,
				}, createdRoute)
			}, Timeout, Interval).Should(Succeed())

			Expect(createdRoute.Spec.Hostnames).Should(HaveLen(1))
			Expect(string(createdRoute.Spec.Hostnames[0])).Should(Equal("example.com"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, route)).Should(Succeed())
		})
	})
})

var _ = Describe("Backend Controller", func() {
	Context("When creating a Backend", func() {
		It("Should create successfully with service reference", func() {
			backend := &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend",
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Service: &avapigwv1alpha1.ServiceRef{
						Name: "my-service",
						Port: 8080,
					},
				},
			}

			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())

			// Verify the backend was created
			createdBackend := &avapigwv1alpha1.Backend{}
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      "test-backend",
					Namespace: TestNamespace,
				}, createdBackend)
			}, Timeout, Interval).Should(Succeed())

			Expect(createdBackend.Spec.Service).ShouldNot(BeNil())
			Expect(createdBackend.Spec.Service.Name).Should(Equal("my-service"))
			Expect(createdBackend.Spec.Service.Port).Should(Equal(int32(8080)))

			// Cleanup
			Expect(k8sClient.Delete(ctx, backend)).Should(Succeed())
		})

		It("Should create successfully with direct endpoints", func() {
			backend := &avapigwv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend-endpoints",
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.BackendSpec{
					Endpoints: []avapigwv1alpha1.EndpointConfig{
						{
							Address: "10.0.0.1",
							Port:    8080,
						},
						{
							Address: "10.0.0.2",
							Port:    8080,
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, backend)).Should(Succeed())

			// Verify the backend was created
			createdBackend := &avapigwv1alpha1.Backend{}
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      "test-backend-endpoints",
					Namespace: TestNamespace,
				}, createdBackend)
			}, Timeout, Interval).Should(Succeed())

			Expect(createdBackend.Spec.Endpoints).Should(HaveLen(2))

			// Cleanup
			Expect(k8sClient.Delete(ctx, backend)).Should(Succeed())
		})
	})
})

var _ = Describe("RateLimitPolicy Controller", func() {
	Context("When creating a RateLimitPolicy", func() {
		It("Should create successfully with valid spec", func() {
			policy := &avapigwv1alpha1.RateLimitPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ratelimit",
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.RateLimitPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: "avapigw.vyrodovalexey.github.com",
						Kind:  "HTTPRoute",
						Name:  "test-httproute",
					},
					Rules: []avapigwv1alpha1.RateLimitRule{
						{
							Name: "default",
							Limit: avapigwv1alpha1.RateLimitValue{
								Requests: 100,
								Unit:     avapigwv1alpha1.RateLimitUnitMinute,
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			// Verify the policy was created
			createdPolicy := &avapigwv1alpha1.RateLimitPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      "test-ratelimit",
					Namespace: TestNamespace,
				}, createdPolicy)
			}, Timeout, Interval).Should(Succeed())

			Expect(createdPolicy.Spec.Rules).Should(HaveLen(1))
			Expect(createdPolicy.Spec.Rules[0].Limit.Requests).Should(Equal(int32(100)))

			// Cleanup
			Expect(k8sClient.Delete(ctx, policy)).Should(Succeed())
		})
	})
})

var _ = Describe("AuthPolicy Controller", func() {
	Context("When creating an AuthPolicy", func() {
		It("Should create successfully with JWT authentication", func() {
			enabled := true
			policy := &avapigwv1alpha1.AuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-authpolicy",
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.AuthPolicySpec{
					TargetRef: avapigwv1alpha1.TargetRef{
						Group: "avapigw.vyrodovalexey.github.com",
						Kind:  "HTTPRoute",
						Name:  "test-httproute",
					},
					Authentication: &avapigwv1alpha1.AuthenticationConfig{
						JWT: &avapigwv1alpha1.JWTAuthConfig{
							Enabled: &enabled,
							Issuer:  stringPtr("https://auth.example.com"),
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).Should(Succeed())

			// Verify the policy was created
			createdPolicy := &avapigwv1alpha1.AuthPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Name:      "test-authpolicy",
					Namespace: TestNamespace,
				}, createdPolicy)
			}, Timeout, Interval).Should(Succeed())

			Expect(createdPolicy.Spec.Authentication).ShouldNot(BeNil())
			Expect(createdPolicy.Spec.Authentication.JWT).ShouldNot(BeNil())
			Expect(*createdPolicy.Spec.Authentication.JWT.Enabled).Should(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, policy)).Should(Succeed())
		})
	})
})

// Note: stringPtr is defined in helpers_test.go
