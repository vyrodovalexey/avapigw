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

var _ = Describe("VaultSecret Controller Integration Tests", func() {
	// Note: These tests run with Vault disabled, so they test the controller's
	// behavior when Vault integration is not available.

	Context("VaultSecret Creation (Vault Disabled)", func() {
		It("should create VaultSecret and report Vault disabled status", func() {
			vaultSecret := newVaultSecret(TestNamespace, uniqueName("vs-disabled"),
				"https://vault.example.com:8200",
				"secret/data/myapp/config",
				"target-secret",
			)

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Wait for VaultSecret to report pending status (Vault disabled)
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret); err != nil {
					return ""
				}
				return vaultSecret.Status.Phase
			}, Timeout, Interval).Should(Equal(avapigwv1alpha1.PhaseStatusPending))

			// Verify condition indicates Vault is disabled
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			cond := vaultSecret.Status.GetCondition(avapigwv1alpha1.ConditionTypeReady)
			Expect(cond).ShouldNot(BeNil())
			Expect(cond.Status).Should(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).Should(Equal("VaultDisabled"))
		})
	})

	Context("VaultSecret with Kubernetes Auth Configuration", func() {
		It("should create VaultSecret with Kubernetes auth", func() {
			vaultSecret := &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("vs-k8s-auth"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "https://vault.example.com:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role:      "my-role",
								MountPath: stringPtr("kubernetes"),
							},
						},
					},
					Path: "secret/data/myapp/config",
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "target-secret",
					},
				},
			}

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Verify configuration is preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			Expect(vaultSecret.Spec.VaultConnection.Auth.Kubernetes).ShouldNot(BeNil())
			Expect(vaultSecret.Spec.VaultConnection.Auth.Kubernetes.Role).Should(Equal("my-role"))
		})
	})

	Context("VaultSecret with Token Auth Configuration", func() {
		It("should create VaultSecret with token auth", func() {
			// Create token secret
			tokenSecret := newSecret(TestNamespace, uniqueName("vault-token"), map[string][]byte{
				"token": []byte("s.example-token"),
			})
			Expect(k8sClient.Create(ctx, tokenSecret)).Should(Succeed())
			defer cleanupResource(tokenSecret)

			vaultSecret := &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("vs-token-auth"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "https://vault.example.com:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Token: &avapigwv1alpha1.TokenAuthConfig{
								SecretRef: avapigwv1alpha1.SecretObjectReference{
									Name: tokenSecret.Name,
								},
							},
						},
					},
					Path: "secret/data/myapp/config",
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "target-secret",
					},
				},
			}

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Verify configuration is preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			Expect(vaultSecret.Spec.VaultConnection.Auth.Token).ShouldNot(BeNil())
		})
	})

	Context("VaultSecret with AppRole Auth Configuration", func() {
		It("should create VaultSecret with AppRole auth", func() {
			// Create secret ID secret
			secretIDSecret := newSecret(TestNamespace, uniqueName("approle-secret"), map[string][]byte{
				"secret-id": []byte("example-secret-id"),
			})
			Expect(k8sClient.Create(ctx, secretIDSecret)).Should(Succeed())
			defer cleanupResource(secretIDSecret)

			vaultSecret := &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("vs-approle-auth"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "https://vault.example.com:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							AppRole: &avapigwv1alpha1.AppRoleAuthConfig{
								RoleID: "example-role-id",
								SecretIDRef: avapigwv1alpha1.SecretObjectReference{
									Name: secretIDSecret.Name,
								},
							},
						},
					},
					Path: "secret/data/myapp/config",
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "target-secret",
					},
				},
			}

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Verify configuration is preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			Expect(vaultSecret.Spec.VaultConnection.Auth.AppRole).ShouldNot(BeNil())
			Expect(vaultSecret.Spec.VaultConnection.Auth.AppRole.RoleID).Should(Equal("example-role-id"))
		})
	})

	Context("VaultSecret with Key Mappings", func() {
		It("should create VaultSecret with key mappings", func() {
			vaultSecret := &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("vs-key-mapping"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "https://vault.example.com:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "my-role",
							},
						},
					},
					Path: "secret/data/myapp/config",
					Keys: []avapigwv1alpha1.VaultKeyMapping{
						{
							VaultKey:  "database_password",
							TargetKey: "DB_PASSWORD",
						},
						{
							VaultKey:  "api_key",
							TargetKey: "API_KEY",
						},
					},
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "target-secret",
					},
				},
			}

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Verify key mappings are preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			Expect(vaultSecret.Spec.Keys).Should(HaveLen(2))
			Expect(vaultSecret.Spec.Keys[0].VaultKey).Should(Equal("database_password"))
			Expect(vaultSecret.Spec.Keys[0].TargetKey).Should(Equal("DB_PASSWORD"))
		})
	})

	Context("VaultSecret with Refresh Configuration", func() {
		It("should create VaultSecret with refresh configuration", func() {
			vaultSecret := &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("vs-refresh"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "https://vault.example.com:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "my-role",
							},
						},
					},
					Path: "secret/data/myapp/config",
					Refresh: &avapigwv1alpha1.VaultRefreshConfig{
						Enabled:       boolPtr(true),
						Interval:      durationPtr("5m"),
						JitterPercent: int32Ptr(10),
					},
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "target-secret",
					},
				},
			}

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Verify refresh configuration is preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			Expect(vaultSecret.Spec.Refresh).ShouldNot(BeNil())
			Expect(*vaultSecret.Spec.Refresh.Enabled).Should(BeTrue())
			Expect(*vaultSecret.Spec.Refresh.JitterPercent).Should(Equal(int32(10)))
		})

		It("should create VaultSecret with refresh disabled", func() {
			vaultSecret := &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("vs-no-refresh"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "https://vault.example.com:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "my-role",
							},
						},
					},
					Path: "secret/data/myapp/config",
					Refresh: &avapigwv1alpha1.VaultRefreshConfig{
						Enabled: boolPtr(false),
					},
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "target-secret",
					},
				},
			}

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Verify refresh is disabled
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			Expect(*vaultSecret.Spec.Refresh.Enabled).Should(BeFalse())
		})
	})

	Context("VaultSecret Target Configuration", func() {
		It("should create VaultSecret with target secret configuration", func() {
			vaultSecret := &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("vs-target-config"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "https://vault.example.com:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "my-role",
							},
						},
					},
					Path: "secret/data/myapp/config",
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "my-app-secrets",
						Labels: map[string]string{
							"app": "my-app",
						},
						Annotations: map[string]string{
							"description": "Secrets from Vault",
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Verify target configuration is preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			Expect(vaultSecret.Spec.Target.Labels).Should(HaveKeyWithValue("app", "my-app"))
			Expect(vaultSecret.Spec.Target.Annotations).Should(HaveKeyWithValue("description", "Secrets from Vault"))
		})

		It("should create VaultSecret with TLS secret type", func() {
			vaultSecret := &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("vs-tls-type"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "https://vault.example.com:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "my-role",
							},
						},
					},
					Path: "pki/issue/my-role",
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "my-tls-cert",
						Type: stringPtr("kubernetes.io/tls"),
					},
				},
			}

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Verify target type is preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			Expect(*vaultSecret.Spec.Target.Type).Should(Equal("kubernetes.io/tls"))
		})
	})

	Context("VaultSecret Deletion", func() {
		It("should delete VaultSecret cleanly", func() {
			vaultSecret := newVaultSecret(TestNamespace, uniqueName("vs-delete"),
				"https://vault.example.com:8200",
				"secret/data/myapp/config",
				"target-secret",
			)

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())

			// Wait for initial reconciliation
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret); err != nil {
					return false
				}
				return vaultSecret.Status.Phase != ""
			}, Timeout, Interval).Should(BeTrue())

			// Delete VaultSecret
			Expect(k8sClient.Delete(ctx, vaultSecret)).Should(Succeed())

			// Wait for deletion
			waitForDeletion(vaultSecret, Timeout)
		})
	})

	Context("VaultSecret with TLS Configuration", func() {
		It("should create VaultSecret with TLS CA certificate", func() {
			// Create CA cert secret
			caCertSecret := newSecret(TestNamespace, uniqueName("vault-ca"), map[string][]byte{
				"ca.crt": []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
			})
			Expect(k8sClient.Create(ctx, caCertSecret)).Should(Succeed())
			defer cleanupResource(caCertSecret)

			vaultSecret := &avapigwv1alpha1.VaultSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uniqueName("vs-tls"),
					Namespace: TestNamespace,
				},
				Spec: avapigwv1alpha1.VaultSecretSpec{
					VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
						Address: "https://vault.example.com:8200",
						Auth: avapigwv1alpha1.VaultAuthConfig{
							Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
								Role: "my-role",
							},
						},
						TLS: &avapigwv1alpha1.VaultTLSConfig{
							CACertRef: &avapigwv1alpha1.SecretObjectReference{
								Name: caCertSecret.Name,
							},
						},
					},
					Path: "secret/data/myapp/config",
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: "target-secret",
					},
				},
			}

			Expect(k8sClient.Create(ctx, vaultSecret)).Should(Succeed())
			defer cleanupResource(vaultSecret)

			// Verify TLS configuration is preserved
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(vaultSecret), vaultSecret)).Should(Succeed())
			Expect(vaultSecret.Spec.VaultConnection.TLS).ShouldNot(BeNil())
			Expect(vaultSecret.Spec.VaultConnection.TLS.CACertRef).ShouldNot(BeNil())
		})
	})
})
