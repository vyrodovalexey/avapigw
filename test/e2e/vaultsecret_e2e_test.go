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
	"encoding/base64"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

var _ = Describe("VaultSecret E2E", Ordered, func() {
	var (
		tokenSecretName string
	)

	BeforeAll(func() {
		skipIfVaultNotAvailable()

		// Create a secret containing the Vault token for token auth tests
		tokenSecretName = generateUniqueName("vault-token")
		createSecret(tokenSecretName, map[string][]byte{
			"token": []byte(testConfig.VaultToken),
		})

		// Ensure test secrets exist in Vault
		createVaultKV2Secret("avapigw/e2e/basic", map[string]interface{}{
			"username": "e2e-user",
			"password": "e2e-password",
		})

		createVaultKV2Secret("avapigw/e2e/multikey", map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		})

		createVaultKV2Secret("avapigw/e2e/base64", map[string]interface{}{
			"encoded": base64.StdEncoding.EncodeToString([]byte("decoded-value")),
			"plain":   "plain-value",
		})
	})

	AfterAll(func() {
		deleteSecret(tokenSecretName)
		deleteVaultKV2Secret("avapigw/e2e/basic")
		deleteVaultKV2Secret("avapigw/e2e/multikey")
		deleteVaultKV2Secret("avapigw/e2e/base64")
	})

	Context("VaultSecret with Token Auth", func() {
		var vsName string
		var targetSecretName string

		BeforeEach(func() {
			vsName = generateUniqueName("vs-token")
			targetSecretName = generateUniqueName("target-secret")
		})

		AfterEach(func() {
			deleteVaultSecret(vsName)
			deleteSecret(targetSecretName)
		})

		It("should create VaultSecret and sync to K8s Secret", func() {
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/basic",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			// Wait for VaultSecret to be ready
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				vs, err := getVaultSecret(vsName)
				if err != nil {
					return ""
				}
				return vs.Status.Phase
			}, DefaultTimeout, DefaultInterval).Should(Equal(avapigwv1alpha1.PhaseStatusReady))

			// Verify target secret was created
			secret := waitForSecretWithData(targetSecretName, []string{"username", "password"}, ShortTimeout)
			Expect(string(secret.Data["username"])).To(Equal("e2e-user"))
			Expect(string(secret.Data["password"])).To(Equal("e2e-password"))

			// Verify VaultSecret status
			vs, err := getVaultSecret(vsName)
			Expect(err).NotTo(HaveOccurred())
			Expect(vs.Status.TargetSecretName).NotTo(BeNil())
			Expect(*vs.Status.TargetSecretName).To(Equal(targetSecretName))
		})

		It("should handle key mappings correctly", func() {
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/multikey",
				MountPoint: stringPtr("secret"),
				Keys: []avapigwv1alpha1.VaultKeyMapping{
					{
						VaultKey:  "key1",
						TargetKey: "mapped-key1",
					},
					{
						VaultKey:  "key2",
						TargetKey: "mapped-key2",
					},
				},
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			waitForVaultSecretReady(vsName, DefaultTimeout)

			// Verify mapped keys
			secret := waitForSecretWithData(targetSecretName, []string{"mapped-key1", "mapped-key2"}, ShortTimeout)
			Expect(string(secret.Data["mapped-key1"])).To(Equal("value1"))
			Expect(string(secret.Data["mapped-key2"])).To(Equal("value2"))

			// key3 should not be present (not mapped)
			_, exists := secret.Data["key3"]
			Expect(exists).To(BeFalse())
			_, exists = secret.Data["mapped-key3"]
			Expect(exists).To(BeFalse())

			_ = vs // silence unused warning
		})

		It("should handle Base64 encoding", func() {
			encoding := avapigwv1alpha1.VaultValueEncodingBase64
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/base64",
				MountPoint: stringPtr("secret"),
				Keys: []avapigwv1alpha1.VaultKeyMapping{
					{
						VaultKey:  "encoded",
						TargetKey: "decoded",
						Encoding:  &encoding,
					},
					{
						VaultKey:  "plain",
						TargetKey: "plain",
					},
				},
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			waitForVaultSecretReady(vsName, DefaultTimeout)

			secret := waitForSecretWithData(targetSecretName, []string{"decoded", "plain"}, ShortTimeout)
			// The base64 encoded value should be decoded
			Expect(string(secret.Data["decoded"])).To(Equal("decoded-value"))
			Expect(string(secret.Data["plain"])).To(Equal("plain-value"))

			_ = vs
		})

		It("should apply target secret labels and annotations", func() {
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/basic",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
					Labels: map[string]string{
						"app":         "test-app",
						"environment": "e2e",
					},
					Annotations: map[string]string{
						"description": "E2E test secret",
						"managed-by":  "vaultsecret",
					},
				},
			})

			waitForVaultSecretReady(vsName, DefaultTimeout)

			secret := waitForSecret(targetSecretName, ShortTimeout)
			Expect(secret.Labels["app"]).To(Equal("test-app"))
			Expect(secret.Labels["environment"]).To(Equal("e2e"))
			Expect(secret.Annotations["description"]).To(Equal("E2E test secret"))
			Expect(secret.Annotations["managed-by"]).To(Equal("vaultsecret"))

			_ = vs
		})
	})

	Context("VaultSecret with Kubernetes Auth", func() {
		var vsName string
		var targetSecretName string

		BeforeEach(func() {
			skipIfKubernetesAuthNotConfigured()
			vsName = generateUniqueName("vs-k8s")
			targetSecretName = generateUniqueName("target-k8s")
		})

		AfterEach(func() {
			deleteVaultSecret(vsName)
			deleteSecret(targetSecretName)
		})

		It("should authenticate using Kubernetes auth method", func() {
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: testConfig.VaultAddr,
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
							Role: testConfig.VaultRole,
						},
					},
				},
				Path:       "avapigw/e2e/basic",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			// Wait for VaultSecret to be ready (may take longer with K8s auth)
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				vs, err := getVaultSecret(vsName)
				if err != nil {
					return ""
				}
				return vs.Status.Phase
			}, LongTimeout, DefaultInterval).Should(Equal(avapigwv1alpha1.PhaseStatusReady))

			// Verify target secret was created
			secret := waitForSecretWithData(targetSecretName, []string{"username", "password"}, ShortTimeout)
			Expect(string(secret.Data["username"])).To(Equal("e2e-user"))

			_ = vs
		})
	})

	Context("Secret Refresh on Vault Update", func() {
		var vsName string
		var targetSecretName string
		var secretPath string

		BeforeEach(func() {
			vsName = generateUniqueName("vs-refresh")
			targetSecretName = generateUniqueName("target-refresh")
			secretPath = fmt.Sprintf("avapigw/e2e/refresh-%d", time.Now().UnixNano())

			// Create initial secret in Vault
			createVaultKV2Secret(secretPath, map[string]interface{}{
				"value": "initial-value",
			})
		})

		AfterEach(func() {
			deleteVaultSecret(vsName)
			deleteSecret(targetSecretName)
			deleteVaultKV2Secret(secretPath)
		})

		It("should refresh secret when Vault secret is updated", func() {
			refreshInterval := avapigwv1alpha1.Duration("10s")
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       secretPath,
				MountPoint: stringPtr("secret"),
				Refresh: &avapigwv1alpha1.VaultRefreshConfig{
					Enabled:  boolPtr(true),
					Interval: &refreshInterval,
				},
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
				},
			})

			waitForVaultSecretReady(vsName, DefaultTimeout)

			// Verify initial value
			secret := waitForSecretWithData(targetSecretName, []string{"value"}, ShortTimeout)
			Expect(string(secret.Data["value"])).To(Equal("initial-value"))

			// Update secret in Vault
			updateVaultKV2Secret(secretPath, map[string]interface{}{
				"value": "updated-value",
			})

			// Wait for refresh (with some buffer)
			time.Sleep(15 * time.Second)

			// Verify updated value
			Eventually(func() string {
				secret, err := getSecret(targetSecretName)
				if err != nil {
					return ""
				}
				return string(secret.Data["value"])
			}, 30*time.Second, DefaultInterval).Should(Equal("updated-value"))

			_ = vs
		})
	})

	Context("VaultSecret Deletion and Cleanup", func() {
		var vsName string
		var targetSecretName string

		BeforeEach(func() {
			vsName = generateUniqueName("vs-cleanup")
			targetSecretName = generateUniqueName("target-cleanup")
		})

		It("should delete target secret when VaultSecret is deleted (Delete policy)", func() {
			deletionPolicy := avapigwv1alpha1.SecretDeletionPolicyDelete
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/basic",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name:           targetSecretName,
					DeletionPolicy: &deletionPolicy,
				},
			})

			waitForVaultSecretReady(vsName, DefaultTimeout)
			waitForSecret(targetSecretName, ShortTimeout)

			// Delete VaultSecret
			err := k8sClient.Delete(ctx, vs)
			Expect(err).NotTo(HaveOccurred())

			// Wait for VaultSecret to be deleted
			waitForResourceDeletion(vs, ShortTimeout)

			// Target secret should also be deleted
			Eventually(func() bool {
				_, err := getSecret(targetSecretName)
				return err != nil
			}, ShortTimeout, DefaultInterval).Should(BeTrue())
		})

		It("should retain target secret when VaultSecret is deleted (Retain policy)", func() {
			deletionPolicy := avapigwv1alpha1.SecretDeletionPolicyRetain
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/basic",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name:           targetSecretName,
					DeletionPolicy: &deletionPolicy,
				},
			})

			waitForVaultSecretReady(vsName, DefaultTimeout)
			waitForSecret(targetSecretName, ShortTimeout)

			// Delete VaultSecret
			err := k8sClient.Delete(ctx, vs)
			Expect(err).NotTo(HaveOccurred())

			// Wait for VaultSecret to be deleted
			waitForResourceDeletion(vs, ShortTimeout)

			// Target secret should still exist
			time.Sleep(2 * time.Second)
			secret, err := getSecret(targetSecretName)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret).NotTo(BeNil())

			// Cleanup
			deleteSecret(targetSecretName)
		})
	})

	Context("Error Handling", func() {
		var vsName string

		BeforeEach(func() {
			vsName = generateUniqueName("vs-error")
		})

		AfterEach(func() {
			deleteVaultSecret(vsName)
		})

		It("should handle non-existent Vault path gracefully", func() {
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
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
				Path:       "avapigw/e2e/nonexistent-path",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: "target-nonexistent",
				},
			})

			// Should eventually show error status
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				vs, err := getVaultSecret(vsName)
				if err != nil {
					return ""
				}
				return vs.Status.Phase
			}, DefaultTimeout, DefaultInterval).Should(Equal(avapigwv1alpha1.PhaseStatusError))

			// Verify error message is set
			vs, err := getVaultSecret(vsName)
			Expect(err).NotTo(HaveOccurred())
			Expect(vs.Status.LastVaultError).NotTo(BeNil())

			_ = vs
		})

		It("should handle invalid Vault address gracefully", func() {
			vs := createVaultSecret(vsName, avapigwv1alpha1.VaultSecretSpec{
				VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
					Address: "http://invalid-vault-address:8200",
					Auth: avapigwv1alpha1.VaultAuthConfig{
						Token: &avapigwv1alpha1.TokenAuthConfig{
							SecretRef: avapigwv1alpha1.SecretObjectReference{
								Name: tokenSecretName,
							},
						},
					},
				},
				Path:       "avapigw/e2e/basic",
				MountPoint: stringPtr("secret"),
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: "target-invalid",
				},
			})

			// Should eventually show error status
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				vs, err := getVaultSecret(vsName)
				if err != nil {
					return ""
				}
				return vs.Status.Phase
			}, DefaultTimeout, DefaultInterval).Should(Equal(avapigwv1alpha1.PhaseStatusError))

			_ = vs
		})
	})

	Context("Multiple VaultSecrets", func() {
		It("should handle multiple VaultSecrets concurrently", func() {
			const numSecrets = 5
			vsNames := make([]string, numSecrets)
			targetNames := make([]string, numSecrets)

			// Create multiple VaultSecrets
			for i := 0; i < numSecrets; i++ {
				vsNames[i] = generateUniqueName(fmt.Sprintf("vs-multi-%d", i))
				targetNames[i] = generateUniqueName(fmt.Sprintf("target-multi-%d", i))

				createVaultSecret(vsNames[i], avapigwv1alpha1.VaultSecretSpec{
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
					Path:       "avapigw/e2e/basic",
					MountPoint: stringPtr("secret"),
					Target: &avapigwv1alpha1.VaultTargetConfig{
						Name: targetNames[i],
					},
				})
			}

			// Wait for all to be ready
			for i := 0; i < numSecrets; i++ {
				waitForVaultSecretReady(vsNames[i], DefaultTimeout)
				waitForSecret(targetNames[i], ShortTimeout)
			}

			// Verify all secrets have correct data
			for i := 0; i < numSecrets; i++ {
				secret, err := getSecret(targetNames[i])
				Expect(err).NotTo(HaveOccurred())
				Expect(string(secret.Data["username"])).To(Equal("e2e-user"))
			}

			// Cleanup
			for i := 0; i < numSecrets; i++ {
				deleteVaultSecret(vsNames[i])
				deleteSecret(targetNames[i])
			}
		})
	})
})

// Helper to list all VaultSecrets in namespace
func listVaultSecrets() (*avapigwv1alpha1.VaultSecretList, error) {
	list := &avapigwv1alpha1.VaultSecretList{}
	err := k8sClient.List(ctx, list, client.InNamespace(testNamespace))
	return list, err
}

// Helper to get VaultSecret condition
func getVaultSecretCondition(vs *avapigwv1alpha1.VaultSecret, condType avapigwv1alpha1.ConditionType) *avapigwv1alpha1.Condition {
	for i := range vs.Status.Conditions {
		if vs.Status.Conditions[i].Type == condType {
			return &vs.Status.Conditions[i]
		}
	}
	return nil
}
