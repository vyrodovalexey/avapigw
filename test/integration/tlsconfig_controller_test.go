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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// generateSelfSignedCert generates a self-signed certificate for testing
func generateSelfSignedCert(dnsNames []string, notBefore, notAfter time.Time) ([]byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "test.example.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

// createTLSSecretWithCert creates a TLS secret with a generated certificate
func createTLSSecretWithCert(namespace, name string, dnsNames []string, validDays int) (*corev1.Secret, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validDays) * 24 * time.Hour)

	certPEM, keyPEM, err := generateSelfSignedCert(dnsNames, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}, nil
}

// createExpiredTLSSecret creates a TLS secret with an expired certificate
func createExpiredTLSSecret(namespace, name string) (*corev1.Secret, error) {
	notBefore := time.Now().Add(-365 * 24 * time.Hour)
	notAfter := time.Now().Add(-1 * 24 * time.Hour) // Expired yesterday

	certPEM, keyPEM, err := generateSelfSignedCert([]string{"test.example.com"}, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}, nil
}

// createExpiringSoonTLSSecret creates a TLS secret with a certificate expiring soon
func createExpiringSoonTLSSecret(namespace, name string, expiresInDays int) (*corev1.Secret, error) {
	notBefore := time.Now().Add(-30 * 24 * time.Hour)
	notAfter := time.Now().Add(time.Duration(expiresInDays) * 24 * time.Hour)

	certPEM, keyPEM, err := generateSelfSignedCert([]string{"test.example.com"}, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}, nil
}

var _ = Describe("TLSConfig Controller Integration", func() {
	var testNs string

	BeforeEach(func() {
		testNs = createTestNamespace("tlsconfig-test")
	})

	AfterEach(func() {
		deleteTestNamespace(testNs)
	})

	Context("when creating a TLSConfig", func() {
		It("should reconcile with a valid TLS secret", func() {
			By("creating a TLS secret with valid certificate")
			tlsSecret, err := createTLSSecretWithCert(testNs, "valid-tls-secret", []string{"test.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig referencing the secret")
			tlsConfig := newTLSConfig(testNs, "test-tlsconfig", "valid-tls-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig becomes ready")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)
			waitForCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue, Timeout)

			By("verifying certificate info is populated")
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig); err != nil {
					return false
				}
				return tlsConfig.Status.Certificate != nil &&
					tlsConfig.Status.Certificate.NotAfter != nil &&
					tlsConfig.Status.Certificate.NotBefore != nil
			}, Timeout, Interval).Should(BeTrue())

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(tlsSecret)
		})

		It("should handle TLSConfig with TLS version constraints", func() {
			By("creating a TLS secret")
			tlsSecret, err := createTLSSecretWithCert(testNs, "tls-version-secret", []string{"test.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig with TLS version constraints")
			tlsConfig := newTLSConfigWithVersions(testNs, "tlsconfig-versions", "tls-version-secret",
				avapigwv1alpha1.TLSVersion12, avapigwv1alpha1.TLSVersion13)
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig becomes ready")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("verifying the TLS version constraints are set")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig)).To(Succeed())
			Expect(tlsConfig.Spec.MinVersion).NotTo(BeNil())
			Expect(*tlsConfig.Spec.MinVersion).To(Equal(avapigwv1alpha1.TLSVersion12))
			Expect(tlsConfig.Spec.MaxVersion).NotTo(BeNil())
			Expect(*tlsConfig.Spec.MaxVersion).To(Equal(avapigwv1alpha1.TLSVersion13))

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(tlsSecret)
		})

		It("should handle TLSConfig with rotation configuration", func() {
			By("creating a TLS secret")
			tlsSecret, err := createTLSSecretWithCert(testNs, "tls-rotation-secret", []string{"test.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig with rotation configuration")
			tlsConfig := newTLSConfigWithRotation(testNs, "tlsconfig-rotation", "tls-rotation-secret", "1h", "720h")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig becomes ready")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("verifying the rotation configuration is set")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig)).To(Succeed())
			Expect(tlsConfig.Spec.Rotation).NotTo(BeNil())
			Expect(tlsConfig.Spec.Rotation.Enabled).NotTo(BeNil())
			Expect(*tlsConfig.Spec.Rotation.Enabled).To(BeTrue())

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(tlsSecret)
		})

		It("should handle TLSConfig with missing secret", func() {
			By("creating a TLSConfig referencing non-existent secret")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-missing-secret", "non-existent-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig enters error state")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusError, Timeout)
			waitForCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tlsConfig)
		})

		It("should handle TLSConfig with invalid certificate data", func() {
			By("creating a secret with invalid certificate data")
			invalidSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-cert-secret",
					Namespace: testNs,
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": []byte("not a valid certificate"),
					"tls.key": []byte("not a valid key"),
				},
			}
			Expect(k8sClient.Create(ctx, invalidSecret)).To(Succeed())

			By("creating a TLSConfig referencing the invalid secret")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-invalid-cert", "invalid-cert-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig enters error state")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusError, Timeout)
			waitForCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse, Timeout)

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(invalidSecret)
		})

		It("should handle TLSConfig with expired certificate", func() {
			By("creating a TLS secret with expired certificate")
			expiredSecret, err := createExpiredTLSSecret(testNs, "expired-tls-secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, expiredSecret)).To(Succeed())

			By("creating a TLSConfig referencing the expired secret")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-expired", "expired-tls-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig enters error state due to expired certificate")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusError, Timeout)

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(expiredSecret)
		})

		It("should handle TLSConfig with certificate expiring soon", func() {
			By("creating a TLS secret with certificate expiring in 7 days")
			expiringSoonSecret, err := createExpiringSoonTLSSecret(testNs, "expiring-soon-secret", 7)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, expiringSoonSecret)).To(Succeed())

			By("creating a TLSConfig with 30-day renewal threshold")
			tlsConfig := newTLSConfigWithRotation(testNs, "tlsconfig-expiring-soon", "expiring-soon-secret", "1h", "720h")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig enters degraded state")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusDegraded, Timeout)

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(expiringSoonSecret)
		})

		It("should handle TLSConfig with custom key names", func() {
			By("creating a secret with custom key names")
			customSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "custom-keys-secret",
					Namespace: testNs,
				},
				Type: corev1.SecretTypeOpaque,
			}

			// Generate certificate
			certPEM, keyPEM, err := generateSelfSignedCert([]string{"test.example.com"}, time.Now(), time.Now().Add(365*24*time.Hour))
			Expect(err).NotTo(HaveOccurred())

			customSecret.Data = map[string][]byte{
				"server.crt": certPEM,
				"server.key": keyPEM,
			}
			Expect(k8sClient.Create(ctx, customSecret)).To(Succeed())

			By("creating a TLSConfig with custom key names")
			tlsConfig := &avapigwv1alpha1.TLSConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tlsconfig-custom-keys",
					Namespace: testNs,
				},
				Spec: avapigwv1alpha1.TLSConfigSpec{
					CertificateSource: avapigwv1alpha1.CertificateSource{
						Secret: &avapigwv1alpha1.SecretCertificateSource{
							Name:    "custom-keys-secret",
							CertKey: stringPtr("server.crt"),
							KeyKey:  stringPtr("server.key"),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig becomes ready")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(customSecret)
		})

		It("should handle TLSConfig with missing certificate key", func() {
			By("creating a secret missing the certificate key")
			incompleteSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "incomplete-secret",
					Namespace: testNs,
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.key": []byte("some key data"),
					// Missing tls.crt
				},
			}
			Expect(k8sClient.Create(ctx, incompleteSecret)).To(Succeed())

			By("creating a TLSConfig referencing the incomplete secret")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-incomplete", "incomplete-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig enters error state")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusError, Timeout)

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(incompleteSecret)
		})
	})

	Context("when updating a TLSConfig", func() {
		It("should reconcile after secret is updated", func() {
			By("creating a TLS secret")
			tlsSecret, err := createTLSSecretWithCert(testNs, "update-tls-secret", []string{"old.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-update", "update-tls-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("recording the initial fingerprint")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig)).To(Succeed())
			initialFingerprint := ""
			if tlsConfig.Status.Certificate != nil && tlsConfig.Status.Certificate.Fingerprint != nil {
				initialFingerprint = *tlsConfig.Status.Certificate.Fingerprint
			}

			By("updating the secret with a new certificate")
			newCertPEM, newKeyPEM, err := generateSelfSignedCert([]string{"new.example.com"}, time.Now(), time.Now().Add(365*24*time.Hour))
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsSecret), tlsSecret)).To(Succeed())
			tlsSecret.Data["tls.crt"] = newCertPEM
			tlsSecret.Data["tls.key"] = newKeyPEM
			Expect(k8sClient.Update(ctx, tlsSecret)).To(Succeed())

			By("verifying the TLSConfig is updated with new certificate info")
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig); err != nil {
					return false
				}
				if tlsConfig.Status.Certificate == nil || tlsConfig.Status.Certificate.Fingerprint == nil {
					return false
				}
				// Fingerprint should change
				return *tlsConfig.Status.Certificate.Fingerprint != initialFingerprint
			}, LongTimeout, Interval).Should(BeTrue())

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(tlsSecret)
		})

		It("should reconcile after TLS version constraints are updated", func() {
			By("creating a TLS secret")
			tlsSecret, err := createTLSSecretWithCert(testNs, "version-update-secret", []string{"test.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig with TLS 1.2 minimum")
			tlsConfig := newTLSConfigWithVersions(testNs, "tlsconfig-version-update", "version-update-secret",
				avapigwv1alpha1.TLSVersion12, avapigwv1alpha1.TLSVersion13)
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("updating the TLSConfig to require TLS 1.3 minimum")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig)).To(Succeed())
			tls13 := avapigwv1alpha1.TLSVersion13
			tlsConfig.Spec.MinVersion = &tls13
			Expect(k8sClient.Update(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig is still ready")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("verifying the updated version constraint")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig)).To(Succeed())
			Expect(*tlsConfig.Spec.MinVersion).To(Equal(avapigwv1alpha1.TLSVersion13))

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(tlsSecret)
		})
	})

	Context("when deleting a TLSConfig", func() {
		It("should clean up properly", func() {
			By("creating a TLS secret")
			tlsSecret, err := createTLSSecretWithCert(testNs, "delete-tls-secret", []string{"test.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-delete", "delete-tls-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("deleting the TLSConfig")
			Expect(k8sClient.Delete(ctx, tlsConfig)).To(Succeed())

			By("verifying the TLSConfig is deleted")
			waitForDeletion(tlsConfig, Timeout)

			By("verifying the secret still exists")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsSecret), tlsSecret)).To(Succeed())

			By("cleaning up")
			cleanupResource(tlsSecret)
		})
	})

	Context("when secret is deleted", func() {
		It("should update TLSConfig status", func() {
			By("creating a TLS secret")
			tlsSecret, err := createTLSSecretWithCert(testNs, "secret-delete-test", []string{"test.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-secret-delete", "secret-delete-test")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("deleting the secret")
			Expect(k8sClient.Delete(ctx, tlsSecret)).To(Succeed())
			waitForDeletion(tlsSecret, Timeout)

			By("verifying the TLSConfig enters error state")
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusError, LongTimeout)

			By("cleaning up")
			cleanupResource(tlsConfig)
		})
	})

	Context("certificate information extraction", func() {
		It("should extract DNS names from certificate", func() {
			By("creating a TLS secret with multiple DNS names")
			tlsSecret, err := createTLSSecretWithCert(testNs, "multi-dns-secret",
				[]string{"api.example.com", "www.example.com", "admin.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-multi-dns", "multi-dns-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("verifying DNS names are extracted")
			Eventually(func() []string {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig); err != nil {
					return nil
				}
				if tlsConfig.Status.Certificate == nil {
					return nil
				}
				return tlsConfig.Status.Certificate.DNSNames
			}, Timeout, Interval).Should(ContainElements("api.example.com", "www.example.com", "admin.example.com"))

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(tlsSecret)
		})

		It("should extract issuer and subject from certificate", func() {
			By("creating a TLS secret")
			tlsSecret, err := createTLSSecretWithCert(testNs, "issuer-subject-secret", []string{"test.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-issuer-subject", "issuer-subject-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("verifying issuer and subject are extracted")
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig); err != nil {
					return false
				}
				if tlsConfig.Status.Certificate == nil {
					return false
				}
				return tlsConfig.Status.Certificate.Issuer != nil &&
					tlsConfig.Status.Certificate.Subject != nil &&
					*tlsConfig.Status.Certificate.Issuer != "" &&
					*tlsConfig.Status.Certificate.Subject != ""
			}, Timeout, Interval).Should(BeTrue())

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(tlsSecret)
		})

		It("should extract serial number and fingerprint from certificate", func() {
			By("creating a TLS secret")
			tlsSecret, err := createTLSSecretWithCert(testNs, "serial-fingerprint-secret", []string{"test.example.com"}, 365)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Create(ctx, tlsSecret)).To(Succeed())

			By("creating a TLSConfig")
			tlsConfig := newTLSConfig(testNs, "tlsconfig-serial-fingerprint", "serial-fingerprint-secret")
			Expect(k8sClient.Create(ctx, tlsConfig)).To(Succeed())
			waitForPhase(tlsConfig, avapigwv1alpha1.PhaseStatusReady, Timeout)

			By("verifying serial number and fingerprint are extracted")
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tlsConfig), tlsConfig); err != nil {
					return false
				}
				if tlsConfig.Status.Certificate == nil {
					return false
				}
				return tlsConfig.Status.Certificate.SerialNumber != nil &&
					tlsConfig.Status.Certificate.Fingerprint != nil &&
					*tlsConfig.Status.Certificate.SerialNumber != "" &&
					*tlsConfig.Status.Certificate.Fingerprint != ""
			}, Timeout, Interval).Should(BeTrue())

			By("cleaning up")
			cleanupResource(tlsConfig)
			cleanupResource(tlsSecret)
		})
	})
})
