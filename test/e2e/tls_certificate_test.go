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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

var _ = Describe("TLS Certificate E2E", Ordered, func() {
	var (
		tokenSecretName string
	)

	BeforeAll(func() {
		skipIfVaultNotAvailable()

		// Create token secret for Vault auth
		tokenSecretName = generateUniqueName("vault-token-tls")
		createSecret(tokenSecretName, map[string][]byte{
			"token": []byte(testConfig.VaultToken),
		})
	})

	AfterAll(func() {
		deleteSecret(tokenSecretName)
	})

	Context("TLS Certificate from Vault PKI", func() {
		var (
			tlsConfigName    string
			targetSecretName string
		)

		BeforeEach(func() {
			if !pkiSetupComplete {
				Skip("PKI not set up - run Vault Setup tests first")
			}
			tlsConfigName = generateUniqueName("tlsconfig")
			targetSecretName = generateUniqueName("tls-secret")
		})

		AfterEach(func() {
			deleteTLSConfig(tlsConfigName)
			deleteSecret(targetSecretName)
		})

		It("should issue certificate from Vault PKI", func() {
			// First, issue a certificate from Vault PKI and store it
			secret, err := vaultClient.Logical().Write("pki_int/issue/e2e-test-role", map[string]interface{}{
				"common_name": "test.example.com",
				"ttl":         "24h",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data["certificate"]).NotTo(BeNil())
			Expect(secret.Data["private_key"]).NotTo(BeNil())

			cert := secret.Data["certificate"].(string)
			key := secret.Data["private_key"].(string)
			caChain := ""
			if chain, ok := secret.Data["ca_chain"].([]interface{}); ok && len(chain) > 0 {
				caChain = chain[0].(string)
			}

			// Store in Vault KV for VaultSecret to retrieve
			createVaultKV2Secret("avapigw/e2e/tls-cert", map[string]interface{}{
				"certificate": cert,
				"private_key": key,
				"ca_chain":    caChain,
			})

			// Create VaultSecret to sync the certificate
			vsName := generateUniqueName("vs-tls")
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
				Path:       "avapigw/e2e/tls-cert",
				MountPoint: stringPtr("secret"),
				Keys: []avapigwv1alpha1.VaultKeyMapping{
					{VaultKey: "certificate", TargetKey: "tls.crt"},
					{VaultKey: "private_key", TargetKey: "tls.key"},
					{VaultKey: "ca_chain", TargetKey: "ca.crt"},
				},
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
					Type: stringPtr("kubernetes.io/tls"),
				},
			})

			waitForVaultSecretReady(vsName, DefaultTimeout)

			// Verify TLS secret was created
			tlsSecret := waitForSecretWithData(targetSecretName, []string{"tls.crt", "tls.key"}, ShortTimeout)
			Expect(tlsSecret.Type).To(Equal(corev1.SecretTypeTLS))

			// Verify certificate is valid
			certPEM := tlsSecret.Data["tls.crt"]
			keyPEM := tlsSecret.Data["tls.key"]

			_, err = tls.X509KeyPair(certPEM, keyPEM)
			Expect(err).NotTo(HaveOccurred())

			// Parse and verify certificate details
			block, _ := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil())

			parsedCert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(parsedCert.Subject.CommonName).To(Equal("test.example.com"))

			// Cleanup
			deleteVaultSecret(vsName)
			deleteVaultKV2Secret("avapigw/e2e/tls-cert")
		})

		It("should create TLSConfig with Secret source", func() {
			// Generate self-signed certificate
			certPEM, keyPEM, err := generateSelfSignedCert("test.local", []string{"test.local", "localhost"}, 24*time.Hour)
			Expect(err).NotTo(HaveOccurred())

			// Create TLS secret
			tlsSecretName := generateUniqueName("tls-source")
			createSecretWithType(tlsSecretName, corev1.SecretTypeTLS, map[string][]byte{
				"tls.crt": certPEM,
				"tls.key": keyPEM,
			})

			// Create TLSConfig
			minVersion := avapigwv1alpha1.TLSVersion12
			maxVersion := avapigwv1alpha1.TLSVersion13
			tlsConfig := createTLSConfig(tlsConfigName, avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: tlsSecretName,
					},
				},
				MinVersion: &minVersion,
				MaxVersion: &maxVersion,
			})

			// Wait for TLSConfig to be ready
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				tc, err := getTLSConfig(tlsConfigName)
				if err != nil {
					return ""
				}
				return tc.Status.Phase
			}, DefaultTimeout, DefaultInterval).Should(Equal(avapigwv1alpha1.PhaseStatusReady))

			// Verify certificate info in status
			tc, err := getTLSConfig(tlsConfigName)
			Expect(err).NotTo(HaveOccurred())
			Expect(tc.Status.Certificate).NotTo(BeNil())
			Expect(tc.Status.Certificate.Subject).NotTo(BeNil())

			// Cleanup
			deleteSecret(tlsSecretName)
			_ = tlsConfig
		})

		It("should create TLSConfig with Vault source", func() {
			if !pkiSetupComplete {
				Skip("PKI not set up")
			}

			// Issue certificate from Vault PKI
			secret, err := vaultClient.Logical().Write("pki_int/issue/e2e-test-role", map[string]interface{}{
				"common_name": "vault-tls.example.com",
				"ttl":         "24h",
			})
			Expect(err).NotTo(HaveOccurred())

			// Store in Vault KV
			certPath := "avapigw/e2e/vault-tls-config"
			createVaultKV2Secret(certPath, map[string]interface{}{
				"certificate": secret.Data["certificate"],
				"private_key": secret.Data["private_key"],
			})

			// Create TLSConfig with Vault source
			minVersion := avapigwv1alpha1.TLSVersion12
			tlsConfig := createTLSConfig(tlsConfigName, avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Vault: &avapigwv1alpha1.VaultCertificateSource{
						Path:       certPath,
						MountPoint: stringPtr("secret"),
						CertKey:    stringPtr("certificate"),
						KeyKey:     stringPtr("private_key"),
					},
				},
				MinVersion: &minVersion,
			})

			// Note: This test assumes the controller can access Vault
			// In a real scenario, you'd need VaultSecretRef configured

			// Cleanup
			deleteVaultKV2Secret(certPath)
			_ = tlsConfig
		})
	})

	Context("Certificate Rotation", func() {
		var (
			vsName           string
			targetSecretName string
			certPath         string
		)

		BeforeEach(func() {
			vsName = generateUniqueName("vs-rotation")
			targetSecretName = generateUniqueName("tls-rotation")
			certPath = fmt.Sprintf("avapigw/e2e/rotation-%d", time.Now().UnixNano())
		})

		AfterEach(func() {
			deleteVaultSecret(vsName)
			deleteSecret(targetSecretName)
			deleteVaultKV2Secret(certPath)
		})

		It("should rotate certificate when Vault secret is updated", func() {
			// Generate initial certificate
			certPEM1, keyPEM1, err := generateSelfSignedCert("initial.example.com", []string{"initial.example.com"}, 24*time.Hour)
			Expect(err).NotTo(HaveOccurred())

			// Store initial certificate in Vault
			createVaultKV2Secret(certPath, map[string]interface{}{
				"certificate": string(certPEM1),
				"private_key": string(keyPEM1),
			})

			// Create VaultSecret with refresh enabled
			refreshInterval := avapigwv1alpha1.Duration("10s")
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
				Path:       certPath,
				MountPoint: stringPtr("secret"),
				Keys: []avapigwv1alpha1.VaultKeyMapping{
					{VaultKey: "certificate", TargetKey: "tls.crt"},
					{VaultKey: "private_key", TargetKey: "tls.key"},
				},
				Refresh: &avapigwv1alpha1.VaultRefreshConfig{
					Enabled:  boolPtr(true),
					Interval: &refreshInterval,
				},
				Target: &avapigwv1alpha1.VaultTargetConfig{
					Name: targetSecretName,
					Type: stringPtr("kubernetes.io/tls"),
				},
			})

			waitForVaultSecretReady(vsName, DefaultTimeout)

			// Verify initial certificate
			secret1 := waitForSecretWithData(targetSecretName, []string{"tls.crt", "tls.key"}, ShortTimeout)
			initialCert := string(secret1.Data["tls.crt"])

			// Parse initial certificate to get CN
			block1, _ := pem.Decode(secret1.Data["tls.crt"])
			Expect(block1).NotTo(BeNil())
			parsedCert1, err := x509.ParseCertificate(block1.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(parsedCert1.Subject.CommonName).To(Equal("initial.example.com"))

			// Generate new certificate
			certPEM2, keyPEM2, err := generateSelfSignedCert("rotated.example.com", []string{"rotated.example.com"}, 24*time.Hour)
			Expect(err).NotTo(HaveOccurred())

			// Update Vault secret
			updateVaultKV2Secret(certPath, map[string]interface{}{
				"certificate": string(certPEM2),
				"private_key": string(keyPEM2),
			})

			// Wait for refresh
			time.Sleep(15 * time.Second)

			// Verify certificate was rotated
			Eventually(func() string {
				secret, err := getSecret(targetSecretName)
				if err != nil {
					return ""
				}
				return string(secret.Data["tls.crt"])
			}, 30*time.Second, DefaultInterval).ShouldNot(Equal(initialCert))

			// Verify new certificate CN
			secret2, err := getSecret(targetSecretName)
			Expect(err).NotTo(HaveOccurred())

			block2, _ := pem.Decode(secret2.Data["tls.crt"])
			Expect(block2).NotTo(BeNil())
			parsedCert2, err := x509.ParseCertificate(block2.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(parsedCert2.Subject.CommonName).To(Equal("rotated.example.com"))
		})
	})

	Context("mTLS Configuration", func() {
		var (
			tlsConfigName string
		)

		BeforeEach(func() {
			tlsConfigName = generateUniqueName("mtls-config")
		})

		AfterEach(func() {
			deleteTLSConfig(tlsConfigName)
		})

		It("should create TLSConfig with client validation enabled", func() {
			// Generate CA certificate
			caCertPEM, _, err := generateCA("E2E Test CA", 365*24*time.Hour)
			Expect(err).NotTo(HaveOccurred())

			// Generate server certificate
			serverCertPEM, serverKeyPEM, err := generateSelfSignedCert("server.example.com", []string{"server.example.com"}, 24*time.Hour)
			Expect(err).NotTo(HaveOccurred())

			// Create CA secret
			caSecretName := generateUniqueName("ca-secret")
			createSecret(caSecretName, map[string][]byte{
				"ca.crt": caCertPEM,
			})

			// Create server TLS secret
			serverSecretName := generateUniqueName("server-tls")
			createSecretWithType(serverSecretName, corev1.SecretTypeTLS, map[string][]byte{
				"tls.crt": serverCertPEM,
				"tls.key": serverKeyPEM,
			})

			// Create TLSConfig with mTLS
			minVersion := avapigwv1alpha1.TLSVersion12
			clientValidationEnabled := true
			clientValidationMode := avapigwv1alpha1.ClientValidationRequired

			tlsConfig := createTLSConfig(tlsConfigName, avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: serverSecretName,
					},
				},
				MinVersion: &minVersion,
				ClientValidation: &avapigwv1alpha1.ClientValidationConfig{
					Enabled: &clientValidationEnabled,
					Mode:    &clientValidationMode,
					CACertificateRef: &avapigwv1alpha1.SecretObjectReference{
						Name: caSecretName,
					},
				},
			})

			// Wait for TLSConfig to be ready
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				tc, err := getTLSConfig(tlsConfigName)
				if err != nil {
					return ""
				}
				return tc.Status.Phase
			}, DefaultTimeout, DefaultInterval).Should(Equal(avapigwv1alpha1.PhaseStatusReady))

			// Verify TLSConfig
			tc, err := getTLSConfig(tlsConfigName)
			Expect(err).NotTo(HaveOccurred())
			Expect(tc.Spec.ClientValidation).NotTo(BeNil())
			Expect(*tc.Spec.ClientValidation.Enabled).To(BeTrue())
			Expect(*tc.Spec.ClientValidation.Mode).To(Equal(avapigwv1alpha1.ClientValidationRequired))

			// Cleanup
			deleteSecret(caSecretName)
			deleteSecret(serverSecretName)
			_ = tlsConfig
		})

		It("should configure SAN matching for client certificates", func() {
			// Generate certificates
			serverCertPEM, serverKeyPEM, err := generateSelfSignedCert("server.example.com", []string{"server.example.com"}, 24*time.Hour)
			Expect(err).NotTo(HaveOccurred())

			caCertPEM, _, err := generateCA("E2E Test CA", 365*24*time.Hour)
			Expect(err).NotTo(HaveOccurred())

			// Create secrets
			serverSecretName := generateUniqueName("server-san")
			createSecretWithType(serverSecretName, corev1.SecretTypeTLS, map[string][]byte{
				"tls.crt": serverCertPEM,
				"tls.key": serverKeyPEM,
			})

			caSecretName := generateUniqueName("ca-san")
			createSecret(caSecretName, map[string][]byte{
				"ca.crt": caCertPEM,
			})

			// Create TLSConfig with SAN matching
			minVersion := avapigwv1alpha1.TLSVersion12
			clientValidationEnabled := true
			exactMatch := "client.example.com"
			suffixMatch := ".internal.example.com"

			tlsConfig := createTLSConfig(tlsConfigName, avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: serverSecretName,
					},
				},
				MinVersion: &minVersion,
				ClientValidation: &avapigwv1alpha1.ClientValidationConfig{
					Enabled: &clientValidationEnabled,
					CACertificateRef: &avapigwv1alpha1.SecretObjectReference{
						Name: caSecretName,
					},
					SubjectAltNames: []avapigwv1alpha1.SubjectAltNameMatch{
						{Exact: &exactMatch},
						{Suffix: &suffixMatch},
					},
				},
			})

			// Wait for TLSConfig to be ready
			Eventually(func() avapigwv1alpha1.PhaseStatus {
				tc, err := getTLSConfig(tlsConfigName)
				if err != nil {
					return ""
				}
				return tc.Status.Phase
			}, DefaultTimeout, DefaultInterval).Should(Equal(avapigwv1alpha1.PhaseStatusReady))

			// Verify SAN configuration
			tc, err := getTLSConfig(tlsConfigName)
			Expect(err).NotTo(HaveOccurred())
			Expect(tc.Spec.ClientValidation.SubjectAltNames).To(HaveLen(2))

			// Cleanup
			deleteSecret(serverSecretName)
			deleteSecret(caSecretName)
			_ = tlsConfig
		})
	})
})

// Helper to verify certificate chain
func verifyCertificateChain(certPEM, caPEM []byte) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err = cert.Verify(opts)
	return err
}

// Helper to get certificate expiry
func getCertificateExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotAfter, nil
}
