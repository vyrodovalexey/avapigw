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

	vault "github.com/hashicorp/vault/api"
)

var _ = Describe("Vault Setup", Ordered, func() {
	BeforeAll(func() {
		skipIfVaultNotAvailable()
	})

	Context("Vault Connectivity", func() {
		It("should verify Vault is accessible and unsealed", func() {
			health, err := vaultClient.Sys().Health()
			Expect(err).NotTo(HaveOccurred())
			Expect(health.Initialized).To(BeTrue(), "Vault should be initialized")
			Expect(health.Sealed).To(BeFalse(), "Vault should be unsealed")

			GinkgoWriter.Printf("Vault health: initialized=%v, sealed=%v, version=%s\n",
				health.Initialized, health.Sealed, health.Version)
		})

		It("should verify token is valid", func() {
			secret, err := vaultClient.Auth().Token().LookupSelf()
			Expect(err).NotTo(HaveOccurred())
			Expect(secret).NotTo(BeNil())
			Expect(secret.Data).NotTo(BeNil())

			GinkgoWriter.Printf("Token lookup successful\n")
		})
	})

	Context("KV v2 Secrets Engine", func() {
		It("should verify KV v2 secrets engine is enabled", func() {
			mounts, err := vaultClient.Sys().ListMounts()
			Expect(err).NotTo(HaveOccurred())

			// Check if secret/ mount exists
			secretMount, exists := mounts["secret/"]
			if !exists {
				// Enable KV v2 at secret/
				err = vaultClient.Sys().Mount("secret", &vault.MountInput{
					Type: "kv",
					Options: map[string]string{
						"version": "2",
					},
				})
				Expect(err).NotTo(HaveOccurred())
				GinkgoWriter.Printf("Enabled KV v2 secrets engine at secret/\n")
			} else {
				Expect(secretMount.Type).To(Equal("kv"), "secret/ should be KV type")
				GinkgoWriter.Printf("KV v2 secrets engine already enabled at secret/\n")
			}
		})

		It("should create test secrets in Vault", func() {
			testSecrets := map[string]map[string]interface{}{
				"avapigw/test/basic": {
					"username": "testuser",
					"password": "testpassword123",
				},
				"avapigw/test/database": {
					"host":     "db.example.com",
					"port":     "5432",
					"database": "testdb",
					"username": "dbuser",
					"password": "dbpassword",
				},
				"avapigw/test/api-keys": {
					"api_key":    "sk-test-12345",
					"api_secret": "secret-67890",
				},
				"avapigw/test/multikey": {
					"key1": "value1",
					"key2": "value2",
					"key3": "value3",
				},
			}

			for path, data := range testSecrets {
				createVaultKV2Secret(path, data)
				GinkgoWriter.Printf("Created test secret at %s\n", path)
			}

			// Verify secrets were created
			for path := range testSecrets {
				data, err := getVaultKV2Secret(path)
				Expect(err).NotTo(HaveOccurred())
				Expect(data).NotTo(BeEmpty())
			}
		})

		It("should read and verify test secrets", func() {
			data, err := getVaultKV2Secret("avapigw/test/basic")
			Expect(err).NotTo(HaveOccurred())
			Expect(data["username"]).To(Equal("testuser"))
			Expect(data["password"]).To(Equal("testpassword123"))
		})
	})

	Context("Kubernetes Auth Method", func() {
		It("should verify Kubernetes auth method is enabled", func() {
			auths, err := vaultClient.Sys().ListAuth()
			Expect(err).NotTo(HaveOccurred())

			k8sAuth, exists := auths["kubernetes/"]
			if !exists {
				Skip("Kubernetes auth method not enabled - skipping K8s auth tests")
			}

			Expect(k8sAuth.Type).To(Equal("kubernetes"))
			GinkgoWriter.Printf("Kubernetes auth method is enabled\n")
		})

		It("should verify Vault role exists", func() {
			skipIfKubernetesAuthNotConfigured()

			path := fmt.Sprintf("auth/kubernetes/role/%s", testConfig.VaultRole)
			secret, err := vaultClient.Logical().Read(path)
			if err != nil || secret == nil {
				Skip(fmt.Sprintf("Vault role '%s' not configured", testConfig.VaultRole))
			}

			GinkgoWriter.Printf("Vault role '%s' exists\n", testConfig.VaultRole)
		})
	})

	Context("PKI Secrets Engine", func() {
		var pkiMountPath = "pki"
		var pkiIntMountPath = "pki_int"

		It("should enable PKI secrets engine for root CA", func() {
			mounts, err := vaultClient.Sys().ListMounts()
			Expect(err).NotTo(HaveOccurred())

			if _, exists := mounts[pkiMountPath+"/"]; !exists {
				err = vaultClient.Sys().Mount(pkiMountPath, &vault.MountInput{
					Type: "pki",
					Config: vault.MountConfigInput{
						MaxLeaseTTL: "87600h", // 10 years
					},
				})
				Expect(err).NotTo(HaveOccurred())
				GinkgoWriter.Printf("Enabled PKI secrets engine at %s/\n", pkiMountPath)
			} else {
				GinkgoWriter.Printf("PKI secrets engine already enabled at %s/\n", pkiMountPath)
			}
		})

		It("should generate root CA certificate", func() {
			// Check if root CA already exists
			secret, err := vaultClient.Logical().Read(pkiMountPath + "/cert/ca")
			if err == nil && secret != nil && secret.Data["certificate"] != nil {
				GinkgoWriter.Printf("Root CA already exists\n")
				return
			}

			// Generate root CA
			_, err = vaultClient.Logical().Write(pkiMountPath+"/root/generate/internal", map[string]interface{}{
				"common_name": "E2E Test Root CA",
				"ttl":         "87600h",
				"issuer_name": "root-2024",
			})
			Expect(err).NotTo(HaveOccurred())
			GinkgoWriter.Printf("Generated root CA certificate\n")

			// Configure CA and CRL URLs
			_, err = vaultClient.Logical().Write(pkiMountPath+"/config/urls", map[string]interface{}{
				"issuing_certificates":    fmt.Sprintf("%s/v1/%s/ca", testConfig.VaultAddr, pkiMountPath),
				"crl_distribution_points": fmt.Sprintf("%s/v1/%s/crl", testConfig.VaultAddr, pkiMountPath),
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should enable intermediate PKI secrets engine", func() {
			mounts, err := vaultClient.Sys().ListMounts()
			Expect(err).NotTo(HaveOccurred())

			if _, exists := mounts[pkiIntMountPath+"/"]; !exists {
				err = vaultClient.Sys().Mount(pkiIntMountPath, &vault.MountInput{
					Type: "pki",
					Config: vault.MountConfigInput{
						MaxLeaseTTL: "43800h", // 5 years
					},
				})
				Expect(err).NotTo(HaveOccurred())
				GinkgoWriter.Printf("Enabled intermediate PKI at %s/\n", pkiIntMountPath)
			} else {
				GinkgoWriter.Printf("Intermediate PKI already enabled at %s/\n", pkiIntMountPath)
			}
		})

		It("should generate and sign intermediate CA", func() {
			// Check if intermediate CA already exists
			secret, err := vaultClient.Logical().Read(pkiIntMountPath + "/cert/ca")
			if err == nil && secret != nil && secret.Data["certificate"] != nil {
				GinkgoWriter.Printf("Intermediate CA already exists\n")
				return
			}

			// Generate intermediate CSR
			csrSecret, err := vaultClient.Logical().Write(pkiIntMountPath+"/intermediate/generate/internal", map[string]interface{}{
				"common_name": "E2E Test Intermediate CA",
				"issuer_name": "intermediate-2024",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(csrSecret.Data["csr"]).NotTo(BeNil())

			csr := csrSecret.Data["csr"].(string)

			// Sign intermediate with root
			signedSecret, err := vaultClient.Logical().Write(pkiMountPath+"/root/sign-intermediate", map[string]interface{}{
				"csr":         csr,
				"format":      "pem_bundle",
				"ttl":         "43800h",
				"common_name": "E2E Test Intermediate CA",
			})
			Expect(err).NotTo(HaveOccurred())

			// Set signed certificate
			_, err = vaultClient.Logical().Write(pkiIntMountPath+"/intermediate/set-signed", map[string]interface{}{
				"certificate": signedSecret.Data["certificate"],
			})
			Expect(err).NotTo(HaveOccurred())
			GinkgoWriter.Printf("Generated and signed intermediate CA\n")
		})

		It("should create PKI role for certificate issuance", func() {
			roleName := "e2e-test-role"

			_, err := vaultClient.Logical().Write(pkiIntMountPath+"/roles/"+roleName, map[string]interface{}{
				"allowed_domains":  []string{"example.com", "test.local", "localhost"},
				"allow_subdomains": true,
				"allow_localhost":  true,
				"allow_ip_sans":    true,
				"max_ttl":          "720h", // 30 days
				"ttl":              "24h",
			})
			Expect(err).NotTo(HaveOccurred())
			GinkgoWriter.Printf("Created PKI role '%s'\n", roleName)
		})

		It("should issue a test certificate", func() {
			secret, err := vaultClient.Logical().Write("pki_int/issue/e2e-test-role", map[string]interface{}{
				"common_name": "test.example.com",
				"ttl":         "1h",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data["certificate"]).NotTo(BeNil())
			Expect(secret.Data["private_key"]).NotTo(BeNil())
			Expect(secret.Data["ca_chain"]).NotTo(BeNil())

			GinkgoWriter.Printf("Successfully issued test certificate\n")
			pkiSetupComplete = true
		})
	})

	Context("Vault Policies", func() {
		It("should create test policy for avapigw", func() {
			policyName := "avapigw-e2e-test"
			policy := `
# Allow reading secrets for avapigw tests
path "secret/data/avapigw/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/avapigw/*" {
  capabilities = ["read", "list"]
}

# Allow issuing certificates
path "pki_int/issue/e2e-test-role" {
  capabilities = ["create", "update"]
}

# Allow reading PKI CA
path "pki_int/cert/ca" {
  capabilities = ["read"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}
`
			err := vaultClient.Sys().PutPolicy(policyName, policy)
			Expect(err).NotTo(HaveOccurred())
			GinkgoWriter.Printf("Created Vault policy '%s'\n", policyName)
		})

		It("should verify policy exists", func() {
			policy, err := vaultClient.Sys().GetPolicy("avapigw-e2e-test")
			Expect(err).NotTo(HaveOccurred())
			Expect(policy).NotTo(BeEmpty())
		})
	})

	AfterAll(func() {
		vaultSetupComplete = true
		GinkgoWriter.Printf("Vault setup completed successfully\n")
	})
})

// Helper to enable a secrets engine
func enableSecretsEngine(path, engineType string, options map[string]string) error {
	return vaultClient.Sys().Mount(path, &vault.MountInput{
		Type:    engineType,
		Options: options,
	})
}

// Helper to check if a secrets engine is enabled
func isSecretsEngineEnabled(path string) bool {
	mounts, err := vaultClient.Sys().ListMounts()
	if err != nil {
		return false
	}
	_, exists := mounts[path+"/"]
	return exists
}

// Helper to wait for Vault to be ready
func waitForVaultReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		health, err := vaultClient.Sys().Health()
		if err == nil && !health.Sealed && health.Initialized {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("vault not ready within %v", timeout)
}
