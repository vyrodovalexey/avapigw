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
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vault "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Constants for Vault Kubernetes authentication setup
const (
	// testServiceAccountName is the name of the service account used for testing
	testServiceAccountName = "avapigw-test-sa"

	// vaultPolicyName is the name of the Vault policy for E2E tests
	vaultPolicyName = "avapigw-e2e-test"

	// kubernetesAuthPath is the path where Kubernetes auth is mounted in Vault
	kubernetesAuthPath = "kubernetes"
)

var _ = Describe("Vault Kubernetes Authentication Setup", Ordered, func() {
	BeforeAll(func() {
		if testConfig.ShouldSkipVaultTests() {
			Skip("Vault tests are skipped (SKIP_VAULT_TESTS=true)")
		}

		if vaultClient == nil {
			Skip("Vault client not initialized")
		}
	})

	Context("Enable Kubernetes Auth Method", func() {
		It("should check if kubernetes auth is already enabled", func() {
			auths, err := vaultClient.Sys().ListAuth()
			Expect(err).NotTo(HaveOccurred(), "Failed to list auth methods")

			if _, exists := auths[kubernetesAuthPath+"/"]; exists {
				GinkgoWriter.Printf("Kubernetes auth method already enabled at %s/\n", kubernetesAuthPath)
			} else {
				GinkgoWriter.Printf("Kubernetes auth method not yet enabled\n")
			}
		})

		It("should enable kubernetes auth method if not already enabled", func() {
			err := enableKubernetesAuth()
			Expect(err).NotTo(HaveOccurred(), "Failed to enable Kubernetes auth method")

			// Verify it's enabled
			auths, err := vaultClient.Sys().ListAuth()
			Expect(err).NotTo(HaveOccurred())
			Expect(auths).To(HaveKey(kubernetesAuthPath + "/"))

			GinkgoWriter.Printf("Kubernetes auth method is enabled at %s/\n", kubernetesAuthPath)
		})
	})

	Context("Configure Kubernetes Auth", func() {
		It("should configure kubernetes auth method with K8s details", func() {
			err := configureKubernetesAuth()
			Expect(err).NotTo(HaveOccurred(), "Failed to configure Kubernetes auth method")

			// Verify configuration was applied
			secret, err := vaultClient.Logical().Read("auth/kubernetes/config")
			Expect(err).NotTo(HaveOccurred())
			Expect(secret).NotTo(BeNil())

			GinkgoWriter.Printf("Kubernetes auth method configured successfully\n")
			GinkgoWriter.Printf("  kubernetes_host: %s\n", testConfig.K8sAPIServer)
			if testConfig.K8sCACert != "" {
				GinkgoWriter.Printf("  kubernetes_ca_cert: <certificate present>\n")
			}
		})
	})

	Context("Create Test Policy", func() {
		It("should create Vault policy for E2E tests", func() {
			err := createVaultPolicyForK8sAuth()
			Expect(err).NotTo(HaveOccurred(), "Failed to create Vault policy")

			// Verify policy exists
			policy, err := vaultClient.Sys().GetPolicy(vaultPolicyName)
			Expect(err).NotTo(HaveOccurred())
			Expect(policy).NotTo(BeEmpty())

			GinkgoWriter.Printf("Vault policy '%s' created successfully\n", vaultPolicyName)
		})
	})

	Context("Create Test Role", func() {
		It("should create Vault role for test service account", func() {
			err := createVaultRoleForK8sAuth()
			Expect(err).NotTo(HaveOccurred(), "Failed to create Vault role")

			// Verify role exists
			path := fmt.Sprintf("auth/kubernetes/role/%s", testConfig.VaultRole)
			secret, err := vaultClient.Logical().Read(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret).NotTo(BeNil())

			GinkgoWriter.Printf("Vault role '%s' created successfully\n", testConfig.VaultRole)
			GinkgoWriter.Printf("  bound_service_account_names: [default, %s]\n", testServiceAccountName)
			GinkgoWriter.Printf("  bound_service_account_namespaces: [%s]\n", testConfig.TestNamespace)
			GinkgoWriter.Printf("  policies: [%s]\n", vaultPolicyName)
		})
	})

	Context("Create Test Service Account in K8s", func() {
		It("should create ServiceAccount for testing", func() {
			err := createTestServiceAccount()
			Expect(err).NotTo(HaveOccurred(), "Failed to create test service account")

			// Verify service account exists
			sa := &corev1.ServiceAccount{}
			err = k8sClient.Get(ctx, client.ObjectKey{
				Name:      testServiceAccountName,
				Namespace: testNamespace,
			}, sa)
			Expect(err).NotTo(HaveOccurred())

			GinkgoWriter.Printf("ServiceAccount '%s' created in namespace '%s'\n", testServiceAccountName, testNamespace)
		})

		It("should create ClusterRoleBinding for the service account", func() {
			err := createTestClusterRoleBinding()
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			// Verify ClusterRoleBinding exists
			crb := &rbacv1.ClusterRoleBinding{}
			err = k8sClient.Get(ctx, client.ObjectKey{
				Name: fmt.Sprintf("%s-auth-delegator", testServiceAccountName),
			}, crb)
			Expect(err).NotTo(HaveOccurred())

			GinkgoWriter.Printf("ClusterRoleBinding '%s-auth-delegator' created\n", testServiceAccountName)
		})

		It("should create a token secret for the service account", func() {
			err := createServiceAccountTokenSecret()
			Expect(err).NotTo(HaveOccurred(), "Failed to create token secret")

			// Wait for the token to be populated
			Eventually(func() bool {
				secret := &corev1.Secret{}
				err := k8sClient.Get(ctx, client.ObjectKey{
					Name:      fmt.Sprintf("%s-token", testServiceAccountName),
					Namespace: testNamespace,
				}, secret)
				if err != nil {
					return false
				}
				_, hasToken := secret.Data["token"]
				return hasToken
			}, ShortTimeout, DefaultInterval).Should(BeTrue(), "Token secret should have token data")

			GinkgoWriter.Printf("Token secret '%s-token' created and populated\n", testServiceAccountName)
		})
	})

	Context("Verify Authentication Works", func() {
		It("should get service account token from K8s", func() {
			token, err := getServiceAccountToken()
			Expect(err).NotTo(HaveOccurred(), "Failed to get service account token")
			Expect(token).NotTo(BeEmpty())

			GinkgoWriter.Printf("Successfully retrieved service account token (length: %d)\n", len(token))
		})

		It("should authenticate to Vault using the service account token", func() {
			err := testKubernetesAuth()
			Expect(err).NotTo(HaveOccurred(), "Failed to authenticate to Vault using Kubernetes auth")

			GinkgoWriter.Printf("Successfully authenticated to Vault using Kubernetes auth\n")
		})
	})

	AfterAll(func() {
		GinkgoWriter.Printf("Vault Kubernetes authentication setup completed\n")
	})
})

// enableKubernetesAuth enables the Kubernetes auth method in Vault if not already enabled.
func enableKubernetesAuth() error {
	auths, err := vaultClient.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("failed to list auth methods: %w", err)
	}

	// Check if already enabled
	if _, exists := auths[kubernetesAuthPath+"/"]; exists {
		GinkgoWriter.Printf("Kubernetes auth method already enabled, skipping\n")
		return nil
	}

	// Enable Kubernetes auth method
	err = vaultClient.Sys().EnableAuthWithOptions(kubernetesAuthPath, &vault.EnableAuthOptions{
		Type: "kubernetes",
	})
	if err != nil {
		return fmt.Errorf("failed to enable kubernetes auth: %w", err)
	}

	GinkgoWriter.Printf("Enabled Kubernetes auth method at %s/\n", kubernetesAuthPath)
	return nil
}

// configureKubernetesAuth configures the Kubernetes auth method with K8s cluster details.
func configureKubernetesAuth() error {
	configData := map[string]interface{}{
		"kubernetes_host":      testConfig.K8sAPIServer,
		"disable_local_ca_jwt": true, // Required for external K8s clusters
	}

	// Add CA certificate if provided
	if testConfig.K8sCACert != "" {
		configData["kubernetes_ca_cert"] = testConfig.K8sCACert
	}

	_, err := vaultClient.Logical().Write("auth/kubernetes/config", configData)
	if err != nil {
		return fmt.Errorf("failed to configure kubernetes auth: %w", err)
	}

	return nil
}

// createVaultPolicyForK8sAuth creates the Vault policy for E2E tests.
func createVaultPolicyForK8sAuth() error {
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

	err := vaultClient.Sys().PutPolicy(vaultPolicyName, policy)
	if err != nil {
		return fmt.Errorf("failed to create vault policy: %w", err)
	}

	return nil
}

// createVaultRoleForK8sAuth creates the Vault role for the test service account.
func createVaultRoleForK8sAuth() error {
	rolePath := fmt.Sprintf("auth/kubernetes/role/%s", testConfig.VaultRole)

	roleData := map[string]interface{}{
		"bound_service_account_names":      []string{"default", testServiceAccountName},
		"bound_service_account_namespaces": []string{testConfig.TestNamespace},
		"policies":                         []string{vaultPolicyName},
		"ttl":                              "1h",
		"max_ttl":                          "4h",
	}

	_, err := vaultClient.Logical().Write(rolePath, roleData)
	if err != nil {
		return fmt.Errorf("failed to create vault role: %w", err)
	}

	return nil
}

// createTestServiceAccount creates the test ServiceAccount in Kubernetes.
func createTestServiceAccount() error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testServiceAccountName,
			Namespace: testNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "avapigw-e2e-test",
				"app.kubernetes.io/managed-by": "e2e-tests",
			},
		},
	}

	err := k8sClient.Create(ctx, sa)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			GinkgoWriter.Printf("ServiceAccount '%s' already exists, skipping creation\n", testServiceAccountName)
			return nil
		}
		return fmt.Errorf("failed to create service account: %w", err)
	}

	return nil
}

// createTestClusterRoleBinding creates a ClusterRoleBinding for the test service account.
// This allows the service account to authenticate with the Kubernetes API.
func createTestClusterRoleBinding() error {
	crbName := fmt.Sprintf("%s-auth-delegator", testServiceAccountName)

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: crbName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "avapigw-e2e-test",
				"app.kubernetes.io/managed-by": "e2e-tests",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:auth-delegator",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      testServiceAccountName,
				Namespace: testNamespace,
			},
		},
	}

	err := k8sClient.Create(ctx, crb)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			GinkgoWriter.Printf("ClusterRoleBinding '%s' already exists, skipping creation\n", crbName)
			return nil
		}
		return fmt.Errorf("failed to create cluster role binding: %w", err)
	}

	return nil
}

// createServiceAccountTokenSecret creates a token secret for the service account.
// In Kubernetes 1.24+, tokens are not automatically created for service accounts.
func createServiceAccountTokenSecret() error {
	secretName := fmt.Sprintf("%s-token", testServiceAccountName)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: testNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "avapigw-e2e-test",
				"app.kubernetes.io/managed-by": "e2e-tests",
			},
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": testServiceAccountName,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}

	err := k8sClient.Create(ctx, secret)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			GinkgoWriter.Printf("Token secret '%s' already exists, skipping creation\n", secretName)
			return nil
		}
		return fmt.Errorf("failed to create token secret: %w", err)
	}

	return nil
}

// getServiceAccountToken retrieves the service account token from Kubernetes.
func getServiceAccountToken() (string, error) {
	secretName := fmt.Sprintf("%s-token", testServiceAccountName)

	// Create a new context with timeout for this operation
	tokenCtx, cancel := context.WithTimeout(context.Background(), ShortTimeout)
	defer cancel()

	for {
		select {
		case <-tokenCtx.Done():
			return "", fmt.Errorf("timeout waiting for service account token")
		default:
			secret := &corev1.Secret{}
			err := k8sClient.Get(tokenCtx, client.ObjectKey{
				Name:      secretName,
				Namespace: testNamespace,
			}, secret)
			if err != nil {
				time.Sleep(DefaultInterval)
				continue
			}

			tokenBytes, ok := secret.Data["token"]
			if !ok || len(tokenBytes) == 0 {
				time.Sleep(DefaultInterval)
				continue
			}

			return string(tokenBytes), nil
		}
	}
}

// testKubernetesAuth tests the Kubernetes authentication flow with Vault.
func testKubernetesAuth() error {
	// Get the service account token
	token, err := getServiceAccountToken()
	if err != nil {
		return fmt.Errorf("failed to get service account token: %w", err)
	}

	// Attempt to authenticate to Vault using the Kubernetes auth method
	authPath := fmt.Sprintf("auth/%s/login", kubernetesAuthPath)
	authData := map[string]interface{}{
		"role": testConfig.VaultRole,
		"jwt":  token,
	}

	secret, err := vaultClient.Logical().Write(authPath, authData)
	if err != nil {
		return fmt.Errorf("failed to authenticate to vault: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("authentication succeeded but no auth info returned")
	}

	// Verify we got a valid token
	if secret.Auth.ClientToken == "" {
		return fmt.Errorf("authentication succeeded but no client token returned")
	}

	// Safely print token info (handle short tokens)
	clientToken := secret.Auth.ClientToken
	tokenDisplay := clientToken
	if len(clientToken) > 12 {
		tokenDisplay = clientToken[:8] + "..." + clientToken[len(clientToken)-4:]
	}

	GinkgoWriter.Printf("Vault authentication successful:\n")
	GinkgoWriter.Printf("  Client Token: %s\n", tokenDisplay)
	GinkgoWriter.Printf("  Policies: %v\n", secret.Auth.Policies)
	GinkgoWriter.Printf("  Token TTL: %d seconds\n", secret.Auth.LeaseDuration)

	return nil
}
