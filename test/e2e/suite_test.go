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
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vault "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	testconfig "github.com/vyrodovalexey/avapigw/test/config"
)

// Test configuration constants for timeouts
const (
	// DefaultTimeout for test operations
	DefaultTimeout = 2 * time.Minute

	// DefaultInterval for polling
	DefaultInterval = time.Second

	// ShortTimeout for quick operations
	ShortTimeout = 30 * time.Second

	// LongTimeout for slow operations
	LongTimeout = 5 * time.Minute
)

// Global test variables
var (
	// Kubernetes clients
	cfg          *rest.Config
	k8sClient    client.Client
	k8sClientset *kubernetes.Clientset
	ctx          context.Context
	cancel       context.CancelFunc

	// Vault client
	vaultClient *vault.Client

	// Test configuration loaded from environment
	testConfig *testconfig.TestEnvConfig

	// Test namespace (convenience variable from testConfig)
	testNamespace string

	// Test state
	vaultSetupComplete bool
	pkiSetupComplete   bool
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)

	// Check if we should skip E2E tests
	if os.Getenv("SKIP_E2E") == "true" {
		t.Skip("Skipping E2E tests (SKIP_E2E=true)")
	}

	RunSpecs(t, "E2E Test Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.Background())

	By("Loading configuration from environment")
	loadConfiguration()

	By("Setting up Kubernetes client")
	setupKubernetesClient()

	By("Verifying CRDs are installed")
	verifyCRDsInstalled()

	By("Creating test namespace")
	createTestNamespace()

	By("Setting up Vault client")
	setupVaultClient()

	By("Verifying Vault connectivity")
	verifyVaultConnectivity()
})

var _ = AfterSuite(func() {
	By("Cleaning up test resources")
	cleanupTestResources()

	By("Deleting test namespace")
	deleteTestNamespace()

	cancel()
})

// loadConfiguration loads test configuration from environment variables using testconfig package
func loadConfiguration() {
	testConfig = testconfig.LoadTestEnvConfig()
	testNamespace = testConfig.TestNamespace

	GinkgoWriter.Printf("Configuration loaded:\n")
	GinkgoWriter.Printf("%s\n", testConfig.LogConfig())
}

// setupKubernetesClient initializes the Kubernetes client
func setupKubernetesClient() {
	var err error

	// Try to load kubeconfig
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}

	cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		// Try in-cluster config
		cfg, err = rest.InClusterConfig()
		Expect(err).NotTo(HaveOccurred(), "Failed to load kubeconfig")
	}
	Expect(cfg).NotTo(BeNil())

	// Register API types
	err = avapigwv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred(), "Failed to register API types")

	// Create controller-runtime client
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes client")
	Expect(k8sClient).NotTo(BeNil())

	// Create clientset for native operations
	k8sClientset, err = kubernetes.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred(), "Failed to create Kubernetes clientset")
	Expect(k8sClientset).NotTo(BeNil())

	GinkgoWriter.Printf("Kubernetes client initialized successfully\n")
}

// verifyCRDsInstalled checks that required CRDs are installed
func verifyCRDsInstalled() {
	// Try to list Gateways to verify CRD is installed
	gatewayList := &avapigwv1alpha1.GatewayList{}
	err := k8sClient.List(ctx, gatewayList)
	if err != nil {
		Skip("CRDs not installed. Run 'make install' first. Error: " + err.Error())
	}

	// Try to list VaultSecrets
	vaultSecretList := &avapigwv1alpha1.VaultSecretList{}
	err = k8sClient.List(ctx, vaultSecretList)
	if err != nil {
		Skip("VaultSecret CRD not installed. Run 'make install' first. Error: " + err.Error())
	}

	GinkgoWriter.Printf("CRDs verified successfully\n")
}

// createTestNamespace creates the test namespace
func createTestNamespace() {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "avapigw-e2e-test",
				"app.kubernetes.io/managed-by": "e2e-tests",
			},
		},
	}

	err := k8sClient.Create(ctx, ns)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")
	}

	// Wait for namespace to be active
	Eventually(func() bool {
		var namespace corev1.Namespace
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: testNamespace}, &namespace); err != nil {
			return false
		}
		return namespace.Status.Phase == corev1.NamespaceActive
	}, ShortTimeout, DefaultInterval).Should(BeTrue(), "Namespace should become active")

	GinkgoWriter.Printf("Test namespace '%s' created\n", testNamespace)
}

// setupVaultClient initializes the Vault client using test configuration
func setupVaultClient() {
	// Skip if Vault tests are disabled
	if testConfig.ShouldSkipVaultTests() {
		GinkgoWriter.Printf("Vault tests are skipped, not initializing Vault client\n")
		return
	}

	var err error
	vaultClient, err = testConfig.NewVaultClient()
	if err != nil {
		GinkgoWriter.Printf("Warning: Failed to create Vault client: %v\n", err)
		GinkgoWriter.Printf("Vault-related tests will be skipped\n")
		return
	}

	GinkgoWriter.Printf("Vault client initialized for %s\n", testConfig.VaultAddr)
}

// verifyVaultConnectivity checks that Vault is accessible
func verifyVaultConnectivity() {
	// Skip if Vault client is not initialized
	if vaultClient == nil {
		GinkgoWriter.Printf("Vault client not initialized, skipping connectivity check\n")
		return
	}

	health, err := vaultClient.Sys().Health()
	if err != nil {
		GinkgoWriter.Printf("Warning: Vault is not accessible: %v\n", err)
		GinkgoWriter.Printf("Vault-related tests will be skipped\n")
		vaultClient = nil
		return
	}

	if health.Sealed {
		GinkgoWriter.Printf("Warning: Vault is sealed\n")
		GinkgoWriter.Printf("Vault-related tests will be skipped\n")
		vaultClient = nil
		return
	}

	GinkgoWriter.Printf("Vault connectivity verified (initialized: %v, sealed: %v)\n",
		health.Initialized, health.Sealed)
}

// cleanupTestResources cleans up all test resources
func cleanupTestResources() {
	if k8sClient == nil {
		return
	}

	// Delete all VaultSecrets in test namespace
	vaultSecrets := &avapigwv1alpha1.VaultSecretList{}
	if err := k8sClient.List(ctx, vaultSecrets, client.InNamespace(testNamespace)); err == nil {
		for _, vs := range vaultSecrets.Items {
			_ = k8sClient.Delete(ctx, &vs)
		}
	}

	// Delete all Gateways in test namespace
	gateways := &avapigwv1alpha1.GatewayList{}
	if err := k8sClient.List(ctx, gateways, client.InNamespace(testNamespace)); err == nil {
		for _, gw := range gateways.Items {
			_ = k8sClient.Delete(ctx, &gw)
		}
	}

	// Delete all HTTPRoutes in test namespace
	routes := &avapigwv1alpha1.HTTPRouteList{}
	if err := k8sClient.List(ctx, routes, client.InNamespace(testNamespace)); err == nil {
		for _, r := range routes.Items {
			_ = k8sClient.Delete(ctx, &r)
		}
	}

	// Delete all Backends in test namespace
	backends := &avapigwv1alpha1.BackendList{}
	if err := k8sClient.List(ctx, backends, client.InNamespace(testNamespace)); err == nil {
		for _, b := range backends.Items {
			_ = k8sClient.Delete(ctx, &b)
		}
	}

	// Delete all TLSConfigs in test namespace
	tlsConfigs := &avapigwv1alpha1.TLSConfigList{}
	if err := k8sClient.List(ctx, tlsConfigs, client.InNamespace(testNamespace)); err == nil {
		for _, tc := range tlsConfigs.Items {
			_ = k8sClient.Delete(ctx, &tc)
		}
	}

	// Delete all Secrets in test namespace (except default ones)
	secrets := &corev1.SecretList{}
	if err := k8sClient.List(ctx, secrets, client.InNamespace(testNamespace)); err == nil {
		for _, s := range secrets.Items {
			if s.Type != corev1.SecretTypeServiceAccountToken {
				_ = k8sClient.Delete(ctx, &s)
			}
		}
	}

	// Wait for resources to be deleted
	time.Sleep(2 * time.Second)
	GinkgoWriter.Printf("Test resources cleaned up\n")
}

// deleteTestNamespace deletes the test namespace
func deleteTestNamespace() {
	if k8sClient == nil {
		return
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
		},
	}

	err := k8sClient.Delete(ctx, ns)
	if err != nil && !apierrors.IsNotFound(err) {
		GinkgoWriter.Printf("Warning: Failed to delete test namespace: %v\n", err)
	}

	GinkgoWriter.Printf("Test namespace '%s' deletion initiated\n", testNamespace)
}

// skipIfVaultNotAvailable skips the test if Vault is not available
func skipIfVaultNotAvailable() {
	if testConfig.ShouldSkipVaultTests() {
		Skip("Vault tests are skipped (SKIP_VAULT_TESTS=true)")
	}

	if vaultClient == nil {
		Skip("Vault client not initialized")
	}

	health, err := vaultClient.Sys().Health()
	if err != nil || health.Sealed {
		Skip("Vault is not available or sealed")
	}
}

// skipIfKubernetesAuthNotConfigured skips if K8s auth is not configured
func skipIfKubernetesAuthNotConfigured() {
	skipIfVaultNotAvailable()

	// Check if kubernetes auth is enabled
	auths, err := vaultClient.Sys().ListAuth()
	if err != nil {
		Skip("Cannot list auth methods: " + err.Error())
	}

	if _, ok := auths["kubernetes/"]; !ok {
		Skip("Kubernetes auth method not enabled in Vault")
	}
}

// skipIfKeycloakNotAvailable skips the test if Keycloak is not available
func skipIfKeycloakNotAvailable() {
	if testConfig.ShouldSkipKeycloakTests() {
		Skip("Keycloak tests are skipped (SKIP_KEYCLOAK_TESTS=true)")
	}

	if testConfig.KeycloakClientSecret == "" {
		Skip("Keycloak client secret not configured")
	}
}

// generateUniqueName generates a unique name for test resources
func generateUniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%100000)
}

// waitForCondition waits for a condition to be true
func waitForCondition(timeout time.Duration, condition func() bool, message string) {
	Eventually(condition, timeout, DefaultInterval).Should(BeTrue(), message)
}

// waitForResourceDeletion waits for a resource to be deleted
func waitForResourceDeletion(obj client.Object, timeout time.Duration) {
	Eventually(func() bool {
		err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)
		return apierrors.IsNotFound(err)
	}, timeout, DefaultInterval).Should(BeTrue(), "Resource should be deleted")
}

// getVaultAddr returns the Vault address from test configuration
func getVaultAddr() string {
	return testConfig.VaultAddr
}

// getVaultRole returns the Vault role from test configuration
func getVaultRole() string {
	return testConfig.VaultRole
}

// getTestConfig returns the test configuration
func getTestConfig() *testconfig.TestEnvConfig {
	return testConfig
}
