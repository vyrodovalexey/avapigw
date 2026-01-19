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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"

	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// Kubernetes Resource Helpers
// ============================================================================

// createSecret creates a Kubernetes Secret
func createSecret(name string, data map[string][]byte) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Data: data,
	}

	err := k8sClient.Create(ctx, secret)
	Expect(err).NotTo(HaveOccurred(), "Failed to create secret %s", name)

	return secret
}

// createSecretWithType creates a Kubernetes Secret with a specific type
func createSecretWithType(name string, secretType corev1.SecretType, data map[string][]byte) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Type: secretType,
		Data: data,
	}

	err := k8sClient.Create(ctx, secret)
	Expect(err).NotTo(HaveOccurred(), "Failed to create secret %s", name)

	return secret
}

// getSecret retrieves a Kubernetes Secret
func getSecret(name string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: testNamespace,
	}, secret)
	return secret, err
}

// deleteSecret deletes a Kubernetes Secret
func deleteSecret(name string) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
	}
	_ = k8sClient.Delete(ctx, secret)
}

// waitForSecret waits for a secret to exist
func waitForSecret(name string, timeout time.Duration) *corev1.Secret {
	var secret *corev1.Secret
	Eventually(func() error {
		var err error
		secret, err = getSecret(name)
		return err
	}, timeout, DefaultInterval).Should(Succeed(), "Secret %s should exist", name)
	return secret
}

// waitForSecretWithData waits for a secret to exist with specific data keys
func waitForSecretWithData(name string, keys []string, timeout time.Duration) *corev1.Secret {
	var secret *corev1.Secret
	Eventually(func() bool {
		var err error
		secret, err = getSecret(name)
		if err != nil {
			return false
		}
		for _, key := range keys {
			if _, ok := secret.Data[key]; !ok {
				return false
			}
		}
		return true
	}, timeout, DefaultInterval).Should(BeTrue(), "Secret %s should have keys %v", name, keys)
	return secret
}

// createService creates a Kubernetes Service
func createService(name string, port int32, targetPort int32) *corev1.Service {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       port,
					TargetPort: intstr.FromInt32(targetPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"app": name,
			},
		},
	}

	err := k8sClient.Create(ctx, service)
	Expect(err).NotTo(HaveOccurred(), "Failed to create service %s", name)

	return service
}

// createPod creates a simple test pod
func createPod(name string, image string, port int32) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels: map[string]string{
				"app": name,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "main",
					Image: image,
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: port,
						},
					},
				},
			},
		},
	}

	err := k8sClient.Create(ctx, pod)
	Expect(err).NotTo(HaveOccurred(), "Failed to create pod %s", name)

	return pod
}

// waitForPodReady waits for a pod to be ready
func waitForPodReady(name string, timeout time.Duration) {
	Eventually(func() bool {
		pod := &corev1.Pod{}
		err := k8sClient.Get(ctx, client.ObjectKey{
			Name:      name,
			Namespace: testNamespace,
		}, pod)
		if err != nil {
			return false
		}
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				return true
			}
		}
		return false
	}, timeout, DefaultInterval).Should(BeTrue(), "Pod %s should be ready", name)
}

// ============================================================================
// VaultSecret Helpers
// ============================================================================

// createVaultSecret creates a VaultSecret resource
func createVaultSecret(name string, spec avapigwv1alpha1.VaultSecretSpec) *avapigwv1alpha1.VaultSecret {
	vs := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: spec,
	}

	err := k8sClient.Create(ctx, vs)
	Expect(err).NotTo(HaveOccurred(), "Failed to create VaultSecret %s", name)

	return vs
}

// createVaultSecretWithDefaults creates a VaultSecret with default configuration from testConfig
func createVaultSecretWithDefaults(name, path, targetSecretName string) *avapigwv1alpha1.VaultSecret {
	spec := avapigwv1alpha1.VaultSecretSpec{
		VaultConnection: avapigwv1alpha1.VaultConnectionConfig{
			Address: testConfig.VaultAddr,
			Auth: avapigwv1alpha1.VaultAuthConfig{
				Kubernetes: &avapigwv1alpha1.KubernetesAuthConfig{
					Role: testConfig.VaultRole,
				},
			},
		},
		Path: path,
		Target: &avapigwv1alpha1.VaultTargetConfig{
			Name: targetSecretName,
		},
	}
	return createVaultSecret(name, spec)
}

// getVaultSecret retrieves a VaultSecret resource
func getVaultSecret(name string) (*avapigwv1alpha1.VaultSecret, error) {
	vs := &avapigwv1alpha1.VaultSecret{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: testNamespace,
	}, vs)
	return vs, err
}

// deleteVaultSecret deletes a VaultSecret resource
func deleteVaultSecret(name string) {
	vs := &avapigwv1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
	}
	_ = k8sClient.Delete(ctx, vs)
}

// waitForVaultSecretReady waits for a VaultSecret to be ready
func waitForVaultSecretReady(name string, timeout time.Duration) *avapigwv1alpha1.VaultSecret {
	var vs *avapigwv1alpha1.VaultSecret
	Eventually(func() bool {
		var err error
		vs, err = getVaultSecret(name)
		if err != nil {
			return false
		}
		return vs.Status.Phase == avapigwv1alpha1.PhaseStatusReady
	}, timeout, DefaultInterval).Should(BeTrue(), "VaultSecret %s should be ready", name)
	return vs
}

// waitForVaultSecretPhase waits for a VaultSecret to reach a specific phase
func waitForVaultSecretPhase(name string, phase avapigwv1alpha1.PhaseStatus, timeout time.Duration) {
	Eventually(func() avapigwv1alpha1.PhaseStatus {
		vs, err := getVaultSecret(name)
		if err != nil {
			return ""
		}
		return vs.Status.Phase
	}, timeout, DefaultInterval).Should(Equal(phase), "VaultSecret %s should be in phase %s", name, phase)
}

// ============================================================================
// Gateway Helpers
// ============================================================================

// createGateway creates a Gateway resource
func createGateway(name string, listeners []avapigwv1alpha1.Listener) *avapigwv1alpha1.Gateway {
	gw := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: listeners,
		},
	}

	err := k8sClient.Create(ctx, gw)
	Expect(err).NotTo(HaveOccurred(), "Failed to create Gateway %s", name)

	return gw
}

// getGateway retrieves a Gateway resource
func getGateway(name string) (*avapigwv1alpha1.Gateway, error) {
	gw := &avapigwv1alpha1.Gateway{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: testNamespace,
	}, gw)
	return gw, err
}

// deleteGateway deletes a Gateway resource
func deleteGateway(name string) {
	gw := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
	}
	_ = k8sClient.Delete(ctx, gw)
}

// waitForGatewayReady waits for a Gateway to be ready
func waitForGatewayReady(name string, timeout time.Duration) *avapigwv1alpha1.Gateway {
	var gw *avapigwv1alpha1.Gateway
	Eventually(func() bool {
		var err error
		gw, err = getGateway(name)
		if err != nil {
			return false
		}
		return gw.Status.Phase == avapigwv1alpha1.PhaseStatusReady
	}, timeout, DefaultInterval).Should(BeTrue(), "Gateway %s should be ready", name)
	return gw
}

// ============================================================================
// HTTPRoute Helpers
// ============================================================================

// createHTTPRoute creates an HTTPRoute resource
func createHTTPRoute(name string, spec avapigwv1alpha1.HTTPRouteSpec) *avapigwv1alpha1.HTTPRoute {
	route := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: spec,
	}

	err := k8sClient.Create(ctx, route)
	Expect(err).NotTo(HaveOccurred(), "Failed to create HTTPRoute %s", name)

	return route
}

// getHTTPRoute retrieves an HTTPRoute resource
func getHTTPRoute(name string) (*avapigwv1alpha1.HTTPRoute, error) {
	route := &avapigwv1alpha1.HTTPRoute{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: testNamespace,
	}, route)
	return route, err
}

// deleteHTTPRoute deletes an HTTPRoute resource
func deleteHTTPRoute(name string) {
	route := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
	}
	_ = k8sClient.Delete(ctx, route)
}

// ============================================================================
// Backend Helpers
// ============================================================================

// createBackend creates a Backend resource
func createBackend(name string, spec avapigwv1alpha1.BackendSpec) *avapigwv1alpha1.Backend {
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: spec,
	}

	err := k8sClient.Create(ctx, backend)
	Expect(err).NotTo(HaveOccurred(), "Failed to create Backend %s", name)

	return backend
}

// getBackend retrieves a Backend resource
func getBackend(name string) (*avapigwv1alpha1.Backend, error) {
	backend := &avapigwv1alpha1.Backend{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: testNamespace,
	}, backend)
	return backend, err
}

// deleteBackend deletes a Backend resource
func deleteBackend(name string) {
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
	}
	_ = k8sClient.Delete(ctx, backend)
}

// ============================================================================
// TLSConfig Helpers
// ============================================================================

// createTLSConfig creates a TLSConfig resource
func createTLSConfig(name string, spec avapigwv1alpha1.TLSConfigSpec) *avapigwv1alpha1.TLSConfig {
	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: spec,
	}

	err := k8sClient.Create(ctx, tlsConfig)
	Expect(err).NotTo(HaveOccurred(), "Failed to create TLSConfig %s", name)

	return tlsConfig
}

// getTLSConfig retrieves a TLSConfig resource
func getTLSConfig(name string) (*avapigwv1alpha1.TLSConfig, error) {
	tlsConfig := &avapigwv1alpha1.TLSConfig{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: testNamespace,
	}, tlsConfig)
	return tlsConfig, err
}

// deleteTLSConfig deletes a TLSConfig resource
func deleteTLSConfig(name string) {
	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
	}
	_ = k8sClient.Delete(ctx, tlsConfig)
}

// ============================================================================
// Vault Helpers
// ============================================================================

// createVaultKV2Secret creates a secret in Vault KV v2
func createVaultKV2Secret(path string, data map[string]interface{}) {
	skipIfVaultNotAvailable()

	fullPath := fmt.Sprintf("secret/data/%s", path)
	_, err := vaultClient.Logical().Write(fullPath, map[string]interface{}{
		"data": data,
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to create Vault secret at %s", path)
}

// getVaultKV2Secret retrieves a secret from Vault KV v2
func getVaultKV2Secret(path string) (map[string]interface{}, error) {
	fullPath := fmt.Sprintf("secret/data/%s", path)
	secret, err := vaultClient.Logical().Read(fullPath)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found at %s", path)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret data format at %s", path)
	}

	return data, nil
}

// deleteVaultKV2Secret deletes a secret from Vault KV v2
func deleteVaultKV2Secret(path string) {
	fullPath := fmt.Sprintf("secret/metadata/%s", path)
	_, _ = vaultClient.Logical().Delete(fullPath)
}

// updateVaultKV2Secret updates a secret in Vault KV v2
func updateVaultKV2Secret(path string, data map[string]interface{}) {
	createVaultKV2Secret(path, data)
}

// ============================================================================
// HTTP Client Helpers
// ============================================================================

// httpClient creates an HTTP client with optional TLS configuration
func httpClient(tlsConfig *tls.Config, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// httpGet performs an HTTP GET request
func httpGet(url string, headers map[string]string) (*http.Response, error) {
	client := httpClient(nil, 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return client.Do(req)
}

// httpGetWithTLS performs an HTTPS GET request with TLS
func httpGetWithTLS(url string, tlsConfig *tls.Config, headers map[string]string) (*http.Response, error) {
	client := httpClient(tlsConfig, 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return client.Do(req)
}

// httpPost performs an HTTP POST request
func httpPost(url string, body []byte, contentType string, headers map[string]string) (*http.Response, error) {
	client := httpClient(nil, 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return client.Do(req)
}

// readResponseBody reads and returns the response body
func readResponseBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ============================================================================
// Certificate Helpers
// ============================================================================

// generateSelfSignedCert generates a self-signed certificate
func generateSelfSignedCert(commonName string, dnsNames []string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"E2E Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM, nil
}

// generateCA generates a CA certificate
func generateCA(commonName string, validFor time.Duration) (caCertPEM, caKeyPEM []byte, err error) {
	caPriv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"E2E Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, err
	}

	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPriv)})

	return caCertPEM, caKeyPEM, nil
}

// ============================================================================
// Utility Helpers
// ============================================================================

// stringPtr returns a pointer to a string
func stringPtr(s string) *string {
	return &s
}

// int32Ptr returns a pointer to an int32
func int32Ptr(i int32) *int32 {
	return &i
}

// boolPtr returns a pointer to a bool
func boolPtr(b bool) *bool {
	return &b
}

// base64Encode encodes a string to base64
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// base64Decode decodes a base64 string
func base64Decode(s string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// resourceExists checks if a resource exists
func resourceExists(obj client.Object) bool {
	err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)
	return err == nil
}

// resourceNotExists checks if a resource does not exist
func resourceNotExists(obj client.Object) bool {
	err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)
	return apierrors.IsNotFound(err)
}

// retryWithBackoff retries a function with exponential backoff
func retryWithBackoff(ctx context.Context, maxRetries int, initialDelay time.Duration, fn func() error) error {
	delay := initialDelay
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}

	return lastErr
}
