// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Secret data keys used for certificate persistence. ca.crt/tls.crt/tls.key
// follow the kubernetes.io/tls conventions so the gateway (and helm's
// genCA fallback in grpc-cert-secret.yaml) can mount the same Secret;
// ca.key additionally stores the CA private key so the operator can keep
// signing from the same CA across restarts.
const (
	secretKeyCACert  = "ca.crt"
	secretKeyCAKey   = "ca.key"
	secretKeyTLSCert = "tls.crt"
	secretKeyTLSKey  = "tls.key"
)

// secretSyncTimeout bounds individual Secret API operations during
// persistence so a slow API server cannot stall certificate issuance.
const secretSyncTimeout = 10 * time.Second

// SecretStore abstracts the Kubernetes Secret operations needed for
// certificate persistence. It is satisfied by sigs.k8s.io/controller-runtime
// client.Client and by fake clients in tests.
type SecretStore interface {
	Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error
	Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error
	Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error
}

// persistenceEnabled reports whether Secret persistence is configured.
func (p *selfSignedProvider) persistenceEnabled() bool {
	return p.config.SecretClient != nil && p.config.SecretName != "" && p.config.SecretNamespace != ""
}

// secretKey returns the namespaced name of the persistence Secret.
func (p *selfSignedProvider) secretKey() types.NamespacedName {
	return types.NamespacedName{Namespace: p.config.SecretNamespace, Name: p.config.SecretName}
}

// loadPersistedCA loads the CA from the configured Secret. It returns nil
// when the Secret is missing, incomplete (no CA key material — for example
// a helm genCA Secret without ca.key cannot be reused for signing), fails
// to parse, or the CA is expired/expiring within RotateBefore.
func (p *selfSignedProvider) loadPersistedCA(ctx context.Context) *Certificate {
	getCtx, cancel := context.WithTimeout(ctx, secretSyncTimeout)
	defer cancel()

	secret := &corev1.Secret{}
	if err := p.config.SecretClient.Get(getCtx, p.secretKey(), secret); err != nil {
		if !apierrors.IsNotFound(err) {
			p.logger.Warn("failed to read certificate secret; generating a fresh CA",
				observability.String("secret", p.config.SecretName),
				observability.Error(err),
			)
		}
		return nil
	}

	ca, err := parseCAFromSecret(secret)
	if err != nil {
		p.logger.Warn("persisted CA is not reusable; regenerating",
			observability.String("secret", p.config.SecretName),
			observability.Error(err),
		)
		return nil
	}

	if ca.IsExpiringSoon(p.config.RotateBefore) {
		p.logger.Info("persisted CA is expired or expiring soon; regenerating",
			observability.String("secret", p.config.SecretName),
			observability.Time("ca_expiration", ca.Expiration),
		)
		return nil
	}

	GetCertMetrics().caReuseTotal.WithLabelValues(providerSelfSigned).Inc()
	p.logger.Info("reusing persisted CA from secret",
		observability.String("secret", p.config.SecretName),
		observability.Time("ca_expiration", ca.Expiration),
	)

	p.primeServingCertificate(secret, ca)

	return ca
}

// parseCAFromSecret parses and validates the CA certificate and key from
// the Secret data.
func parseCAFromSecret(secret *corev1.Secret) (*Certificate, error) {
	caCertPEM := secret.Data[secretKeyCACert]
	caKeyPEM := secret.Data[secretKeyCAKey]
	if len(caCertPEM) == 0 || len(caKeyPEM) == 0 {
		return nil, fmt.Errorf("secret is missing %s or %s", secretKeyCACert, secretKeyCAKey)
	}

	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid CA certificate: %w", err)
	}
	if !caCert.IsCA {
		return nil, fmt.Errorf("persisted certificate is not a CA")
	}

	caKey, err := parseRSAPrivateKeyPEM(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid CA private key: %w", err)
	}

	if !caKey.PublicKey.Equal(caCert.PublicKey) {
		return nil, fmt.Errorf("CA private key does not match CA certificate")
	}

	return &Certificate{
		Certificate:    caCert,
		PrivateKey:     caKey,
		CertificatePEM: caCertPEM,
		PrivateKeyPEM:  caKeyPEM,
		SerialNumber:   caCert.SerialNumber.String(),
		Expiration:     caCert.NotAfter,
	}, nil
}

// primeServingCertificate loads a persisted serving certificate
// (tls.crt/tls.key) into the certificate cache when it is valid, signed by
// the given CA, and not expiring soon, so a restart does not re-issue an
// otherwise healthy serving certificate.
func (p *selfSignedProvider) primeServingCertificate(secret *corev1.Secret, ca *Certificate) {
	certPEM := secret.Data[secretKeyTLSCert]
	keyPEM := secret.Data[secretKeyTLSKey]
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return
	}

	leaf, err := parseCertificatePEM(certPEM)
	if err != nil {
		p.logger.Debug("persisted serving certificate unparsable; will re-issue",
			observability.Error(err),
		)
		return
	}

	key, err := parseRSAPrivateKeyPEM(keyPEM)
	if err != nil {
		p.logger.Debug("persisted serving key unparsable; will re-issue",
			observability.Error(err),
		)
		return
	}

	if err := leaf.CheckSignatureFrom(ca.Certificate); err != nil {
		p.logger.Debug("persisted serving certificate not signed by the persisted CA; will re-issue",
			observability.Error(err),
		)
		return
	}

	cert := &Certificate{
		Certificate:    leaf,
		PrivateKey:     key,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		CAChainPEM:     ca.CertificatePEM,
		SerialNumber:   leaf.SerialNumber.String(),
		Expiration:     leaf.NotAfter,
	}

	if !cert.IsValid() || cert.IsExpiringSoon(p.config.RotateBefore) {
		return
	}

	p.mu.Lock()
	p.certs[leaf.Subject.CommonName] = cert
	p.mu.Unlock()

	p.logger.Info("reusing persisted serving certificate",
		observability.String("common_name", leaf.Subject.CommonName),
		observability.Time("expiration", leaf.NotAfter),
	)
}

// persistCA writes the CA to the configured Secret, creating or updating it.
// On a create/update conflict it re-reads the Secret and, when the winning
// writer persisted a valid CA, returns it for adoption (closing the TOCTOU
// window between concurrent replicas). Returns nil when the given CA should
// be kept (persisted successfully or persistence failed non-adoptably).
func (p *selfSignedProvider) persistCA(ctx context.Context, ca *Certificate) *Certificate {
	syncCtx, cancel := context.WithTimeout(ctx, secretSyncTimeout)
	defer cancel()

	secret := &corev1.Secret{}
	err := p.config.SecretClient.Get(syncCtx, p.secretKey(), secret)

	switch {
	case apierrors.IsNotFound(err):
		return p.createCASecret(syncCtx, ca)
	case err != nil:
		p.recordSecretSync("get", err)
		return nil
	default:
		return p.updateCASecret(syncCtx, secret, ca)
	}
}

// createCASecret creates the persistence Secret with the CA material.
func (p *selfSignedProvider) createCASecret(ctx context.Context, ca *Certificate) *Certificate {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.config.SecretName,
			Namespace: p.config.SecretNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "avapigw-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			secretKeyCACert: ca.CertificatePEM,
			secretKeyCAKey:  ca.PrivateKeyPEM,
		},
	}

	err := p.config.SecretClient.Create(ctx, secret)
	if apierrors.IsAlreadyExists(err) {
		// Lost the create race: adopt the winner's CA when valid.
		return p.adoptPersistedCA(ctx)
	}
	p.recordSecretSync("create", err)
	return nil
}

// updateCASecret replaces the CA material in an existing Secret, keeping
// unrelated keys intact. A conflict triggers adoption of the winner's CA.
func (p *selfSignedProvider) updateCASecret(
	ctx context.Context, secret *corev1.Secret, ca *Certificate,
) *Certificate {
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[secretKeyCACert] = ca.CertificatePEM
	secret.Data[secretKeyCAKey] = ca.PrivateKeyPEM
	// A serving certificate signed by a previous CA is no longer valid.
	delete(secret.Data, secretKeyTLSCert)
	delete(secret.Data, secretKeyTLSKey)

	err := p.config.SecretClient.Update(ctx, secret)
	if apierrors.IsConflict(err) {
		return p.adoptPersistedCA(ctx)
	}
	p.recordSecretSync("update", err)
	return nil
}

// adoptPersistedCA re-reads the Secret after a lost write race and returns
// the persisted CA when it is reusable; nil keeps the locally generated CA.
func (p *selfSignedProvider) adoptPersistedCA(ctx context.Context) *Certificate {
	secret := &corev1.Secret{}
	if err := p.config.SecretClient.Get(ctx, p.secretKey(), secret); err != nil {
		p.recordSecretSync("get", err)
		return nil
	}

	ca, err := parseCAFromSecret(secret)
	if err != nil || ca.IsExpiringSoon(p.config.RotateBefore) {
		p.logger.Warn("concurrent writer persisted a non-reusable CA; keeping local CA",
			observability.Error(err),
		)
		return nil
	}

	GetCertMetrics().caReuseTotal.WithLabelValues(providerSelfSigned).Inc()
	p.logger.Info("adopted CA persisted by concurrent writer",
		observability.String("secret", p.config.SecretName),
		observability.Time("ca_expiration", ca.Expiration),
	)
	return ca
}

// persistServingCertificate stores the issued serving certificate in the
// Secret next to the CA (best-effort: issuance never fails on Secret
// errors, they are logged and counted instead).
func (p *selfSignedProvider) persistServingCertificate(ctx context.Context, cert *Certificate) {
	if !p.persistenceEnabled() {
		return
	}

	syncCtx, cancel := context.WithTimeout(ctx, secretSyncTimeout)
	defer cancel()

	secret := &corev1.Secret{}
	if err := p.config.SecretClient.Get(syncCtx, p.secretKey(), secret); err != nil {
		p.recordSecretSync("get", err)
		return
	}

	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[secretKeyTLSCert] = cert.CertificatePEM
	secret.Data[secretKeyTLSKey] = cert.PrivateKeyPEM

	err := p.config.SecretClient.Update(syncCtx, secret)
	p.recordSecretSync("update", err)
}

// recordSecretSync records the outcome of a Secret persistence operation
// (metric + log). A nil error records success silently.
func (p *selfSignedProvider) recordSecretSync(operation string, err error) {
	if err != nil {
		GetCertMetrics().secretSyncTotal.WithLabelValues(operation, resultError).Inc()
		p.logger.Error("certificate secret persistence failed",
			observability.String("operation", operation),
			observability.String("secret", p.config.SecretName),
			observability.String("namespace", p.config.SecretNamespace),
			observability.Error(err),
		)
		return
	}
	GetCertMetrics().secretSyncTotal.WithLabelValues(operation, resultSuccess).Inc()
	p.logger.Debug("certificate secret persisted",
		observability.String("operation", operation),
		observability.String("secret", p.config.SecretName),
	)
}

// parseCertificatePEM parses a single certificate from PEM bytes.
func parseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != pemTypeCertificate {
		return nil, fmt.Errorf("no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// parseRSAPrivateKeyPEM parses an RSA private key from PEM bytes,
// accepting both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY")
// encodings (helm genCA emits PKCS#1; other tooling may emit PKCS#8).
func parseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no private key PEM block found")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}
