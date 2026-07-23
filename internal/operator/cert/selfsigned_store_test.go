// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testSecretName      = "test-grpc-cert"
	testSecretNamespace = "test-ns"
)

// newSecretScheme builds a scheme with core/v1 registered.
func newSecretScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	return scheme
}

// newPersistingProvider creates a self-signed provider with Secret
// persistence wired to the given store.
func newPersistingProvider(t *testing.T, store SecretStore) Manager {
	t.Helper()
	mgr, err := NewSelfSignedProviderWithContext(context.Background(), &SelfSignedProviderConfig{
		KeySize:         2048, // fast test keys
		SecretName:      testSecretName,
		SecretNamespace: testSecretNamespace,
		SecretClient:    store,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

// getPersistedSecret fetches the persistence Secret from the fake client.
func getPersistedSecret(t *testing.T, c client.Client) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{}
	err := c.Get(context.Background(), types.NamespacedName{
		Namespace: testSecretNamespace, Name: testSecretName,
	}, secret)
	require.NoError(t, err)
	return secret
}

// generateTestCA produces a CA certificate/key PEM pair with the given
// validity window (relative to now).
func generateTestCA(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "persisted-test-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

// TestSelfSignedProvider_Persistence_CreatesSecret verifies a fresh
// provider persists its generated CA (cert + key) to the Secret.
func TestSelfSignedProvider_Persistence_CreatesSecret(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).Build()

	mgr := newPersistingProvider(t, fakeClient)

	secret := getPersistedSecret(t, fakeClient)
	assert.NotEmpty(t, secret.Data[secretKeyCACert], "ca.crt must be persisted")
	assert.NotEmpty(t, secret.Data[secretKeyCAKey], "ca.key must be persisted")

	// The persisted CA must equal the provider's CA PEM.
	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.Equal(t, caPEM, secret.Data[secretKeyCACert])
}

// TestSelfSignedProvider_Persistence_ReusesValidCA verifies restart
// behavior: a second provider adopting the same Secret reuses the CA
// instead of regenerating (the gateway keeps verifying against the same
// ca.crt).
func TestSelfSignedProvider_Persistence_ReusesValidCA(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).Build()

	first := newPersistingProvider(t, fakeClient)
	firstCA, err := first.GetCAPEM(context.Background())
	require.NoError(t, err)

	// "Restart": a new provider against the same Secret.
	second := newPersistingProvider(t, fakeClient)
	secondCA, err := second.GetCAPEM(context.Background())
	require.NoError(t, err)

	assert.Equal(t, firstCA, secondCA, "restarted provider must reuse the persisted CA")
}

// TestSelfSignedProvider_Persistence_ReusesServingCert verifies the
// persisted serving certificate is primed into the cache on restart so the
// same leaf keeps being served.
func TestSelfSignedProvider_Persistence_ReusesServingCert(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).Build()
	ctx := context.Background()

	first := newPersistingProvider(t, fakeClient)
	issued, err := first.GetCertificate(ctx, &CertificateRequest{
		CommonName: "avapigw-operator",
		DNSNames:   []string{"avapigw-operator.test-ns.svc"},
	})
	require.NoError(t, err)

	secret := getPersistedSecret(t, fakeClient)
	assert.Equal(t, issued.CertificatePEM, secret.Data[secretKeyTLSCert],
		"serving certificate must be persisted")
	assert.Equal(t, issued.PrivateKeyPEM, secret.Data[secretKeyTLSKey],
		"serving key must be persisted")

	second := newPersistingProvider(t, fakeClient)
	reused, err := second.GetCertificate(ctx, &CertificateRequest{
		CommonName: "avapigw-operator",
	})
	require.NoError(t, err)
	assert.Equal(t, issued.SerialNumber, reused.SerialNumber,
		"restarted provider must serve the persisted certificate, not re-issue")
}

// TestSelfSignedProvider_Persistence_RegeneratesExpiredCA verifies an
// expired persisted CA is replaced (regenerate-if-expired) and stale
// serving material is dropped from the Secret.
func TestSelfSignedProvider_Persistence_RegeneratesExpiredCA(t *testing.T) {
	certPEM, keyPEM := generateTestCA(t,
		time.Now().Add(-48*time.Hour), time.Now().Add(-1*time.Hour))

	seed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testSecretNamespace},
		Data: map[string][]byte{
			secretKeyCACert:  certPEM,
			secretKeyCAKey:   keyPEM,
			secretKeyTLSCert: []byte("stale-cert"),
			secretKeyTLSKey:  []byte("stale-key"),
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).WithObjects(seed).Build()

	mgr := newPersistingProvider(t, fakeClient)

	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, certPEM, caPEM, "expired CA must be regenerated")

	secret := getPersistedSecret(t, fakeClient)
	assert.Equal(t, caPEM, secret.Data[secretKeyCACert], "regenerated CA must be persisted")
	assert.Empty(t, secret.Data[secretKeyTLSCert], "stale serving cert must be dropped")
	assert.Empty(t, secret.Data[secretKeyTLSKey], "stale serving key must be dropped")
}

// TestSelfSignedProvider_Persistence_RegeneratesExpiringSoonCA verifies a
// CA inside the RotateBefore window is regenerated proactively.
func TestSelfSignedProvider_Persistence_RegeneratesExpiringSoonCA(t *testing.T) {
	// Valid, but expires within the default RotateBefore (7 days).
	certPEM, keyPEM := generateTestCA(t,
		time.Now().Add(-24*time.Hour), time.Now().Add(24*time.Hour))

	seed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testSecretNamespace},
		Data:       map[string][]byte{secretKeyCACert: certPEM, secretKeyCAKey: keyPEM},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).WithObjects(seed).Build()

	mgr := newPersistingProvider(t, fakeClient)

	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, certPEM, caPEM, "expiring-soon CA must be regenerated")
}

// TestSelfSignedProvider_Persistence_RegeneratesCorruptData verifies
// unusable persisted data falls back to regeneration (matrix).
func TestSelfSignedProvider_Persistence_RegeneratesCorruptData(t *testing.T) {
	validCert, validKey := generateTestCA(t, time.Now(), time.Now().Add(365*24*time.Hour))
	_, otherKey := generateTestCA(t, time.Now(), time.Now().Add(365*24*time.Hour))

	tests := []struct {
		name string
		data map[string][]byte
	}{
		{name: "missing ca.key (helm-genCA without key)", data: map[string][]byte{
			secretKeyCACert: validCert,
		}},
		{name: "missing ca.crt", data: map[string][]byte{
			secretKeyCAKey: validKey,
		}},
		{name: "garbage ca.crt", data: map[string][]byte{
			secretKeyCACert: []byte("not-pem"), secretKeyCAKey: validKey,
		}},
		{name: "garbage ca.key", data: map[string][]byte{
			secretKeyCACert: validCert, secretKeyCAKey: []byte("not-pem"),
		}},
		{name: "mismatched key pair", data: map[string][]byte{
			secretKeyCACert: validCert, secretKeyCAKey: otherKey,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testSecretNamespace},
				Data:       tt.data,
			}
			fakeClient := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).WithObjects(seed).Build()

			mgr := newPersistingProvider(t, fakeClient)

			caPEM, err := mgr.GetCAPEM(context.Background())
			require.NoError(t, err)

			secret := getPersistedSecret(t, fakeClient)
			assert.Equal(t, caPEM, secret.Data[secretKeyCACert],
				"regenerated CA must overwrite the unusable data")
			assert.NotEmpty(t, secret.Data[secretKeyCAKey])
		})
	}
}

// TestSelfSignedProvider_Persistence_NonCACertRejected verifies a leaf
// certificate persisted as CA is not adopted.
func TestSelfSignedProvider_Persistence_NonCACertRejected(t *testing.T) {
	// Issue a leaf from a throwaway provider and persist it as "CA".
	helper, err := NewSelfSignedProvider(&SelfSignedProviderConfig{KeySize: 2048})
	require.NoError(t, err)
	defer helper.Close()
	leaf, err := helper.GetCertificate(context.Background(), &CertificateRequest{CommonName: "leaf"})
	require.NoError(t, err)

	seed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testSecretNamespace},
		Data: map[string][]byte{
			secretKeyCACert: leaf.CertificatePEM,
			secretKeyCAKey:  leaf.PrivateKeyPEM,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).WithObjects(seed).Build()

	mgr := newPersistingProvider(t, fakeClient)
	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, leaf.CertificatePEM, caPEM, "a non-CA certificate must not be adopted")
}

// TestSelfSignedProvider_Persistence_Disabled verifies the legacy
// behavior is preserved when no Secret store is configured.
func TestSelfSignedProvider_Persistence_Disabled(t *testing.T) {
	mgr, err := NewSelfSignedProviderWithContext(context.Background(), &SelfSignedProviderConfig{
		KeySize: 2048,
		// SecretName set but no client: persistence stays off.
		SecretName: testSecretName,
	})
	require.NoError(t, err)
	defer mgr.Close()

	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, caPEM)
}

// erroringSecretStore wraps a SecretStore and injects errors per operation.
type erroringSecretStore struct {
	inner     SecretStore
	getErr    error
	createErr error
	updateErr error
}

func (s *erroringSecretStore) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	if s.getErr != nil {
		return s.getErr
	}
	return s.inner.Get(ctx, key, obj, opts...)
}

func (s *erroringSecretStore) Create(
	ctx context.Context, obj client.Object, opts ...client.CreateOption,
) error {
	if s.createErr != nil {
		return s.createErr
	}
	return s.inner.Create(ctx, obj, opts...)
}

func (s *erroringSecretStore) Update(
	ctx context.Context, obj client.Object, opts ...client.UpdateOption,
) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	return s.inner.Update(ctx, obj, opts...)
}

// TestSelfSignedProvider_Persistence_StoreErrorsNonFatal verifies Secret
// API failures degrade gracefully to the in-memory CA.
func TestSelfSignedProvider_Persistence_StoreErrorsNonFatal(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).Build()

	tests := []struct {
		name  string
		store SecretStore
	}{
		{name: "get fails", store: &erroringSecretStore{
			inner: fakeClient, getErr: fmt.Errorf("api down"),
		}},
		{name: "create fails", store: &erroringSecretStore{
			inner: fakeClient, createErr: fmt.Errorf("forbidden"),
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newPersistingProvider(t, tt.store)
			caPEM, err := mgr.GetCAPEM(context.Background())
			require.NoError(t, err, "provider must work despite persistence failures")
			assert.NotEmpty(t, caPEM)
		})
	}
}

// TestSelfSignedProvider_Persistence_CreateConflictAdoptsWinner verifies
// the TOCTOU race handling: losing the Secret create race adopts the
// winner's CA so all replicas issue from the same CA.
func TestSelfSignedProvider_Persistence_CreateConflictAdoptsWinner(t *testing.T) {
	winnerCert, winnerKey := generateTestCA(t, time.Now(), time.Now().Add(365*24*time.Hour))
	fakeClient := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).Build()

	store := &racingSecretStore{inner: fakeClient, winnerCert: winnerCert, winnerKey: winnerKey}
	mgr := newPersistingProvider(t, store)

	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.Equal(t, winnerCert, caPEM, "loser of the create race must adopt the winner's CA")
}

// racingSecretStore simulates a concurrent replica winning the Secret
// create race: the first Create returns AlreadyExists after writing the
// winner's CA into the store.
type racingSecretStore struct {
	inner      client.Client
	winnerCert []byte
	winnerKey  []byte
	raced      bool
}

func (s *racingSecretStore) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	return s.inner.Get(ctx, key, obj, opts...)
}

func (s *racingSecretStore) Create(
	ctx context.Context, obj client.Object, opts ...client.CreateOption,
) error {
	if !s.raced {
		s.raced = true
		// The "winner" persists first...
		winner := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testSecretNamespace},
			Data: map[string][]byte{
				secretKeyCACert: s.winnerCert,
				secretKeyCAKey:  s.winnerKey,
			},
		}
		if err := s.inner.Create(ctx, winner); err != nil {
			return err
		}
		// ...and our create loses the race.
		return apierrors.NewAlreadyExists(
			schema.GroupResource{Resource: "secrets"}, testSecretName)
	}
	return s.inner.Create(ctx, obj, opts...)
}

func (s *racingSecretStore) Update(
	ctx context.Context, obj client.Object, opts ...client.UpdateOption,
) error {
	return s.inner.Update(ctx, obj, opts...)
}

// TestSelfSignedProvider_GetCAPEM_Closed verifies the closed-provider path.
func TestSelfSignedProvider_GetCAPEM_Closed(t *testing.T) {
	mgr, err := NewSelfSignedProvider(&SelfSignedProviderConfig{KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, mgr.Close())

	_, err = mgr.GetCAPEM(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

// TestParseRSAPrivateKeyPEM_PKCS8 verifies PKCS#8 keys are accepted
// (tooling other than helm genCA may emit them).
func TestParseRSAPrivateKeyPEM_PKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := parseRSAPrivateKeyPEM(pemBytes)
	require.NoError(t, err)
	assert.True(t, key.Equal(parsed))
}

// TestParseRSAPrivateKeyPEM_NotRSA verifies non-RSA PKCS#8 keys are rejected.
func TestParseRSAPrivateKeyPEM_NotRSA(t *testing.T) {
	_, err := parseRSAPrivateKeyPEM([]byte("garbage"))
	require.Error(t, err)
}
