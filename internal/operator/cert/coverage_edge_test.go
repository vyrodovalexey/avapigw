// Package cert edge-path tests for the file provider CA handling and the
// selfsigned persistence corner cases.
package cert

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Type aliases keeping the SecretStore test doubles concise.
type (
	clientObjectKey    = client.ObjectKey
	clientObject       = client.Object
	clientGetOption    = client.GetOption
	clientCreateOption = client.CreateOption
	clientUpdateOption = client.UpdateOption
)

// assertAnError mirrors assert.AnError for non-assert contexts.
var assertAnError = assert.AnError

// newAlreadyExistsError returns a Kubernetes AlreadyExists API error.
func newAlreadyExistsError() error {
	return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, testSecretName)
}

// newConflictError returns a Kubernetes Conflict API error.
func newConflictError() error {
	return apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, testSecretName, assertAnError)
}

// TestFileProvider_CASource covers the CA-source description helper via
// the GetCA parse-error path.
func TestFileProvider_CASource(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeFileProviderFixtures(t, dir)

	// Overwrite the CA file with a decodable-but-unparsable PEM so GetCA
	// fails at pool building and reports the CA source.
	require.NoError(t, os.WriteFile(caFile,
		[]byte("-----BEGIN GARBAGE-----\nZHVtbXk=\n-----END GARBAGE-----\n"), 0o600))

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	_, err = mgr.GetCA(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), caFile, "error must name the CA source file")

	// And the bundle-source variant (no CAFile).
	p := &fileProvider{config: &FileProviderConfig{CertFile: certFile, KeyFile: keyFile}}
	assert.Equal(t, certFile, p.caSource())
}

// TestFileProvider_FilesChanged_StatError verifies missing source files
// count as changed (forcing a reload that surfaces the error).
func TestFileProvider_FilesChanged_StatError(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeFileProviderFixtures(t, dir)

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	_, err = mgr.GetCertificate(context.Background(), nil)
	require.NoError(t, err)

	// Remove the key file: the next GetCertificate must fail via reload.
	require.NoError(t, os.Remove(keyFile))
	_, err = mgr.GetCertificate(context.Background(), nil)
	require.Error(t, err)
}

// TestFileProvider_LoadCAChain_UnreadableCAFile verifies a configured but
// unreadable CA file degrades to a nil chain (warned, not fatal).
func TestFileProvider_LoadCAChain_UnreadableCAFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeFileProviderFixtures(t, dir)

	mgr, err := NewFileProvider(&FileProviderConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	require.NoError(t, err)
	defer mgr.Close()

	// Remove ca.crt then force a reload: the chain becomes unavailable but
	// the serving certificate still loads.
	require.NoError(t, os.Remove(caFile))
	rotated, err := mgr.RotateCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, rotated.CAChainPEM)
}

// TestSelfSignedProvider_PrimeServingCert_SkipsInvalid covers the
// persisted-serving-cert rejection paths (garbage cert/key, foreign CA,
// expiring leaf).
func TestSelfSignedProvider_PrimeServingCert_SkipsInvalid(t *testing.T) {
	ctx := context.Background()

	// Provider A issues a leaf; provider B's CA will NOT match it.
	providerA := newPersistingProvider(t,
		fake.NewClientBuilder().WithScheme(newSecretScheme(t)).Build())
	foreignLeaf, err := providerA.GetCertificate(ctx, &CertificateRequest{CommonName: "foreign"})
	require.NoError(t, err)

	tests := []struct {
		name string
		data map[string][]byte
	}{
		{name: "garbage tls.crt", data: map[string][]byte{
			secretKeyTLSCert: []byte("junk"), secretKeyTLSKey: []byte("junk"),
		}},
		{name: "garbage tls.key", data: map[string][]byte{
			secretKeyTLSCert: foreignLeaf.CertificatePEM, secretKeyTLSKey: []byte("junk"),
		}},
		{name: "leaf signed by a different CA", data: map[string][]byte{
			secretKeyTLSCert: foreignLeaf.CertificatePEM, secretKeyTLSKey: foreignLeaf.PrivateKeyPEM,
		}},
		{name: "missing key", data: map[string][]byte{
			secretKeyTLSCert: foreignLeaf.CertificatePEM,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Seed a secret with a VALID CA from a fresh provider run plus
			// the invalid serving material.
			store := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).Build()
			seedProvider := newPersistingProvider(t, store)
			caPEM, err := seedProvider.GetCAPEM(ctx)
			require.NoError(t, err)

			secret := getPersistedSecret(t, store)
			for k, v := range tt.data {
				secret.Data[k] = v
			}
			require.NoError(t, store.Update(ctx, secret))

			// Restart: CA reused, serving material rejected -> re-issued.
			restarted := newPersistingProvider(t, store)
			reusedCA, err := restarted.GetCAPEM(ctx)
			require.NoError(t, err)
			assert.Equal(t, caPEM, reusedCA, "CA must still be reused")

			issued, err := restarted.GetCertificate(ctx, &CertificateRequest{CommonName: "fresh"})
			require.NoError(t, err)
			assert.NotEqual(t, foreignLeaf.SerialNumber, issued.SerialNumber,
				"invalid persisted serving material must be re-issued, not reused")
		})
	}
}

// TestSelfSignedProvider_AdoptPersistedCA_GetError covers the adoption
// re-read failure path after a lost create race.
func TestSelfSignedProvider_AdoptPersistedCA_GetError(t *testing.T) {
	inner := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).Build()

	// Get succeeds during bootstrap load (not found), Create loses the
	// race, and the adoption re-read fails.
	store := &conflictThenGetErrorStore{inner: inner}
	mgr := newPersistingProvider(t, store)

	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err, "provider must keep the local CA when adoption fails")
	assert.NotEmpty(t, caPEM)
}

// conflictThenGetErrorStore makes Create fail with AlreadyExists and the
// subsequent adoption Get fail.
type conflictThenGetErrorStore struct {
	inner    SecretStore
	getCalls int
}

func (s *conflictThenGetErrorStore) Get(
	ctx context.Context, key clientObjectKey, obj clientObject, opts ...clientGetOption,
) error {
	s.getCalls++
	if s.getCalls == 1 {
		// bootstrap load: behave like NotFound via the inner fake client
		return s.inner.Get(ctx, key, obj, opts...)
	}
	return assertAnError
}

func (s *conflictThenGetErrorStore) Create(
	ctx context.Context, obj clientObject, opts ...clientCreateOption,
) error {
	return newAlreadyExistsError()
}

func (s *conflictThenGetErrorStore) Update(
	ctx context.Context, obj clientObject, opts ...clientUpdateOption,
) error {
	return s.inner.Update(ctx, obj, opts...)
}

// TestSelfSignedProvider_UpdateConflictAdoptsWinner covers the update
// conflict adoption path (existing secret, conflicting write).
func TestSelfSignedProvider_UpdateConflictAdoptsWinner(t *testing.T) {
	winnerCert, winnerKey := generateTestCA(t, time.Now(), time.Now().Add(365*24*time.Hour))

	// Seed an EXPIRED CA so bootstrap regenerates and takes the update path.
	expiredCert, expiredKey := generateTestCA(t,
		time.Now().Add(-48*time.Hour), time.Now().Add(-1*time.Hour))
	seed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testSecretNamespace},
		Data:       map[string][]byte{secretKeyCACert: expiredCert, secretKeyCAKey: expiredKey},
	}
	inner := fake.NewClientBuilder().WithScheme(newSecretScheme(t)).WithObjects(seed).Build()

	store := &updateConflictStore{inner: inner, winnerCert: winnerCert, winnerKey: winnerKey}
	mgr := newPersistingProvider(t, store)

	caPEM, err := mgr.GetCAPEM(context.Background())
	require.NoError(t, err)
	assert.Equal(t, winnerCert, caPEM,
		"update conflict must adopt the concurrent writer's CA")
}

// updateConflictStore fails the first Update with a Conflict after writing
// the winner's CA.
type updateConflictStore struct {
	inner      SecretStore
	winnerCert []byte
	winnerKey  []byte
	conflicted bool
}

func (s *updateConflictStore) Get(
	ctx context.Context, key clientObjectKey, obj clientObject, opts ...clientGetOption,
) error {
	return s.inner.Get(ctx, key, obj, opts...)
}

func (s *updateConflictStore) Create(
	ctx context.Context, obj clientObject, opts ...clientCreateOption,
) error {
	return s.inner.Create(ctx, obj, opts...)
}

func (s *updateConflictStore) Update(
	ctx context.Context, obj clientObject, opts ...clientUpdateOption,
) error {
	if !s.conflicted {
		s.conflicted = true
		// Winner writes its CA first...
		secret := &corev1.Secret{}
		if err := s.inner.Get(ctx, clientObjectKey{
			Namespace: testSecretNamespace, Name: testSecretName,
		}, secret); err != nil {
			return err
		}
		secret.Data[secretKeyCACert] = s.winnerCert
		secret.Data[secretKeyCAKey] = s.winnerKey
		if err := s.inner.Update(ctx, secret); err != nil {
			return err
		}
		// ...and our update conflicts.
		return newConflictError()
	}
	return s.inner.Update(ctx, obj, opts...)
}

// TestInitWebhookInjectorMetrics_Exported covers the exported metrics
// initializer wrapper (idempotent via sync.Once).
func TestInitWebhookInjectorMetrics_Exported(t *testing.T) {
	InitWebhookInjectorMetrics(nil)
	assert.NotNil(t, getWebhookInjectorMetrics())
}

// TestFileProvider_ReloadAfterRotateKeepsChainFallback exercises the
// bundle-chain loader on reload (no CAFile).
func TestFileProvider_ReloadAfterRotateKeepsChainFallback(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeFileProviderFixtures(t, dir)

	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	leafPEM, err := os.ReadFile(certFile)
	require.NoError(t, err)
	bundle := filepath.Join(dir, "bundle.crt")
	require.NoError(t, os.WriteFile(bundle, append(leafPEM, caPEM...), 0o600))

	mgr, err := NewFileProvider(&FileProviderConfig{CertFile: bundle, KeyFile: keyFile})
	require.NoError(t, err)
	defer mgr.Close()

	rotated, err := mgr.RotateCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, string(caPEM), string(rotated.CAChainPEM))
}
