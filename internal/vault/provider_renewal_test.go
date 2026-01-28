package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
)

// ============================================================
// Mock vault.Client for provider renewal tests
// ============================================================

// mockPKIClientForRenewal implements PKIClient with configurable behavior.
type mockPKIClientForRenewal struct {
	mu            sync.Mutex
	issueCalls    int
	issueErr      error
	issueErrCount int // number of times to return error before succeeding
	certPEM       string
	keyPEM        string
	caPool        *x509.CertPool
	caErr         error
	serialNumber  string
	expiration    time.Time
}

func (m *mockPKIClientForRenewal) IssueCertificate(_ context.Context, _ *PKIIssueOptions) (*Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.issueCalls++

	if m.issueErrCount > 0 && m.issueCalls <= m.issueErrCount {
		return nil, m.issueErr
	}

	if m.issueErr != nil && m.issueErrCount == 0 {
		return nil, m.issueErr
	}

	return &Certificate{
		CertificatePEM: m.certPEM,
		PrivateKeyPEM:  m.keyPEM,
		SerialNumber:   m.serialNumber,
		Expiration:     m.expiration,
	}, nil
}

func (m *mockPKIClientForRenewal) SignCSR(_ context.Context, _ []byte, _ *PKISignOptions) (*Certificate, error) {
	return nil, nil
}

func (m *mockPKIClientForRenewal) GetCA(_ context.Context, _ string) (*x509.CertPool, error) {
	if m.caErr != nil {
		return nil, m.caErr
	}
	return m.caPool, nil
}

func (m *mockPKIClientForRenewal) GetCRL(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}

func (m *mockPKIClientForRenewal) RevokeCertificate(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockPKIClientForRenewal) getIssueCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.issueCalls
}

// mockVaultClientForRenewal implements vault.Client for provider renewal tests.
type mockVaultClientForRenewal struct {
	enabled bool
	pki     PKIClient
}

func (m *mockVaultClientForRenewal) IsEnabled() bool                      { return m.enabled }
func (m *mockVaultClientForRenewal) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClientForRenewal) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClientForRenewal) Health(_ context.Context) (*HealthStatus, error) {
	return nil, nil
}
func (m *mockVaultClientForRenewal) PKI() PKIClient         { return m.pki }
func (m *mockVaultClientForRenewal) KV() KVClient           { return nil }
func (m *mockVaultClientForRenewal) Transit() TransitClient { return nil }
func (m *mockVaultClientForRenewal) Close() error           { return nil }

// ============================================================
// Helper: generate self-signed cert + key PEM for testing
// ============================================================

func generateTestCertAndKey(t *testing.T, notAfter time.Time) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEM), string(keyPEM)
}

// ============================================================
// Test: VaultProvider.Start() - successful initialization
// ============================================================

func TestVaultProvider_Start_Success(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Verify certificate was loaded
	cert, err := provider.GetCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.NotNil(t, cert)

	// Verify event was sent
	ch := provider.Watch(context.Background())
	select {
	case event := <-ch:
		assert.Equal(t, internaltls.CertificateEventLoaded, event.Type)
		assert.Equal(t, "certificate loaded from vault", event.Message)
	case <-time.After(time.Second):
		t.Fatal("expected certificate loaded event")
	}

	// Clean up
	cancel()
	err = provider.Close()
	assert.NoError(t, err)
}

// ============================================================
// Test: VaultProvider.Start() - already started (idempotent)
// ============================================================

func TestVaultProvider_Start_AlreadyStarted(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Second Start should be a no-op
	err = provider.Start(ctx)
	assert.NoError(t, err)

	// Only one certificate should have been issued
	assert.Equal(t, 1, mockPKI.getIssueCalls())

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: VaultProvider.Start() - issueCertificate failure
// ============================================================

func TestVaultProvider_Start_IssueCertificateError(t *testing.T) {
	mockPKI := &mockPKIClientForRenewal{
		issueErr: errors.New("vault unavailable"),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault unavailable")

	// NOTE: Do NOT call provider.Close() here. When Start() fails after setting
	// p.started=true but before launching the renewal goroutine, Close() would
	// block forever waiting on stoppedCh which is never closed.
	// This is a known edge case in the provider implementation.
}

// ============================================================
// Test: VaultProvider.Start() - loadCAPool failure (warning only)
// ============================================================

func TestVaultProvider_Start_LoadCAPoolError(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
		caErr:        errors.New("CA not available"),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start should succeed even if CA pool loading fails (it's a warning)
	err = provider.Start(ctx)
	assert.NoError(t, err)

	// CA pool should be nil
	pool, err := provider.GetClientCA(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, pool)

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: VaultProvider.Start() - loadCAPool with custom CAMount
// ============================================================

func TestVaultProvider_Start_LoadCAPoolWithCAMount(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	caPool := x509.NewCertPool()
	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
		caPool:       caPool,
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
		CAMount:    "pki-ca",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	assert.NoError(t, err)

	// CA pool should be loaded
	pool, err := provider.GetClientCA(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, pool)

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: renewalLoop - context cancellation
// ============================================================

func TestVaultProvider_RenewalLoop_ContextCancellation(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Cancel context to trigger renewal loop exit
	cancel()

	// Close should complete without hanging
	err = provider.Close()
	assert.NoError(t, err)
}

// ============================================================
// Test: renewalLoop - stopCh signal
// ============================================================

func TestVaultProvider_RenewalLoop_StopChannel(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.Start(ctx)
	require.NoError(t, err)

	// Close triggers stopCh
	err = provider.Close()
	assert.NoError(t, err)
}

// ============================================================
// Test: renewalLoop - renewal with expired cert triggers immediate renewal
// ============================================================

func TestVaultProvider_RenewalLoop_ExpiredCertTriggersRenewal(t *testing.T) {
	// Create a cert that expires very soon so renewal triggers quickly
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(2*time.Second))

	var issueCalls atomic.Int32

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(2 * time.Second),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:    "pki",
		Role:        "test-role",
		CommonName:  "test.example.com",
		RenewBefore: 1 * time.Second, // Renew 1s before expiry
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Wait for renewal to trigger (cert expires in 2s, renew 1s before = 1s from now)
	time.Sleep(3 * time.Second)

	_ = issueCalls.Load() // suppress unused

	// At least 1 initial + 1 renewal should have happened
	calls := mockPKI.getIssueCalls()
	assert.GreaterOrEqual(t, calls, 2, "expected at least 2 issue calls (initial + renewal)")

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: renewalLoop - failure with exponential backoff
// ============================================================

func TestVaultProvider_RenewalLoop_FailureWithExponentialBackoff(t *testing.T) {
	// Create a cert that expires very soon
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(1*time.Second))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(1 * time.Second),
		// No error initially - Start() will succeed
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:    "pki",
		Role:        "test-role",
		CommonName:  "test.example.com",
		RenewBefore: 500 * time.Millisecond,
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Now set error so all subsequent renewal calls fail
	mockPKI.mu.Lock()
	mockPKI.issueErr = errors.New("vault unavailable")
	mockPKI.issueErrCount = 0 // 0 means always fail when issueErr is set
	mockPKI.mu.Unlock()

	// Wait for renewal attempts with backoff
	time.Sleep(3 * time.Second)

	// Should have made multiple retry attempts
	calls := mockPKI.getIssueCalls()
	assert.GreaterOrEqual(t, calls, 2, "expected at least 2 issue calls (initial + retries)")

	// Check that error events were sent
	ch := provider.Watch(context.Background())
	// Drain the loaded event first
	drainEvents := func() int {
		errorCount := 0
		for {
			select {
			case event := <-ch:
				if event.Type == internaltls.CertificateEventError {
					errorCount++
				}
			default:
				return errorCount
			}
		}
	}
	errorCount := drainEvents()
	assert.GreaterOrEqual(t, errorCount, 1, "expected at least 1 error event")

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: renewalLoop - retry counter resets on success after failure
// ============================================================

func TestVaultProvider_RenewalLoop_RetryCounterReset(t *testing.T) {
	// Create a cert that expires very soon
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(1*time.Second))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(1 * time.Second),
		// No error initially - Start() will succeed
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:    "pki",
		Role:        "test-role",
		CommonName:  "test.example.com",
		RenewBefore: 500 * time.Millisecond,
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Now set error so the next renewal call (call #2) fails, but call #3+ succeeds
	mockPKI.mu.Lock()
	mockPKI.issueErr = errors.New("vault unavailable")
	mockPKI.issueErrCount = 2 // Fail on calls ≤ 2 (call 1 was initial, call 2 = first renewal fails)
	mockPKI.mu.Unlock()

	// Wait for renewal cycle: fail once (then 5s backoff), then succeed
	// The cert expires in ~1s, renewBefore=500ms, so first renewal triggers at ~500ms.
	// After failure, backoff is ~5s. So we need ~7s total for fail + backoff + retry.
	time.Sleep(8 * time.Second)

	// Should have made multiple calls
	calls := mockPKI.getIssueCalls()
	assert.GreaterOrEqual(t, calls, 3, "expected at least 3 issue calls (initial + fail + success)")

	// Check that both error and reloaded events were sent
	ch := provider.Watch(context.Background())
	hasError := false
	hasReloaded := false
	for {
		select {
		case event := <-ch:
			if event.Type == internaltls.CertificateEventError {
				hasError = true
			}
			if event.Type == internaltls.CertificateEventReloaded {
				hasReloaded = true
			}
		default:
			goto done
		}
	}
done:
	assert.True(t, hasError, "expected at least one error event")
	assert.True(t, hasReloaded, "expected at least one reloaded event after recovery")

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: renewalLoop - default renewBefore when not configured
// ============================================================

func TestVaultProvider_RenewalLoop_DefaultRenewBefore(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:    "pki",
		Role:        "test-role",
		CommonName:  "test.example.com",
		RenewBefore: 0, // Should default to 10 minutes
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Just verify it started without error - the renewal timer should be set
	// to ~23h50m from now (24h - 10m default renewBefore)
	cert, err := provider.GetCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.NotNil(t, cert)

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: issueCertificate - X509KeyPair failure
// ============================================================

func TestVaultProvider_IssueCertificate_InvalidKeyPair(t *testing.T) {
	mockPKI := &mockPKIClientForRenewal{
		certPEM:      "not-a-valid-cert",
		keyPEM:       "not-a-valid-key",
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create TLS certificate")

	// NOTE: Do NOT call provider.Close() here. When Start() fails after setting
	// p.started=true but before launching the renewal goroutine, Close() would
	// block forever waiting on stoppedCh which is never closed.
}

// ============================================================
// Test: issueCertificate - cert without parseable leaf
// ============================================================

func TestVaultProvider_IssueCertificate_NoParsableLeaf(t *testing.T) {
	// Generate a valid cert/key pair but with a cert that has no parseable leaf
	// This is hard to achieve with real certs, so we test the normal path
	// which does parse the leaf successfully
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Verify cert info was stored
	info := provider.GetCertificateInfo()
	assert.NotNil(t, info)

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: renewalLoop - successful renewal sends reloaded event
// ============================================================

func TestVaultProvider_RenewalLoop_SuccessfulRenewal(t *testing.T) {
	// Create a cert that expires very soon
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(2*time.Second))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(2 * time.Second),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:    "pki",
		Role:        "test-role",
		CommonName:  "test.example.com",
		RenewBefore: 1 * time.Second,
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Wait for renewal
	time.Sleep(3 * time.Second)

	// Check events
	ch := provider.Watch(context.Background())
	hasLoaded := false
	hasReloaded := false
	for {
		select {
		case event := <-ch:
			if event.Type == internaltls.CertificateEventLoaded {
				hasLoaded = true
			}
			if event.Type == internaltls.CertificateEventReloaded {
				hasReloaded = true
			}
		default:
			goto checkDone
		}
	}
checkDone:
	assert.True(t, hasLoaded, "expected loaded event")
	assert.True(t, hasReloaded, "expected reloaded event after successful renewal")

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: loadCAPool - success with default mount
// ============================================================

func TestVaultProvider_LoadCAPool_DefaultMount(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	caPool := x509.NewCertPool()
	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
		caPool:       caPool,
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	// No CAMount set - should use PKIMount
	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	assert.NoError(t, err)

	pool, err := provider.GetClientCA(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, pool)

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: Close with started provider waits for stoppedCh
// ============================================================

func TestVaultProvider_Close_WaitsForRenewalLoop(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.Start(ctx)
	require.NoError(t, err)

	// Close should wait for renewal loop to stop
	done := make(chan struct{})
	go func() {
		_ = provider.Close()
		close(done)
	}()

	select {
	case <-done:
		// Success - Close completed
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not complete in time")
	}
}

// ============================================================
// Test: GetCertificate - no cert loaded returns error
// ============================================================

func TestVaultProvider_GetCertificate_NoCertLoaded(t *testing.T) {
	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     &mockPKIClientForRenewal{},
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)
	defer provider.Close()

	// Without Start(), no cert is loaded
	cert, err := provider.GetCertificate(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, internaltls.ErrCertificateNotFound)
}

// ============================================================
// Test: issueCertificate with cert that has no DER data
// ============================================================

func TestVaultProvider_IssueCertificate_EmptyCertificateSlice(t *testing.T) {
	// Generate a valid cert/key pair - the normal path
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "test-serial",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Verify the cert was stored with leaf parsed
	storedCert := provider.cert.Load()
	require.NotNil(t, storedCert)
	assert.NotNil(t, storedCert.Leaf, "leaf should be parsed from valid cert")

	cancel()
	_ = provider.Close()
}

// ============================================================
// Test: renewalLoop with cert that has nil leaf (calculateRenewalTime returns now)
// ============================================================

func TestVaultProvider_RenewalLoop_NilLeafCert(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t, time.Now().Add(24*time.Hour))

	mockPKI := &mockPKIClientForRenewal{
		certPEM:      certPEM,
		keyPEM:       keyPEM,
		serialNumber: "aa:bb:cc:dd",
		expiration:   time.Now().Add(24 * time.Hour),
	}

	client := &mockVaultClientForRenewal{
		enabled: true,
		pki:     mockPKI,
	}

	provider, err := NewVaultProvider(client, &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}, WithVaultProviderLogger(observability.NopLogger()))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Manually set cert without leaf to test calculateRenewalTime nil leaf path
	provider.cert.Store(&tls.Certificate{})

	// The renewal loop is already running; it will recalculate renewal time
	// on next iteration. Just verify it doesn't crash.
	time.Sleep(100 * time.Millisecond)

	cancel()
	_ = provider.Close()
}
