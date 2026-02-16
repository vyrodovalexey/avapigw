// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// MockVaultClient is a mock implementation of vault.Client for testing.
type MockVaultClient struct {
	mock.Mock
}

func (m *MockVaultClient) IsEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockVaultClient) Authenticate(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockVaultClient) RenewToken(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockVaultClient) Health(ctx context.Context) (*vault.HealthStatus, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vault.HealthStatus), args.Error(1)
}

func (m *MockVaultClient) PKI() vault.PKIClient {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(vault.PKIClient)
}

func (m *MockVaultClient) KV() vault.KVClient {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(vault.KVClient)
}

func (m *MockVaultClient) Transit() vault.TransitClient {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(vault.TransitClient)
}

func (m *MockVaultClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockPKIClient is a mock implementation of vault.PKIClient for testing.
type MockPKIClient struct {
	mock.Mock
}

func (m *MockPKIClient) IssueCertificate(ctx context.Context, opts *vault.PKIIssueOptions) (*vault.Certificate, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vault.Certificate), args.Error(1)
}

func (m *MockPKIClient) SignCSR(ctx context.Context, csr []byte, opts *vault.PKISignOptions) (*vault.Certificate, error) {
	args := m.Called(ctx, csr, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vault.Certificate), args.Error(1)
}

func (m *MockPKIClient) GetCA(ctx context.Context, mount string) (*x509.CertPool, error) {
	args := m.Called(ctx, mount)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

func (m *MockPKIClient) GetCRL(ctx context.Context, mount string) ([]byte, error) {
	args := m.Called(ctx, mount)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockPKIClient) RevokeCertificate(ctx context.Context, mount, serial string) error {
	args := m.Called(ctx, mount, serial)
	return args.Error(0)
}

// testVaultProvider creates a vaultProvider with mocked dependencies for testing.
func newTestVaultProvider(vaultClient vault.Client, config *VaultProviderConfig) *vaultProvider {
	return &vaultProvider{
		config:      config,
		vaultClient: vaultClient,
		logger:      observability.NopLogger(),
		certs:       make(map[string]*Certificate),
	}
}

// ============================================================================
// NewVaultProvider Tests
// ============================================================================

func TestNewVaultProvider_NilConfig(t *testing.T) {
	// Arrange & Act
	provider, err := NewVaultProvider(context.Background(), nil)

	// Assert
	require.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "config is required")
}

func TestNewVaultProvider_EmptyAddress(t *testing.T) {
	// Arrange
	config := &VaultProviderConfig{
		Address: "",
		Role:    "test-role",
	}

	// Act
	provider, err := NewVaultProvider(context.Background(), config)

	// Assert
	require.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "vault address is required")
}

func TestNewVaultProvider_EmptyRole(t *testing.T) {
	// Arrange
	config := &VaultProviderConfig{
		Address: "http://localhost:8200",
		Role:    "",
	}

	// Act
	provider, err := NewVaultProvider(context.Background(), config)

	// Assert
	require.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "vault PKI role is required")
}

func TestNewVaultProvider_DefaultPKIMount(t *testing.T) {
	// Arrange
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		Role:     "test-role",
		PKIMount: "", // Should default to "pki"
	}

	// Act - This will fail at vault client creation, but we can verify defaults are set
	_, _ = NewVaultProvider(context.Background(), config)

	// Assert - config should have default PKIMount
	assert.Equal(t, "pki", config.PKIMount)
}

func TestNewVaultProvider_DefaultTTL(t *testing.T) {
	// Arrange
	config := &VaultProviderConfig{
		Address: "http://localhost:8200",
		Role:    "test-role",
		TTL:     0, // Should default to 24 hours
	}

	// Act - This will fail at vault client creation, but we can verify defaults are set
	_, _ = NewVaultProvider(context.Background(), config)

	// Assert - config should have default TTL
	assert.Equal(t, 24*time.Hour, config.TTL)
}

func TestNewVaultProvider_DefaultRotateBefore(t *testing.T) {
	// Arrange
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		Role:         "test-role",
		RotateBefore: 0, // Should default to 1 hour
	}

	// Act - This will fail at vault client creation, but we can verify defaults are set
	_, _ = NewVaultProvider(context.Background(), config)

	// Assert - config should have default RotateBefore
	assert.Equal(t, 1*time.Hour, config.RotateBefore)
}

// ============================================================================
// GetCertificate Tests
// ============================================================================

func TestVaultProvider_GetCertificate_ProviderClosed(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
		TTL:      24 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)
	provider.closed.Store(true)

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
	})

	// Assert
	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "certificate provider is closed")
}

func TestVaultProvider_GetCertificate_NilRequest(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
		TTL:      24 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Act
	cert, err := provider.GetCertificate(context.Background(), nil)

	// Assert
	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "common name is required")
}

func TestVaultProvider_GetCertificate_EmptyCommonName(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
		TTL:      24 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "",
	})

	// Assert
	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "common name is required")
}

func TestVaultProvider_GetCertificate_CachedValid(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Pre-cache a valid certificate
	cachedCert := &Certificate{
		Certificate:    &x509.Certificate{},
		SerialNumber:   "cached-serial",
		Expiration:     time.Now().Add(12 * time.Hour), // Valid and not expiring soon
		CertificatePEM: []byte("cached-cert"),
		PrivateKeyPEM:  []byte("cached-key"),
	}
	provider.certs["test.example.com"] = cachedCert

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
	})

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "cached-serial", cert.SerialNumber)
}

func TestVaultProvider_GetCertificate_CachedExpiringSoon(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 2 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Pre-cache a certificate that's expiring soon
	cachedCert := &Certificate{
		Certificate:    &x509.Certificate{},
		SerialNumber:   "cached-serial",
		Expiration:     time.Now().Add(30 * time.Minute), // Expiring within RotateBefore
		CertificatePEM: []byte("cached-cert"),
		PrivateKeyPEM:  []byte("cached-key"),
	}
	provider.certs["test.example.com"] = cachedCert

	// Setup mock for new certificate issuance
	newVaultCert := &vault.Certificate{
		Certificate:    &x509.Certificate{},
		CertificatePEM: "new-cert-pem",
		PrivateKeyPEM:  "new-key-pem",
		CAChainPEM:     "ca-chain-pem",
		SerialNumber:   "new-serial",
		Expiration:     time.Now().Add(24 * time.Hour),
	}
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.Anything).Return(newVaultCert, nil)

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
	})

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "new-serial", cert.SerialNumber)
	mockPKI.AssertExpectations(t)
}

func TestVaultProvider_GetCertificate_IssueNew(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Setup mock for certificate issuance
	vaultCert := &vault.Certificate{
		Certificate:    &x509.Certificate{},
		CertificatePEM: "cert-pem",
		PrivateKeyPEM:  "key-pem",
		CAChainPEM:     "ca-chain-pem",
		SerialNumber:   "test-serial",
		Expiration:     time.Now().Add(24 * time.Hour),
	}
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.MatchedBy(func(opts *vault.PKIIssueOptions) bool {
		return opts.Mount == "pki" &&
			opts.Role == "test-role" &&
			opts.CommonName == "test.example.com"
	})).Return(vaultCert, nil)

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName:  "test.example.com",
		DNSNames:    []string{"test.example.com", "localhost"},
		IPAddresses: []string{"127.0.0.1"},
	})

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "test-serial", cert.SerialNumber)
	assert.Equal(t, []byte("cert-pem"), cert.CertificatePEM)
	assert.Equal(t, []byte("key-pem"), cert.PrivateKeyPEM)
	assert.Equal(t, []byte("ca-chain-pem"), cert.CAChainPEM)
	mockPKI.AssertExpectations(t)
}

func TestVaultProvider_GetCertificate_IssueError(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Setup mock for certificate issuance failure
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.Anything).Return(nil, errors.New("vault error"))

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
	})

	// Assert
	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to issue certificate from vault")
	mockPKI.AssertExpectations(t)
}

func TestVaultProvider_GetCertificate_CustomTTL(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	customTTL := 48 * time.Hour

	// Setup mock for certificate issuance with custom TTL
	vaultCert := &vault.Certificate{
		Certificate:    &x509.Certificate{},
		CertificatePEM: "cert-pem",
		PrivateKeyPEM:  "key-pem",
		SerialNumber:   "test-serial",
		Expiration:     time.Now().Add(customTTL),
	}
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.MatchedBy(func(opts *vault.PKIIssueOptions) bool {
		return opts.TTL == customTTL
	})).Return(vaultCert, nil)

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
		TTL:        customTTL,
	})

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cert)
	mockPKI.AssertExpectations(t)
}

// ============================================================================
// GetCA Tests
// ============================================================================

func TestVaultProvider_GetCA_ProviderClosed(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)
	provider.closed.Store(true)

	// Act
	pool, err := provider.GetCA(context.Background())

	// Assert
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "certificate provider is closed")
}

func TestVaultProvider_GetCA_Success(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)

	// Setup mock
	caPool := x509.NewCertPool()
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("GetCA", mock.Anything, "pki").Return(caPool, nil)

	// Act
	pool, err := provider.GetCA(context.Background())

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, pool)
	mockPKI.AssertExpectations(t)
}

func TestVaultProvider_GetCA_Error(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)

	// Setup mock
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("GetCA", mock.Anything, "pki").Return(nil, errors.New("vault error"))

	// Act
	pool, err := provider.GetCA(context.Background())

	// Assert
	require.Error(t, err)
	assert.Nil(t, pool)
	mockPKI.AssertExpectations(t)
}

// ============================================================================
// RotateCertificate Tests
// ============================================================================

func TestVaultProvider_RotateCertificate_ProviderClosed(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)
	provider.closed.Store(true)

	// Act
	cert, err := provider.RotateCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
	})

	// Assert
	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "certificate provider is closed")
}

func TestVaultProvider_RotateCertificate_NilRequest(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)

	// Act
	cert, err := provider.RotateCertificate(context.Background(), nil)

	// Assert
	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "common name is required")
}

func TestVaultProvider_RotateCertificate_EmptyCommonName(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)

	// Act
	cert, err := provider.RotateCertificate(context.Background(), &CertificateRequest{
		CommonName: "",
	})

	// Assert
	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "common name is required")
}

func TestVaultProvider_RotateCertificate_Success(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Pre-cache an existing certificate
	provider.certs["test.example.com"] = &Certificate{
		SerialNumber: "old-serial",
	}

	// Setup mock for new certificate issuance
	vaultCert := &vault.Certificate{
		Certificate:    &x509.Certificate{},
		CertificatePEM: "new-cert-pem",
		PrivateKeyPEM:  "new-key-pem",
		SerialNumber:   "new-serial",
		Expiration:     time.Now().Add(24 * time.Hour),
	}
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.Anything).Return(vaultCert, nil)

	// Act
	cert, err := provider.RotateCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
	})

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "new-serial", cert.SerialNumber)
	// Verify the cache was updated
	assert.Equal(t, "new-serial", provider.certs["test.example.com"].SerialNumber)
	mockPKI.AssertExpectations(t)
}

// ============================================================================
// Close Tests
// ============================================================================

func TestVaultProvider_Close_Success(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)
	provider.certs["test.example.com"] = &Certificate{SerialNumber: "test"}

	mockClient.On("Close").Return(nil)

	// Act
	err := provider.Close()

	// Assert
	require.NoError(t, err)
	assert.True(t, provider.closed.Load())
	assert.Nil(t, provider.certs)
	mockClient.AssertExpectations(t)
}

func TestVaultProvider_Close_NilVaultClient(t *testing.T) {
	// Arrange
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := &vaultProvider{
		config:      config,
		vaultClient: nil,
		certs:       make(map[string]*Certificate),
	}

	// Act
	err := provider.Close()

	// Assert
	require.NoError(t, err)
	assert.True(t, provider.closed.Load())
}

func TestVaultProvider_Close_VaultClientError(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)

	mockClient.On("Close").Return(errors.New("close error"))

	// Act
	err := provider.Close()

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "close error")
	assert.True(t, provider.closed.Load())
	mockClient.AssertExpectations(t)
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestVaultProvider_ConcurrentGetCertificate(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Setup mock for certificate issuance
	vaultCert := &vault.Certificate{
		Certificate:    &x509.Certificate{},
		CertificatePEM: "cert-pem",
		PrivateKeyPEM:  "key-pem",
		SerialNumber:   "test-serial",
		Expiration:     time.Now().Add(24 * time.Hour),
	}
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.Anything).Return(vaultCert, nil)

	// Act - Run concurrent requests
	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := provider.GetCertificate(context.Background(), &CertificateRequest{
				CommonName: "test.example.com",
			})
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	// Assert - No errors should occur
	for err := range errCh {
		t.Errorf("Concurrent GetCertificate error: %v", err)
	}
}

// ============================================================================
// Table-Driven Tests
// ============================================================================

func TestVaultProvider_GetCertificate_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		request     *CertificateRequest
		setupMock   func(*MockVaultClient, *MockPKIClient)
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil request",
			request:     nil,
			setupMock:   func(c *MockVaultClient, p *MockPKIClient) {},
			wantErr:     true,
			errContains: "common name is required",
		},
		{
			name: "empty common name",
			request: &CertificateRequest{
				CommonName: "",
			},
			setupMock:   func(c *MockVaultClient, p *MockPKIClient) {},
			wantErr:     true,
			errContains: "common name is required",
		},
		{
			name: "successful issuance",
			request: &CertificateRequest{
				CommonName: "test.example.com",
				DNSNames:   []string{"test.example.com"},
			},
			setupMock: func(c *MockVaultClient, p *MockPKIClient) {
				vaultCert := &vault.Certificate{
					Certificate:    &x509.Certificate{},
					CertificatePEM: "cert-pem",
					PrivateKeyPEM:  "key-pem",
					SerialNumber:   "test-serial",
					Expiration:     time.Now().Add(24 * time.Hour),
				}
				c.On("PKI").Return(p)
				p.On("IssueCertificate", mock.Anything, mock.Anything).Return(vaultCert, nil)
			},
			wantErr: false,
		},
		{
			name: "vault error",
			request: &CertificateRequest{
				CommonName: "test.example.com",
			},
			setupMock: func(c *MockVaultClient, p *MockPKIClient) {
				c.On("PKI").Return(p)
				p.On("IssueCertificate", mock.Anything, mock.Anything).Return(nil, errors.New("vault unavailable"))
			},
			wantErr:     true,
			errContains: "failed to issue certificate from vault",
		},
		{
			name: "with IP addresses",
			request: &CertificateRequest{
				CommonName:  "test.example.com",
				IPAddresses: []string{"127.0.0.1", "192.168.1.1"},
			},
			setupMock: func(c *MockVaultClient, p *MockPKIClient) {
				vaultCert := &vault.Certificate{
					Certificate:    &x509.Certificate{},
					CertificatePEM: "cert-pem",
					PrivateKeyPEM:  "key-pem",
					SerialNumber:   "test-serial",
					Expiration:     time.Now().Add(24 * time.Hour),
				}
				c.On("PKI").Return(p)
				p.On("IssueCertificate", mock.Anything, mock.MatchedBy(func(opts *vault.PKIIssueOptions) bool {
					return len(opts.IPSANs) == 2
				})).Return(vaultCert, nil)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			mockClient := new(MockVaultClient)
			mockPKI := new(MockPKIClient)
			config := &VaultProviderConfig{
				Address:      "http://localhost:8200",
				PKIMount:     "pki",
				Role:         "test-role",
				TTL:          24 * time.Hour,
				RotateBefore: 1 * time.Hour,
			}
			provider := newTestVaultProvider(mockClient, config)
			tt.setupMock(mockClient, mockPKI)

			// Act
			cert, err := provider.GetCertificate(context.Background(), tt.request)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, cert)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cert)
			}
		})
	}
}

// ============================================================================
// VaultProviderConfig Tests
// ============================================================================

func TestVaultProviderConfig_Defaults(t *testing.T) {
	tests := []struct {
		name           string
		config         *VaultProviderConfig
		expectedMount  string
		expectedTTL    time.Duration
		expectedRotate time.Duration
	}{
		{
			name: "all defaults",
			config: &VaultProviderConfig{
				Address: "http://localhost:8200",
				Role:    "test-role",
			},
			expectedMount:  "pki",
			expectedTTL:    24 * time.Hour,
			expectedRotate: 1 * time.Hour,
		},
		{
			name: "custom mount",
			config: &VaultProviderConfig{
				Address:  "http://localhost:8200",
				Role:     "test-role",
				PKIMount: "custom-pki",
			},
			expectedMount:  "custom-pki",
			expectedTTL:    24 * time.Hour,
			expectedRotate: 1 * time.Hour,
		},
		{
			name: "custom TTL",
			config: &VaultProviderConfig{
				Address: "http://localhost:8200",
				Role:    "test-role",
				TTL:     48 * time.Hour,
			},
			expectedMount:  "pki",
			expectedTTL:    48 * time.Hour,
			expectedRotate: 1 * time.Hour,
		},
		{
			name: "custom rotate before",
			config: &VaultProviderConfig{
				Address:      "http://localhost:8200",
				Role:         "test-role",
				RotateBefore: 2 * time.Hour,
			},
			expectedMount:  "pki",
			expectedTTL:    24 * time.Hour,
			expectedRotate: 2 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act - This will fail at vault client creation, but defaults are set
			_, _ = NewVaultProvider(context.Background(), tt.config)

			// Assert
			assert.Equal(t, tt.expectedMount, tt.config.PKIMount)
			assert.Equal(t, tt.expectedTTL, tt.config.TTL)
			assert.Equal(t, tt.expectedRotate, tt.config.RotateBefore)
		})
	}
}

// ============================================================================
// authenticateWithRetry Tests
// ============================================================================

func TestAuthenticateWithRetry_Success(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     3,
		RetryBaseDelay: 10 * time.Millisecond,
		RetryMaxDelay:  100 * time.Millisecond,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Mock successful authentication
	mockClient.On("Authenticate", mock.Anything).Return(nil)

	// Act
	err := authenticateWithRetry(context.Background(), mockClient, config, logger, metrics)

	// Assert
	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestAuthenticateWithRetry_FailureThenSuccess(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     3,
		RetryBaseDelay: 10 * time.Millisecond,
		RetryMaxDelay:  100 * time.Millisecond,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Mock first call fails, second succeeds
	mockClient.On("Authenticate", mock.Anything).Return(errors.New("auth failed")).Once()
	mockClient.On("Authenticate", mock.Anything).Return(nil).Once()

	// Act
	err := authenticateWithRetry(context.Background(), mockClient, config, logger, metrics)

	// Assert
	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestAuthenticateWithRetry_AllRetriesFail(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     2,
		RetryBaseDelay: 10 * time.Millisecond,
		RetryMaxDelay:  50 * time.Millisecond,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Mock all calls fail
	mockClient.On("Authenticate", mock.Anything).Return(errors.New("auth failed"))

	// Act
	err := authenticateWithRetry(context.Background(), mockClient, config, logger, metrics)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to authenticate with vault")
	mockClient.AssertExpectations(t)
}

func TestAuthenticateWithRetry_ContextCanceled(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     5,
		RetryBaseDelay: 100 * time.Millisecond,
		RetryMaxDelay:  1 * time.Second,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Create canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Mock authentication to fail (but context should cancel first)
	mockClient.On("Authenticate", mock.Anything).Return(errors.New("auth failed")).Maybe()

	// Act
	err := authenticateWithRetry(ctx, mockClient, config, logger, metrics)

	// Assert
	require.Error(t, err)
}

// ============================================================================
// getVaultAuthMetrics Tests
// ============================================================================

func TestGetVaultAuthMetrics_Singleton(t *testing.T) {
	// Act
	metrics1 := getVaultAuthMetrics()
	metrics2 := getVaultAuthMetrics()

	// Assert - should return the same instance
	assert.Same(t, metrics1, metrics2)
	assert.NotNil(t, metrics1.authRetriesTotal)
}

func TestGetVaultAuthMetrics_MetricsInitialized(t *testing.T) {
	// Act
	metrics := getVaultAuthMetrics()

	// Assert
	assert.NotNil(t, metrics)
	assert.NotNil(t, metrics.authRetriesTotal)
}

// ============================================================================
// VaultProviderConfig Retry Defaults Tests
// ============================================================================

func TestVaultProviderConfig_RetryDefaults(t *testing.T) {
	tests := []struct {
		name                   string
		config                 *VaultProviderConfig
		expectedMaxRetries     int
		expectedRetryBaseDelay time.Duration
		expectedRetryMaxDelay  time.Duration
	}{
		{
			name: "all retry defaults",
			config: &VaultProviderConfig{
				Address: "http://localhost:8200",
				Role:    "test-role",
			},
			expectedMaxRetries:     DefaultVaultMaxRetries,
			expectedRetryBaseDelay: DefaultVaultRetryBaseDelay,
			expectedRetryMaxDelay:  DefaultVaultRetryMaxDelay,
		},
		{
			name: "custom max retries",
			config: &VaultProviderConfig{
				Address:    "http://localhost:8200",
				Role:       "test-role",
				MaxRetries: 5,
			},
			expectedMaxRetries:     5,
			expectedRetryBaseDelay: DefaultVaultRetryBaseDelay,
			expectedRetryMaxDelay:  DefaultVaultRetryMaxDelay,
		},
		{
			name: "custom retry delays",
			config: &VaultProviderConfig{
				Address:        "http://localhost:8200",
				Role:           "test-role",
				RetryBaseDelay: 2 * time.Second,
				RetryMaxDelay:  60 * time.Second,
			},
			expectedMaxRetries:     DefaultVaultMaxRetries,
			expectedRetryBaseDelay: 2 * time.Second,
			expectedRetryMaxDelay:  60 * time.Second,
		},
		{
			name: "zero max retries uses default",
			config: &VaultProviderConfig{
				Address:    "http://localhost:8200",
				Role:       "test-role",
				MaxRetries: 0,
			},
			expectedMaxRetries:     DefaultVaultMaxRetries,
			expectedRetryBaseDelay: DefaultVaultRetryBaseDelay,
			expectedRetryMaxDelay:  DefaultVaultRetryMaxDelay,
		},
		{
			name: "negative max retries uses default",
			config: &VaultProviderConfig{
				Address:    "http://localhost:8200",
				Role:       "test-role",
				MaxRetries: -1,
			},
			expectedMaxRetries:     DefaultVaultMaxRetries,
			expectedRetryBaseDelay: DefaultVaultRetryBaseDelay,
			expectedRetryMaxDelay:  DefaultVaultRetryMaxDelay,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act - This will fail at vault client creation, but defaults are set
			_, _ = NewVaultProvider(context.Background(), tt.config)

			// Assert
			assert.Equal(t, tt.expectedMaxRetries, tt.config.MaxRetries)
			assert.Equal(t, tt.expectedRetryBaseDelay, tt.config.RetryBaseDelay)
			assert.Equal(t, tt.expectedRetryMaxDelay, tt.config.RetryMaxDelay)
		})
	}
}

// ============================================================================
// Certificate Validity Tests
// ============================================================================

func TestCertificate_IsValid_NilCertificate(t *testing.T) {
	var cert *Certificate
	assert.False(t, cert.IsValid())
}

func TestCertificate_IsValid_NilX509Certificate(t *testing.T) {
	cert := &Certificate{
		Certificate: nil,
	}
	assert.False(t, cert.IsValid())
}

func TestCertificate_IsValid_Expired(t *testing.T) {
	cert := &Certificate{
		Certificate: &x509.Certificate{},
		Expiration:  time.Now().Add(-1 * time.Hour),
	}
	assert.False(t, cert.IsValid())
}

func TestCertificate_IsValid_Valid(t *testing.T) {
	cert := &Certificate{
		Certificate: &x509.Certificate{},
		Expiration:  time.Now().Add(24 * time.Hour),
	}
	assert.True(t, cert.IsValid())
}

func TestCertificate_IsExpiringSoon_NilCertificate(t *testing.T) {
	var cert *Certificate
	assert.True(t, cert.IsExpiringSoon(1*time.Hour))
}

func TestCertificate_IsExpiringSoon_NilX509Certificate(t *testing.T) {
	cert := &Certificate{
		Certificate: nil,
	}
	assert.True(t, cert.IsExpiringSoon(1*time.Hour))
}

func TestCertificate_IsExpiringSoon_ExpiringSoon(t *testing.T) {
	cert := &Certificate{
		Certificate: &x509.Certificate{},
		Expiration:  time.Now().Add(30 * time.Minute),
	}
	assert.True(t, cert.IsExpiringSoon(1*time.Hour))
}

func TestCertificate_IsExpiringSoon_NotExpiringSoon(t *testing.T) {
	cert := &Certificate{
		Certificate: &x509.Certificate{},
		Expiration:  time.Now().Add(24 * time.Hour),
	}
	assert.False(t, cert.IsExpiringSoon(1*time.Hour))
}

// Ensure vaultProvider implements Manager interface
var _ Manager = (*vaultProvider)(nil)

// ============================================================================
// Additional authenticateWithRetry Tests
// ============================================================================

func TestAuthenticateWithRetry_MultipleFailuresThenSuccess(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     5,
		RetryBaseDelay: 5 * time.Millisecond,
		RetryMaxDelay:  50 * time.Millisecond,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Mock first 3 calls fail, 4th succeeds
	mockClient.On("Authenticate", mock.Anything).Return(errors.New("auth failed")).Times(3)
	mockClient.On("Authenticate", mock.Anything).Return(nil).Once()

	// Act
	err := authenticateWithRetry(context.Background(), mockClient, config, logger, metrics)

	// Assert
	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestAuthenticateWithRetry_ContextDeadlineExceeded(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     10,
		RetryBaseDelay: 100 * time.Millisecond,
		RetryMaxDelay:  1 * time.Second,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Create context with deadline
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	// Mock authentication to fail
	mockClient.On("Authenticate", mock.Anything).Return(errors.New("auth failed")).Maybe()

	// Act
	err := authenticateWithRetry(ctx, mockClient, config, logger, metrics)

	// Assert
	require.Error(t, err)
}

func TestAuthenticateWithRetry_ImmediateSuccess(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     3,
		RetryBaseDelay: 10 * time.Millisecond,
		RetryMaxDelay:  100 * time.Millisecond,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Mock immediate success
	mockClient.On("Authenticate", mock.Anything).Return(nil).Once()

	// Act
	err := authenticateWithRetry(context.Background(), mockClient, config, logger, metrics)

	// Assert
	require.NoError(t, err)
	mockClient.AssertExpectations(t)
	// Verify only one call was made
	mockClient.AssertNumberOfCalls(t, "Authenticate", 1)
}

// ============================================================================
// getVaultAuthMetrics Additional Tests
// ============================================================================

func TestGetVaultAuthMetrics_ConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	results := make([]*vaultAuthMetrics, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = getVaultAuthMetrics()
		}(i)
	}

	wg.Wait()

	// All results should be the same instance
	for i := 1; i < 10; i++ {
		if results[i] != results[0] {
			t.Error("getVaultAuthMetrics() should return the same instance")
		}
	}
}

// ============================================================================
// VaultProvider Edge Cases
// ============================================================================

func TestVaultProvider_GetCertificate_CachedExpired(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Pre-cache an expired certificate
	cachedCert := &Certificate{
		Certificate:    &x509.Certificate{},
		SerialNumber:   "expired-serial",
		Expiration:     time.Now().Add(-1 * time.Hour), // Already expired
		CertificatePEM: []byte("expired-cert"),
		PrivateKeyPEM:  []byte("expired-key"),
	}
	provider.certs["test.example.com"] = cachedCert

	// Setup mock for new certificate issuance
	newVaultCert := &vault.Certificate{
		Certificate:    &x509.Certificate{},
		CertificatePEM: "new-cert-pem",
		PrivateKeyPEM:  "new-key-pem",
		CAChainPEM:     "ca-chain-pem",
		SerialNumber:   "new-serial",
		Expiration:     time.Now().Add(24 * time.Hour),
	}
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.Anything).Return(newVaultCert, nil)

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
	})

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "new-serial", cert.SerialNumber)
	mockPKI.AssertExpectations(t)
}

func TestVaultProvider_GetCertificate_CachedNilCertificate(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Pre-cache a certificate with nil x509.Certificate
	cachedCert := &Certificate{
		Certificate:    nil, // Invalid - nil certificate
		SerialNumber:   "invalid-serial",
		Expiration:     time.Now().Add(12 * time.Hour),
		CertificatePEM: []byte("invalid-cert"),
		PrivateKeyPEM:  []byte("invalid-key"),
	}
	provider.certs["test.example.com"] = cachedCert

	// Setup mock for new certificate issuance
	newVaultCert := &vault.Certificate{
		Certificate:    &x509.Certificate{},
		CertificatePEM: "new-cert-pem",
		PrivateKeyPEM:  "new-key-pem",
		CAChainPEM:     "ca-chain-pem",
		SerialNumber:   "new-serial",
		Expiration:     time.Now().Add(24 * time.Hour),
	}
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.Anything).Return(newVaultCert, nil)

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
	})

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "new-serial", cert.SerialNumber)
	mockPKI.AssertExpectations(t)
}

// ============================================================================
// VaultProviderConfig Validation Tests
// ============================================================================

func TestVaultProviderConfig_AllFieldsSet(t *testing.T) {
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "custom-pki",
		Role:           "custom-role",
		TTL:            48 * time.Hour,
		RotateBefore:   2 * time.Hour,
		MaxRetries:     5,
		RetryBaseDelay: 2 * time.Second,
		RetryMaxDelay:  60 * time.Second,
	}

	// Act - This will fail at vault client creation, but we can verify config is preserved
	_, _ = NewVaultProvider(context.Background(), config)

	// Assert - custom values should be preserved
	assert.Equal(t, "custom-pki", config.PKIMount)
	assert.Equal(t, 48*time.Hour, config.TTL)
	assert.Equal(t, 2*time.Hour, config.RotateBefore)
	assert.Equal(t, 5, config.MaxRetries)
	assert.Equal(t, 2*time.Second, config.RetryBaseDelay)
	assert.Equal(t, 60*time.Second, config.RetryMaxDelay)
}

// ============================================================================
// Certificate Validity Edge Cases
// ============================================================================

func TestCertificate_IsValid_ExactlyAtExpiration(t *testing.T) {
	cert := &Certificate{
		Certificate: &x509.Certificate{},
		Expiration:  time.Now(),
	}
	// At exact expiration time, should be invalid
	assert.False(t, cert.IsValid())
}

func TestCertificate_IsExpiringSoon_ExactlyAtThreshold(t *testing.T) {
	threshold := 1 * time.Hour
	cert := &Certificate{
		Certificate: &x509.Certificate{},
		Expiration:  time.Now().Add(threshold),
	}
	// At exact threshold, should be expiring soon
	assert.True(t, cert.IsExpiringSoon(threshold))
}

func TestCertificate_IsExpiringSoon_JustAfterThreshold(t *testing.T) {
	threshold := 1 * time.Hour
	cert := &Certificate{
		Certificate: &x509.Certificate{},
		Expiration:  time.Now().Add(threshold + 1*time.Second),
	}
	// Just after threshold, should not be expiring soon
	assert.False(t, cert.IsExpiringSoon(threshold))
}

func TestCertificate_IsExpiringSoon_ZeroThreshold(t *testing.T) {
	cert := &Certificate{
		Certificate: &x509.Certificate{},
		Expiration:  time.Now().Add(24 * time.Hour),
	}
	// With zero threshold, should not be expiring soon
	assert.False(t, cert.IsExpiringSoon(0))
}

// ============================================================================
// VaultProvider Concurrent Operations Tests
// ============================================================================

func TestVaultProvider_ConcurrentGetCA(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)

	// Setup mock
	caPool := x509.NewCertPool()
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("GetCA", mock.Anything, "pki").Return(caPool, nil)

	// Act - Run concurrent requests
	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := provider.GetCA(context.Background())
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Assert - No errors should occur
	for err := range errCh {
		t.Errorf("Concurrent GetCA error: %v", err)
	}
}

func TestVaultProvider_ConcurrentRotateCertificate(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Setup mock for certificate issuance
	vaultCert := &vault.Certificate{
		Certificate:    &x509.Certificate{},
		CertificatePEM: "cert-pem",
		PrivateKeyPEM:  "key-pem",
		SerialNumber:   "test-serial",
		Expiration:     time.Now().Add(24 * time.Hour),
	}
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.Anything).Return(vaultCert, nil)

	// Act - Run concurrent requests
	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := provider.RotateCertificate(context.Background(), &CertificateRequest{
				CommonName: "test.example.com",
			})
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Assert - No errors should occur
	for err := range errCh {
		t.Errorf("Concurrent RotateCertificate error: %v", err)
	}
}

// ============================================================================
// VaultProvider Close Edge Cases
// ============================================================================

func TestVaultProvider_Close_MultipleCalls(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)

	mockClient.On("Close").Return(nil)

	// Act - Close multiple times
	err1 := provider.Close()
	err2 := provider.Close()

	// Assert - First close should succeed, second should also succeed (idempotent)
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.True(t, provider.closed.Load())
}

func TestVaultProvider_OperationsAfterClose(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:  "http://localhost:8200",
		PKIMount: "pki",
		Role:     "test-role",
	}
	provider := newTestVaultProvider(mockClient, config)

	mockClient.On("Close").Return(nil)

	// Close the provider
	_ = provider.Close()

	// Act & Assert - All operations should fail
	_, err := provider.GetCertificate(context.Background(), &CertificateRequest{CommonName: "test"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate provider is closed")

	_, err = provider.GetCA(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate provider is closed")

	_, err = provider.RotateCertificate(context.Background(), &CertificateRequest{CommonName: "test"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate provider is closed")
}

// ============================================================================
// issueCertificate Tests
// ============================================================================

func TestVaultProvider_issueCertificate_WithAllOptions(t *testing.T) {
	// Arrange
	mockClient := new(MockVaultClient)
	mockPKI := new(MockPKIClient)
	config := &VaultProviderConfig{
		Address:      "http://localhost:8200",
		PKIMount:     "pki",
		Role:         "test-role",
		TTL:          24 * time.Hour,
		RotateBefore: 1 * time.Hour,
	}
	provider := newTestVaultProvider(mockClient, config)

	// Setup mock for certificate issuance with all options
	vaultCert := &vault.Certificate{
		Certificate:    &x509.Certificate{},
		CertificatePEM: "cert-pem",
		PrivateKeyPEM:  "key-pem",
		CAChainPEM:     "ca-chain-pem",
		SerialNumber:   "test-serial",
		Expiration:     time.Now().Add(24 * time.Hour),
	}
	mockClient.On("PKI").Return(mockPKI)
	mockPKI.On("IssueCertificate", mock.Anything, mock.MatchedBy(func(opts *vault.PKIIssueOptions) bool {
		return opts.Mount == "pki" &&
			opts.Role == "test-role" &&
			opts.CommonName == "test.example.com" &&
			len(opts.AltNames) == 2 &&
			len(opts.IPSANs) == 2
	})).Return(vaultCert, nil)

	// Act
	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName:  "test.example.com",
		DNSNames:    []string{"test.example.com", "localhost"},
		IPAddresses: []string{"127.0.0.1", "192.168.1.1"},
	})

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "test-serial", cert.SerialNumber)
	assert.Equal(t, []byte("cert-pem"), cert.CertificatePEM)
	assert.Equal(t, []byte("key-pem"), cert.PrivateKeyPEM)
	assert.Equal(t, []byte("ca-chain-pem"), cert.CAChainPEM)
	mockPKI.AssertExpectations(t)
}

// ============================================================================
// NewVaultProvider Retry Configuration Tests
// ============================================================================

func TestNewVaultProvider_NegativeRetryValues(t *testing.T) {
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		Role:           "test-role",
		MaxRetries:     -5,
		RetryBaseDelay: -1 * time.Second,
		RetryMaxDelay:  -30 * time.Second,
	}

	// Act - This will fail at vault client creation, but defaults should be applied
	_, _ = NewVaultProvider(context.Background(), config)

	// Assert - negative values should be replaced with defaults
	assert.Equal(t, DefaultVaultMaxRetries, config.MaxRetries)
	assert.Equal(t, DefaultVaultRetryBaseDelay, config.RetryBaseDelay)
	assert.Equal(t, DefaultVaultRetryMaxDelay, config.RetryMaxDelay)
}

// ============================================================================
// errors.Join / errors.Is / errors.As Tests for authenticateWithRetry
// ============================================================================

func TestAuthenticateWithRetry_ErrorsIs_WorksOnReturnedError(t *testing.T) {
	// Arrange: create a sentinel error type to verify errors.Is works
	sentinelErr := errors.New("sentinel auth error")
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     1,
		RetryBaseDelay: 5 * time.Millisecond,
		RetryMaxDelay:  10 * time.Millisecond,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Mock all calls fail with the sentinel error
	mockClient.On("Authenticate", mock.Anything).Return(sentinelErr)

	// Act
	err := authenticateWithRetry(context.Background(), mockClient, config, logger, metrics)

	// Assert: the returned error should contain the sentinel error via errors.Is
	require.Error(t, err)
	assert.True(t, errors.Is(err, sentinelErr),
		"errors.Is should find the sentinel error in the joined error chain")
	assert.Contains(t, err.Error(), "failed to authenticate with vault")
	assert.Contains(t, err.Error(), "sentinel auth error")
}

// customAuthError is a typed error for testing errors.As.
type customAuthError struct {
	Code    int
	Message string
}

func (e *customAuthError) Error() string {
	return e.Message
}

func TestAuthenticateWithRetry_ErrorsAs_WorksOnReturnedError(t *testing.T) {
	// Arrange: create a typed error to verify errors.As works
	typedErr := &customAuthError{Code: 403, Message: "forbidden"}
	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     1,
		RetryBaseDelay: 5 * time.Millisecond,
		RetryMaxDelay:  10 * time.Millisecond,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Mock all calls fail with the typed error
	mockClient.On("Authenticate", mock.Anything).Return(typedErr)

	// Act
	err := authenticateWithRetry(context.Background(), mockClient, config, logger, metrics)

	// Assert: the returned error should allow errors.As to extract the typed error
	require.Error(t, err)
	var target *customAuthError
	assert.True(t, errors.As(err, &target),
		"errors.As should extract customAuthError from the joined error chain")
	assert.Equal(t, 403, target.Code)
	assert.Equal(t, "forbidden", target.Message)
}

func TestAuthenticateWithRetry_AllOriginalErrorsPreserved(t *testing.T) {
	// Arrange: create distinct errors for each attempt
	err1 := errors.New("attempt-1-error")
	err2 := errors.New("attempt-2-error")
	err3 := errors.New("attempt-3-error")

	mockClient := new(MockVaultClient)
	config := &VaultProviderConfig{
		Address:        "http://localhost:8200",
		PKIMount:       "pki",
		Role:           "test-role",
		MaxRetries:     3,
		RetryBaseDelay: 5 * time.Millisecond,
		RetryMaxDelay:  10 * time.Millisecond,
	}
	logger := observability.NopLogger()
	metrics := getVaultAuthMetrics()

	// Mock: each call returns a different error
	mockClient.On("Authenticate", mock.Anything).Return(err1).Once()
	mockClient.On("Authenticate", mock.Anything).Return(err2).Once()
	mockClient.On("Authenticate", mock.Anything).Return(err3).Once()
	// Final attempt (retry #3 = 4th call total) also fails
	mockClient.On("Authenticate", mock.Anything).Return(err3).Once()

	// Act
	err := authenticateWithRetry(context.Background(), mockClient, config, logger, metrics)

	// Assert: all original errors should be preserved in the chain
	require.Error(t, err)

	// errors.Is should find each original error
	assert.True(t, errors.Is(err, err1),
		"errors.Is should find err1 in the joined error chain")
	assert.True(t, errors.Is(err, err2),
		"errors.Is should find err2 in the joined error chain")
	assert.True(t, errors.Is(err, err3),
		"errors.Is should find err3 in the joined error chain")

	// The error message should contain all attempt descriptions
	errMsg := err.Error()
	assert.Contains(t, errMsg, "attempt-1-error")
	assert.Contains(t, errMsg, "attempt-2-error")
	assert.Contains(t, errMsg, "attempt-3-error")
	assert.Contains(t, errMsg, "failed to authenticate with vault")
	assert.Contains(t, errMsg, "final error")
}
