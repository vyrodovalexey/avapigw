package backend

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/vyrodovalexey/avapigw/internal/backend/auth"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// ---------------------------------------------------------------------------
// Mock auth provider for testing
// ---------------------------------------------------------------------------

// mockAuthProvider implements auth.Provider for testing.
type mockAuthProvider struct {
	name         string
	authType     string
	applyHTTPErr error
	applyGRPCErr error
	refreshErr   error
	closeErr     error
	grpcOpts     []grpc.DialOption
}

func (m *mockAuthProvider) Name() string { return m.name }
func (m *mockAuthProvider) Type() string { return m.authType }

func (m *mockAuthProvider) ApplyHTTP(_ context.Context, req *http.Request) error {
	if m.applyHTTPErr != nil {
		return m.applyHTTPErr
	}
	req.Header.Set("Authorization", "Bearer mock-token")
	return nil
}

func (m *mockAuthProvider) ApplyGRPC(_ context.Context) ([]grpc.DialOption, error) {
	if m.applyGRPCErr != nil {
		return nil, m.applyGRPCErr
	}
	return m.grpcOpts, nil
}

func (m *mockAuthProvider) Refresh(_ context.Context) error {
	return m.refreshErr
}

func (m *mockAuthProvider) Close() error {
	return m.closeErr
}

// Ensure mockAuthProvider implements auth.Provider.
var _ auth.Provider = (*mockAuthProvider)(nil)

// ---------------------------------------------------------------------------
// Mock vault client for testing
// ---------------------------------------------------------------------------

// mockVaultClient is a minimal mock for vault.Client.
type mockVaultClient struct {
	enabled bool
}

func (m *mockVaultClient) IsEnabled() bool                                       { return m.enabled }
func (m *mockVaultClient) Authenticate(_ context.Context) error                  { return nil }
func (m *mockVaultClient) RenewToken(_ context.Context) error                    { return nil }
func (m *mockVaultClient) Health(_ context.Context) (*vault.HealthStatus, error) { return nil, nil }
func (m *mockVaultClient) PKI() vault.PKIClient                                  { return nil }
func (m *mockVaultClient) KV() vault.KVClient                                    { return nil }
func (m *mockVaultClient) Transit() vault.TransitClient                          { return nil }
func (m *mockVaultClient) Close() error                                          { return nil }

// Ensure mockVaultClient implements vault.Client.
var _ vault.Client = (*mockVaultClient)(nil)

// ---------------------------------------------------------------------------
// Tests for initAuthProvider
// ---------------------------------------------------------------------------

func TestInitAuthProvider_NilAuthentication(t *testing.T) {
	t.Parallel()

	// Arrange: backend config with no authentication
	cfg := config.Backend{
		Name: "test-no-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		Authentication: nil,
	}

	// Act
	backend, err := NewBackend(cfg)

	// Assert
	require.NoError(t, err)
	assert.Nil(t, backend.authProvider)
}

func TestInitAuthProvider_AlreadySet(t *testing.T) {
	t.Parallel()

	// Arrange: backend with auth provider already set via option
	mockProvider := &mockAuthProvider{name: "pre-set", authType: "mock"}

	cfg := config.Backend{
		Name: "test-preset-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		Authentication: &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		},
	}

	// Act
	backend, err := NewBackend(cfg, WithAuthProvider(mockProvider))

	// Assert: the pre-set provider should be kept, initAuthProvider should skip
	require.NoError(t, err)
	assert.Same(t, mockProvider, backend.authProvider)
}

func TestInitAuthProvider_BasicAuth(t *testing.T) {
	t.Parallel()

	// Arrange
	cfg := config.Backend{
		Name: "test-basic-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		Authentication: &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "testuser",
				Password: "testpass",
			},
		},
	}

	// Act
	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, backend.authProvider)
	assert.Equal(t, "basic", backend.authProvider.Type())
}

func TestInitAuthProvider_JWTAuth(t *testing.T) {
	t.Parallel()

	// Arrange
	cfg := config.Backend{
		Name: "test-jwt-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		Authentication: &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "my-jwt-token",
			},
		},
	}

	// Act
	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, backend.authProvider)
	assert.Equal(t, "jwt", backend.authProvider.Type())
}

func TestInitAuthProvider_InvalidConfig(t *testing.T) {
	t.Parallel()

	// Arrange: invalid auth type
	cfg := config.Backend{
		Name: "test-invalid-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		Authentication: &config.BackendAuthConfig{
			Type: "unsupported-type",
		},
	}

	// Act
	_, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create auth provider")
}

func TestInitAuthProvider_BasicMissingConfig(t *testing.T) {
	t.Parallel()

	// Arrange: basic type but no basic config
	cfg := config.Backend{
		Name: "test-basic-missing",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		Authentication: &config.BackendAuthConfig{
			Type:  "basic",
			Basic: nil,
		},
	}

	// Act
	_, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create auth provider")
}

func TestInitAuthProvider_JWTMissingConfig(t *testing.T) {
	t.Parallel()

	// Arrange: jwt type but no jwt config
	cfg := config.Backend{
		Name: "test-jwt-missing",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		Authentication: &config.BackendAuthConfig{
			Type: "jwt",
			JWT:  nil,
		},
	}

	// Act
	_, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create auth provider")
}

func TestInitAuthProvider_InferredFromEnabled(t *testing.T) {
	t.Parallel()

	// Arrange: no explicit type, but basic is enabled
	cfg := config.Backend{
		Name: "test-inferred-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		Authentication: &config.BackendAuthConfig{
			Type: "", // empty type, should infer
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		},
	}

	// Act
	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, backend.authProvider)
	assert.Equal(t, "basic", backend.authProvider.Type())
}

// ---------------------------------------------------------------------------
// Tests for ApplyAuth with auth provider
// ---------------------------------------------------------------------------

func TestApplyAuth_WithProvider_Success(t *testing.T) {
	t.Parallel()

	// Arrange
	mockProvider := &mockAuthProvider{name: "test", authType: "mock"}
	cfg := config.Backend{
		Name: "test-apply-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg, WithAuthProvider(mockProvider))
	require.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)

	// Act
	err = backend.ApplyAuth(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "Bearer mock-token", req.Header.Get("Authorization"))
}

func TestApplyAuth_WithProvider_Error(t *testing.T) {
	t.Parallel()

	// Arrange
	expectedErr := errors.New("auth failed")
	mockProvider := &mockAuthProvider{
		name:         "test",
		authType:     "mock",
		applyHTTPErr: expectedErr,
	}
	cfg := config.Backend{
		Name: "test-apply-auth-err",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg, WithAuthProvider(mockProvider))
	require.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)

	// Act
	err = backend.ApplyAuth(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

// ---------------------------------------------------------------------------
// Tests for GetGRPCDialOptions with auth provider
// ---------------------------------------------------------------------------

func TestGetGRPCDialOptions_WithProvider_Success(t *testing.T) {
	t.Parallel()

	// Arrange
	expectedOpts := []grpc.DialOption{
		grpc.WithAuthority("test-authority"),
	}
	mockProvider := &mockAuthProvider{
		name:     "test",
		authType: "mock",
		grpcOpts: expectedOpts,
	}
	cfg := config.Backend{
		Name: "test-grpc-opts",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg, WithAuthProvider(mockProvider))
	require.NoError(t, err)

	// Act
	opts, err := backend.GetGRPCDialOptions(context.Background())

	// Assert
	assert.NoError(t, err)
	assert.Len(t, opts, 1)
}

func TestGetGRPCDialOptions_WithProvider_Error(t *testing.T) {
	t.Parallel()

	// Arrange
	expectedErr := errors.New("grpc auth failed")
	mockProvider := &mockAuthProvider{
		name:         "test",
		authType:     "mock",
		applyGRPCErr: expectedErr,
	}
	cfg := config.Backend{
		Name: "test-grpc-opts-err",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg, WithAuthProvider(mockProvider))
	require.NoError(t, err)

	// Act
	opts, err := backend.GetGRPCDialOptions(context.Background())

	// Assert
	assert.Error(t, err)
	assert.Nil(t, opts)
	assert.Contains(t, err.Error(), "failed to get auth dial options")
}

func TestGetGRPCDialOptions_WithProvider_EmptyOpts(t *testing.T) {
	t.Parallel()

	// Arrange: provider returns empty options (no error)
	mockProvider := &mockAuthProvider{
		name:     "test",
		authType: "mock",
		grpcOpts: nil,
	}
	cfg := config.Backend{
		Name: "test-grpc-empty",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg, WithAuthProvider(mockProvider))
	require.NoError(t, err)

	// Act
	opts, err := backend.GetGRPCDialOptions(context.Background())

	// Assert
	assert.NoError(t, err)
	assert.Empty(t, opts)
}

// ---------------------------------------------------------------------------
// Tests for RefreshAuth with auth provider
// ---------------------------------------------------------------------------

func TestRefreshAuth_WithProvider_Success(t *testing.T) {
	t.Parallel()

	// Arrange
	mockProvider := &mockAuthProvider{
		name:       "test",
		authType:   "mock",
		refreshErr: nil,
	}
	cfg := config.Backend{
		Name: "test-refresh-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg, WithAuthProvider(mockProvider))
	require.NoError(t, err)

	// Act
	err = backend.RefreshAuth(context.Background())

	// Assert
	assert.NoError(t, err)
}

func TestRefreshAuth_WithProvider_Error(t *testing.T) {
	t.Parallel()

	// Arrange
	expectedErr := errors.New("refresh failed")
	mockProvider := &mockAuthProvider{
		name:       "test",
		authType:   "mock",
		refreshErr: expectedErr,
	}
	cfg := config.Backend{
		Name: "test-refresh-auth-err",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg, WithAuthProvider(mockProvider))
	require.NoError(t, err)

	// Act
	err = backend.RefreshAuth(context.Background())

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

// ---------------------------------------------------------------------------
// Tests for Stop with auth provider
// ---------------------------------------------------------------------------

func TestStop_WithAuthProvider_CloseSuccess(t *testing.T) {
	t.Parallel()

	// Arrange
	mockProvider := &mockAuthProvider{
		name:     "test",
		authType: "mock",
		closeErr: nil,
	}
	cfg := config.Backend{
		Name: "test-stop-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg,
		WithAuthProvider(mockProvider),
		WithBackendLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Act
	err = backend.Stop(context.Background())

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, StatusUnknown, backend.Status())
}

func TestStop_WithAuthProvider_CloseError(t *testing.T) {
	t.Parallel()

	// Arrange: auth provider returns error on close
	mockProvider := &mockAuthProvider{
		name:     "test",
		authType: "mock",
		closeErr: errors.New("close failed"),
	}
	cfg := config.Backend{
		Name: "test-stop-auth-err",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
	}

	backend, err := NewBackend(cfg,
		WithAuthProvider(mockProvider),
		WithBackendLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Start the backend first
	err = backend.Start(context.Background())
	require.NoError(t, err)

	// Act: Stop should still succeed (error is logged, not returned)
	err = backend.Stop(context.Background())

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, StatusUnknown, backend.Status())
}

func TestStop_WithHealthCheckAndAuthProvider(t *testing.T) {
	t.Parallel()

	// Arrange: backend with both health check and auth provider
	mockProvider := &mockAuthProvider{
		name:     "test",
		authType: "mock",
		closeErr: nil,
	}
	cfg := config.Backend{
		Name: "test-stop-hc-auth",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		HealthCheck: &config.HealthCheck{
			Path:               "/health",
			Interval:           config.Duration(5000000000), // 5s
			Timeout:            config.Duration(2000000000), // 2s
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
	}

	backend, err := NewBackend(cfg,
		WithAuthProvider(mockProvider),
		WithBackendLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Start to create health checker
	err = backend.Start(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, backend.healthCheck)

	// Act
	err = backend.Stop(context.Background())

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, StatusUnknown, backend.Status())
}

// ---------------------------------------------------------------------------
// Tests for WithRegistryVaultClient
// ---------------------------------------------------------------------------

func TestWithRegistryVaultClient_Option(t *testing.T) {
	t.Parallel()

	// Arrange
	mockClient := &mockVaultClient{enabled: true}

	// Act
	registry := NewRegistry(
		observability.NopLogger(),
		WithRegistryVaultClient(mockClient),
	)

	// Assert
	assert.NotNil(t, registry)
	assert.Same(t, mockClient, registry.vaultClient)
}

func TestWithRegistryVaultClient_Nil(t *testing.T) {
	t.Parallel()

	// Act
	registry := NewRegistry(
		observability.NopLogger(),
		WithRegistryVaultClient(nil),
	)

	// Assert
	assert.NotNil(t, registry)
	assert.Nil(t, registry.vaultClient)
}

func TestWithRegistryVaultClient_LoadFromConfig(t *testing.T) {
	t.Parallel()

	// Arrange: registry with vault client should pass it to backends
	mockClient := &mockVaultClient{enabled: true}
	registry := NewRegistry(
		observability.NopLogger(),
		WithRegistryVaultClient(mockClient),
	)

	backends := []config.Backend{
		{
			Name: "backend-with-vault",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}

	// Act
	err := registry.LoadFromConfig(backends)

	// Assert
	require.NoError(t, err)
	b, exists := registry.Get("backend-with-vault")
	assert.True(t, exists)

	sb, ok := b.(*ServiceBackend)
	require.True(t, ok)
	assert.Same(t, mockClient, sb.vaultClient)
}

func TestWithRegistryVaultClient_ReloadFromConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	mockClient := &mockVaultClient{enabled: true}
	registry := NewRegistry(
		observability.NopLogger(),
		WithRegistryVaultClient(mockClient),
	)

	// Load initial
	initial := []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}
	err := registry.LoadFromConfig(initial)
	require.NoError(t, err)

	// Act: reload
	updated := []config.Backend{
		{
			Name: "backend-b",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.2", Port: 9090},
			},
		},
	}
	err = registry.ReloadFromConfig(context.Background(), updated)
	require.NoError(t, err)

	// Assert: new backend should have vault client
	b, exists := registry.Get("backend-b")
	assert.True(t, exists)

	sb, ok := b.(*ServiceBackend)
	require.True(t, ok)
	assert.Same(t, mockClient, sb.vaultClient)
}

// ---------------------------------------------------------------------------
// Tests for initTLS with vault client
// ---------------------------------------------------------------------------

func TestInitTLS_WithVaultClient(t *testing.T) {
	t.Parallel()

	// Arrange: TLS enabled with vault client
	mockClient := &mockVaultClient{enabled: true}
	cfg := config.Backend{
		Name: "test-tls-vault",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8443},
		},
		TLS: &config.BackendTLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		},
	}

	// Act
	backend, err := NewBackend(cfg,
		WithBackendLogger(observability.NopLogger()),
		WithVaultClient(mockClient),
	)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, backend.TLSConfig())
	assert.Same(t, mockClient, backend.vaultClient)
}

// ---------------------------------------------------------------------------
// Tests for WithHealthCheckTLS
// ---------------------------------------------------------------------------

func TestWithHealthCheckTLS_Option(t *testing.T) {
	t.Parallel()

	// Arrange
	host := NewHost("10.0.0.1", 8080, 1)
	cfg := config.HealthCheck{
		Path:             "/health",
		HealthyThreshold: 1,
	}

	// Act
	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckTLS(true),
	)

	// Assert
	assert.True(t, hc.useTLS)
}

func TestWithHealthCheckTLS_False(t *testing.T) {
	t.Parallel()

	// Arrange
	host := NewHost("10.0.0.1", 8080, 1)
	cfg := config.HealthCheck{
		Path:             "/health",
		HealthyThreshold: 1,
	}

	// Act
	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckTLS(false),
	)

	// Assert
	assert.False(t, hc.useTLS)
}

// ---------------------------------------------------------------------------
// Tests for Start with TLS health check
// ---------------------------------------------------------------------------

func TestStart_WithTLS_HealthCheck(t *testing.T) {
	t.Parallel()

	// Arrange: backend with TLS and health check
	cfg := config.Backend{
		Name: "test-tls-hc",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8443},
		},
		TLS: &config.BackendTLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		},
		HealthCheck: &config.HealthCheck{
			Path:               "/health",
			Interval:           config.Duration(5000000000),
			Timeout:            config.Duration(2000000000),
			HealthyThreshold:   1,
			UnhealthyThreshold: 1,
		},
	}

	backend, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Act
	err = backend.Start(context.Background())
	require.NoError(t, err)

	// Assert: health checker should be created with TLS
	assert.NotNil(t, backend.healthCheck)
	assert.True(t, backend.healthCheck.useTLS)

	// Cleanup
	err = backend.Stop(context.Background())
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Table-driven tests for ApplyAuth, GetGRPCDialOptions, RefreshAuth
// ---------------------------------------------------------------------------

func TestApplyAuth_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		provider   auth.Provider
		expectErr  bool
		expectAuth string
	}{
		{
			name:       "nil provider",
			provider:   nil,
			expectErr:  false,
			expectAuth: "",
		},
		{
			name:       "successful auth",
			provider:   &mockAuthProvider{name: "ok", authType: "mock"},
			expectErr:  false,
			expectAuth: "Bearer mock-token",
		},
		{
			name:       "failed auth",
			provider:   &mockAuthProvider{name: "fail", authType: "mock", applyHTTPErr: errors.New("fail")},
			expectErr:  true,
			expectAuth: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			cfg := config.Backend{
				Name: "test-" + tt.name,
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 8080},
				},
			}

			var opts []BackendOption
			if tt.provider != nil {
				opts = append(opts, WithAuthProvider(tt.provider))
			}

			backend, err := NewBackend(cfg, opts...)
			require.NoError(t, err)

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)

			// Act
			err = backend.ApplyAuth(context.Background(), req)

			// Assert
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.expectAuth != "" {
				assert.Equal(t, tt.expectAuth, req.Header.Get("Authorization"))
			}
		})
	}
}

func TestGetGRPCDialOptions_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		provider  auth.Provider
		expectErr bool
		expectLen int
	}{
		{
			name:      "nil provider",
			provider:  nil,
			expectErr: false,
			expectLen: 0,
		},
		{
			name: "provider with options",
			provider: &mockAuthProvider{
				name:     "ok",
				authType: "mock",
				grpcOpts: []grpc.DialOption{grpc.WithAuthority("test")},
			},
			expectErr: false,
			expectLen: 1,
		},
		{
			name: "provider with error",
			provider: &mockAuthProvider{
				name:         "fail",
				authType:     "mock",
				applyGRPCErr: errors.New("grpc fail"),
			},
			expectErr: true,
			expectLen: 0,
		},
		{
			name: "provider with empty options",
			provider: &mockAuthProvider{
				name:     "empty",
				authType: "mock",
				grpcOpts: nil,
			},
			expectErr: false,
			expectLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			cfg := config.Backend{
				Name: "test-grpc-" + tt.name,
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 8080},
				},
			}

			var opts []BackendOption
			if tt.provider != nil {
				opts = append(opts, WithAuthProvider(tt.provider))
			}

			backend, err := NewBackend(cfg, opts...)
			require.NoError(t, err)

			// Act
			dialOpts, err := backend.GetGRPCDialOptions(context.Background())

			// Assert
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, dialOpts)
			} else {
				assert.NoError(t, err)
				assert.Len(t, dialOpts, tt.expectLen)
			}
		})
	}
}

func TestRefreshAuth_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		provider  auth.Provider
		expectErr bool
	}{
		{
			name:      "nil provider",
			provider:  nil,
			expectErr: false,
		},
		{
			name:      "successful refresh",
			provider:  &mockAuthProvider{name: "ok", authType: "mock", refreshErr: nil},
			expectErr: false,
		},
		{
			name:      "failed refresh",
			provider:  &mockAuthProvider{name: "fail", authType: "mock", refreshErr: errors.New("refresh fail")},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			cfg := config.Backend{
				Name: "test-refresh-" + tt.name,
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 8080},
				},
			}

			var opts []BackendOption
			if tt.provider != nil {
				opts = append(opts, WithAuthProvider(tt.provider))
			}

			backend, err := NewBackend(cfg, opts...)
			require.NoError(t, err)

			// Act
			err = backend.RefreshAuth(context.Background())

			// Assert
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests for Stop table-driven
// ---------------------------------------------------------------------------

func TestStop_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider auth.Provider
	}{
		{
			name:     "no auth provider",
			provider: nil,
		},
		{
			name:     "auth provider close success",
			provider: &mockAuthProvider{name: "ok", authType: "mock", closeErr: nil},
		},
		{
			name:     "auth provider close error",
			provider: &mockAuthProvider{name: "fail", authType: "mock", closeErr: errors.New("close error")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			cfg := config.Backend{
				Name: "test-stop-" + tt.name,
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 8080},
				},
			}

			var opts []BackendOption
			opts = append(opts, WithBackendLogger(observability.NopLogger()))
			if tt.provider != nil {
				opts = append(opts, WithAuthProvider(tt.provider))
			}

			backend, err := NewBackend(cfg, opts...)
			require.NoError(t, err)

			// Start the backend
			err = backend.Start(context.Background())
			require.NoError(t, err)

			// Act: Stop should always return nil (errors are logged)
			err = backend.Stop(context.Background())

			// Assert
			assert.NoError(t, err)
			assert.Equal(t, StatusUnknown, backend.Status())
		})
	}
}

// ---------------------------------------------------------------------------
// Tests for NewBackend with auth provider error path
// ---------------------------------------------------------------------------

func TestNewBackend_AuthProviderError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		auth *config.BackendAuthConfig
	}{
		{
			name: "unsupported auth type",
			auth: &config.BackendAuthConfig{
				Type: "invalid",
			},
		},
		{
			name: "basic type without config",
			auth: &config.BackendAuthConfig{
				Type: "basic",
			},
		},
		{
			name: "jwt type without config",
			auth: &config.BackendAuthConfig{
				Type: "jwt",
			},
		},
		{
			name: "mtls type without config",
			auth: &config.BackendAuthConfig{
				Type: "mtls",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Backend{
				Name: "test-auth-err-" + tt.name,
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 8080},
				},
				Authentication: tt.auth,
			}

			_, err := NewBackend(cfg, WithBackendLogger(observability.NopLogger()))
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to create auth provider")
		})
	}
}

// ---------------------------------------------------------------------------
// Tests for initAuthProvider with vault client
// ---------------------------------------------------------------------------

func TestInitAuthProvider_WithVaultClient(t *testing.T) {
	t.Parallel()

	// Arrange: basic auth with vault client
	mockClient := &mockVaultClient{enabled: true}
	cfg := config.Backend{
		Name: "test-auth-vault",
		Hosts: []config.BackendHost{
			{Address: "10.0.0.1", Port: 8080},
		},
		Authentication: &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		},
	}

	// Act
	backend, err := NewBackend(cfg,
		WithBackendLogger(observability.NopLogger()),
		WithVaultClient(mockClient),
	)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, backend.authProvider)
	assert.Same(t, mockClient, backend.vaultClient)
}

// ---------------------------------------------------------------------------
// Tests for Registry with both metrics and vault client
// ---------------------------------------------------------------------------

func TestRegistry_WithMetricsAndVaultClient(t *testing.T) {
	t.Parallel()

	// Arrange
	metrics := observability.NewMetrics("test_combined")
	mockClient := &mockVaultClient{enabled: true}

	registry := NewRegistry(
		observability.NopLogger(),
		WithRegistryMetrics(metrics),
		WithRegistryVaultClient(mockClient),
	)

	backends := []config.Backend{
		{
			Name: "combined-backend",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8080},
			},
		},
	}

	// Act
	err := registry.LoadFromConfig(backends)
	require.NoError(t, err)

	// Assert
	b, exists := registry.Get("combined-backend")
	assert.True(t, exists)

	sb, ok := b.(*ServiceBackend)
	require.True(t, ok)
	assert.Same(t, metrics, sb.metrics)
	assert.Same(t, mockClient, sb.vaultClient)
}
