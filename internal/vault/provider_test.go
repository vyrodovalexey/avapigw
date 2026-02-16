package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestVaultProviderConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *VaultProviderConfig
		expectError bool
		errorField  string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "empty PKI mount",
			config: &VaultProviderConfig{
				Role:       "test-role",
				CommonName: "test.example.com",
			},
			expectError: true,
			errorField:  "pkiMount",
		},
		{
			name: "empty role",
			config: &VaultProviderConfig{
				PKIMount:   "pki",
				CommonName: "test.example.com",
			},
			expectError: true,
			errorField:  "role",
		},
		{
			name: "empty common name",
			config: &VaultProviderConfig{
				PKIMount: "pki",
				Role:     "test-role",
			},
			expectError: true,
			errorField:  "commonName",
		},
		{
			name: "negative TTL",
			config: &VaultProviderConfig{
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
				TTL:        -1 * time.Hour,
			},
			expectError: true,
			errorField:  "ttl",
		},
		{
			name: "negative renewBefore",
			config: &VaultProviderConfig{
				PKIMount:    "pki",
				Role:        "test-role",
				CommonName:  "test.example.com",
				RenewBefore: -1 * time.Hour,
			},
			expectError: true,
			errorField:  "renewBefore",
		},
		{
			name: "renewBefore greater than TTL",
			config: &VaultProviderConfig{
				PKIMount:    "pki",
				Role:        "test-role",
				CommonName:  "test.example.com",
				TTL:         1 * time.Hour,
				RenewBefore: 2 * time.Hour,
			},
			expectError: true,
			errorField:  "renewBefore",
		},
		{
			name: "renewBefore equal to TTL",
			config: &VaultProviderConfig{
				PKIMount:    "pki",
				Role:        "test-role",
				CommonName:  "test.example.com",
				TTL:         1 * time.Hour,
				RenewBefore: 1 * time.Hour,
			},
			expectError: true,
			errorField:  "renewBefore",
		},
		{
			name: "valid config",
			config: &VaultProviderConfig{
				PKIMount:   "pki",
				Role:       "test-role",
				CommonName: "test.example.com",
			},
			expectError: false,
		},
		{
			name: "valid config with TTL and renewBefore",
			config: &VaultProviderConfig{
				PKIMount:    "pki",
				Role:        "test-role",
				CommonName:  "test.example.com",
				TTL:         24 * time.Hour,
				RenewBefore: 1 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "valid config with all fields",
			config: &VaultProviderConfig{
				PKIMount:    "pki",
				Role:        "test-role",
				CommonName:  "test.example.com",
				AltNames:    []string{"alt1.example.com", "alt2.example.com"},
				IPSANs:      []string{"192.168.1.1"},
				TTL:         24 * time.Hour,
				RenewBefore: 1 * time.Hour,
				CAMount:     "pki-ca",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVaultProviderConfig_Clone(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		var cfg *VaultProviderConfig
		clone := cfg.Clone()
		if clone != nil {
			t.Error("Clone() of nil should return nil")
		}
	})

	t.Run("full config", func(t *testing.T) {
		original := &VaultProviderConfig{
			PKIMount:    "pki",
			Role:        "test-role",
			CommonName:  "test.example.com",
			AltNames:    []string{"alt1.example.com", "alt2.example.com"},
			IPSANs:      []string{"192.168.1.1", "10.0.0.1"},
			TTL:         24 * time.Hour,
			RenewBefore: 1 * time.Hour,
			CAMount:     "pki-ca",
		}

		clone := original.Clone()

		// Verify basic fields
		if clone.PKIMount != original.PKIMount {
			t.Error("Clone().PKIMount mismatch")
		}
		if clone.Role != original.Role {
			t.Error("Clone().Role mismatch")
		}
		if clone.CommonName != original.CommonName {
			t.Error("Clone().CommonName mismatch")
		}
		if clone.TTL != original.TTL {
			t.Error("Clone().TTL mismatch")
		}
		if clone.RenewBefore != original.RenewBefore {
			t.Error("Clone().RenewBefore mismatch")
		}
		if clone.CAMount != original.CAMount {
			t.Error("Clone().CAMount mismatch")
		}

		// Verify slices are deep copied
		if len(clone.AltNames) != len(original.AltNames) {
			t.Error("Clone().AltNames length mismatch")
		}
		if len(clone.IPSANs) != len(original.IPSANs) {
			t.Error("Clone().IPSANs length mismatch")
		}

		// Verify modifying clone doesn't affect original
		clone.AltNames[0] = "modified"
		if original.AltNames[0] == "modified" {
			t.Error("Modifying clone should not affect original")
		}
	})

	t.Run("config without slices", func(t *testing.T) {
		original := &VaultProviderConfig{
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.example.com",
		}

		clone := original.Clone()

		if clone.AltNames != nil {
			t.Error("Clone().AltNames should be nil")
		}
		if clone.IPSANs != nil {
			t.Error("Clone().IPSANs should be nil")
		}
	})
}

func TestNewVaultProvider_NilClient(t *testing.T) {
	config := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	_, err := NewVaultProvider(nil, config)
	if err == nil {
		t.Error("NewVaultProvider() should return error for nil client")
	}
	if !errors.Is(err, &ConfigurationError{}) {
		t.Errorf("NewVaultProvider() error = %v, want ConfigurationError", err)
	}
}

func TestNewVaultProvider_DisabledClient(t *testing.T) {
	client := &disabledClient{}
	config := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	_, err := NewVaultProvider(client, config)
	if !errors.Is(err, ErrVaultDisabled) {
		t.Errorf("NewVaultProvider() error = %v, want ErrVaultDisabled", err)
	}
}

func TestNewVaultProvider_NilConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	_, err = NewVaultProvider(client, nil)
	if err == nil {
		t.Error("NewVaultProvider() should return error for nil config")
	}
}

func TestNewVaultProvider_InvalidConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	providerConfig := &VaultProviderConfig{
		// Missing required fields
	}

	_, err = NewVaultProvider(client, providerConfig)
	if err == nil {
		t.Error("NewVaultProvider() should return error for invalid config")
	}
}

func TestNewVaultProvider_ValidConfig(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	if err != nil {
		t.Errorf("NewVaultProvider() error = %v", err)
	}
	if provider == nil {
		t.Error("NewVaultProvider() returned nil provider")
	}
}

func TestNewVaultProvider_WithOptions(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	customLogger := observability.NopLogger()
	customMetrics := newTestMetrics("custom")

	provider, err := NewVaultProvider(
		client,
		providerConfig,
		WithVaultProviderLogger(customLogger),
		WithVaultProviderMetrics(customMetrics),
	)
	if err != nil {
		t.Errorf("NewVaultProvider() error = %v", err)
	}
	if provider == nil {
		t.Error("NewVaultProvider() returned nil provider")
	}
	if provider.metrics != customMetrics {
		t.Error("WithVaultProviderMetrics should set custom metrics")
	}
}

func TestVaultProvider_GetCertificate_Closed(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	if err != nil {
		t.Fatalf("NewVaultProvider() error = %v", err)
	}

	// Close the provider
	_ = provider.Close()

	// Try to get certificate
	_, err = provider.GetCertificate(context.Background(), nil)
	if err == nil {
		t.Error("GetCertificate() should return error for closed provider")
	}
}

func TestVaultProvider_GetClientCA_Closed(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	if err != nil {
		t.Fatalf("NewVaultProvider() error = %v", err)
	}

	// Close the provider
	_ = provider.Close()

	// Try to get client CA
	_, err = provider.GetClientCA(context.Background())
	if err == nil {
		t.Error("GetClientCA() should return error for closed provider")
	}
}

func TestVaultProvider_Close_Idempotent(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	if err != nil {
		t.Fatalf("NewVaultProvider() error = %v", err)
	}

	// First close
	err = provider.Close()
	if err != nil {
		t.Errorf("First Close() error = %v", err)
	}

	// Second close should not error
	err = provider.Close()
	if err != nil {
		t.Errorf("Second Close() error = %v", err)
	}
}

func TestVaultProvider_Watch(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	if err != nil {
		t.Fatalf("NewVaultProvider() error = %v", err)
	}
	defer provider.Close()

	ch := provider.Watch(context.Background())
	if ch == nil {
		t.Error("Watch() should not return nil channel")
	}
}

func TestVaultProvider_GetCertificateInfo(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	if err != nil {
		t.Fatalf("NewVaultProvider() error = %v", err)
	}
	defer provider.Close()

	// Before Start(), certificate info should be nil
	info := provider.GetCertificateInfo()
	if info != nil {
		t.Error("GetCertificateInfo() should return nil before Start()")
	}
}

func TestWithVaultProviderLogger(t *testing.T) {
	logger := observability.NopLogger()
	opt := WithVaultProviderLogger(logger)

	provider := &VaultProvider{}
	opt(provider)

	if provider.logger == nil {
		t.Error("WithVaultProviderLogger should set the logger")
	}
}

func TestWithVaultProviderMetrics(t *testing.T) {
	metrics := newTestMetrics("test")
	opt := WithVaultProviderMetrics(metrics)

	provider := &VaultProvider{}
	opt(provider)

	if provider.metrics != metrics {
		t.Error("WithVaultProviderMetrics should set the metrics")
	}
}

func TestVaultProvider_CalculateRenewalTime(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Note: Not calling Close() to avoid 5s timeout

	providerConfig := &VaultProviderConfig{
		PKIMount:   "pki",
		Role:       "test-role",
		CommonName: "test.example.com",
	}

	provider, err := NewVaultProvider(client, providerConfig)
	if err != nil {
		t.Fatalf("NewVaultProvider() error = %v", err)
	}
	defer provider.Close()

	// Without certificate, should return now
	renewAt := provider.calculateRenewalTime(10 * time.Minute)
	if renewAt.After(time.Now().Add(time.Second)) {
		t.Error("calculateRenewalTime() should return now when no certificate")
	}
}
