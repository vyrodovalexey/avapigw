// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"testing"
	"time"
)

func TestNewSelfSignedProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  *SelfSignedProviderConfig
		wantErr bool
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "empty config uses defaults",
			config:  &SelfSignedProviderConfig{},
			wantErr: false,
		},
		{
			name: "custom config",
			config: &SelfSignedProviderConfig{
				CACommonName: "test-ca",
				CAValidity:   365 * 24 * time.Hour,
				CertValidity: 30 * 24 * time.Hour,
				RotateBefore: 7 * 24 * time.Hour,
				KeySize:      2048,
				Organization: []string{"test-org"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewSelfSignedProvider(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSelfSignedProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && provider == nil {
				t.Error("NewSelfSignedProvider() returned nil provider")
			}
			if provider != nil {
				_ = provider.Close()
			}
		})
	}
}

func TestSelfSignedProvider_GetCertificate(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048, // Use smaller key for faster tests
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()

	tests := []struct {
		name    string
		req     *CertificateRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name:    "empty common name",
			req:     &CertificateRequest{CommonName: ""},
			wantErr: true,
		},
		{
			name: "valid request",
			req: &CertificateRequest{
				CommonName: "test.example.com",
				DNSNames:   []string{"test.example.com", "localhost"},
			},
			wantErr: false,
		},
		{
			name: "request with IP addresses",
			req: &CertificateRequest{
				CommonName:  "test-ip.example.com",
				IPAddresses: []string{"127.0.0.1", "::1"},
			},
			wantErr: false,
		},
		{
			name: "request with custom TTL",
			req: &CertificateRequest{
				CommonName: "test-ttl.example.com",
				TTL:        24 * time.Hour,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := provider.GetCertificate(ctx, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if cert == nil {
					t.Error("GetCertificate() returned nil certificate")
					return
				}
				if cert.Certificate == nil {
					t.Error("GetCertificate() returned certificate with nil x509 cert")
				}
				if len(cert.CertificatePEM) == 0 {
					t.Error("GetCertificate() returned certificate with empty PEM")
				}
				if len(cert.PrivateKeyPEM) == 0 {
					t.Error("GetCertificate() returned certificate with empty private key PEM")
				}
				if !cert.IsValid() {
					t.Error("GetCertificate() returned invalid certificate")
				}
			}
		})
	}
}

func TestSelfSignedProvider_GetCertificate_Caching(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		RotateBefore: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName: "cached.example.com",
	}

	// First request should issue a new certificate
	cert1, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("First GetCertificate() error = %v", err)
	}

	// Second request should return the cached certificate
	cert2, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("Second GetCertificate() error = %v", err)
	}

	// Both should have the same serial number (cached)
	if cert1.SerialNumber != cert2.SerialNumber {
		t.Error("GetCertificate() should return cached certificate")
	}
}

func TestSelfSignedProvider_GetCA(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()

	pool, err := provider.GetCA(ctx)
	if err != nil {
		t.Errorf("GetCA() error = %v", err)
		return
	}
	if pool == nil {
		t.Error("GetCA() returned nil pool")
	}
}

func TestSelfSignedProvider_RotateCertificate(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()

	tests := []struct {
		name    string
		req     *CertificateRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name:    "empty common name",
			req:     &CertificateRequest{CommonName: ""},
			wantErr: true,
		},
		{
			name: "valid request",
			req: &CertificateRequest{
				CommonName: "rotate.example.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := provider.RotateCertificate(ctx, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("RotateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && cert == nil {
				t.Error("RotateCertificate() returned nil certificate")
			}
		})
	}
}

func TestSelfSignedProvider_RotateCertificate_NewSerial(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName: "rotate-new.example.com",
	}

	// First certificate
	cert1, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("First GetCertificate() error = %v", err)
	}

	// Rotate should issue a new certificate with different serial
	cert2, err := provider.RotateCertificate(ctx, req)
	if err != nil {
		t.Fatalf("RotateCertificate() error = %v", err)
	}

	if cert1.SerialNumber == cert2.SerialNumber {
		t.Error("RotateCertificate() should issue new certificate with different serial")
	}
}

func TestSelfSignedProvider_Close(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Close should succeed
	if err := provider.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Operations after close should fail
	ctx := context.Background()

	_, err = provider.GetCertificate(ctx, &CertificateRequest{CommonName: "test"})
	if err == nil {
		t.Error("GetCertificate() should fail after Close()")
	}

	_, err = provider.GetCA(ctx)
	if err == nil {
		t.Error("GetCA() should fail after Close()")
	}

	_, err = provider.RotateCertificate(ctx, &CertificateRequest{CommonName: "test"})
	if err == nil {
		t.Error("RotateCertificate() should fail after Close()")
	}
}

func TestSelfSignedProvider_CertificateContent(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		Organization: []string{"Test Org"},
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName: "content.example.com",
		DNSNames:   []string{"content.example.com", "alt.example.com"},
	}

	cert, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	// Verify certificate content
	if cert.Certificate.Subject.CommonName != req.CommonName {
		t.Errorf("Certificate CN = %v, want %v", cert.Certificate.Subject.CommonName, req.CommonName)
	}

	// Verify DNS names
	foundDNS := make(map[string]bool)
	for _, dns := range cert.Certificate.DNSNames {
		foundDNS[dns] = true
	}
	for _, expected := range req.DNSNames {
		if !foundDNS[expected] {
			t.Errorf("Certificate missing DNS name: %v", expected)
		}
	}

	// Verify organization
	if len(cert.Certificate.Subject.Organization) == 0 || cert.Certificate.Subject.Organization[0] != "Test Org" {
		t.Errorf("Certificate organization = %v, want [Test Org]", cert.Certificate.Subject.Organization)
	}

	// Verify CA chain is present
	if len(cert.CAChainPEM) == 0 {
		t.Error("Certificate missing CA chain")
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	// Generate multiple serial numbers and verify they're unique
	serials := make(map[string]bool)
	for i := 0; i < 100; i++ {
		serial, err := generateSerialNumber()
		if err != nil {
			t.Fatalf("generateSerialNumber() error = %v", err)
		}
		if serial == nil {
			t.Fatal("generateSerialNumber() returned nil")
		}
		serialStr := serial.String()
		if serials[serialStr] {
			t.Errorf("generateSerialNumber() generated duplicate serial: %v", serialStr)
		}
		serials[serialStr] = true
	}
}

// ============================================================================
// Manager Tests
// ============================================================================

func TestNewManager_NilConfig(t *testing.T) {
	// Arrange & Act
	manager, err := NewManager(context.Background(), nil)

	// Assert - should default to self-signed
	if err != nil {
		t.Errorf("NewManager(nil) error = %v, want nil", err)
	}
	if manager == nil {
		t.Error("NewManager(nil) should return a manager")
	}
	if manager != nil {
		_ = manager.Close()
	}
}

func TestNewManager_SelfSignedMode(t *testing.T) {
	// Arrange
	config := &ManagerConfig{
		Mode: CertModeSelfSigned,
		SelfSigned: &SelfSignedProviderConfig{
			KeySize: 2048,
		},
	}

	// Act
	manager, err := NewManager(context.Background(), config)

	// Assert
	if err != nil {
		t.Errorf("NewManager() error = %v, want nil", err)
	}
	if manager == nil {
		t.Error("NewManager() should return a manager")
	}
	if manager != nil {
		_ = manager.Close()
	}
}

func TestNewManager_VaultMode_NilConfig(t *testing.T) {
	// Arrange
	config := &ManagerConfig{
		Mode:  CertModeVault,
		Vault: nil, // Missing vault config
	}

	// Act
	manager, err := NewManager(context.Background(), config)

	// Assert
	if err == nil {
		t.Error("NewManager() should return error when vault config is nil")
	}
	if manager != nil {
		t.Error("NewManager() should return nil manager on error")
	}
}

func TestNewManager_UnknownMode(t *testing.T) {
	// Arrange
	config := &ManagerConfig{
		Mode: "unknown",
	}

	// Act
	manager, err := NewManager(context.Background(), config)

	// Assert - should default to self-signed
	if err != nil {
		t.Errorf("NewManager() error = %v, want nil (should default to self-signed)", err)
	}
	if manager == nil {
		t.Error("NewManager() should return a manager")
	}
	if manager != nil {
		_ = manager.Close()
	}
}

// ============================================================================
// Additional SelfSigned Provider Tests
// ============================================================================

func TestSelfSignedProvider_GetCA_NilCA(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Access internal state to set CA to nil
	p := provider.(*selfSignedProvider)
	p.mu.Lock()
	p.ca = nil
	p.mu.Unlock()

	ctx := context.Background()
	_, err = provider.GetCA(ctx)
	if err == nil {
		t.Error("GetCA() should return error when CA is nil")
	}
}

func TestSelfSignedProvider_IssueCertificate_NilCA(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Access internal state to set CA to nil
	p := provider.(*selfSignedProvider)
	p.mu.Lock()
	p.ca = nil
	p.mu.Unlock()

	ctx := context.Background()
	_, err = provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test.example.com",
	})
	if err == nil {
		t.Error("GetCertificate() should return error when CA is nil")
	}
}
