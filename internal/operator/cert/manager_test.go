// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto/x509"
	"testing"
	"time"
)

func TestCertificate_IsExpiringSoon(t *testing.T) {
	// Create a minimal x509.Certificate for testing
	dummyCert := &x509.Certificate{}

	tests := []struct {
		name       string
		cert       *Certificate
		within     time.Duration
		wantResult bool
	}{
		{
			name:       "nil certificate",
			cert:       nil,
			within:     time.Hour,
			wantResult: true,
		},
		{
			name:       "nil x509 certificate",
			cert:       &Certificate{},
			within:     time.Hour,
			wantResult: true,
		},
		{
			name: "expiring soon",
			cert: &Certificate{
				Certificate: dummyCert,
				Expiration:  time.Now().Add(30 * time.Minute),
			},
			within:     time.Hour,
			wantResult: true,
		},
		{
			name: "not expiring soon",
			cert: &Certificate{
				Certificate: dummyCert,
				Expiration:  time.Now().Add(2 * time.Hour),
			},
			within:     time.Hour,
			wantResult: false,
		},
		{
			name: "already expired",
			cert: &Certificate{
				Certificate: dummyCert,
				Expiration:  time.Now().Add(-time.Hour),
			},
			within:     time.Hour,
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert.IsExpiringSoon(tt.within)
			if got != tt.wantResult {
				t.Errorf("IsExpiringSoon() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}

func TestCertificate_IsValid(t *testing.T) {
	// Create a minimal x509.Certificate for testing
	dummyCert := &x509.Certificate{}

	tests := []struct {
		name       string
		cert       *Certificate
		wantResult bool
	}{
		{
			name:       "nil certificate",
			cert:       nil,
			wantResult: false,
		},
		{
			name:       "nil x509 certificate",
			cert:       &Certificate{},
			wantResult: false,
		},
		{
			name: "valid certificate",
			cert: &Certificate{
				Certificate: dummyCert,
				Expiration:  time.Now().Add(time.Hour),
			},
			wantResult: true,
		},
		{
			name: "expired certificate",
			cert: &Certificate{
				Certificate: dummyCert,
				Expiration:  time.Now().Add(-time.Hour),
			},
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert.IsValid()
			if got != tt.wantResult {
				t.Errorf("IsValid() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}

func TestCertificate_TLSCertificate(t *testing.T) {
	tests := []struct {
		name    string
		cert    *Certificate
		wantErr bool
	}{
		{
			name:    "nil certificate",
			cert:    nil,
			wantErr: true,
		},
		{
			name:    "empty certificate PEM",
			cert:    &Certificate{},
			wantErr: true,
		},
		{
			name: "missing private key",
			cert: &Certificate{
				CertificatePEM: []byte("cert"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.cert.TLSCertificate()
			if (err != nil) != tt.wantErr {
				t.Errorf("TLSCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCertificate_TLSCertificate_ValidCert(t *testing.T) {
	// Create a self-signed provider to get a valid certificate
	provider, err := NewSelfSignedProvider(nil)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer func() {
		_ = provider.Close()
	}()

	cert, err := provider.GetCertificate(context.Background(), &CertificateRequest{
		CommonName: "test.example.com",
	})
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	tlsCert, err := cert.TLSCertificate()
	if err != nil {
		t.Errorf("TLSCertificate() error = %v, want nil", err)
	}
	if tlsCert == nil {
		t.Error("TLSCertificate() returned nil")
	}
}

func TestNewManager(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		config  *ManagerConfig
		wantErr bool
	}{
		{
			name:    "nil config defaults to self-signed",
			config:  nil,
			wantErr: false,
		},
		{
			name: "self-signed mode",
			config: &ManagerConfig{
				Mode: CertModeSelfSigned,
			},
			wantErr: false,
		},
		{
			name: "vault mode without config",
			config: &ManagerConfig{
				Mode: CertModeVault,
			},
			wantErr: true,
		},
		{
			name: "unknown mode defaults to self-signed",
			config: &ManagerConfig{
				Mode: "unknown",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewManager(ctx, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && mgr == nil {
				t.Error("NewManager() returned nil manager")
			}
			if mgr != nil {
				_ = mgr.Close()
			}
		})
	}
}

func TestCertificateMode_Constants(t *testing.T) {
	// Verify the constants are defined correctly
	if CertModeSelfSigned != "selfsigned" {
		t.Errorf("CertModeSelfSigned = %q, want %q", CertModeSelfSigned, "selfsigned")
	}
	if CertModeVault != "vault" {
		t.Errorf("CertModeVault = %q, want %q", CertModeVault, "vault")
	}
}
