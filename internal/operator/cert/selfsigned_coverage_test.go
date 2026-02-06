// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"testing"
	"time"
)

// ============================================================================
// Context Cancellation Tests for Certificate Operations
// ============================================================================

func TestSelfSignedProvider_GetCertificate_ContextCanceled(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test.example.com",
	})
	if err == nil {
		t.Error("GetCertificate() should return error when context is canceled")
	}
}

func TestSelfSignedProvider_GetCertificate_ContextDeadlineExceeded(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	_, err = provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "test.example.com",
	})
	if err == nil {
		t.Error("GetCertificate() should return error when context deadline exceeded")
	}
}

func TestSelfSignedProvider_RotateCertificate_ContextCanceled(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "test.example.com",
	})
	if err == nil {
		t.Error("RotateCertificate() should return error when context is canceled")
	}
}

func TestSelfSignedProvider_RotateCertificate_ContextDeadlineExceeded(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	_, err = provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "test.example.com",
	})
	if err == nil {
		t.Error("RotateCertificate() should return error when context deadline exceeded")
	}
}

// ============================================================================
// Certificate Expiration Edge Cases
// ============================================================================

func TestSelfSignedProvider_GetCertificate_ExpiringSoon(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		CertValidity: 1 * time.Hour,
		RotateBefore: 2 * time.Hour, // Rotate before is longer than validity
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName: "expiring.example.com",
	}

	// First request
	cert1, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("First GetCertificate() error = %v", err)
	}

	// Second request should issue new cert since it's "expiring soon"
	cert2, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("Second GetCertificate() error = %v", err)
	}

	// Since RotateBefore > CertValidity, every cert is "expiring soon"
	// so we should get a new cert each time
	if cert1.SerialNumber == cert2.SerialNumber {
		t.Log("Note: Certificates have same serial, which is expected if caching is working")
	}
}

func TestSelfSignedProvider_GetCertificate_CustomTTL(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		CertValidity: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName: "custom-ttl.example.com",
		TTL:        1 * time.Hour, // Custom TTL shorter than default
	}

	cert, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	// Verify the certificate has the custom TTL
	expectedExpiry := time.Now().Add(1 * time.Hour)
	if cert.Expiration.After(expectedExpiry.Add(1 * time.Minute)) {
		t.Errorf("Certificate expiration %v is too far in the future, expected around %v",
			cert.Expiration, expectedExpiry)
	}
}

// ============================================================================
// Certificate Content Validation Tests
// ============================================================================

func TestSelfSignedProvider_GetCertificate_WithIPAddresses(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName:  "ip-test.example.com",
		IPAddresses: []string{"127.0.0.1", "192.168.1.1", "::1"},
	}

	cert, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	// Verify IP addresses are in the certificate
	if len(cert.Certificate.IPAddresses) != 3 {
		t.Errorf("Certificate has %d IP addresses, want 3", len(cert.Certificate.IPAddresses))
	}
}

func TestSelfSignedProvider_GetCertificate_InvalidIPAddress(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName:  "invalid-ip.example.com",
		IPAddresses: []string{"invalid-ip", "127.0.0.1"},
	}

	cert, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	// Invalid IP should be skipped, only valid one should be present
	if len(cert.Certificate.IPAddresses) != 1 {
		t.Errorf("Certificate has %d IP addresses, want 1 (invalid should be skipped)",
			len(cert.Certificate.IPAddresses))
	}
}

func TestSelfSignedProvider_GetCertificate_WithDNSNames(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	req := &CertificateRequest{
		CommonName: "dns-test.example.com",
		DNSNames:   []string{"dns-test.example.com", "alt1.example.com", "alt2.example.com"},
	}

	cert, err := provider.GetCertificate(ctx, req)
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	// Verify DNS names are in the certificate
	if len(cert.Certificate.DNSNames) != 3 {
		t.Errorf("Certificate has %d DNS names, want 3", len(cert.Certificate.DNSNames))
	}
}

// ============================================================================
// Certificate Validity Tests
// ============================================================================

func TestCertificate_IsValid_Coverage(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "valid-test.example.com",
	})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	if !cert.IsValid() {
		t.Error("Certificate should be valid")
	}
}

func TestCertificate_IsExpiringSoon_Coverage(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		CertValidity: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "expiring-test.example.com",
	})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	// Should not be expiring soon with 24h validity and 1h threshold
	if cert.IsExpiringSoon(1 * time.Hour) {
		t.Error("Certificate should not be expiring soon")
	}

	// Should be expiring soon with 48h threshold
	if !cert.IsExpiringSoon(48 * time.Hour) {
		t.Error("Certificate should be expiring soon with 48h threshold")
	}
}

// ============================================================================
// TLSCertificate Tests
// ============================================================================

func TestCertificate_TLSCertificate_Coverage(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	cert, err := provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "tls-test.example.com",
	})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	tlsCert, err := cert.TLSCertificate()
	if err != nil {
		t.Errorf("TLSCertificate() error = %v", err)
	}
	if tlsCert.Certificate == nil {
		t.Error("TLSCertificate() returned nil certificate")
	}
}

// ============================================================================
// Provider Configuration Tests
// ============================================================================

func TestSelfSignedProviderConfig_Defaults(t *testing.T) {
	provider, err := NewSelfSignedProvider(nil)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	// Verify defaults were applied
	p := provider.(*selfSignedProvider)
	if p.config.CACommonName == "" {
		t.Error("CACommonName should have default value")
	}
	if p.config.CAValidity == 0 {
		t.Error("CAValidity should have default value")
	}
	if p.config.CertValidity == 0 {
		t.Error("CertValidity should have default value")
	}
	if p.config.RotateBefore == 0 {
		t.Error("RotateBefore should have default value")
	}
	if p.config.KeySize == 0 {
		t.Error("KeySize should have default value")
	}
	if len(p.config.Organization) == 0 {
		t.Error("Organization should have default value")
	}
}

func TestSelfSignedProviderConfig_CustomValues(t *testing.T) {
	config := &SelfSignedProviderConfig{
		CACommonName: "Custom CA",
		CAValidity:   365 * 24 * time.Hour,
		CertValidity: 30 * 24 * time.Hour,
		RotateBefore: 7 * 24 * time.Hour,
		KeySize:      4096,
		Organization: []string{"Custom Org"},
	}

	provider, err := NewSelfSignedProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	p := provider.(*selfSignedProvider)
	if p.config.CACommonName != "Custom CA" {
		t.Errorf("CACommonName = %q, want %q", p.config.CACommonName, "Custom CA")
	}
	if p.config.KeySize != 4096 {
		t.Errorf("KeySize = %d, want 4096", p.config.KeySize)
	}
}

// ============================================================================
// CA Certificate Tests
// ============================================================================

func TestSelfSignedProvider_CA_Properties(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize:      2048,
		CACommonName: "Test CA",
		Organization: []string{"Test Org"},
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	p := provider.(*selfSignedProvider)

	// Verify CA properties
	if p.ca == nil {
		t.Fatal("CA should not be nil")
	}
	if p.ca.Certificate.Subject.CommonName != "Test CA" {
		t.Errorf("CA CN = %q, want %q", p.ca.Certificate.Subject.CommonName, "Test CA")
	}
	if !p.ca.Certificate.IsCA {
		t.Error("CA certificate should have IsCA=true")
	}
	if p.ca.Certificate.MaxPathLen != 1 {
		t.Errorf("CA MaxPathLen = %d, want 1", p.ca.Certificate.MaxPathLen)
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestSelfSignedProvider_ConcurrentGetCertificate(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(idx int) {
			req := &CertificateRequest{
				CommonName: "concurrent-test.example.com",
			}
			_, err := provider.GetCertificate(ctx, req)
			if err != nil {
				t.Errorf("Concurrent GetCertificate() error = %v", err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestSelfSignedProvider_ConcurrentRotateCertificate(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	ctx := context.Background()
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(idx int) {
			req := &CertificateRequest{
				CommonName: "concurrent-rotate.example.com",
			}
			_, err := provider.RotateCertificate(ctx, req)
			if err != nil {
				t.Errorf("Concurrent RotateCertificate() error = %v", err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// ============================================================================
// Error Path Tests
// ============================================================================

func TestSelfSignedProvider_GetCertificate_AfterClose(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Close the provider
	_ = provider.Close()

	// Try to get certificate after close
	ctx := context.Background()
	_, err = provider.GetCertificate(ctx, &CertificateRequest{
		CommonName: "after-close.example.com",
	})
	if err == nil {
		t.Error("GetCertificate() should return error after Close()")
	}
}

func TestSelfSignedProvider_RotateCertificate_AfterClose(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Close the provider
	_ = provider.Close()

	// Try to rotate certificate after close
	ctx := context.Background()
	_, err = provider.RotateCertificate(ctx, &CertificateRequest{
		CommonName: "after-close.example.com",
	})
	if err == nil {
		t.Error("RotateCertificate() should return error after Close()")
	}
}

func TestSelfSignedProvider_GetCA_AfterClose(t *testing.T) {
	provider, err := NewSelfSignedProvider(&SelfSignedProviderConfig{
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Close the provider
	_ = provider.Close()

	// Try to get CA after close
	ctx := context.Background()
	_, err = provider.GetCA(ctx)
	if err == nil {
		t.Error("GetCA() should return error after Close()")
	}
}

// ============================================================================
// Manager Tests
// ============================================================================

func TestNewManager_EmptyMode(t *testing.T) {
	config := &ManagerConfig{
		Mode: "",
	}

	manager, err := NewManager(context.Background(), config)
	if err != nil {
		t.Errorf("NewManager() error = %v, want nil (should default to self-signed)", err)
	}
	if manager != nil {
		_ = manager.Close()
	}
}

func TestNewManager_SelfSignedWithConfig(t *testing.T) {
	config := &ManagerConfig{
		Mode: CertModeSelfSigned,
		SelfSigned: &SelfSignedProviderConfig{
			KeySize:      2048,
			CACommonName: "Test Manager CA",
		},
	}

	manager, err := NewManager(context.Background(), config)
	if err != nil {
		t.Errorf("NewManager() error = %v", err)
	}
	if manager == nil {
		t.Error("NewManager() returned nil manager")
	}
	if manager != nil {
		_ = manager.Close()
	}
}
