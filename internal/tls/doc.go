// Package tls provides comprehensive TLS infrastructure for the Ava API Gateway.
//
// This package implements TLS configuration, certificate management, and secure
// transport functionality with support for:
//
//   - Multiple TLS modes: SIMPLE, MUTUAL (mTLS), OPTIONAL_MUTUAL, PASSTHROUGH, and INSECURE
//   - TLS version control (TLS 1.0 through TLS 1.3)
//   - Cipher suite management with secure defaults
//   - Certificate hot-reload without restart
//   - File-based and Vault-based certificate providers
//   - Client certificate validation with CN/SAN filtering
//   - Prometheus metrics for TLS connections and certificate expiry
//   - SNI-based certificate selection
//
// # TLS Modes
//
// The package supports several TLS termination modes:
//
//   - SIMPLE: Server presents certificate, no client verification
//   - MUTUAL: Both server and client must present valid certificates (mTLS)
//   - OPTIONAL_MUTUAL: Server presents certificate, client certificate optional
//   - PASSTHROUGH: TLS is not terminated, traffic is passed through (SNI routing)
//   - AUTO_PASSTHROUGH: SNI-encoded destination routing
//   - INSECURE: Plaintext communication (development only)
//
// # Certificate Sources
//
// Certificates can be loaded from multiple sources:
//
//   - File: PEM-encoded certificate and key files
//   - Inline: PEM-encoded certificate and key data in configuration
//   - Vault: HashiCorp Vault PKI secrets engine
//
// # Hot Reload
//
// The package supports certificate hot-reload through file watching:
//
//	provider, err := tls.NewFileProvider(config, tls.WithLogger(logger))
//	if err != nil {
//	    return err
//	}
//
//	// Watch for certificate changes
//	go func() {
//	    for event := range provider.Watch(ctx) {
//	        switch event.Type {
//	        case tls.CertificateEventReloaded:
//	            logger.Info("certificate reloaded")
//	        case tls.CertificateEventError:
//	            logger.Error("certificate reload error", observability.Error(event.Error))
//	        }
//	    }
//	}()
//
// # Example Usage
//
// Basic TLS configuration:
//
//	config := &tls.Config{
//	    Mode:       tls.TLSModeSimple,
//	    MinVersion: tls.TLSVersion12,
//	    MaxVersion: tls.TLSVersion13,
//	    ServerCertificate: &tls.CertificateConfig{
//	        Source:   tls.CertificateSourceFile,
//	        CertFile: "/path/to/cert.pem",
//	        KeyFile:  "/path/to/key.pem",
//	    },
//	}
//
//	manager, err := tls.NewManager(config, tls.WithLogger(logger))
//	if err != nil {
//	    return err
//	}
//
//	tlsConfig, err := manager.GetTLSConfig(ctx)
//	if err != nil {
//	    return err
//	}
//
// mTLS configuration:
//
//	config := &tls.Config{
//	    Mode:       tls.TLSModeMutual,
//	    MinVersion: tls.TLSVersion12,
//	    ServerCertificate: &tls.CertificateConfig{
//	        Source:   tls.CertificateSourceFile,
//	        CertFile: "/path/to/server-cert.pem",
//	        KeyFile:  "/path/to/server-key.pem",
//	    },
//	    ClientValidation: &tls.ClientValidationConfig{
//	        Enabled:           true,
//	        CAFile:            "/path/to/ca.pem",
//	        RequireClientCert: true,
//	        AllowedCNs:        []string{"client.example.com"},
//	    },
//	}
//
// # Metrics
//
// The package exposes Prometheus metrics for monitoring:
//
//   - gateway_tls_connections_total: Total TLS connections by version, cipher, and mode
//   - gateway_tls_handshake_duration_seconds: TLS handshake duration histogram
//   - gateway_tls_certificate_expiry_seconds: Time until certificate expiry
//   - gateway_tls_certificate_reload_total: Certificate reload attempts by status
//
// # Security Considerations
//
// The package enforces secure defaults:
//
//   - Minimum TLS version is 1.2 by default
//   - Only secure cipher suites are enabled by default
//   - InsecureSkipVerify is disabled by default and logs warnings when enabled
//   - Legacy TLS versions (1.0, 1.1) require explicit opt-in
package tls
