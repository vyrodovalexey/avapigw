// Package mtls provides mutual TLS certificate validation for the
// API Gateway.
//
// This package implements client certificate validation, identity
// extraction, and certificate chain verification for mTLS
// authentication.
//
// # Features
//
//   - Client certificate validation and chain verification
//   - Certificate identity extraction (subject DN, issuer, SANs)
//   - Certificate fingerprint computation (SHA-256)
//   - Allowed CN and SAN filtering
//   - Certificate expiration and revocation checking
//   - Prometheus metrics for validation operations
//
// # Validation
//
// The Validator validates client certificates:
//
//	validator, err := mtls.NewValidator(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	certInfo, err := validator.Validate(ctx, peerCerts)
//	if err != nil {
//	    // Handle invalid certificate
//	}
package mtls
