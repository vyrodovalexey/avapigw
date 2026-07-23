// Package main is the entry point for the avapigw-operator.
package main

import (
	"context"
	"crypto/rand"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

// certRotationCheckInterval is the base interval between serving-certificate
// expiry checks. A per-tick jitter (up to certRotationJitterFraction of the
// interval) desynchronizes HA replicas.
const certRotationCheckInterval = 1 * time.Minute

// certRotationJitterFraction is the maximum fraction of the check interval
// added as random jitter.
const certRotationJitterFraction = 0.2

// certificateUpdater receives rotated serving certificates. Implemented by
// *operatorgrpc.Server; a narrow interface keeps the rotation loop testable.
type certificateUpdater interface {
	UpdateCertificate(c *cert.Certificate) error
	ServingCertificateExpiration() time.Time
}

// certRotationLoop periodically re-issues the operator's serving certificate
// before it expires and swaps it into the gRPC server (via the
// tls.Config.GetCertificate pattern) and the webhook certificate directory
// (controller-runtime's certwatcher reloads the files natively).
type certRotationLoop struct {
	certManager  cert.Manager
	grpcServer   certificateUpdater
	request      *cert.CertificateRequest
	rotateBefore time.Duration
	// webhookCertDir, when non-empty, receives the rotated tls.crt/tls.key.
	webhookCertDir string
	checkInterval  time.Duration
	// expirationOverride, when set, supplies the current certificate
	// expiration (used when no gRPC server is running, e.g. webhook-only).
	expiration time.Time
}

// startCertRotationIfNeeded launches the serving-certificate rotation loop
// for internally provisioned certificates (selfsigned and vault providers).
// External providers (file, cert-manager) rotate on disk and are watched by
// the file provider / controller-runtime directly.
func startCertRotationIfNeeded(
	ctx context.Context,
	cfg *Config,
	certManager cert.Manager,
	grpcServer *operatorgrpc.Server,
	initialCert *cert.Certificate,
) {
	if usesExternalWebhookCerts(cfg) {
		return
	}
	if grpcServer == nil && !cfg.EnableWebhooks {
		return
	}
	if initialCert == nil {
		return
	}

	loop := &certRotationLoop{
		certManager: certManager,
		request: &cert.CertificateRequest{
			CommonName: cfg.CertServiceName,
			DNSNames:   getCertDNSNames(cfg),
		},
		rotateBefore:  certRotateBefore(cfg.CertProvider),
		checkInterval: certRotationCheckInterval,
		expiration:    initialCert.Expiration,
	}
	if grpcServer != nil {
		loop.grpcServer = grpcServer
	}
	if cfg.EnableWebhooks {
		loop.webhookCertDir = cfg.WebhookCertDir
	}

	setupLog.Info("serving certificate rotation loop started",
		"common_name", cfg.CertServiceName,
		"rotate_before", loop.rotateBefore.String(),
		"expiration", initialCert.Expiration,
	)

	go loop.run(ctx)
}

// certRotateBefore returns the provider-appropriate rotation lead time.
func certRotateBefore(provider string) time.Duration {
	if cert.CertificateMode(provider) == cert.CertModeVault {
		return cert.DefaultVaultRotateBefore
	}
	return cert.DefaultRotateBefore
}

// run checks the serving certificate on every (jittered) tick and rotates
// it when it enters the rotate-before window. Rotation failures are logged
// and retried on the next tick.
func (l *certRotationLoop) run(ctx context.Context) {
	timer := time.NewTimer(l.nextInterval())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			setupLog.Info("serving certificate rotation loop stopped")
			return
		case <-timer.C:
		}

		if l.dueForRotation() {
			l.rotate(ctx)
		}

		timer.Reset(l.nextInterval())
	}
}

// nextInterval returns the check interval with random jitter applied.
func (l *certRotationLoop) nextInterval() time.Duration {
	jitterRange := int64(float64(l.checkInterval) * certRotationJitterFraction)
	if jitterRange <= 0 {
		return l.checkInterval
	}
	n, err := rand.Int(rand.Reader, big.NewInt(jitterRange))
	if err != nil {
		return l.checkInterval
	}
	return l.checkInterval + time.Duration(n.Int64())
}

// dueForRotation reports whether the current serving certificate is inside
// the rotate-before window. The gRPC server's live certificate is
// authoritative when available; otherwise the tracked expiration is used.
func (l *certRotationLoop) dueForRotation() bool {
	expiration := l.expiration
	if l.grpcServer != nil {
		if exp := l.grpcServer.ServingCertificateExpiration(); !exp.IsZero() {
			expiration = exp
		}
	}
	if expiration.IsZero() {
		return false
	}
	return time.Until(expiration) < l.rotateBefore
}

// rotate re-issues the serving certificate and distributes it to the gRPC
// server and the webhook certificate directory.
func (l *certRotationLoop) rotate(ctx context.Context) {
	newCert, err := l.certManager.RotateCertificate(ctx, l.request)
	if err != nil {
		setupLog.Error(err, "serving certificate rotation failed; will retry",
			"common_name", l.request.CommonName,
		)
		return
	}

	l.expiration = newCert.Expiration

	if l.grpcServer != nil {
		if err := l.grpcServer.UpdateCertificate(newCert); err != nil {
			setupLog.Error(err, "failed to update gRPC serving certificate")
		}
	}

	if l.webhookCertDir != "" {
		if err := rewriteWebhookCertFiles(l.webhookCertDir, newCert); err != nil {
			setupLog.Error(err, "failed to rewrite webhook certificate files",
				"cert_dir", l.webhookCertDir,
			)
		}
	}

	setupLog.Info("serving certificate rotated",
		"common_name", l.request.CommonName,
		"expiration", newCert.Expiration,
	)
}

// rewriteWebhookCertFiles writes the rotated certificate and key into the
// webhook certificate directory in place. controller-runtime's certwatcher
// watches these files and hot-reloads them for the webhook server.
func rewriteWebhookCertFiles(dir string, c *cert.Certificate) error {
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), c.CertificatePEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "tls.key"), c.PrivateKeyPEM, 0o600)
}
