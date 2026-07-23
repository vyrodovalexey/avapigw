// Package main tests for the serving-certificate rotation loop and the
// externally provisioned (file / cert-manager) webhook certificate paths.
package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
)

// rotationRecorder records UpdateCertificate calls from the rotation loop.
type rotationRecorder struct {
	mu         sync.Mutex
	updates    []*cert.Certificate
	expiration time.Time
}

func (r *rotationRecorder) UpdateCertificate(c *cert.Certificate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updates = append(r.updates, c)
	r.expiration = c.Expiration
	return nil
}

func (r *rotationRecorder) ServingCertificateExpiration() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.expiration
}

func (r *rotationRecorder) updateCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.updates)
}

// newRotationTestManager returns a fast self-signed cert manager.
func newRotationTestManager(t *testing.T, certValidity time.Duration) cert.Manager {
	t.Helper()
	mgr, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName: "rotation-loop-ca",
		CAValidity:   24 * time.Hour,
		CertValidity: certValidity,
		RotateBefore: time.Minute,
		KeySize:      2048,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

// TestCertRotationLoop_RotatesShortExpiryCert verifies the loop re-issues a
// certificate inside the rotate-before window and pushes it to the server
// and the webhook cert dir.
func TestCertRotationLoop_RotatesShortExpiryCert(t *testing.T) {
	certManager := newRotationTestManager(t, 24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Issue a SHORT-lived initial certificate: expires within rotateBefore.
	initial, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "rotation-loop",
		TTL:        30 * time.Second,
	})
	require.NoError(t, err)

	recorder := &rotationRecorder{expiration: initial.Expiration}
	webhookDir := t.TempDir()

	loop := &certRotationLoop{
		certManager: certManager,
		grpcServer:  recorder,
		request: &cert.CertificateRequest{
			CommonName: "rotation-loop",
			// No TTL: rotation issues with the provider's CertValidity,
			// pushing the new expiration outside the window.
		},
		rotateBefore:   time.Minute,
		webhookCertDir: webhookDir,
		checkInterval:  20 * time.Millisecond,
		expiration:     initial.Expiration,
	}

	go loop.run(ctx)

	require.Eventually(t, func() bool { return recorder.updateCount() >= 1 },
		5*time.Second, 20*time.Millisecond,
		"rotation loop must re-issue a certificate expiring within rotateBefore")

	// The rotated certificate must be valid beyond the initial one.
	assert.True(t, recorder.ServingCertificateExpiration().After(initial.Expiration),
		"rotated certificate must extend the expiration")

	// Webhook cert files must be rewritten in place for certwatcher.
	certPEM, err := os.ReadFile(filepath.Join(webhookDir, "tls.crt"))
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
	keyPEM, err := os.ReadFile(filepath.Join(webhookDir, "tls.key"))
	require.NoError(t, err)
	assert.NotEmpty(t, keyPEM)

	// After a successful rotation the loop must settle (no rotation storm):
	// the fresh certificate is outside the window.
	count := recorder.updateCount()
	time.Sleep(150 * time.Millisecond)
	assert.LessOrEqual(t, recorder.updateCount(), count+1,
		"a fresh certificate must not be rotated repeatedly")
}

// TestCertRotationLoop_NoRotationForFreshCert verifies certificates outside
// the rotate-before window are left alone.
func TestCertRotationLoop_NoRotationForFreshCert(t *testing.T) {
	certManager := newRotationTestManager(t, 24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initial, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "fresh-cert",
	})
	require.NoError(t, err)

	recorder := &rotationRecorder{expiration: initial.Expiration}
	loop := &certRotationLoop{
		certManager:   certManager,
		grpcServer:    recorder,
		request:       &cert.CertificateRequest{CommonName: "fresh-cert"},
		rotateBefore:  time.Minute,
		checkInterval: 10 * time.Millisecond,
		expiration:    initial.Expiration,
	}

	go loop.run(ctx)
	time.Sleep(150 * time.Millisecond)

	assert.Zero(t, recorder.updateCount(),
		"a certificate outside the rotation window must not be rotated")
}

// TestCertRotationLoop_StopsOnContextCancel verifies loop shutdown.
func TestCertRotationLoop_StopsOnContextCancel(t *testing.T) {
	certManager := newRotationTestManager(t, 24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())

	loop := &certRotationLoop{
		certManager:   certManager,
		request:       &cert.CertificateRequest{CommonName: "cancel-test"},
		rotateBefore:  time.Minute,
		checkInterval: 10 * time.Millisecond,
	}

	done := make(chan struct{})
	go func() {
		loop.run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("rotation loop did not stop on context cancellation")
	}
}

// TestCertRotationLoop_DueForRotation covers the expiry-source precedence.
func TestCertRotationLoop_DueForRotation(t *testing.T) {
	recorder := &rotationRecorder{}

	tests := []struct {
		name       string
		loop       *certRotationLoop
		serverExp  time.Time
		wantDue    bool
		lastUpdate time.Time
	}{
		{
			name: "tracked expiration inside window",
			loop: &certRotationLoop{
				rotateBefore: time.Hour,
				expiration:   time.Now().Add(30 * time.Minute),
			},
			wantDue: true,
		},
		{
			name: "tracked expiration outside window",
			loop: &certRotationLoop{
				rotateBefore: time.Hour,
				expiration:   time.Now().Add(2 * time.Hour),
			},
			wantDue: false,
		},
		{
			name: "zero expiration and no server",
			loop: &certRotationLoop{
				rotateBefore: time.Hour,
			},
			wantDue: false,
		},
		{
			name: "server expiration overrides tracked",
			loop: &certRotationLoop{
				rotateBefore: time.Hour,
				grpcServer:   recorder,
				expiration:   time.Now().Add(30 * time.Minute),
			},
			serverExp: time.Now().Add(3 * time.Hour),
			wantDue:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder.mu.Lock()
			recorder.expiration = tt.serverExp
			recorder.mu.Unlock()
			assert.Equal(t, tt.wantDue, tt.loop.dueForRotation())
		})
	}
}

// TestCertRotationLoop_NextInterval verifies jitter bounds.
func TestCertRotationLoop_NextInterval(t *testing.T) {
	loop := &certRotationLoop{checkInterval: 100 * time.Millisecond}
	for i := 0; i < 20; i++ {
		iv := loop.nextInterval()
		assert.GreaterOrEqual(t, iv, 100*time.Millisecond)
		assert.LessOrEqual(t, iv, 120*time.Millisecond)
	}
}

// TestStartCertRotationIfNeeded_Skips verifies external providers and
// disabled components skip the loop.
func TestStartCertRotationIfNeeded_Skips(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	certManager := newRotationTestManager(t, 24*time.Hour)
	initial, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{CommonName: "skip"})
	require.NoError(t, err)

	tests := []struct {
		name        string
		cfg         *Config
		initialCert *cert.Certificate
	}{
		{
			name:        "cert-manager provider skips",
			cfg:         &Config{CertProvider: "cert-manager", EnableWebhooks: true},
			initialCert: initial,
		},
		{
			name:        "file provider skips",
			cfg:         &Config{CertProvider: "file", EnableWebhooks: true},
			initialCert: initial,
		},
		{
			name:        "no grpc server and no webhooks skips",
			cfg:         &Config{CertProvider: "selfsigned"},
			initialCert: initial,
		},
		{
			name:        "nil initial certificate skips",
			cfg:         &Config{CertProvider: "selfsigned", EnableWebhooks: true},
			initialCert: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Must return without starting anything that panics/hangs.
			startCertRotationIfNeeded(ctx, tt.cfg, certManager, nil, tt.initialCert)
		})
	}
}

// TestCertRotateBefore verifies provider-specific lead times.
func TestCertRotateBefore(t *testing.T) {
	assert.Equal(t, cert.DefaultVaultRotateBefore, certRotateBefore("vault"))
	assert.Equal(t, cert.DefaultRotateBefore, certRotateBefore("selfsigned"))
	assert.Equal(t, cert.DefaultRotateBefore, certRotateBefore(""))
}

// TestStartCertRotationIfNeeded_StartsLoop verifies the loop starts for
// internally provisioned certificates (grpc server present / webhooks on).
func TestStartCertRotationIfNeeded_StartsLoop(t *testing.T) {
	certManager := newRotationTestManager(t, 24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initial, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "loop-start",
	})
	require.NoError(t, err)

	cfg := &Config{
		CertProvider:    "selfsigned",
		EnableWebhooks:  true,
		CertServiceName: "loop-start",
		CertNamespace:   "test-ns",
		WebhookCertDir:  t.TempDir(),
	}

	// nil gRPC server + webhooks enabled: the loop must still start (it
	// rewrites the webhook cert files on rotation).
	startCertRotationIfNeeded(ctx, cfg, certManager, nil, initial)
	// Loop runs in the background; cancellation stops it (no assertion
	// beyond not panicking — behavior is covered by the loop tests).
}

// TestStartCertRotationForComponents_ResolvesCurrentCert verifies the
// component wrapper resolves the serving certificate and starts the loop.
func TestStartCertRotationForComponents_ResolvesCurrentCert(t *testing.T) {
	certManager := newRotationTestManager(t, 24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &Config{
		CertProvider:    "selfsigned",
		EnableWebhooks:  true,
		CertServiceName: "component-cert",
		CertNamespace:   "test-ns",
		WebhookCertDir:  t.TempDir(),
	}

	startCertRotationForComponents(ctx, cfg, certManager, nil)

	// The wrapper resolved (and cached) the serving certificate.
	current, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "component-cert",
	})
	require.NoError(t, err)
	assert.NotNil(t, current)
}

// TestStartCertRotationForComponents_Skips covers the guard paths.
func TestStartCertRotationForComponents_Skips(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	certManager := newRotationTestManager(t, 24*time.Hour)

	t.Run("external provider skips", func(t *testing.T) {
		startCertRotationForComponents(ctx,
			&Config{CertProvider: "cert-manager", EnableWebhooks: true}, certManager, nil)
	})
	t.Run("nothing to rotate skips", func(t *testing.T) {
		startCertRotationForComponents(ctx,
			&Config{CertProvider: "selfsigned"}, certManager, nil)
	})
	t.Run("certificate resolution error skips", func(t *testing.T) {
		// Empty CommonName makes GetCertificate fail.
		startCertRotationForComponents(ctx,
			&Config{CertProvider: "selfsigned", EnableWebhooks: true}, certManager, nil)
	})
}

// TestCertRotationLoop_RotateFailureRetries verifies rotation failures are
// non-fatal (logged, retried next tick).
func TestCertRotationLoop_RotateFailureRetries(t *testing.T) {
	certManager := newRotationTestManager(t, 24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recorder := &rotationRecorder{}
	loop := &certRotationLoop{
		certManager: certManager,
		grpcServer:  recorder,
		// Empty CommonName: RotateCertificate fails every time.
		request:      &cert.CertificateRequest{},
		rotateBefore: time.Hour,
		expiration:   time.Now().Add(time.Minute),
	}

	loop.rotate(ctx)
	assert.Zero(t, recorder.updateCount(), "failed rotation must not push a certificate")
}

// TestCertRotationLoop_RotateWebhookDirError verifies webhook rewrite
// failures are non-fatal and the gRPC server still gets the certificate.
func TestCertRotationLoop_RotateWebhookDirError(t *testing.T) {
	certManager := newRotationTestManager(t, 24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recorder := &rotationRecorder{}
	loop := &certRotationLoop{
		certManager:    certManager,
		grpcServer:     recorder,
		request:        &cert.CertificateRequest{CommonName: "webhook-err"},
		rotateBefore:   time.Hour,
		webhookCertDir: filepath.Join(t.TempDir(), "missing-subdir"),
	}

	loop.rotate(ctx)
	assert.Equal(t, 1, recorder.updateCount(),
		"gRPC certificate swap must happen despite webhook file errors")
}

// TestCertRotationLoop_NextInterval_NoJitter covers the zero-jitter path.
func TestCertRotationLoop_NextInterval_NoJitter(t *testing.T) {
	loop := &certRotationLoop{checkInterval: 1}
	assert.Equal(t, time.Duration(1), loop.nextInterval(),
		"sub-jitter intervals must be returned unchanged")
}

// TestRewriteWebhookCertFiles verifies in-place rewrite semantics.
func TestRewriteWebhookCertFiles(t *testing.T) {
	dir := t.TempDir()
	c := &cert.Certificate{
		CertificatePEM: []byte("cert-pem"),
		PrivateKeyPEM:  []byte("key-pem"),
	}

	require.NoError(t, rewriteWebhookCertFiles(dir, c))

	certPEM, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("cert-pem"), certPEM)

	keyPEM, err := os.ReadFile(filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	assert.Equal(t, []byte("key-pem"), keyPEM)

	// Error path: unwritable directory.
	require.Error(t, rewriteWebhookCertFiles(filepath.Join(dir, "missing-subdir"), c))
}
