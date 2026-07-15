package tls

// Regression tests for WP14-ctx: createContextWithTimeout accepts a parent
// context so caller/lifecycle cancellation propagates into time-bounded
// certificate operations, while construction-time roots keep an explicit
// context.Background() parent.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ctxRecordingProvider wraps certificate lookups and records whether the
// context it received was already canceled. It fails the lookup with the
// context error when the context is done, so cancellation propagation is
// observable.
type ctxRecordingProvider struct {
	mu          sync.Mutex
	cert        *tls.Certificate
	clientCA    *x509.CertPool
	sawCanceled bool
	eventCh     chan CertificateEvent
}

func newCtxRecordingProvider() *ctxRecordingProvider {
	return &ctxRecordingProvider{eventCh: make(chan CertificateEvent)}
}

func (p *ctxRecordingProvider) recordCtx(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		p.sawCanceled = true
		return err
	}
	return nil
}

func (p *ctxRecordingProvider) canceledSeen() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sawCanceled
}

func (p *ctxRecordingProvider) GetCertificate(
	ctx context.Context, _ *tls.ClientHelloInfo,
) (*tls.Certificate, error) {
	if err := p.recordCtx(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cert, nil
}

func (p *ctxRecordingProvider) GetClientCA(ctx context.Context) (*x509.CertPool, error) {
	if err := p.recordCtx(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clientCA, nil
}

func (p *ctxRecordingProvider) Watch(_ context.Context) <-chan CertificateEvent {
	return p.eventCh
}

func (p *ctxRecordingProvider) Close() error { return nil }

var _ CertificateProvider = (*ctxRecordingProvider)(nil)

// newMutualManagerWithProvider builds a mutual-TLS manager backed by the
// given recording provider, using generated test certificates.
func newMutualManagerWithProvider(t *testing.T, provider *ctxRecordingProvider) *Manager {
	t.Helper()

	certs := generateTestCertificates(t)
	t.Cleanup(certs.cleanup)

	cert, err := tls.LoadX509KeyPair(certs.certFile, certs.keyFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(certs.caPEM))

	provider.mu.Lock()
	provider.cert = &cert
	provider.clientCA = caPool
	provider.mu.Unlock()

	manager, err := NewManager(&Config{
		Mode:       TLSModeMutual,
		MinVersion: TLSVersion12,
		ServerCertificate: &CertificateConfig{
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
			CAFile:  certs.caFile,
		},
	}, WithCertificateProvider(provider))
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })

	return manager
}

// TestManager_CreateContextWithTimeout_ParentPropagation verifies that the
// derived context inherits cancellation from the parent and carries the
// requested deadline.
func TestManager_CreateContextWithTimeout_ParentPropagation(t *testing.T) {
	t.Parallel()

	provider := newCtxRecordingProvider()
	manager := newMutualManagerWithProvider(t, provider)

	t.Run("live parent gets deadline", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := manager.createContextWithTimeout(context.Background(), DefaultCertificateLoadTimeout)
		defer cancel()

		deadline, ok := ctx.Deadline()
		require.True(t, ok, "derived context must carry a deadline")
		assert.LessOrEqual(t, time.Until(deadline), DefaultCertificateLoadTimeout)
		assert.NoError(t, ctx.Err())
	})

	t.Run("canceled parent propagates", func(t *testing.T) {
		t.Parallel()
		parent, cancelParent := context.WithCancel(context.Background())
		cancelParent()

		ctx, cancel := manager.createContextWithTimeout(parent, DefaultCertificateLoadTimeout)
		defer cancel()

		assert.ErrorIs(t, ctx.Err(), context.Canceled,
			"cancellation must propagate from the parent into the derived context")
	})
}

// TestManager_RebuildTLSConfig_CanceledContextPropagates verifies the watcher
// context flows through handleCertificateEvent -> rebuildTLSConfig ->
// provider.GetClientCA.
func TestManager_RebuildTLSConfig_CanceledContextPropagates(t *testing.T) {
	t.Parallel()

	provider := newCtxRecordingProvider()
	manager := newMutualManagerWithProvider(t, provider)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := manager.rebuildTLSConfig(ctx)
	require.Error(t, err, "rebuild must fail when the caller context is canceled")
	assert.ErrorIs(t, err, context.Canceled)
	assert.True(t, provider.canceledSeen(), "provider must observe the canceled caller context")
}

// TestManager_HandleCertificateEvent_ReloadHonorsWatcherContext verifies that
// a reload event processed with a canceled watcher context does not panic and
// propagates cancellation into the CA reload.
func TestManager_HandleCertificateEvent_ReloadHonorsWatcherContext(t *testing.T) {
	t.Parallel()

	provider := newCtxRecordingProvider()
	manager := newMutualManagerWithProvider(t, provider)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Must not panic; the rebuild error is logged internally.
	manager.handleCertificateEvent(ctx, CertificateEvent{
		Type:    CertificateEventReloaded,
		Message: "reload with canceled watcher context",
	})

	assert.True(t, provider.canceledSeen(), "provider must observe the canceled watcher context")
}

// TestManager_CheckCertificateExpiry_CanceledContextPropagates verifies the
// expiry monitor's lifecycle context reaches the provider.
func TestManager_CheckCertificateExpiry_CanceledContextPropagates(t *testing.T) {
	t.Parallel()

	provider := newCtxRecordingProvider()
	manager := newMutualManagerWithProvider(t, provider)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Must not panic; the check aborts early on the canceled context.
	manager.checkCertificateExpiry(ctx)

	assert.True(t, provider.canceledSeen(), "provider must observe the canceled monitor context")
}

// TestManager_GetCertificateCallback_NilHelloContext verifies the handshake
// callback tolerates a manually constructed ClientHelloInfo whose Context()
// is nil (falls back to Background) — a regression guard for the parent-ctx
// change.
func TestManager_GetCertificateCallback_NilHelloContext(t *testing.T) {
	t.Parallel()

	provider := newCtxRecordingProvider()
	manager := newMutualManagerWithProvider(t, provider)

	tlsConfig := manager.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	require.NotNil(t, tlsConfig.GetCertificate)

	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	require.NoError(t, err, "callback must not panic or fail on a hello without context")
	assert.NotNil(t, cert)
}
