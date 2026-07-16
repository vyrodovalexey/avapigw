package server

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// recordingTLSMetrics is a MetricsRecorder capturing handshake observations.
type recordingTLSMetrics struct {
	tlspkg.NopMetrics

	mu             sync.Mutex
	durations      []time.Duration
	modes          []tlspkg.TLSMode
	errorReasons   []string
	connectionHits int
}

func (r *recordingTLSMetrics) RecordHandshakeDuration(d time.Duration, _ uint16, mode tlspkg.TLSMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.durations = append(r.durations, d)
	r.modes = append(r.modes, mode)
}

func (r *recordingTLSMetrics) RecordHandshakeError(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errorReasons = append(r.errorReasons, reason)
}

func (r *recordingTLSMetrics) RecordConnection(_ uint16, _ uint16, _ tlspkg.TLSMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectionHits++
}

func (r *recordingTLSMetrics) durationCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.durations)
}

func (r *recordingTLSMetrics) reasons() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.errorReasons))
	copy(out, r.errorReasons)
	return out
}

func (r *recordingTLSMetrics) lastMode() tlspkg.TLSMode {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.modes) == 0 {
		return ""
	}
	return r.modes[len(r.modes)-1]
}

// drivePerConnHandshake simulates one handshake against an instrumented
// config: it invokes the installed GetConfigForClient hook and the returned
// per-connection VerifyConnection with the given state.
func drivePerConnHandshake(t *testing.T, cfg *tls.Config, cs tls.ConnectionState) error {
	t.Helper()

	require.NotNil(t, cfg.GetConfigForClient, "handshake timing hook must be installed")
	perConn, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, perConn)
	require.Nil(t, perConn.GetConfigForClient, "per-connection config must not re-instrument")
	return perConn.VerifyConnection(cs)
}

func TestConfigureGRPCTLS_HandshakeTiming_MetricsPath(t *testing.T) {
	t.Parallel()

	metrics := &recordingTLSMetrics{}
	s := &Server{
		logger:     observability.NopLogger(),
		tlsMetrics: metrics,
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	s.configureGRPCTLS(tlsConfig)

	err := drivePerConnHandshake(t, tlsConfig, tls.ConnectionState{Version: tls.VersionTLS13})
	require.NoError(t, err)

	assert.Equal(t, 1, metrics.durationCount(), "handshake duration recorded")
	assert.Equal(t, tlspkg.TLSModeSimple, metrics.lastMode(), "mode derived from state without peer certs")

	err = drivePerConnHandshake(t, tlsConfig, tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{}},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, metrics.durationCount())
	assert.Equal(t, tlspkg.TLSModeMutual, metrics.lastMode(), "mode derived from peer certificates")
}

func TestConfigureGRPCTLS_HandshakeTiming_ManagerPath(t *testing.T) {
	t.Parallel()

	certFile, keyFile, cleanup := createTestCertFiles(t)
	defer cleanup()

	metrics := &recordingTLSMetrics{}
	manager, err := tlspkg.NewManager(&tlspkg.Config{
		Mode: tlspkg.TLSModeSimple,
		ServerCertificate: &tlspkg.CertificateConfig{
			Source:   tlspkg.CertificateSourceFile,
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	}, tlspkg.WithManagerMetrics(metrics))
	require.NoError(t, err)
	defer manager.Close()

	s := &Server{
		logger:     observability.NopLogger(),
		tlsManager: manager,
		tlsMetrics: metrics,
	}

	tlsConfig := manager.GetTLSConfig().Clone()
	s.configureGRPCTLS(tlsConfig)

	err = drivePerConnHandshake(t, tlsConfig, tls.ConnectionState{Version: tls.VersionTLS13})
	require.NoError(t, err)

	assert.Equal(t, 1, metrics.durationCount(), "manager records the handshake on its metrics recorder")
	assert.Equal(t, tlspkg.TLSModeSimple, metrics.lastMode(), "manager labels the sample with its configured mode")
}

func TestConfigureGRPCTLS_HandshakeTiming_ALPNFailureChainPreserved(t *testing.T) {
	t.Parallel()

	metrics := &recordingTLSMetrics{}
	s := &Server{
		logger:      observability.NopLogger(),
		tlsMetrics:  metrics,
		requireALPN: true,
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	s.configureGRPCTLS(tlsConfig)

	// Empty negotiated protocol: the chained ALPN verification must reject the
	// connection and the instrumentation must record the bounded verify
	// failure without a duration sample.
	err := drivePerConnHandshake(t, tlsConfig, tls.ConnectionState{Version: tls.VersionTLS13})
	require.Error(t, err)

	assert.Zero(t, metrics.durationCount(), "no duration sample for a rejected connection")
	reasons := metrics.reasons()
	assert.Contains(t, reasons, "no_alpn", "ALPN enforcement error preserved through the chain")
	assert.Contains(t, reasons, tlspkg.HandshakeErrorReasonVerifyFailed,
		"instrumentation records the bounded verify failure")

	// A protocol-carrying connection passes and records a duration.
	err = drivePerConnHandshake(t, tlsConfig, tls.ConnectionState{
		Version:            tls.VersionTLS13,
		NegotiatedProtocol: "h2",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, metrics.durationCount())
}

func TestConfigureGRPCTLS_HandshakeTiming_NoSinksNoHook(t *testing.T) {
	t.Parallel()

	s := &Server{logger: observability.NopLogger()}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	s.configureGRPCTLS(tlsConfig)

	assert.Nil(t, tlsConfig.GetConfigForClient,
		"no hook installed when neither manager nor metrics are configured")
}
