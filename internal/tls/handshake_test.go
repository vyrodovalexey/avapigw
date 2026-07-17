package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handshakeObservations collects handshake observer invocations thread-safely.
type handshakeObservations struct {
	mu        sync.Mutex
	durations []time.Duration
	states    []*tls.ConnectionState
	failures  []string
}

func (o *handshakeObservations) onSuccess(d time.Duration, cs *tls.ConnectionState) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.durations = append(o.durations, d)
	o.states = append(o.states, cs)
}

func (o *handshakeObservations) onFailure(reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failures = append(o.failures, reason)
}

func (o *handshakeObservations) successCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.durations)
}

func (o *handshakeObservations) failureCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.failures)
}

func (o *handshakeObservations) firstDuration() time.Duration {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.durations) == 0 {
		return 0
	}
	return o.durations[0]
}

func (o *handshakeObservations) firstState() *tls.ConnectionState {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.states) == 0 {
		return nil
	}
	return o.states[0]
}

func (o *handshakeObservations) firstFailure() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.failures) == 0 {
		return ""
	}
	return o.failures[0]
}

// serverTLSConfigForHandshakeTest builds a server tls.Config from generated
// test certificates.
func serverTLSConfigForHandshakeTest(t *testing.T, certs *testCertificates) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(certs.certPEM, certs.keyPEM)
	require.NoError(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// clientTLSConfigForHandshakeTest builds a client tls.Config trusting the test CA.
func clientTLSConfigForHandshakeTest(t *testing.T, certs *testCertificates) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certs.caPEM))
	return &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}

// runInstrumentedHandshake starts a one-shot TLS server with the given
// (already instrumented) config, dials it with clientCfg, and returns the
// client-side and server-side handshake errors. The server drives its
// handshake explicitly so instrumentation callbacks have fired by the time
// this helper returns.
func runInstrumentedHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) (clientErr, serverErr error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, serverCfg)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		serverDone <- tlsConn.HandshakeContext(ctx)
	}()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	clientConn, clientErr := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), clientCfg)
	if clientConn != nil {
		defer clientConn.Close()
	}

	select {
	case serverErr = <-serverDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for server-side handshake")
	}
	return clientErr, serverErr
}

func TestInstrumentHandshakeTiming_NilConfig(t *testing.T) {
	t.Parallel()

	// Must not panic.
	InstrumentHandshakeTiming(nil, func(time.Duration, *tls.ConnectionState) {}, nil)
}

func TestInstrumentHandshakeTiming_NilObserverLeavesConfigUntouched(t *testing.T) {
	t.Parallel()

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	InstrumentHandshakeTiming(cfg, nil, func(string) {})
	assert.Nil(t, cfg.GetConfigForClient, "nil success observer must not install a hook")
}

func TestInstrumentHandshakeTiming_SuccessfulHandshake(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	obs := &handshakeObservations{}
	serverCfg := serverTLSConfigForHandshakeTest(t, certs)
	InstrumentHandshakeTiming(serverCfg, obs.onSuccess, obs.onFailure)

	clientErr, serverErr := runInstrumentedHandshake(t, serverCfg, clientTLSConfigForHandshakeTest(t, certs))
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	require.Equal(t, 1, obs.successCount(), "exactly one handshake observation")
	assert.Equal(t, 0, obs.failureCount(), "no failure observations")

	d := obs.firstDuration()
	assert.Positive(t, d, "handshake duration must be > 0")
	assert.Less(t, d, 5*time.Second, "handshake duration must be sane")

	state := obs.firstState()
	require.NotNil(t, state)
	assert.GreaterOrEqual(t, state.Version, uint16(tls.VersionTLS12))
	assert.Equal(t, TLSModeSimple, ConnectionStateMode(state))
}

func TestInstrumentHandshakeTiming_PreservesVerifyConnectionChain(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	var chainCalls atomic.Int32
	obs := &handshakeObservations{}
	serverCfg := serverTLSConfigForHandshakeTest(t, certs)
	serverCfg.VerifyConnection = func(tls.ConnectionState) error {
		chainCalls.Add(1)
		return nil
	}
	InstrumentHandshakeTiming(serverCfg, obs.onSuccess, obs.onFailure)

	clientErr, serverErr := runInstrumentedHandshake(t, serverCfg, clientTLSConfigForHandshakeTest(t, certs))
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	assert.Equal(t, int32(1), chainCalls.Load(), "original VerifyConnection must run")
	assert.Equal(t, 1, obs.successCount())
}

func TestInstrumentHandshakeTiming_VerifyConnectionFailure(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	obs := &handshakeObservations{}
	serverCfg := serverTLSConfigForHandshakeTest(t, certs)
	serverCfg.VerifyConnection = func(tls.ConnectionState) error {
		return errors.New("connection rejected by policy")
	}
	InstrumentHandshakeTiming(serverCfg, obs.onSuccess, obs.onFailure)

	clientErr, serverErr := runInstrumentedHandshake(t, serverCfg, clientTLSConfigForHandshakeTest(t, certs))
	require.Error(t, serverErr, "server handshake must fail when VerifyConnection rejects")
	_ = clientErr // client may observe an alert or EOF depending on timing

	assert.Equal(t, 0, obs.successCount(), "failed handshake must not record a duration sample")
	require.Equal(t, 1, obs.failureCount(), "failure must be recorded exactly once")
	assert.Equal(t, HandshakeErrorReasonVerifyFailed, obs.firstFailure(), "bounded failure reason")
}

func TestInstrumentHandshakeTiming_NilFailureObserver(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	obs := &handshakeObservations{}
	serverCfg := serverTLSConfigForHandshakeTest(t, certs)
	serverCfg.VerifyConnection = func(tls.ConnectionState) error {
		return errors.New("rejected")
	}
	InstrumentHandshakeTiming(serverCfg, obs.onSuccess, nil)

	_, serverErr := runInstrumentedHandshake(t, serverCfg, clientTLSConfigForHandshakeTest(t, certs))
	require.Error(t, serverErr)
	assert.Equal(t, 0, obs.successCount())
}

func TestInstrumentHandshakeTiming_ChainsGetConfigForClient(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	// The pre-existing hook returns an override config carrying its own
	// VerifyConnection marker; both the override semantics and the timing
	// observation must survive.
	var overrideVerifyCalls atomic.Int32
	override := serverTLSConfigForHandshakeTest(t, certs)
	override.VerifyConnection = func(tls.ConnectionState) error {
		overrideVerifyCalls.Add(1)
		return nil
	}

	var origHookCalls atomic.Int32
	serverCfg := serverTLSConfigForHandshakeTest(t, certs)
	serverCfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		origHookCalls.Add(1)
		return override, nil
	}

	obs := &handshakeObservations{}
	InstrumentHandshakeTiming(serverCfg, obs.onSuccess, obs.onFailure)

	clientErr, serverErr := runInstrumentedHandshake(t, serverCfg, clientTLSConfigForHandshakeTest(t, certs))
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	assert.Equal(t, int32(1), origHookCalls.Load(), "pre-existing GetConfigForClient must be chained")
	assert.Equal(t, int32(1), overrideVerifyCalls.Load(), "override config's VerifyConnection must run")
	assert.Equal(t, 1, obs.successCount(), "timing observation recorded for the override config")
}

func TestInstrumentHandshakeTiming_GetConfigForClientError(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	hookErr := errors.New("config selection failed")
	serverCfg := serverTLSConfigForHandshakeTest(t, certs)
	serverCfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return nil, hookErr
	}

	obs := &handshakeObservations{}
	InstrumentHandshakeTiming(serverCfg, obs.onSuccess, obs.onFailure)

	_, serverErr := runInstrumentedHandshake(t, serverCfg, clientTLSConfigForHandshakeTest(t, certs))
	require.Error(t, serverErr, "hook error must abort the handshake")

	assert.Equal(t, 0, obs.successCount(), "no success observation on hook error")
	assert.Equal(t, 0, obs.failureCount(), "hook errors abort before verification; not a verify failure")
}

// generateHandshakeMTLSChain builds an in-memory CA plus CA-signed server and
// client keypairs suitable for driving real mutual-TLS handshakes.
func generateHandshakeMTLSChain(t *testing.T) (caPool *x509.CertPool, serverCert, clientCert tls.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Handshake Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	caPool = x509.NewCertPool()
	caPool.AddCert(caCert)

	newLeaf := func(serial int64, cn string, eku x509.ExtKeyUsage, dnsNames []string) tls.Certificate {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, keyErr)
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{eku},
			DNSNames:              dnsNames,
			BasicConstraintsValid: true,
		}
		der, certErr := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		require.NoError(t, certErr)
		leaf, parseErr := x509.ParseCertificate(der)
		require.NoError(t, parseErr)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	}

	serverCert = newLeaf(11, "localhost", x509.ExtKeyUsageServerAuth, []string{"localhost"})
	clientCert = newLeaf(12, "handshake-client", x509.ExtKeyUsageClientAuth, nil)
	return caPool, serverCert, clientCert
}

func TestInstrumentHandshakeTiming_MutualTLS_ClientCertObserved(t *testing.T) {
	t.Parallel()

	caPool, serverCert, clientCert := generateHandshakeMTLSChain(t)

	obs := &handshakeObservations{}
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	InstrumentHandshakeTiming(serverCfg, obs.onSuccess, obs.onFailure)

	clientCfg := &tls.Config{
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientCert},
	}

	clientErr, serverErr := runInstrumentedHandshake(t, serverCfg, clientCfg)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	require.Equal(t, 1, obs.successCount())
	state := obs.firstState()
	require.NotNil(t, state)
	require.NotEmpty(t, state.PeerCertificates, "peer certificate captured in the observed state")
	assert.Equal(t, TLSModeMutual, ConnectionStateMode(state))
}

func TestInstrumentHandshakeTiming_MutualTLS_MissingClientCertNotObserved(t *testing.T) {
	t.Parallel()

	caPool, serverCert, _ := generateHandshakeMTLSChain(t)

	obs := &handshakeObservations{}
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	InstrumentHandshakeTiming(serverCfg, obs.onSuccess, obs.onFailure)

	// No client certificate: the handshake aborts during certificate
	// processing, before VerifyConnection. Nothing must be observed and, by
	// design, nothing can leak: the per-connection closure is dropped with
	// the connection (no shared tracking state exists at all).
	clientCfg := &tls.Config{RootCAs: caPool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	_, serverErr := runInstrumentedHandshake(t, serverCfg, clientCfg)
	require.Error(t, serverErr, "missing required client certificate must fail the handshake")

	assert.Equal(t, 0, obs.successCount(), "aborted handshake records no duration sample")
	assert.Equal(t, 0, obs.failureCount(), "abort happens before connection verification")
}

func TestInstrumentHandshakeTiming_ConcurrentHandshakes(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificates(t)
	defer certs.cleanup()

	obs := &handshakeObservations{}
	serverCfg := serverTLSConfigForHandshakeTest(t, certs)
	InstrumentHandshakeTiming(serverCfg, obs.onSuccess, obs.onFailure)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	const handshakes = 8

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < handshakes; i++ {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				tlsConn := tls.Server(c, serverCfg)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = tlsConn.HandshakeContext(ctx)
			}(conn)
		}
	}()

	// Build the client config once, outside the goroutines, so no testing
	// assertions run off the test goroutine.
	clientCfg := clientTLSConfigForHandshakeTest(t, certs)

	var clientWg sync.WaitGroup
	for i := 0; i < handshakes; i++ {
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			conn, dialErr := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), clientCfg.Clone())
			if dialErr == nil {
				_ = conn.Close()
			}
		}()
	}
	clientWg.Wait()
	wg.Wait()

	assert.Equal(t, handshakes, obs.successCount(),
		"every concurrent handshake observed exactly once")
	assert.Equal(t, 0, obs.failureCount())
}

func TestConnectionStateMode(t *testing.T) {
	t.Parallel()

	assert.Equal(t, TLSModeSimple, ConnectionStateMode(nil))
	assert.Equal(t, TLSModeSimple, ConnectionStateMode(&tls.ConnectionState{}))
	assert.Equal(t, TLSModeMutual, ConnectionStateMode(&tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
	}))
}

func TestNewHandshakeRecorder_ManagerPath(t *testing.T) {
	t.Parallel()

	metrics := newMockMetrics()
	manager, err := NewManager(&Config{Mode: TLSModeInsecure}, WithManagerMetrics(metrics))
	require.NoError(t, err)
	defer manager.Close()

	onSuccess, onFailure := NewHandshakeRecorder(manager, metrics)
	require.NotNil(t, onSuccess)
	require.NotNil(t, onFailure)

	onSuccess(50*time.Millisecond, &tls.ConnectionState{Version: tls.VersionTLS13})
	assert.Equal(t, 1, metrics.getHandshakeDurationCount(), "manager records on its metrics recorder")

	onFailure("some_reason")
	assert.Equal(t, 1, metrics.getHandshakeErrorCount())
}

func TestNewHandshakeRecorder_MetricsOnlyPath(t *testing.T) {
	t.Parallel()

	metrics := newMockMetrics()
	onSuccess, onFailure := NewHandshakeRecorder(nil, metrics)
	require.NotNil(t, onSuccess)
	require.NotNil(t, onFailure)

	onSuccess(10*time.Millisecond, &tls.ConnectionState{Version: tls.VersionTLS12})
	assert.Equal(t, 1, metrics.getHandshakeDurationCount())

	onSuccess(10*time.Millisecond, &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{}},
	})
	assert.Equal(t, 2, metrics.getHandshakeDurationCount())
}

func TestNewHandshakeRecorder_NilSinks(t *testing.T) {
	t.Parallel()

	onSuccess, onFailure := NewHandshakeRecorder(nil, nil)
	assert.Nil(t, onSuccess)
	assert.Nil(t, onFailure)

	// A config instrumented with nil observers must remain untouched.
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	InstrumentHandshakeTiming(cfg, onSuccess, onFailure)
	assert.Nil(t, cfg.GetConfigForClient)
}
