package redisclient

// Tests for T3.B1 (review M1): the Redis TLS builders must honor
// certFile/keyFile (mTLS client keypair), caFile (private CA pool), and
// min/max protocol versions, and fail loudly when referenced files are
// unreadable instead of silently degrading to system-trust-only TLS.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// writeTestKeypair generates a self-signed cert/key pair (also usable as a
// CA bundle) and returns the certFile, keyFile, caFile paths.
func writeTestKeypair(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()

	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "redis-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	caFile = filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caFile, certPEM, 0o644))
	return certFile, keyFile, caFile
}

func TestNewTLSConfig_FullMaterial(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile := writeTestKeypair(t)

	tlsCfg, err := NewTLSConfig(&config.TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
		MinVersion: "TLS12",
		MaxVersion: "TLS13",
	})
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.Len(t, tlsCfg.Certificates, 1, "client certificate must be loaded for mTLS")
	assert.NotNil(t, tlsCfg.RootCAs, "private CA pool must be loaded")
	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsCfg.MaxVersion)
	assert.False(t, tlsCfg.InsecureSkipVerify)
}

func TestNewTLSConfig_Defaults(t *testing.T) {
	t.Parallel()

	tlsCfg, err := NewTLSConfig(&config.TLSConfig{Enabled: true, InsecureSkipVerify: true})
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.True(t, tlsCfg.InsecureSkipVerify)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion, "default MinVersion must be TLS 1.2")
	assert.Empty(t, tlsCfg.Certificates)
	assert.Nil(t, tlsCfg.RootCAs, "system trust when no CA file configured")
}

func TestNewTLSConfig_Errors(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _ := writeTestKeypair(t)

	tests := []struct {
		name   string
		cfg    *config.TLSConfig
		errSub string
	}{
		{
			name:   "cert without key",
			cfg:    &config.TLSConfig{Enabled: true, CertFile: certFile},
			errSub: "both certFile and keyFile",
		},
		{
			name:   "key without cert",
			cfg:    &config.TLSConfig{Enabled: true, KeyFile: keyFile},
			errSub: "both certFile and keyFile",
		},
		{
			name: "unreadable cert files",
			cfg: &config.TLSConfig{
				Enabled: true, CertFile: "/nonexistent/tls.crt", KeyFile: "/nonexistent/tls.key",
			},
			errSub: "failed to load redis TLS client certificate",
		},
		{
			name:   "unreadable CA file",
			cfg:    &config.TLSConfig{Enabled: true, CAFile: "/nonexistent/ca.crt"},
			errSub: "failed to read redis TLS CA file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewTLSConfig(tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errSub)
		})
	}
}

func TestNewTLSConfig_InvalidCAPEM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "bad-ca.crt")
	require.NoError(t, os.WriteFile(caFile, []byte("not a certificate"), 0o644))

	_, err := NewTLSConfig(&config.TLSConfig{Enabled: true, CAFile: caFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid PEM certificates")
}

func TestBuildStandaloneOptions_TLSMaterialHonored(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile := writeTestKeypair(t)

	opts, err := BuildStandaloneOptions(&Config{
		URL: "redis://localhost:6379",
		TLS: &config.TLSConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, opts.TLSConfig)
	assert.Len(t, opts.TLSConfig.Certificates, 1)
	assert.NotNil(t, opts.TLSConfig.RootCAs)
}

func TestBuildStandaloneOptions_TLSError(t *testing.T) {
	t.Parallel()

	_, err := BuildStandaloneOptions(&Config{
		URL: "redis://localhost:6379",
		TLS: &config.TLSConfig{Enabled: true, CAFile: "/nonexistent/ca.crt"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read redis TLS CA file")
}

func TestBuildFailoverOptions_TLSError(t *testing.T) {
	t.Parallel()

	_, err := BuildFailoverOptions(&Config{
		Sentinel: &config.RedisSentinelConfig{MasterName: "m", SentinelAddrs: []string{"s:26379"}},
		TLS:      &config.TLSConfig{Enabled: true, CAFile: "/nonexistent/ca.crt"},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read redis TLS CA file")
}

func TestTLSConfigFor_DisabledPreservesExisting(t *testing.T) {
	t.Parallel()

	existing := &tls.Config{ServerName: "from-rediss-url", MinVersion: tls.VersionTLS12}

	got, err := tlsConfigFor(&Config{}, existing)
	require.NoError(t, err)
	assert.Same(t, existing, got, "disabled TLS must preserve the rediss:// URL config")

	got, err = tlsConfigFor(&Config{TLS: &config.TLSConfig{Enabled: false}}, existing)
	require.NoError(t, err)
	assert.Same(t, existing, got)
}

// requireInvertedRangeRejectedAtHandshake asserts crypto/tls rejects the
// inverted version range before any I/O: the client handshake fails while
// building ClientHello, so a net.Pipe (never serviced by a server) suffices.
// ServerName is set on a clone the same way go-redis derives it from the
// dial address, so the version-range error is the one that surfaces.
func requireInvertedRangeRejectedAtHandshake(t *testing.T, tlsCfg *tls.Config) {
	t.Helper()

	handshakeCfg := tlsCfg.Clone()
	handshakeCfg.ServerName = "localhost"

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tls.Client(clientConn, handshakeCfg).HandshakeContext(ctx)
	require.Error(t, err, "handshake with MinVersion > MaxVersion must fail")
	assert.Contains(t, err.Error(), "no supported versions",
		"crypto/tls must reject the inverted version range explicitly")
}

// TestBuildOptions_InvertedTLSVersionRange pins the defined behavior for an
// inverted min/max protocol range (MinVersion TLS13 > MaxVersion TLS12):
// the builders pass the range through without clamping or erroring, and
// crypto/tls rejects it deterministically at handshake time — the
// misconfiguration can never silently connect.
func TestBuildOptions_InvertedTLSVersionRange(t *testing.T) {
	t.Parallel()

	invertedTLS := &config.TLSConfig{Enabled: true, MinVersion: "TLS13", MaxVersion: "TLS12"}

	t.Run("standalone passes range through", func(t *testing.T) {
		t.Parallel()

		opts, err := BuildStandaloneOptions(&Config{
			URL: "redis://localhost:6379",
			TLS: invertedTLS,
		})
		require.NoError(t, err, "construction is pass-through: no validation of the version range")
		require.NotNil(t, opts.TLSConfig)
		assert.Equal(t, uint16(tls.VersionTLS13), opts.TLSConfig.MinVersion)
		assert.Equal(t, uint16(tls.VersionTLS12), opts.TLSConfig.MaxVersion)

		requireInvertedRangeRejectedAtHandshake(t, opts.TLSConfig)
	})

	t.Run("failover passes range through", func(t *testing.T) {
		t.Parallel()

		opts, err := BuildFailoverOptions(&Config{
			Sentinel: &config.RedisSentinelConfig{
				MasterName:    "m",
				SentinelAddrs: []string{"s:26379"},
			},
			TLS: invertedTLS,
		}, nil)
		require.NoError(t, err)
		require.NotNil(t, opts.TLSConfig)
		assert.Equal(t, uint16(tls.VersionTLS13), opts.TLSConfig.MinVersion)
		assert.Equal(t, uint16(tls.VersionTLS12), opts.TLSConfig.MaxVersion)

		requireInvertedRangeRejectedAtHandshake(t, opts.TLSConfig)
	})
}
