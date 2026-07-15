package grpcadapter

// WP15 — coverage for the gRPC aggregate Invoker: Invoke happy/error paths over
// an in-process echo backend, targetAddress/auth-header helpers, TLS and mTLS
// handshakes through the real connection pool, and option/constructor branches.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ----------------------------------------------------------------------------
// Options / constructor.
// ----------------------------------------------------------------------------

// HAPPY: WithInvokerLogger applies a non-nil logger via NewInvoker's option loop.
func TestWithInvokerLogger_AppliesLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	inv := NewInvoker(nil, "/pkg.Svc/Method", WithInvokerLogger(logger))

	assert.Same(t, logger, inv.logger, "option must install the provided logger")
	assert.Equal(t, "/pkg.Svc/Method", inv.fullMethod)
}

// EDGE: a nil logger is ignored and the default (nop) logger is retained.
func TestWithInvokerLogger_NilIgnored(t *testing.T) {
	t.Parallel()

	inv := NewInvoker(nil, "/pkg.Svc/Method", WithInvokerLogger(nil))

	assert.NotNil(t, inv.logger, "nil logger must not replace the default")
}

// HAPPY: NewInvoker stores the pool and full method.
func TestNewInvoker_StoresPoolAndMethod(t *testing.T) {
	t.Parallel()

	pool := errPool{err: errors.New("unused")}

	inv := NewInvoker(pool, "/pkg.Svc/Call")

	assert.Equal(t, pool, inv.pool)
	assert.Equal(t, "/pkg.Svc/Call", inv.fullMethod)
	assert.NotNil(t, inv.logger, "default logger must be installed")
}

// ----------------------------------------------------------------------------
// targetAddress.
// ----------------------------------------------------------------------------

// EDGE: targetAddress formats host:port, passes bare hosts through, and joins
// IPv6 hosts with brackets.
func TestTargetAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target aggregate.Target
		want   string
	}{
		{
			name:   "host and port joined",
			target: aggregate.Target{Host: "backend.local", Port: 9090},
			want:   "backend.local:9090",
		},
		{
			name:   "zero port returns host verbatim",
			target: aggregate.Target{Host: "backend.local:8443"},
			want:   "backend.local:8443",
		},
		{
			name:   "negative port returns host verbatim",
			target: aggregate.Target{Host: "backend.local", Port: -1},
			want:   "backend.local",
		},
		{
			name:   "ipv6 host bracketed",
			target: aggregate.Target{Host: "::1", Port: 50051},
			want:   "[::1]:50051",
		},
		{
			name:   "empty host with port",
			target: aggregate.Target{Host: "", Port: 8080},
			want:   ":8080",
		},
		{
			name:   "empty host without port",
			target: aggregate.Target{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, targetAddress(&tt.target))
		})
	}
}

// ----------------------------------------------------------------------------
// Auth header helpers (SECURITY-relevant).
// ----------------------------------------------------------------------------

// HAPPY/EDGE: authHeader dispatches per auth type and passes through
// unauthenticated and unknown types without credentials.
func TestAuthHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		auth      *config.BackendAuthConfig
		wantKey   string
		wantValue string
	}{
		{
			name: "nil auth is a no-op",
			auth: nil,
		},
		{
			name: "empty type is a no-op",
			auth: &config.BackendAuthConfig{},
		},
		{
			name: "unknown type mtls passes through",
			auth: &config.BackendAuthConfig{Type: "mtls"},
		},
		{
			name: "basic dispatches to basicAuthHeader",
			auth: &config.BackendAuthConfig{
				Type: "basic",
				Basic: &config.BackendBasicAuthConfig{
					Enabled:  true,
					Username: "user",
					Password: "pass",
				},
			},
			wantKey: authHeaderKey,
			// base64("user:pass")
			wantValue: "Basic dXNlcjpwYXNz",
		},
		{
			name:    "basic with nil config yields empty credential",
			auth:    &config.BackendAuthConfig{Type: "basic"},
			wantKey: authHeaderKey,
		},
		{
			name: "jwt dispatches to jwtAuthHeader",
			auth: &config.BackendAuthConfig{
				Type: "jwt",
				JWT: &config.BackendJWTAuthConfig{
					Enabled:     true,
					StaticToken: "tok-1",
				},
			},
			wantKey:   authHeaderKey,
			wantValue: "Bearer tok-1",
		},
		{
			name: "jwt with nil config is a no-op",
			auth: &config.BackendAuthConfig{Type: "jwt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, value := authHeader(tt.auth)

			assert.Equal(t, tt.wantKey, key)
			assert.Equal(t, tt.wantValue, value)
		})
	}
}

// HAPPY/EDGE: basicAuthHeader builds an exact base64 credential and returns
// empty for nil/disabled/empty-username configs.
func TestBasicAuthHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		basic *config.BackendBasicAuthConfig
		want  string
	}{
		{
			name: "nil config",
		},
		{
			name:  "disabled",
			basic: &config.BackendBasicAuthConfig{Username: "user", Password: "pass"},
		},
		{
			name:  "empty username",
			basic: &config.BackendBasicAuthConfig{Enabled: true, Password: "pass"},
		},
		{
			name:  "username and password base64-correct",
			basic: &config.BackendBasicAuthConfig{Enabled: true, Username: "user", Password: "pass"},
			want:  "Basic dXNlcjpwYXNz", // base64("user:pass")
		},
		{
			name:  "empty password still encodes",
			basic: &config.BackendBasicAuthConfig{Enabled: true, Username: "user"},
			want:  "Basic dXNlcjo=", // base64("user:")
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, basicAuthHeader(tt.basic))
		})
	}
}

// HAPPY/EDGE: jwtAuthHeader emits "Bearer <token>" by default, honors custom
// header/prefix (header lowercased), and returns empty for nil/disabled/empty
// token configs.
func TestJWTAuthHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		jwt       *config.BackendJWTAuthConfig
		wantKey   string
		wantValue string
	}{
		{
			name: "nil config",
		},
		{
			name: "disabled",
			jwt:  &config.BackendJWTAuthConfig{StaticToken: "tok"},
		},
		{
			name: "empty static token",
			jwt:  &config.BackendJWTAuthConfig{Enabled: true},
		},
		{
			name:      "default header and prefix",
			jwt:       &config.BackendJWTAuthConfig{Enabled: true, StaticToken: "tok-42"},
			wantKey:   "authorization",
			wantValue: "Bearer tok-42",
		},
		{
			name: "custom mixed-case header lowercased",
			jwt: &config.BackendJWTAuthConfig{
				Enabled:     true,
				StaticToken: "tok-42",
				HeaderName:  "X-Api-Token",
			},
			wantKey:   "x-api-token",
			wantValue: "Bearer tok-42",
		},
		{
			name: "custom prefix",
			jwt: &config.BackendJWTAuthConfig{
				Enabled:      true,
				StaticToken:  "tok-42",
				HeaderPrefix: "JWT",
			},
			wantKey:   "authorization",
			wantValue: "JWT tok-42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, value := jwtAuthHeader(tt.jwt)

			assert.Equal(t, tt.wantKey, key)
			assert.Equal(t, tt.wantValue, value)
		})
	}
}

// ----------------------------------------------------------------------------
// tlsConfigFor remaining branches.
//
// NOTE (WP15 / review B.1): the marshal-error branches in tlsConfigFingerprint
// and tlsConfigFor's fingerprint-error return are UNREACHABLE by construction —
// json.Marshal of *config.BackendTLSConfig cannot fail (the struct holds only
// bool/string/[]string/pointer-struct fields, no map/func/chan/cycle). They are
// deliberately left uncovered, per the review's "accept as unreachable and
// document" option.
// ----------------------------------------------------------------------------

// ERROR: a broken TLS config (missing CA file) surfaces a wrapped build error
// and stores no cache entry.
func TestTLSConfigFor_BuildError(t *testing.T) {
	t.Parallel()

	inv := NewInvoker(nil, "/pkg.Svc/Method")
	target := aggregate.Target{
		Name: "bad-ca",
		TLS: &config.BackendTLSConfig{
			Enabled: true,
			CAFile:  "/nonexistent/path/ca.pem",
		},
	}

	cfg, err := inv.tlsConfigFor(&target)

	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "aggregate gRPC TLS for target bad-ca")

	entries := 0
	inv.tlsCache.Range(func(_, _ any) bool {
		entries++
		return true
	})
	assert.Zero(t, entries, "failed builds must not populate the cache")
}

// EDGE: configured ALPN protocols are preserved (no h2 forcing when non-empty).
func TestTLSConfigFor_PreservesConfiguredALPN(t *testing.T) {
	t.Parallel()

	inv := NewInvoker(nil, "/pkg.Svc/Method")
	target := aggregate.Target{
		Name: "alpn-target",
		TLS: &config.BackendTLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
			ALPN:               []string{"h2", "http/1.1"},
		},
	}

	cfg, err := inv.tlsConfigFor(&target)

	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
}

// ----------------------------------------------------------------------------
// Invoke — error paths (unit, no live backend).
// ----------------------------------------------------------------------------

// ERROR: a TLS build failure aborts Invoke before dialing, reporting the error
// both as the transport error and on the per-target response.
func TestInvoke_TLSConfigError(t *testing.T) {
	t.Parallel()

	inv := NewInvoker(errPool{err: errors.New("must not be reached")}, "/pkg.Svc/Method")
	target := aggregate.Target{
		Name: "bad-ca",
		Host: "127.0.0.1",
		Port: 1,
		TLS: &config.BackendTLSConfig{
			Enabled: true,
			CAFile:  "/nonexistent/path/ca.pem",
		},
	}

	resp, err := inv.Invoke(context.Background(), target, &aggregate.Request{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "aggregate gRPC TLS for target bad-ca")
	require.NotNil(t, resp)
	assert.Equal(t, "bad-ca", resp.Target)
	assert.Equal(t, err, resp.Err, "response must carry the same error")
}

// ERROR: a pool dial failure is wrapped with the target address and reported on
// both return values.
func TestInvoke_DialError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("pool exploded")
	inv := NewInvoker(errPool{err: sentinel}, "/pkg.Svc/Method")
	target := aggregate.Target{Name: "t1", Host: "10.255.0.1", Port: 9090}

	resp, err := inv.Invoke(context.Background(), target, &aggregate.Request{})

	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
	assert.Contains(t, err.Error(), "aggregate gRPC dial 10.255.0.1:9090")
	require.NotNil(t, resp)
	assert.Equal(t, "t1", resp.Target)
	assert.Equal(t, err, resp.Err)
}

// ----------------------------------------------------------------------------
// Invoke — in-process echo backend over bufconn.
// ----------------------------------------------------------------------------

// HAPPY: Invoke round-trips request/response bytes through an in-process gRPC
// echo backend; metadata arrives lowercased with the basic-auth credential
// injected, and the response carries gRPC-OK semantics.
func TestInvoke_HappyPath_EchoOverBufconn(t *testing.T) {
	t.Parallel()

	backend, lis := startBufconnEcho(t, echoBehavior{respBody: []byte("pong")})
	pool := newBufconnPool(t, lis)
	inv := NewInvoker(pool, "/agg.Echo/Call", WithInvokerLogger(observability.NopLogger()))

	req := &aggregate.Request{
		Headers: map[string][]string{
			"X-Request-ID": {"req-1"},
			"x-lower":      {"v1"},
		},
		Body: []byte("ping"),
	}
	target := aggregate.Target{
		Name: "echo-a",
		Host: "127.0.0.1",
		Port: 4242,
		Auth: &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := inv.Invoke(ctx, target, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "echo-a", resp.Target)
	assert.NoError(t, resp.Err)
	assert.Zero(t, resp.StatusCode, "gRPC OK must map to status code 0")
	assert.Equal(t, "application/grpc", resp.ContentType)
	assert.Equal(t, []byte("pong"), resp.Body)

	calls := backend.capturedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "/agg.Echo/Call", calls[0].method)
	assert.Equal(t, []byte("ping"), calls[0].body)

	// Metadata contract: keys lowercased on the wire, credential injected.
	md := calls[0].md
	assert.Equal(t, []string{"req-1"}, md.Get("x-request-id"))
	assert.Equal(t, []string{"v1"}, md.Get("x-lower"))
	assert.Equal(t, []string{"Basic dXNlcjpwYXNz"}, md.Get(authHeaderKey))
	for key := range md {
		assert.Equal(t, strings.ToLower(key), key,
			"metadata key %q must be lowercase on the wire", key)
	}

	// The pool was asked for the plaintext host:port target.
	targets, tlsCfgs := pool.seen()
	require.Len(t, targets, 1)
	assert.Equal(t, "127.0.0.1:4242", targets[0])
	assert.Nil(t, tlsCfgs[0], "plaintext target must not build a TLS config")
}

// HAPPY (SECURITY): a static JWT credential travels under its custom lowercase
// header with the Bearer prefix; the default authorization key stays unused.
func TestInvoke_JWTAuthHeaderOnWire(t *testing.T) {
	t.Parallel()

	backend, lis := startBufconnEcho(t, echoBehavior{respBody: []byte("ok")})
	pool := newBufconnPool(t, lis)
	inv := NewInvoker(pool, "/agg.Echo/Call")

	target := aggregate.Target{
		Name: "jwt-target",
		Host: "127.0.0.1",
		Port: 4243,
		Auth: &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				StaticToken: "tok-123",
				HeaderName:  "X-Api-Token",
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := inv.Invoke(ctx, target, &aggregate.Request{Body: []byte("q")})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Err)

	calls := backend.capturedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"Bearer tok-123"}, calls[0].md.Get("x-api-token"))
	assert.Empty(t, calls[0].md.Get(authHeaderKey),
		"custom-header JWT must not populate the default authorization key")
}

// EDGE: with no request headers and no target auth, no application metadata is
// forwarded (only transport-internal keys appear).
func TestInvoke_NoAuth_EmptyMetadata(t *testing.T) {
	t.Parallel()

	backend, lis := startBufconnEcho(t, echoBehavior{respBody: []byte("ok")})
	pool := newBufconnPool(t, lis)
	inv := NewInvoker(pool, "/agg.Echo/Call")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := inv.Invoke(ctx, aggregate.Target{Name: "plain", Host: "h", Port: 1}, &aggregate.Request{})

	require.NoError(t, err)
	require.NoError(t, resp.Err)

	calls := backend.capturedCalls()
	require.Len(t, calls, 1)
	assert.Empty(t, calls[0].md.Get(authHeaderKey), "no credential must be injected")
	for key := range calls[0].md {
		assert.False(t, strings.HasPrefix(key, "x-"),
			"unexpected forwarded application header %q", key)
	}
}

// ERROR: a backend application error is attributed to the target via
// Response.Err while the transport-level error stays nil, so the aggregate
// engine applies FailMode policy instead of aborting the fan-out.
func TestInvoke_BackendErrorViaResponseErr(t *testing.T) {
	t.Parallel()

	_, lis := startBufconnEcho(t, echoBehavior{
		respErr: status.Error(codes.Internal, "backend boom"),
	})
	pool := newBufconnPool(t, lis)
	inv := NewInvoker(pool, "/agg.Echo/Call")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := inv.Invoke(ctx, aggregate.Target{Name: "boom", Host: "h", Port: 1}, &aggregate.Request{})

	require.NoError(t, err, "application errors must travel via Response.Err, not the transport error")
	require.NotNil(t, resp)
	assert.Equal(t, "boom", resp.Target)
	require.Error(t, resp.Err)
	assert.Equal(t, codes.Internal, status.Code(resp.Err))
	assert.Contains(t, resp.Err.Error(), "backend boom")
}

// ERROR: a context deadline expiring mid-call is reported per-target as
// DeadlineExceeded via Response.Err.
func TestInvoke_ContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	_, lis := startBufconnEcho(t, echoBehavior{blockUntilCtxDone: true})
	pool := newBufconnPool(t, lis)
	inv := NewInvoker(pool, "/agg.Echo/Call")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	resp, err := inv.Invoke(ctx, aggregate.Target{Name: "slow", Host: "h", Port: 1}, &aggregate.Request{})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Error(t, resp.Err)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(resp.Err))
}

// ----------------------------------------------------------------------------
// Invoke — TLS/mTLS through the REAL connection pool over 127.0.0.1.
// ----------------------------------------------------------------------------

// newRealPool returns a production ConnectionPool closed via t.Cleanup.
func newRealPool(t *testing.T) *grpcproxy.ConnectionPool {
	t.Helper()
	pool := grpcproxy.NewConnectionPool(grpcproxy.WithPoolLogger(observability.NopLogger()))
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

// HAPPY (TLS): Invoke completes a real TLS handshake against a test CA-signed
// server certificate using the per-target CAFile/ServerName config.
func TestInvoke_TLS_ServerCAVerified(t *testing.T) {
	t.Parallel()

	ca := newTestCertAuthority(t)
	serverCertPEM, serverKeyPEM := ca.issueLeaf(
		t, "echo-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 100)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	backend := startTCPEcho(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}, echoBehavior{respBody: []byte(`{"ok":true}`)})

	caFile := writeTempFile(t, t.TempDir(), "ca.pem", ca.certPEM)
	inv := NewInvoker(newRealPool(t), "/agg.Echo/Call")
	target := aggregate.Target{
		Name: "tls-target",
		Host: backend.host,
		Port: backend.port,
		TLS: &config.BackendTLSConfig{
			Enabled:    true,
			CAFile:     caFile,
			ServerName: "localhost",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := inv.Invoke(ctx, target, &aggregate.Request{Body: []byte("hello")})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Err)
	assert.Equal(t, []byte(`{"ok":true}`), resp.Body)

	calls := backend.capturedCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, []byte("hello"), calls[0].body)
}

// HAPPY (mTLS): the server requires and verifies a client certificate; the
// per-target MUTUAL config presents the CA-signed client keypair.
func TestInvoke_MTLS_ClientCertPresented(t *testing.T) {
	t.Parallel()

	ca := newTestCertAuthority(t)
	serverCertPEM, serverKeyPEM := ca.issueLeaf(
		t, "echo-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 200)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)
	clientCertPEM, clientKeyPEM := ca.issueLeaf(
		t, "aggregate-client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 201)

	backend := startTCPEcho(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, echoBehavior{respBody: []byte("mtls-ok")})

	dir := t.TempDir()
	target := aggregate.Target{
		Name: "mtls-target",
		Host: backend.host,
		Port: backend.port,
		TLS: &config.BackendTLSConfig{
			Enabled:    true,
			Mode:       config.BackendTLSModeMutual,
			CAFile:     writeTempFile(t, dir, "ca.pem", ca.certPEM),
			CertFile:   writeTempFile(t, dir, "client.pem", clientCertPEM),
			KeyFile:    writeTempFile(t, dir, "client-key.pem", clientKeyPEM),
			ServerName: "localhost",
		},
	}
	inv := NewInvoker(newRealPool(t), "/agg.Echo/Call")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := inv.Invoke(ctx, target, &aggregate.Request{Body: []byte("hi")})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Err)
	assert.Equal(t, []byte("mtls-ok"), resp.Body)
	require.Len(t, backend.capturedCalls(), 1, "mutually-authenticated call must reach the handler")
}
