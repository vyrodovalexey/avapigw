package grpcadapter

// WP15 shared test scaffolding: an in-process gRPC echo backend (bufconn for
// hermetic unit paths, 127.0.0.1:0 TCP for real-pool TLS paths), fake ConnPool
// implementations, and a minimal certificate authority for TLS/mTLS handshakes.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
)

// testRawCodec mirrors the gRPC proxy's transparent raw codec so the in-process
// test server (and bufconn clients) can exchange *grpcproxy.Frame payloads with
// the invoker without any proto descriptors. Name() must be "proto" to match
// the content-subtype the pool's forced codec puts on the wire.
type testRawCodec struct{}

func (testRawCodec) Marshal(v interface{}) ([]byte, error) {
	frame, ok := v.(*grpcproxy.Frame)
	if !ok {
		return nil, fmt.Errorf("testRawCodec: unexpected message type %T", v)
	}
	return frame.Payload(), nil
}

func (testRawCodec) Unmarshal(data []byte, v interface{}) error {
	frame, ok := v.(*grpcproxy.Frame)
	if !ok {
		return fmt.Errorf("testRawCodec: unexpected message type %T", v)
	}
	frame.SetPayload(data)
	return nil
}

func (testRawCodec) Name() string { return "proto" }

// capturedCall records what the echo backend observed for a single RPC.
type capturedCall struct {
	method string
	md     metadata.MD
	body   []byte
}

// echoBehavior configures how the echo backend responds. Fields are read-only
// after construction, so handlers need no locking to consult them.
type echoBehavior struct {
	// respBody is sent back as the unary response payload on success.
	respBody []byte

	// respErr, when non-nil, is returned instead of a response message.
	respErr error

	// blockUntilCtxDone makes the handler park until the stream context is
	// canceled (deadline/cancel tests) and return the context error.
	blockUntilCtxDone bool
}

// echoBackend is an in-process gRPC server accepting ANY method via
// UnknownServiceHandler and speaking the transparent Frame codec.
type echoBackend struct {
	server   *grpc.Server
	host     string
	port     int
	behavior echoBehavior

	mu    sync.Mutex
	calls []capturedCall
}

// handle implements grpc.StreamHandler with unary semantics: receive one
// request frame, record it, then respond per the configured behavior.
func (b *echoBackend) handle(_ interface{}, stream grpc.ServerStream) error {
	method, _ := grpc.Method(stream.Context())
	md, _ := metadata.FromIncomingContext(stream.Context())

	in := grpcproxy.NewFrame(nil)
	if err := stream.RecvMsg(in); err != nil {
		return err
	}

	b.mu.Lock()
	b.calls = append(b.calls, capturedCall{method: method, md: md, body: in.Payload()})
	b.mu.Unlock()

	if b.behavior.blockUntilCtxDone {
		<-stream.Context().Done()
		return status.FromContextError(stream.Context().Err()).Err()
	}
	if b.behavior.respErr != nil {
		return b.behavior.respErr
	}
	return stream.SendMsg(grpcproxy.NewFrame(b.behavior.respBody))
}

// capturedCalls returns a snapshot of the calls observed so far.
func (b *echoBackend) capturedCalls() []capturedCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]capturedCall, len(b.calls))
	copy(out, b.calls)
	return out
}

// startTCPEcho starts an echo backend on 127.0.0.1:0. A non-nil tlsCfg enables
// (m)TLS transport credentials. The server is stopped via t.Cleanup.
func startTCPEcho(t *testing.T, tlsCfg *tls.Config, behavior echoBehavior) *echoBackend {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	b := &echoBackend{behavior: behavior, host: "127.0.0.1"}
	tcpAddr, ok := lis.Addr().(*net.TCPAddr)
	require.True(t, ok, "listener address must be *net.TCPAddr")
	b.port = tcpAddr.Port

	opts := []grpc.ServerOption{
		grpc.ForceServerCodec(testRawCodec{}),
		grpc.UnknownServiceHandler(b.handle),
	}
	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	b.server = grpc.NewServer(opts...)

	go func() { _ = b.server.Serve(lis) }()
	t.Cleanup(b.server.Stop)
	return b
}

// startBufconnEcho starts an echo backend on an in-memory bufconn listener.
func startBufconnEcho(t *testing.T, behavior echoBehavior) (*echoBackend, *bufconn.Listener) {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	b := &echoBackend{behavior: behavior, host: "bufconn"}
	b.server = grpc.NewServer(
		grpc.ForceServerCodec(testRawCodec{}),
		grpc.UnknownServiceHandler(b.handle),
	)

	go func() { _ = b.server.Serve(lis) }()
	t.Cleanup(func() {
		b.server.Stop()
		_ = lis.Close()
	})
	return b, lis
}

// bufconnPool is a ConnPool that dials the given bufconn listener regardless of
// the target address, recording every (target, tlsConfig) pair it was asked for.
type bufconnPool struct {
	lis *bufconn.Listener

	mu      sync.Mutex
	conns   []*grpc.ClientConn
	targets []string
	tlsSeen []*tls.Config
}

// newBufconnPool builds a bufconn-backed ConnPool whose connections are closed
// via t.Cleanup.
func newBufconnPool(t *testing.T, lis *bufconn.Listener) *bufconnPool {
	t.Helper()
	p := &bufconnPool{lis: lis}
	t.Cleanup(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, conn := range p.conns {
			_ = conn.Close()
		}
	})
	return p
}

// GetWithTLS implements ConnPool over the in-memory listener.
func (p *bufconnPool) GetWithTLS(
	_ context.Context, target string, tlsConfig *tls.Config,
) (*grpc.ClientConn, error) {
	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.tlsSeen = append(p.tlsSeen, tlsConfig)
	p.mu.Unlock()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return p.lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(testRawCodec{})),
	)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.conns = append(p.conns, conn)
	p.mu.Unlock()
	return conn, nil
}

// seen returns a snapshot of the (target, tlsConfig) pairs requested so far.
func (p *bufconnPool) seen() (targets []string, tlsCfgs []*tls.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	targets = append(targets, p.targets...)
	tlsCfgs = append(tlsCfgs, p.tlsSeen...)
	return targets, tlsCfgs
}

// errPool is a ConnPool that always fails, for dial-error paths.
type errPool struct{ err error }

// GetWithTLS implements ConnPool by returning the configured error.
func (p errPool) GetWithTLS(context.Context, string, *tls.Config) (*grpc.ClientConn, error) {
	return nil, p.err
}

// testCertAuthority is a throwaway CA for TLS/mTLS handshake tests.
type testCertAuthority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// newTestCertAuthority generates a self-signed CA certificate.
func newTestCertAuthority(t *testing.T) *testCertAuthority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aggregate-grpc-test-ca", Organization: []string{"avapigw"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCertAuthority{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issueLeaf issues a CA-signed leaf certificate for localhost/127.0.0.1 with
// the given extended key usages, returning PEM-encoded cert and key.
func (ca *testCertAuthority) issueLeaf(
	t *testing.T, cn string, extUsage []x509.ExtKeyUsage, serial int64,
) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"avapigw"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  extUsage,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// pool returns a cert pool containing only this CA.
func (ca *testCertAuthority) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// writeTempFile writes data into dir under name and returns the full path.
func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}
