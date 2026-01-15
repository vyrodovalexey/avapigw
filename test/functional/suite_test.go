//go:build functional
// +build functional

/*
Package functional provides functional tests for the API Gateway components.
These tests verify the gateway functionality independently of the Kubernetes operator.
*/
package functional

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
	gwgrpc "github.com/vyrodovalexey/avapigw/internal/gateway/server/grpc"
	gwhttp "github.com/vyrodovalexey/avapigw/internal/gateway/server/http"
	"github.com/vyrodovalexey/avapigw/internal/gateway/server/http/middleware"
	"github.com/vyrodovalexey/avapigw/internal/gateway/server/tcp"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit"
)

// TestSuite holds shared test resources
type TestSuite struct {
	t              *testing.T
	logger         *zap.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	backendManager *backend.Manager
	mockBackends   []*MockBackend
	mu             sync.Mutex
}

// MockBackend represents a mock backend server for testing
type MockBackend struct {
	Server     *httptest.Server
	URL        string
	Port       int
	Handler    http.Handler
	Requests   []RecordedRequest
	mu         sync.Mutex
	Healthy    bool
	Latency    time.Duration
	StatusCode int
}

// RecordedRequest stores information about a received request
type RecordedRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
	Time    time.Time
}

// NewTestSuite creates a new test suite
func NewTestSuite(t *testing.T) *TestSuite {
	gin.SetMode(gin.TestMode)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	logger := zaptest.NewLogger(t)

	suite := &TestSuite{
		t:              t,
		logger:         logger,
		ctx:            ctx,
		cancel:         cancel,
		backendManager: backend.NewManager(logger),
		mockBackends:   make([]*MockBackend, 0),
	}

	return suite
}

// Cleanup cleans up test resources
func (s *TestSuite) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop all mock backends
	for _, mb := range s.mockBackends {
		if mb.Server != nil {
			mb.Server.Close()
		}
	}

	// Stop backend manager
	if s.backendManager != nil && s.backendManager.IsRunning() {
		_ = s.backendManager.Stop(s.ctx)
	}

	s.cancel()
}

// CreateMockBackend creates a new mock backend server
func (s *TestSuite) CreateMockBackend(opts ...MockBackendOption) *MockBackend {
	mb := &MockBackend{
		Healthy:    true,
		StatusCode: http.StatusOK,
		Requests:   make([]RecordedRequest, 0),
	}

	for _, opt := range opts {
		opt(mb)
	}

	if mb.Handler == nil {
		mb.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mb.mu.Lock()
			defer mb.mu.Unlock()

			// Record the request
			body, _ := io.ReadAll(r.Body)
			mb.Requests = append(mb.Requests, RecordedRequest{
				Method:  r.Method,
				Path:    r.URL.Path,
				Headers: r.Header.Clone(),
				Body:    body,
				Time:    time.Now(),
			})

			// Simulate latency
			if mb.Latency > 0 {
				time.Sleep(mb.Latency)
			}

			// Check health
			if !mb.Healthy {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}

			w.WriteHeader(mb.StatusCode)
			w.Write([]byte(`{"status":"ok"}`))
		})
	}

	mb.Server = httptest.NewServer(mb.Handler)
	mb.URL = mb.Server.URL

	// Extract port from URL
	_, portStr, _ := net.SplitHostPort(mb.Server.Listener.Addr().String())
	fmt.Sscanf(portStr, "%d", &mb.Port)

	s.mu.Lock()
	s.mockBackends = append(s.mockBackends, mb)
	s.mu.Unlock()

	return mb
}

// MockBackendOption configures a mock backend
type MockBackendOption func(*MockBackend)

// WithLatency sets the response latency
func WithLatency(d time.Duration) MockBackendOption {
	return func(mb *MockBackend) {
		mb.Latency = d
	}
}

// WithStatusCode sets the response status code
func WithStatusCode(code int) MockBackendOption {
	return func(mb *MockBackend) {
		mb.StatusCode = code
	}
}

// WithHandler sets a custom handler
func WithHandler(h http.Handler) MockBackendOption {
	return func(mb *MockBackend) {
		mb.Handler = h
	}
}

// WithUnhealthy marks the backend as unhealthy
func WithUnhealthy() MockBackendOption {
	return func(mb *MockBackend) {
		mb.Healthy = false
	}
}

// GetRequests returns recorded requests
func (mb *MockBackend) GetRequests() []RecordedRequest {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	result := make([]RecordedRequest, len(mb.Requests))
	copy(result, mb.Requests)
	return result
}

// ClearRequests clears recorded requests
func (mb *MockBackend) ClearRequests() {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.Requests = make([]RecordedRequest, 0)
}

// SetHealthy sets the health status
func (mb *MockBackend) SetHealthy(healthy bool) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.Healthy = healthy
}

// SetLatency sets the response latency
func (mb *MockBackend) SetLatency(d time.Duration) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.Latency = d
}

// SetStatusCode sets the response status code
func (mb *MockBackend) SetStatusCode(code int) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.StatusCode = code
}

// CreateHTTPServer creates a new HTTP server for testing
func (s *TestSuite) CreateHTTPServer(config *gwhttp.ServerConfig) *gwhttp.Server {
	if config == nil {
		config = gwhttp.DefaultServerConfig()
		config.Port = GetFreePort(s.t)
	}
	return gwhttp.NewServer(config, s.logger)
}

// CreateGRPCServer creates a new gRPC server for testing
func (s *TestSuite) CreateGRPCServer(config *gwgrpc.ServerConfig) *gwgrpc.Server {
	if config == nil {
		config = gwgrpc.DefaultServerConfig()
		config.Port = GetFreePort(s.t)
		config.EnableHealthCheck = true
		config.EnableReflection = true
	}
	return gwgrpc.NewServer(config, s.backendManager, s.logger)
}

// CreateTCPServer creates a new TCP server for testing
func (s *TestSuite) CreateTCPServer(config *tcp.ServerConfig) *tcp.Server {
	if config == nil {
		config = tcp.DefaultServerConfig()
		config.Port = GetFreePort(s.t)
	}
	return tcp.NewServer(config, s.logger)
}

// CreateBackendManager creates a new backend manager
func (s *TestSuite) CreateBackendManager() *backend.Manager {
	return backend.NewManager(s.logger)
}

// CreateCircuitBreakerRegistry creates a new circuit breaker registry
func (s *TestSuite) CreateCircuitBreakerRegistry() *circuitbreaker.Registry {
	return circuitbreaker.NewRegistry(circuitbreaker.DefaultConfig(), s.logger)
}

// CreateRateLimiter creates a new rate limiter
func (s *TestSuite) CreateRateLimiter(config *ratelimit.FactoryConfig) ratelimit.Limiter {
	if config == nil {
		config = ratelimit.DefaultFactoryConfig()
	}
	limiter, _ := ratelimit.NewLimiter(config)
	return limiter
}

// GetFreePort returns a free port for testing
func GetFreePort(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// WaitForServer waits for a server to be ready
func WaitForServer(t *testing.T, addr string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready within %v", addr, timeout)
}

// WaitForGRPCServer waits for a gRPC server to be ready
func WaitForGRPCServer(t *testing.T, addr string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		cancel()
		if err == nil {
			// Check health
			healthClient := healthpb.NewHealthClient(conn)
			resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})
			conn.Close()
			if err == nil && resp.Status == healthpb.HealthCheckResponse_SERVING {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("gRPC server at %s did not become ready within %v", addr, timeout)
}

// GenerateSelfSignedCert generates a self-signed certificate for testing
func GenerateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte, tlsConfig *tls.Config) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Create TLS config
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return certPEM, keyPEM, tlsConfig
}

// CreateTestHTTPClient creates an HTTP client for testing
func CreateTestHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// CreateTestGRPCClient creates a gRPC client connection for testing
func CreateTestGRPCClient(t *testing.T, addr string) *grpc.ClientConn {
	conn, err := grpc.Dial(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)
	require.NoError(t, err)
	return conn
}

// AssertEventually asserts that a condition becomes true within a timeout
func AssertEventually(t *testing.T, condition func() bool, timeout time.Duration, msg string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v: %s", timeout, msg)
}

// AssertNever asserts that a condition never becomes true within a duration
func AssertNever(t *testing.T, condition func() bool, duration time.Duration, msg string) {
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if condition() {
			t.Fatalf("condition became true: %s", msg)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestMain sets up the test environment
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	m.Run()
}

// Helper function to create middleware chain for testing
func CreateTestMiddlewareChain(logger *zap.Logger) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		middleware.Recovery(logger),
		middleware.Logging(logger),
		middleware.RequestID(),
	}
}

// MockGRPCBackend represents a mock gRPC backend server
type MockGRPCBackend struct {
	Server   *grpc.Server
	Listener net.Listener
	Port     int
	mu       sync.Mutex
}

// NewMockGRPCBackend creates a new mock gRPC backend
func NewMockGRPCBackend(t *testing.T) *MockGRPCBackend {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()

	mb := &MockGRPCBackend{
		Server:   server,
		Listener: listener,
		Port:     listener.Addr().(*net.TCPAddr).Port,
	}

	return mb
}

// Start starts the mock gRPC backend
func (mb *MockGRPCBackend) Start() {
	go mb.Server.Serve(mb.Listener)
}

// Stop stops the mock gRPC backend
func (mb *MockGRPCBackend) Stop() {
	mb.Server.GracefulStop()
}

// Address returns the address of the mock backend
func (mb *MockGRPCBackend) Address() string {
	return fmt.Sprintf("127.0.0.1:%d", mb.Port)
}

// MockTCPBackend represents a mock TCP backend server
type MockTCPBackend struct {
	Listener net.Listener
	Port     int
	Handler  func(net.Conn)
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewMockTCPBackend creates a new mock TCP backend
func NewMockTCPBackend(t *testing.T, handler func(net.Conn)) *MockTCPBackend {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	if handler == nil {
		handler = func(conn net.Conn) {
			defer conn.Close()
			io.Copy(conn, conn) // Echo server
		}
	}

	return &MockTCPBackend{
		Listener: listener,
		Port:     listener.Addr().(*net.TCPAddr).Port,
		Handler:  handler,
		stopCh:   make(chan struct{}),
	}
}

// Start starts the mock TCP backend
func (mb *MockTCPBackend) Start() {
	mb.wg.Add(1)
	go func() {
		defer mb.wg.Done()
		for {
			select {
			case <-mb.stopCh:
				return
			default:
				mb.Listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
				conn, err := mb.Listener.Accept()
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}
				mb.wg.Add(1)
				go func() {
					defer mb.wg.Done()
					mb.Handler(conn)
				}()
			}
		}
	}()
}

// Stop stops the mock TCP backend
func (mb *MockTCPBackend) Stop() {
	close(mb.stopCh)
	mb.Listener.Close()
	mb.wg.Wait()
}

// Address returns the address of the mock backend
func (mb *MockTCPBackend) Address() string {
	return fmt.Sprintf("127.0.0.1:%d", mb.Port)
}
