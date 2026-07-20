// Package helpers provides common test utilities for the API Gateway tests.
//
// This file contains helpers for tests that exercise the LIVE docker-compose
// auth backends (rest_api_3/4/5, grpc_3/4) together with the live Vault and
// Keycloak instances. All endpoints are configurable via environment
// variables; tests skip cleanly when the environment is absent.
package helpers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	internalvault "github.com/vyrodovalexey/avapigw/internal/vault"
)

// LiveAuthBackendConfig holds the live auth-backend endpoints of the
// docker-compose test environment, resolved from environment variables.
type LiveAuthBackendConfig struct {
	// MTLSRestAddr is the host:port of the mTLS REST backend (rest_api_4).
	MTLSRestAddr string
	// OIDCRestURL is the base URL of the OIDC REST backend (rest_api_3).
	OIDCRestURL string
	// BasicRestURL is the base URL of the basic-auth REST backend (rest_api_5).
	BasicRestURL string
	// MTLSGRPCAddr is the host:port of the mTLS gRPC backend (grpc_3).
	MTLSGRPCAddr string
	// OIDCGRPCAddr is the host:port of the OIDC gRPC backend (grpc_4).
	OIDCGRPCAddr string
	// KeycloakURL is the base URL of the live Keycloak.
	KeycloakURL string
	// BackendRealm is the Keycloak realm the backends validate tokens against.
	BackendRealm string
	// BackendClientID is the client_credentials client id for S2S tokens.
	BackendClientID string
	// BackendClientSecret is the client_credentials client secret.
	BackendClientSecret string
	// BackendIssuerHost is the host:port the backends expect in the token
	// issuer URL (the compose backends validate
	// iss=http://host.docker.internal:8090/realms/<realm>).
	BackendIssuerHost string
	// VaultClientCertRole is the Vault PKI role that issues client
	// certificates (EKU clientAuth) accepted by the mTLS backends.
	VaultClientCertRole string
	// VaultBasicAuthPath is the Vault KV path (mount/path format) holding
	// the basic-auth credentials for rest_api_5.
	VaultBasicAuthPath string
}

// GetLiveAuthBackendConfig resolves the live auth-backend endpoints from
// environment variables with docker-compose defaults.
func GetLiveAuthBackendConfig() LiveAuthBackendConfig {
	return LiveAuthBackendConfig{
		MTLSRestAddr:        getEnvOrDefault("TEST_MTLS_REST_BACKEND_ADDR", "127.0.0.1:8804"),
		OIDCRestURL:         getEnvOrDefault("TEST_OIDC_REST_BACKEND_URL", "http://127.0.0.1:8803"),
		BasicRestURL:        getEnvOrDefault("TEST_BASIC_REST_BACKEND_URL", "http://127.0.0.1:8805"),
		MTLSGRPCAddr:        getEnvOrDefault("TEST_MTLS_GRPC_BACKEND_ADDR", "127.0.0.1:8813"),
		OIDCGRPCAddr:        getEnvOrDefault("TEST_OIDC_GRPC_BACKEND_ADDR", "127.0.0.1:8814"),
		KeycloakURL:         GetKeycloakAddr(),
		BackendRealm:        getEnvOrDefault("TEST_KEYCLOAK_BACKEND_REALM", "backend-test"),
		BackendClientID:     getEnvOrDefault("TEST_BACKEND_OIDC_CLIENT_ID", "gateway-backend"),
		BackendClientSecret: getEnvOrDefault("TEST_BACKEND_OIDC_CLIENT_SECRET", "gateway-backend-secret"),
		BackendIssuerHost:   getEnvOrDefault("TEST_BACKEND_ISSUER_HOST", "host.docker.internal:8090"),
		VaultClientCertRole: getEnvOrDefault("TEST_VAULT_PKI_CLIENT_ROLE", "client-role"),
		VaultBasicAuthPath:  getEnvOrDefault("TEST_VAULT_BASIC_AUTH_PATH", "secret/backend-auth/basic"),
	}
}

// SkipIfTCPUnreachable skips the test when a TCP connection to hostport
// cannot be established within 2 seconds. TLS/auth-gated backends cannot be
// probed with plain HTTP health checks, so plain reachability is used.
func SkipIfTCPUnreachable(t *testing.T, hostport, service string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", hostport, 2*time.Second)
	if err != nil {
		t.Skipf("%s not reachable at %s - skipping live-backend test: %v", service, hostport, err)
		return
	}
	_ = conn.Close()
}

// StartIssuerRewriteProxy starts a local reverse proxy in front of Keycloak
// that presents the token issuer host the backends expect.
//
// The compose auth backends validate iss=http://<issuerHost>/realms/<realm>,
// but <issuerHost> (host.docker.internal:8090) is generally NOT resolvable
// from the test host. The proxy bridges that gap without /etc/hosts edits:
//
//   - every request is forwarded to keycloakURL with the Host header set to
//     issuerHost, so Keycloak mints tokens with the backend-expected iss;
//   - response bodies have http://<issuerHost> rewritten to the proxy's own
//     URL so OIDC discovery keeps the client (the gateway's backend-auth
//     provider) talking to the proxy for the token endpoint.
//
// The returned URL is a drop-in OIDC base URL for the gateway config:
// use proxyURL + "/realms/<realm>" as the issuer.
func StartIssuerRewriteProxy(t *testing.T, keycloakURL, issuerHost string) string {
	t.Helper()

	upstream := strings.TrimSuffix(keycloakURL, "/")
	client := &http.Client{Timeout: 15 * time.Second}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "proxy read error", http.StatusBadGateway)
			return
		}
		_ = r.Body.Close()

		outReq, err := http.NewRequestWithContext(
			r.Context(), r.Method, upstream+r.URL.RequestURI(), strings.NewReader(string(body)))
		if err != nil {
			http.Error(w, "proxy request error", http.StatusBadGateway)
			return
		}
		for k, vv := range r.Header {
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
		// Present the backend-expected issuer host to Keycloak.
		outReq.Host = issuerHost

		resp, err := client.Do(outReq)
		if err != nil {
			http.Error(w, "proxy upstream error: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "proxy response read error", http.StatusBadGateway)
			return
		}

		// Keep discovery/token endpoints pointing at this proxy.
		proxyURL := "http://" + r.Host
		rewritten := strings.ReplaceAll(string(respBody), "http://"+issuerHost, proxyURL)

		for k, vv := range resp.Header {
			if strings.EqualFold(k, "Content-Length") {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write([]byte(rewritten))
	}))
	t.Cleanup(server.Close)

	return server.URL
}

// VaultIssuedClientCert holds file paths of a Vault-PKI-issued client
// certificate written to a temp dir cleaned up with the test.
type VaultIssuedClientCert struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// IssueVaultClientCert issues a client certificate from the live Vault PKI
// using the given role (EKU clientAuth for the compose client-role) and
// writes cert/key/CA PEM files into a test temp dir.
func IssueVaultClientCert(
	t *testing.T, setup *VaultTestSetup, role, commonName string,
) *VaultIssuedClientCert {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	path := fmt.Sprintf("%s/issue/%s", setup.PKIMount, role)
	secret, err := setup.Client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"common_name": commonName,
		"ttl":         "1h",
	})
	if err != nil {
		t.Fatalf("failed to issue client certificate from Vault role %s: %v", role, err)
	}
	if secret == nil || secret.Data == nil {
		t.Fatalf("no certificate data returned from Vault role %s", role)
	}

	certPEM, _ := secret.Data["certificate"].(string)
	keyPEM, _ := secret.Data["private_key"].(string)
	caPEM, _ := secret.Data["issuing_ca"].(string)
	if certPEM == "" || keyPEM == "" || caPEM == "" {
		t.Fatalf("incomplete certificate data from Vault role %s", role)
	}

	dir := t.TempDir()
	out := &VaultIssuedClientCert{
		CertFile: dir + "/client.crt",
		KeyFile:  dir + "/client.key",
		CAFile:   dir + "/ca.crt",
	}
	if err := os.WriteFile(out.CertFile, []byte(certPEM), 0o600); err != nil {
		t.Fatalf("failed to write client cert: %v", err)
	}
	if err := os.WriteFile(out.KeyFile, []byte(keyPEM), 0o600); err != nil {
		t.Fatalf("failed to write client key: %v", err)
	}
	if err := os.WriteFile(out.CAFile, []byte(caPEM), 0o600); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}
	return out
}

// NewInternalVaultClient creates and authenticates an internal vault.Client
// against the live test Vault (token auth).
func NewInternalVaultClient(t *testing.T) internalvault.Client {
	t.Helper()

	cfg := GetVaultTestConfig()
	client, err := internalvault.New(&internalvault.Config{
		Enabled:    true,
		Address:    cfg.Address,
		AuthMethod: internalvault.AuthMethodToken,
		Token:      cfg.Token,
	}, observability.NopLogger())
	if err != nil {
		t.Fatalf("failed to create internal vault client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Authenticate(ctx); err != nil {
		_ = client.Close()
		t.Fatalf("failed to authenticate internal vault client: %v", err)
	}

	t.Cleanup(func() { _ = client.Close() })
	return client
}

// StartGatewayWithConfigAndVault starts an HTTP gateway like
// StartGatewayWithConfig but wires the Vault client into the backend
// registry, enabling Vault-backed backend auth providers (mTLS certs, KV
// credentials, OIDC secrets) exactly as cmd/gateway does.
func StartGatewayWithConfigAndVault(
	ctx context.Context,
	cfg *config.GatewayConfig,
	vaultClient internalvault.Client,
) (*GatewayInstance, error) {
	logger := observability.NopLogger()

	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		return nil, fmt.Errorf("failed to load routes: %w", err)
	}

	registryOpts := []backend.RegistryOption{}
	if vaultClient != nil {
		registryOpts = append(registryOpts, backend.WithRegistryVaultClient(vaultClient))
	}
	registry := backend.NewRegistry(logger, registryOpts...)
	if err := registry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		return nil, fmt.Errorf("failed to load backends: %w", err)
	}
	if err := registry.StartAll(ctx); err != nil {
		return nil, fmt.Errorf("failed to start backends: %w", err)
	}

	p := proxy.NewReverseProxy(r, registry,
		proxy.WithProxyLogger(logger),
		proxy.WithWebSocketConfig(cfg.Spec.WebSocket),
	)

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(p),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gateway: %w", err)
	}
	if err := gw.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start gateway: %w", err)
	}

	port := 8080
	if len(cfg.Spec.Listeners) > 0 {
		port = cfg.Spec.Listeners[0].Port
	}

	return &GatewayInstance{
		Gateway:  gw,
		Config:   cfg,
		Router:   r,
		Registry: registry,
		Proxy:    p,
		BaseURL:  fmt.Sprintf("http://127.0.0.1:%d", port),
	}, nil
}

// StartGRPCGatewayWithBackends starts a gRPC gateway with a backend registry
// built from cfg.Spec.GRPCBackends (per-backend TLS and backend-auth
// providers included), mirroring the production wiring in cmd/gateway.
// vaultClient may be nil when no Vault-backed features are used.
func StartGRPCGatewayWithBackends(
	ctx context.Context,
	cfg *config.GatewayConfig,
	vaultClient internalvault.Client,
) (*GRPCGatewayInstance, error) {
	logger := observability.NopLogger()

	var grpcListenerCfg *config.Listener
	for i := range cfg.Spec.Listeners {
		if cfg.Spec.Listeners[i].Protocol == config.ProtocolGRPC {
			grpcListenerCfg = &cfg.Spec.Listeners[i]
			break
		}
	}
	if grpcListenerCfg == nil {
		return nil, fmt.Errorf("no gRPC listener found in configuration")
	}

	grpcRouter := grpcrouter.New()
	if err := grpcRouter.LoadRoutes(cfg.Spec.GRPCRoutes); err != nil {
		return nil, fmt.Errorf("failed to load gRPC routes: %w", err)
	}

	// Build the backend registry from the gRPC backend specs the same way
	// cmd/gateway does (GRPCBackendToBackend conversion).
	registryOpts := []backend.RegistryOption{}
	if vaultClient != nil {
		registryOpts = append(registryOpts, backend.WithRegistryVaultClient(vaultClient))
	}
	registry := backend.NewRegistry(logger, registryOpts...)

	backends := make([]config.Backend, 0, len(cfg.Spec.GRPCBackends))
	for _, gb := range cfg.Spec.GRPCBackends {
		backends = append(backends, config.GRPCBackendToBackend(gb))
	}
	if err := registry.LoadFromConfig(backends); err != nil {
		return nil, fmt.Errorf("failed to load gRPC backends: %w", err)
	}
	if err := registry.StartAll(ctx); err != nil {
		return nil, fmt.Errorf("failed to start gRPC backends: %w", err)
	}

	listenerOpts := []gateway.GRPCListenerOption{
		gateway.WithGRPCListenerLogger(logger),
		gateway.WithGRPCRouter(grpcRouter),
		gateway.WithGRPCBackendRegistry(registry),
	}
	if vaultClient != nil {
		listenerOpts = append(listenerOpts, gateway.WithGRPCVaultClient(vaultClient))
	}

	listener, err := gateway.NewGRPCListener(*grpcListenerCfg, listenerOpts...)
	if err != nil {
		_ = registry.StopAll(ctx)
		return nil, fmt.Errorf("failed to create gRPC listener: %w", err)
	}
	if err := listener.Start(ctx); err != nil {
		_ = registry.StopAll(ctx)
		return nil, fmt.Errorf("failed to start gRPC listener: %w", err)
	}

	return &GRPCGatewayInstance{
		Config:   cfg,
		Router:   grpcRouter,
		Proxy:    listener.Proxy(),
		Server:   listener.Server(),
		Address:  listener.Address(),
		Listener: listener,
		Registry: registry,
	}, nil
}

// TLSClientForFiles builds a client tls.Config from PEM files (client cert +
// CA), suitable for direct verification probes against mTLS backends.
func TLSClientForFiles(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 -- test helper reading its own temp files
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA PEM from %s", caFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// --- Minimal protobuf wire helpers for api.v1.TestService ---
//
// The live grpc-example backends implement api.v1.TestService (see
// test/performance/proto/test_service.proto). The tests proxy raw frames
// through the gateway, so a tiny hand-rolled protobuf encoder/decoder
// (varint + length-delimited fields only) avoids code generation.

// RawFrame is a raw protobuf payload passed through RawProtoCodec.
type RawFrame struct {
	Payload []byte
}

// RawProtoCodec is a grpc codec that passes pre-marshaled protobuf frames
// through unchanged while advertising the standard "proto" codec name.
type RawProtoCodec struct{}

// Marshal returns the raw payload bytes.
func (RawProtoCodec) Marshal(v interface{}) ([]byte, error) {
	f, ok := v.(*RawFrame)
	if !ok {
		return nil, fmt.Errorf("RawProtoCodec: unsupported type %T", v)
	}
	return f.Payload, nil
}

// Unmarshal stores the raw bytes into the frame.
func (RawProtoCodec) Unmarshal(data []byte, v interface{}) error {
	f, ok := v.(*RawFrame)
	if !ok {
		return fmt.Errorf("RawProtoCodec: unsupported type %T", v)
	}
	f.Payload = data
	return nil
}

// Name returns the standard proto codec name so backends accept the frames.
func (RawProtoCodec) Name() string { return "proto" }

// appendVarintField appends a protobuf varint field (wire type 0).
func appendVarintField(b []byte, fieldNum int, value uint64) []byte {
	b = binary.AppendUvarint(b, uint64(fieldNum)<<3|0)
	return binary.AppendUvarint(b, value)
}

// appendStringField appends a protobuf length-delimited field (wire type 2).
func appendStringField(b []byte, fieldNum int, value string) []byte {
	b = binary.AppendUvarint(b, uint64(fieldNum)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(value)))
	return append(b, value...)
}

// EncodeUnaryRequest encodes api.v1.UnaryRequest{message}.
func EncodeUnaryRequest(message string) []byte {
	return appendStringField(nil, 1, message)
}

// EncodeStreamRequest encodes api.v1.StreamRequest{count, interval_ms}.
func EncodeStreamRequest(count, intervalMs int) []byte {
	b := appendVarintField(nil, 1, uint64(count))
	return appendVarintField(b, 2, uint64(intervalMs))
}

// EncodeBidiRequest encodes api.v1.BidirectionalRequest{value, operation}.
func EncodeBidiRequest(value int, operation string) []byte {
	b := appendVarintField(nil, 1, uint64(value))
	return appendStringField(b, 2, operation)
}

// DecodedProtoMessage holds the scalar fields of a decoded protobuf message
// keyed by field number. Varint fields land in Varints, length-delimited
// fields in Strings.
type DecodedProtoMessage struct {
	Varints map[int]uint64
	Strings map[int]string
}

// DecodeProtoMessage decodes a protobuf message consisting of varint and
// length-delimited fields (sufficient for the api.v1.TestService responses).
func DecodeProtoMessage(data []byte) (*DecodedProtoMessage, error) {
	out := &DecodedProtoMessage{
		Varints: map[int]uint64{},
		Strings: map[int]string{},
	}
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, fmt.Errorf("invalid field key")
		}
		data = data[n:]
		fieldNum := int(key >> 3)
		switch key & 7 {
		case 0: // varint
			v, vn := binary.Uvarint(data)
			if vn <= 0 {
				return nil, fmt.Errorf("invalid varint for field %d", fieldNum)
			}
			data = data[vn:]
			out.Varints[fieldNum] = v
		case 2: // length-delimited
			l, ln := binary.Uvarint(data)
			if ln <= 0 || uint64(len(data)-ln) < l {
				return nil, fmt.Errorf("invalid length for field %d", fieldNum)
			}
			data = data[ln:]
			out.Strings[fieldNum] = string(data[:l])
			data = data[l:]
		default:
			return nil, fmt.Errorf("unsupported wire type %d for field %d", key&7, fieldNum)
		}
	}
	return out, nil
}
