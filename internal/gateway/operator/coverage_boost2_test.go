// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/vyrodovalexey/avapigw/internal/config"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// ============================================================================
// buildTLSConfig Coverage Tests - Cover cert/key loading and CA loading
// ============================================================================

// generateSelfSignedCert creates a self-signed certificate and key pair
// in the given directory and returns the paths.
func generateSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)
	certFile.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	err = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, err)
	keyFile.Close()

	return certPath, keyPath
}

// generateCACert creates a CA certificate in the given directory and returns the path.
func generateCACert(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.pem")
	caFile, err := os.Create(caPath)
	require.NoError(t, err)
	err = pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)
	caFile.Close()

	return caPath
}

func TestClient_buildTLSConfig_WithValidCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir)

	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:  true,
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	tlsConfig, err := client.buildTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig)
	assert.Len(t, tlsConfig.Certificates, 1)
}

func TestClient_buildTLSConfig_WithValidCA(t *testing.T) {
	dir := t.TempDir()
	caPath := generateCACert(t, dir)

	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled: true,
			CAFile:  caPath,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	tlsConfig, err := client.buildTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig)
	assert.NotNil(t, tlsConfig.RootCAs)
}

func TestClient_buildTLSConfig_WithCertKeyAndCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir)
	caPath := generateCACert(t, dir)

	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:    true,
			CertFile:   certPath,
			KeyFile:    keyPath,
			CAFile:     caPath,
			ServerName: "test-server",
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	tlsConfig, err := client.buildTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig)
	assert.Len(t, tlsConfig.Certificates, 1)
	assert.NotNil(t, tlsConfig.RootCAs)
	assert.Equal(t, "test-server", tlsConfig.ServerName)
}

func TestClient_buildTLSConfig_InvalidCertFile(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := generateSelfSignedCert(t, dir)

	// Create an invalid cert file
	invalidCertPath := filepath.Join(dir, "invalid_cert.pem")
	err := os.WriteFile(invalidCertPath, []byte("not a valid cert"), 0o600)
	require.NoError(t, err)

	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:  true,
			CertFile: invalidCertPath,
			KeyFile:  keyPath,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	_, err = client.buildTLSConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

func TestClient_buildTLSConfig_InvalidCAFile(t *testing.T) {
	dir := t.TempDir()

	// Create an invalid CA file
	invalidCAPath := filepath.Join(dir, "invalid_ca.pem")
	err := os.WriteFile(invalidCAPath, []byte("not a valid CA cert"), 0o600)
	require.NoError(t, err)

	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled: true,
			CAFile:  invalidCAPath,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	_, err = client.buildTLSConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestClient_buildTLSConfig_NonexistentCAFile(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled: true,
			CAFile:  "/nonexistent/ca.pem",
		},
	}

	// Validation will fail for nonexistent CA file
	_, err := NewClient(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "caFile not found")
}

// ============================================================================
// buildDialOptions with TLS Coverage Tests
// ============================================================================

func TestClient_buildDialOptions_WithTLS(t *testing.T) {
	dir := t.TempDir()
	caPath := generateCACert(t, dir)

	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:    true,
			CAFile:     caPath,
			ServerName: "test-server",
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	opts, err := client.buildDialOptions()
	require.NoError(t, err)
	// Should have keepalive + TLS credentials
	assert.Len(t, opts, 2)
}

func TestClient_buildDialOptions_TLSBuildError(t *testing.T) {
	dir := t.TempDir()

	// Create an invalid CA file that exists but can't be parsed
	invalidCAPath := filepath.Join(dir, "bad_ca.pem")
	err := os.WriteFile(invalidCAPath, []byte("not a valid CA"), 0o600)
	require.NoError(t, err)

	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled: true,
			CAFile:  invalidCAPath,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	_, err = client.buildDialOptions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build TLS config")
}

// ============================================================================
// Connect with TLS Coverage Tests
// ============================================================================

func TestClient_Connect_WithTLSConfig(t *testing.T) {
	dir := t.TempDir()
	caPath := generateCACert(t, dir)

	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:            true,
			CAFile:             caPath,
			InsecureSkipVerify: true,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Connect should succeed (lazy connection with TLS)
	err = client.Connect(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, client.conn)
	assert.NotNil(t, client.client)

	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_Connect_WithTLSBuildError(t *testing.T) {
	dir := t.TempDir()

	// Create an invalid CA file
	invalidCAPath := filepath.Join(dir, "bad_ca.pem")
	err := os.WriteFile(invalidCAPath, []byte("not a valid CA"), 0o600)
	require.NoError(t, err)

	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled: true,
			CAFile:  invalidCAPath,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Connect should fail due to TLS build error
	err = client.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build dial options")
}

// ============================================================================
// Register with InitialConfig Coverage Tests
// ============================================================================

func TestClient_Register_WithInitialConfig(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.RegisterGatewayResponse{
			Success:           true,
			SessionId:         "test-session-initial",
			HeartbeatInterval: durationpb.New(30 * time.Second),
			InitialConfig: &operatorv1alpha1.ConfigurationSnapshot{
				Version:        "v1",
				TotalResources: 1,
			},
		}, nil,
	)

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	snapshotCalled := false
	client, err := NewClient(cfg, WithSnapshotHandler(func(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error {
		snapshotCalled = true
		return nil
	}))
	require.NoError(t, err)

	// Connect
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Register - should apply initial config
	err = client.register(context.Background())
	require.NoError(t, err)

	assert.True(t, snapshotCalled, "snapshot handler should be called for initial config")
	assert.Equal(t, "test-session-initial", client.SessionID())

	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_Register_WithInitialConfigError(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.RegisterGatewayResponse{
			Success:           true,
			SessionId:         "test-session-init-err",
			HeartbeatInterval: durationpb.New(30 * time.Second),
			InitialConfig: &operatorv1alpha1.ConfigurationSnapshot{
				Version:        "v1",
				TotalResources: 1,
			},
		}, nil,
	)

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg, WithSnapshotHandler(func(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error {
		return assert.AnError
	}))
	require.NoError(t, err)

	// Connect
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Register - should succeed even if initial config fails
	err = client.register(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "test-session-init-err", client.SessionID())

	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_Register_RPCError(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
		nil, assert.AnError,
	)

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Connect
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Register - should fail
	err = client.register(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRegistrationFailed)

	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// HandleUpdate with FullSync but nil snapshot
// ============================================================================

func TestClient_HandleUpdate_FullSync_NilSnapshot(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{Received: true}, nil,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Full sync with nil snapshot - should succeed without calling snapshot handler
	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC,
		Version:  "v1",
		Sequence: 1,
		Snapshot: nil, // nil snapshot
	}

	err = client.handleUpdate(context.Background(), update)
	require.NoError(t, err)

	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// HandleUpdate with error in snapshot handler
// ============================================================================

func TestClient_HandleUpdate_FullSync_SnapshotError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{Received: true}, nil,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg, WithSnapshotHandler(func(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error {
		return assert.AnError
	}))
	require.NoError(t, err)

	err = client.Connect(context.Background())
	require.NoError(t, err)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC,
		Version:  "v1",
		Sequence: 1,
		Snapshot: &operatorv1alpha1.ConfigurationSnapshot{
			Version: "v1",
		},
	}

	err = client.handleUpdate(context.Background(), update)
	require.Error(t, err)

	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// HandleUpdate with timestamp
// ============================================================================

func TestClient_HandleUpdate_WithTimestamp(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{Received: true}, nil,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	err = client.Connect(context.Background())
	require.NoError(t, err)

	specificTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:      operatorv1alpha1.UpdateType_UPDATE_TYPE_HEARTBEAT,
		Version:   "v1",
		Sequence:  1,
		Timestamp: timestamppb.New(specificTime),
	}

	err = client.handleUpdate(context.Background(), update)
	require.NoError(t, err)

	// Verify tracking was updated
	client.mu.RLock()
	assert.Equal(t, "v1", client.lastAppliedVersion)
	assert.Equal(t, int64(1), client.lastAppliedSequence)
	client.mu.RUnlock()

	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// sendAcknowledgment error path
// ============================================================================

func TestClient_sendAcknowledgment_Error(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		nil, assert.AnError,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	err = client.Connect(context.Background())
	require.NoError(t, err)

	client.mu.Lock()
	client.sessionID = "test-session"
	client.mu.Unlock()

	// Should not panic on error
	client.sendAcknowledgment(context.Background(), "v1", true, "", time.Second)

	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// GraphQL Handler Coverage Tests
// ============================================================================

func TestConfigHandler_HandleUpdate_GraphQLRouteAdd(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	route := config.GraphQLRoute{
		Name:       "test-graphql-route",
		DepthLimit: 10,
	}
	routeJSON, err := json.Marshal(route)
	require.NoError(t, err)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-graphql-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}

	err = handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)

	// Verify state
	_, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	assert.Len(t, graphqlRoutes, 1)
	assert.Equal(t, "test-graphql-route", graphqlRoutes[0].Name)

	applier.AssertExpectations(t)
}

func TestConfigHandler_HandleUpdate_GraphQLRouteModify(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	// Add initial route
	route := config.GraphQLRoute{
		Name:       "test-graphql-route",
		DepthLimit: 10,
	}
	routeJSON, _ := json.Marshal(route)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-graphql-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}
	err := handler.HandleUpdate(context.Background(), addUpdate)
	require.NoError(t, err)

	// Modify route
	route.DepthLimit = 20
	routeJSON, _ = json.Marshal(route)

	modifyUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_MODIFIED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-graphql-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}
	err = handler.HandleUpdate(context.Background(), modifyUpdate)
	require.NoError(t, err)

	_, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	assert.Len(t, graphqlRoutes, 1)
	assert.Equal(t, 20, graphqlRoutes[0].DepthLimit)
}

func TestConfigHandler_HandleUpdate_GraphQLRouteDelete(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	// Add route first
	route := config.GraphQLRoute{
		Name:       "test-graphql-route",
		DepthLimit: 10,
	}
	routeJSON, _ := json.Marshal(route)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-graphql-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}
	err := handler.HandleUpdate(context.Background(), addUpdate)
	require.NoError(t, err)

	// Delete route
	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}
	err = handler.HandleUpdate(context.Background(), deleteUpdate)
	require.NoError(t, err)

	_, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	assert.Len(t, graphqlRoutes, 0)
}

func TestConfigHandler_HandleUpdate_GraphQLBackendAdd(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	backend := config.GraphQLBackend{
		Name: "test-graphql-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	}
	backendJSON, err := json.Marshal(backend)
	require.NoError(t, err)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
			Name:      "test-graphql-backend",
			Namespace: "default",
			SpecJson:  backendJSON,
		},
	}

	err = handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)

	_, _, _, _, _, graphqlBackends := handler.GetCurrentState()
	assert.Len(t, graphqlBackends, 1)
	assert.Equal(t, "test-graphql-backend", graphqlBackends[0].Name)

	applier.AssertExpectations(t)
}

func TestConfigHandler_HandleUpdate_GraphQLBackendDelete(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	// Add backend first
	backend := config.GraphQLBackend{
		Name: "test-graphql-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	}
	backendJSON, _ := json.Marshal(backend)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
			Name:      "test-graphql-backend",
			Namespace: "default",
			SpecJson:  backendJSON,
		},
	}
	err := handler.HandleUpdate(context.Background(), addUpdate)
	require.NoError(t, err)

	// Delete backend
	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
			Name:      "test-graphql-backend",
			Namespace: "default",
		},
	}
	err = handler.HandleUpdate(context.Background(), deleteUpdate)
	require.NoError(t, err)

	_, _, _, _, _, graphqlBackends := handler.GetCurrentState()
	assert.Len(t, graphqlBackends, 0)
}

// ============================================================================
// GraphQL Handler Error Path Tests
// ============================================================================

func TestConfigHandler_HandleUpdate_GraphQLRouteApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLRoutes", mock.Anything, mock.Anything).Return(assert.AnError)

	handler := NewConfigHandler(applier)

	route := config.GraphQLRoute{Name: "test-graphql-route", DepthLimit: 10}
	routeJSON, _ := json.Marshal(route)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-graphql-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply GraphQL routes")
}

func TestConfigHandler_HandleUpdate_GraphQLBackendApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLBackends", mock.Anything, mock.Anything).Return(assert.AnError)

	handler := NewConfigHandler(applier)

	backend := config.GraphQLBackend{Name: "test-graphql-backend"}
	backendJSON, _ := json.Marshal(backend)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
			Name:      "test-graphql-backend",
			Namespace: "default",
			SpecJson:  backendJSON,
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply GraphQL backends")
}

func TestConfigHandler_HandleUpdate_InvalidGraphQLRouteJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-graphql-route",
			Namespace: "default",
			SpecJson:  []byte("invalid json"),
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal GraphQL route spec")
}

func TestConfigHandler_HandleUpdate_InvalidGraphQLBackendJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
			Name:      "test-graphql-backend",
			Namespace: "default",
			SpecJson:  []byte("invalid json"),
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal GraphQL backend spec")
}

// ============================================================================
// GraphQL Delete Error Path Tests
// ============================================================================

func TestConfigHandler_handleGraphQLRouteDelete_ApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLRoutes", mock.Anything, mock.Anything).Return(nil).Once()
	applier.On("ApplyGraphQLRoutes", mock.Anything, mock.Anything).Return(assert.AnError).Once()

	handler := NewConfigHandler(applier)

	// Add route first
	route := config.GraphQLRoute{Name: "test-graphql-route", DepthLimit: 10}
	routeJSON, _ := json.Marshal(route)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-graphql-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Delete - should fail
	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-graphql-route",
			Namespace: "default",
		},
	}

	err := handler.HandleUpdate(context.Background(), deleteUpdate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply GraphQL routes after deletion")
}

func TestConfigHandler_handleGraphQLBackendDelete_ApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLBackends", mock.Anything, mock.Anything).Return(nil).Once()
	applier.On("ApplyGraphQLBackends", mock.Anything, mock.Anything).Return(assert.AnError).Once()

	handler := NewConfigHandler(applier)

	// Add backend first
	backend := config.GraphQLBackend{Name: "test-graphql-backend"}
	backendJSON, _ := json.Marshal(backend)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
			Name:      "test-graphql-backend",
			Namespace: "default",
			SpecJson:  backendJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Delete - should fail
	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
			Name:      "test-graphql-backend",
			Namespace: "default",
		},
	}

	err := handler.HandleUpdate(context.Background(), deleteUpdate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply GraphQL backends after deletion")
}

// ============================================================================
// HandleSnapshot with GraphQL resources
// ============================================================================

func TestConfigHandler_HandleSnapshot_WithGraphQLResources(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	route := config.GraphQLRoute{Name: "gql-route", DepthLimit: 10}
	routeJSON, _ := json.Marshal(route)

	backend := config.GraphQLBackend{
		Name: "gql-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	}
	backendJSON, _ := json.Marshal(backend)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 2,
		GraphqlRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
				Name:      "gql-route",
				Namespace: "default",
				SpecJson:  routeJSON,
			},
		},
		GraphqlBackends: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
				Name:      "gql-backend",
				Namespace: "default",
				SpecJson:  backendJSON,
			},
		},
	}

	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	_, _, _, _, graphqlRoutes, graphqlBackends := handler.GetCurrentState()
	assert.Len(t, graphqlRoutes, 1)
	assert.Len(t, graphqlBackends, 1)
	assert.Equal(t, "gql-route", graphqlRoutes[0].Name)
	assert.Equal(t, "gql-backend", graphqlBackends[0].Name)
}

func TestConfigHandler_HandleSnapshot_InvalidGraphQLRouteJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		GraphqlRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
				Name:      "invalid-gql-route",
				Namespace: "default",
				SpecJson:  []byte("invalid json"),
			},
		},
	}

	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	_, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	assert.Len(t, graphqlRoutes, 0)
}

func TestConfigHandler_HandleSnapshot_InvalidGraphQLBackendJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		GraphqlBackends: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
				Name:      "invalid-gql-backend",
				Namespace: "default",
				SpecJson:  []byte("invalid json"),
			},
		},
	}

	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	_, _, _, _, _, graphqlBackends := handler.GetCurrentState()
	assert.Len(t, graphqlBackends, 0)
}

// ============================================================================
// handleDelete for GraphQL types
// ============================================================================

func TestConfigHandler_handleDelete_GraphQLRoute(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	// Add a GraphQL route
	route := config.GraphQLRoute{Name: "test-gql-route", DepthLimit: 10}
	routeJSON, _ := json.Marshal(route)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "test-gql-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Delete using handleDelete directly
	resource := &operatorv1alpha1.ConfigurationResource{
		Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
		Name:      "test-gql-route",
		Namespace: "default",
	}

	err := handler.handleDelete(context.Background(), resource, "default/test-gql-route")
	require.NoError(t, err)

	_, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	assert.Len(t, graphqlRoutes, 0)
}

func TestConfigHandler_handleDelete_GraphQLBackend(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	// Add a GraphQL backend
	backend := config.GraphQLBackend{Name: "test-gql-backend"}
	backendJSON, _ := json.Marshal(backend)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
			Name:      "test-gql-backend",
			Namespace: "default",
			SpecJson:  backendJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Delete using handleDelete directly
	resource := &operatorv1alpha1.ConfigurationResource{
		Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
		Name:      "test-gql-backend",
		Namespace: "default",
	}

	err := handler.handleDelete(context.Background(), resource, "default/test-gql-backend")
	require.NoError(t, err)

	_, _, _, _, _, graphqlBackends := handler.GetCurrentState()
	assert.Len(t, graphqlBackends, 0)
}

// ============================================================================
// handleAddOrModify for GraphQL types
// ============================================================================

func TestConfigHandler_handleAddOrModify_GraphQLRoute(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	route := config.GraphQLRoute{Name: "test-gql-route", DepthLimit: 10}
	routeJSON, _ := json.Marshal(route)

	resource := &operatorv1alpha1.ConfigurationResource{
		Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
		Name:      "test-gql-route",
		Namespace: "default",
		SpecJson:  routeJSON,
	}

	err := handler.handleAddOrModify(context.Background(), resource, "default/test-gql-route")
	require.NoError(t, err)

	_, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	assert.Len(t, graphqlRoutes, 1)
}

func TestConfigHandler_handleAddOrModify_GraphQLBackend(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGraphQLBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	backend := config.GraphQLBackend{Name: "test-gql-backend"}
	backendJSON, _ := json.Marshal(backend)

	resource := &operatorv1alpha1.ConfigurationResource{
		Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_BACKEND,
		Name:      "test-gql-backend",
		Namespace: "default",
		SpecJson:  backendJSON,
	}

	err := handler.handleAddOrModify(context.Background(), resource, "default/test-gql-backend")
	require.NoError(t, err)

	_, _, _, _, _, graphqlBackends := handler.GetCurrentState()
	assert.Len(t, graphqlBackends, 1)
}

// ============================================================================
// HandleUpdate with nil handler for config update
// ============================================================================

func TestClient_HandleUpdate_NoHandler(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{Received: true}, nil,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	// No config update handler set
	client, err := NewClient(cfg)
	require.NoError(t, err)

	err = client.Connect(context.Background())
	require.NoError(t, err)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
	}

	// Should succeed even without handler
	err = client.handleUpdate(context.Background(), update)
	require.NoError(t, err)

	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// Start with Connect (no pre-existing connection)
// ============================================================================

func TestClient_Start_WithConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.RegisterGatewayResponse{
			Success:           true,
			SessionId:         "test-session-connect",
			HeartbeatInterval: durationpb.New(30 * time.Second),
		}, nil,
	)
	mockServer.On("StreamConfiguration", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockServer.On("Heartbeat", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.HeartbeatResponse{Acknowledged: true}, nil,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:           true,
		Address:           listener.Addr().String(),
		GatewayName:       "test-gateway",
		GatewayNamespace:  "default",
		HeartbeatInterval: 100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Don't pre-connect - Start should call Connect
	assert.Nil(t, client.conn)

	err = client.Start(context.Background())
	require.NoError(t, err)

	assert.True(t, client.started.Load())
	assert.True(t, client.IsConnected())
	assert.Equal(t, "test-session-connect", client.SessionID())

	// Stop
	err = client.Stop()
	require.NoError(t, err)
}

// ============================================================================
// BuildGatewayStatus with zero lastConfigApplied
// ============================================================================

func TestClient_BuildGatewayStatus_ZeroLastConfigApplied(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	client.startTime = time.Now().Add(-1 * time.Hour)

	// Zero time for lastConfigApplied
	status := client.buildGatewayStatus(time.Time{})
	assert.Equal(t, operatorv1alpha1.HealthState_HEALTH_STATE_HEALTHY, status.Health)
	assert.NotNil(t, status.Uptime)
	assert.Nil(t, status.LastConfigApplied) // Should be nil for zero time
}
