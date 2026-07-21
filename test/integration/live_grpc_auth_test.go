//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
//
// Live gRPC backend-auth tests drive a REAL gRPC gateway against the LIVE
// docker-compose auth backends:
//
//	grpc_3 (:8813)  mTLS  — gateway dials with Vault-PKI-issued client certs
//	grpc_4 (:8814)  OIDC  — gateway injects client_credentials tokens from
//	                        the live Keycloak backend-test realm
//
// Unary, SERVER STREAMING, and BIDI STREAMING all flow through the gateway
// (client -> gateway plaintext, gateway -> backend mTLS/OIDC). Tests skip
// cleanly when the environment is absent AND pre-flight the backend auth
// contract DIRECTLY (bypassing the gateway) with the exact material the
// gateway will use: pre-flight failure means environment drift (CA
// generation mismatch, image/auth-mode drift) and skips with a precise
// diagnostic; pre-flight success makes every gateway-path assertion STRICT.
package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// grpcTestServiceName is the live backend's test service.
const grpcTestServiceName = "api.v1.TestService"

// buildLiveGRPCGatewayConfig builds a gRPC gateway config with one route for
// api.v1.TestService to the named backend.
func buildLiveGRPCGatewayConfig(port int, backendCfg config.GRPCBackend) *config.GatewayConfig {
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "live-grpc-auth-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "grpc",
					Port:     port,
					Protocol: config.ProtocolGRPC,
					Bind:     "127.0.0.1",
					GRPC: &config.GRPCListenerConfig{
						MaxConcurrentStreams: 100,
						MaxRecvMsgSize:       4 * 1024 * 1024,
						MaxSendMsgSize:       4 * 1024 * 1024,
						HealthCheck:          true,
					},
				},
			},
			GRPCRoutes: []config.GRPCRoute{
				{
					Name: "live-test-service",
					Match: []config.GRPCRouteMatch{
						{Service: &config.StringMatch{Exact: grpcTestServiceName}},
					},
					Route: []config.RouteDestination{
						{
							// Destination host references the backend by NAME
							// so the director resolves TLS + auth from the
							// backend registry.
							Destination: config.Destination{
								Host: backendCfg.Name,
								Port: backendCfg.Hosts[0].Port,
							},
						},
					},
					Timeout: config.Duration(30 * time.Second),
				},
			},
			GRPCBackends: []config.GRPCBackend{backendCfg},
		},
	}
}

// dialGateway dials the gateway's plaintext gRPC listener.
func dialGateway(t *testing.T, ctx context.Context, address string) *grpc.ClientConn {
	t.Helper()

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "failed to dial gateway gRPC listener")
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// invokeUnaryThroughGateway performs a raw-codec Unary call and returns the
// decoded response.
func invokeUnaryThroughGateway(
	ctx context.Context, conn *grpc.ClientConn, message string,
) (*helpers.DecodedProtoMessage, error) {
	req := &helpers.RawFrame{Payload: helpers.EncodeUnaryRequest(message)}
	resp := &helpers.RawFrame{}

	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	err := conn.Invoke(callCtx, "/"+grpcTestServiceName+"/Unary", req, resp,
		grpc.ForceCodec(helpers.RawProtoCodec{}))
	if err != nil {
		return nil, err
	}
	return helpers.DecodeProtoMessage(resp.Payload)
}

// serverStreamThroughGateway runs a ServerStream call and returns the
// decoded messages.
func serverStreamThroughGateway(
	ctx context.Context, conn *grpc.ClientConn, count, intervalMs int,
) ([]*helpers.DecodedProtoMessage, error) {
	streamCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	desc := &grpc.StreamDesc{StreamName: "ServerStream", ServerStreams: true}
	stream, err := conn.NewStream(streamCtx, desc, "/"+grpcTestServiceName+"/ServerStream",
		grpc.ForceCodec(helpers.RawProtoCodec{}))
	if err != nil {
		return nil, fmt.Errorf("open server stream: %w", err)
	}

	if err := stream.SendMsg(&helpers.RawFrame{
		Payload: helpers.EncodeStreamRequest(count, intervalMs),
	}); err != nil {
		return nil, fmt.Errorf("send stream request: %w", err)
	}
	if err := stream.CloseSend(); err != nil {
		return nil, fmt.Errorf("close send: %w", err)
	}

	var messages []*helpers.DecodedProtoMessage
	for {
		frame := &helpers.RawFrame{}
		recvErr := stream.RecvMsg(frame)
		if errors.Is(recvErr, io.EOF) {
			return messages, nil
		}
		if recvErr != nil {
			return messages, recvErr
		}
		decoded, decErr := helpers.DecodeProtoMessage(frame.Payload)
		if decErr != nil {
			return messages, decErr
		}
		messages = append(messages, decoded)
	}
}

// bidiStreamThroughGateway sends values over a BidirectionalStream and
// returns the decoded responses.
func bidiStreamThroughGateway(
	ctx context.Context, conn *grpc.ClientConn, values []int, operation string,
) ([]*helpers.DecodedProtoMessage, error) {
	streamCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	desc := &grpc.StreamDesc{
		StreamName:    "BidirectionalStream",
		ServerStreams: true,
		ClientStreams: true,
	}
	stream, err := conn.NewStream(streamCtx, desc,
		"/"+grpcTestServiceName+"/BidirectionalStream",
		grpc.ForceCodec(helpers.RawProtoCodec{}))
	if err != nil {
		return nil, fmt.Errorf("open bidi stream: %w", err)
	}

	var responses []*helpers.DecodedProtoMessage
	for _, v := range values {
		if err := stream.SendMsg(&helpers.RawFrame{
			Payload: helpers.EncodeBidiRequest(v, operation),
		}); err != nil {
			return responses, fmt.Errorf("send bidi request: %w", err)
		}
		frame := &helpers.RawFrame{}
		if err := stream.RecvMsg(frame); err != nil {
			return responses, fmt.Errorf("recv bidi response: %w", err)
		}
		decoded, decErr := helpers.DecodeProtoMessage(frame.Payload)
		if decErr != nil {
			return responses, decErr
		}
		responses = append(responses, decoded)
	}
	if err := stream.CloseSend(); err != nil {
		return responses, fmt.Errorf("close send: %w", err)
	}
	// Drain the trailing EOF for a clean shutdown.
	frame := &helpers.RawFrame{}
	if err := stream.RecvMsg(frame); err != nil && !errors.Is(err, io.EOF) {
		return responses, err
	}
	return responses, nil
}

// warmUpGatewayJourney absorbs transient UNAVAILABLE errors on the FIRST
// gateway-path call (backend churn right after start) with a bounded retry
// (up to 5 attempts, ~2.5s backoff total). It never weakens assertions: the
// strict suite still asserts the final state afterwards.
func warmUpGatewayJourney(t *testing.T, ctx context.Context, conn *grpc.ClientConn) {
	t.Helper()

	const attempts = 5
	for attempt := 1; attempt <= attempts; attempt++ {
		_, err := invokeUnaryThroughGateway(ctx, conn, "warm-up")
		if err == nil {
			return
		}
		t.Logf("gateway journey warm-up attempt %d/%d failed: %v", attempt, attempts, err)
		if attempt < attempts {
			time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
		}
	}
}

// runGRPCStreamingSuite asserts Unary + ServerStream + Bidi through the
// gateway at the given address. Journey-critical checks use require so a
// success log can never follow a failed assertion.
func runGRPCStreamingSuite(t *testing.T, ctx context.Context, gatewayAddr string) {
	t.Helper()

	conn := dialGateway(t, ctx, gatewayAddr)
	warmUpGatewayJourney(t, ctx, conn)

	t.Run("unary through gateway", func(t *testing.T) {
		decoded, err := invokeUnaryThroughGateway(ctx, conn, "live-auth-unary")
		require.NoError(t, err, "unary call through gateway failed")
		require.Equal(t, "live-auth-unary", decoded.Strings[1],
			"backend must echo the unary message")
		require.NotZero(t, decoded.Varints[2], "timestamp must be set")
		t.Log("unary OK: message echoed through gateway")
	})

	t.Run("server streaming through gateway", func(t *testing.T) {
		const wantMessages = 4
		messages, err := serverStreamThroughGateway(ctx, conn, wantMessages, 20)
		require.NoError(t, err, "server stream through gateway failed")
		require.Len(t, messages, wantMessages,
			"backend must stream exactly the requested message count")
		for i, msg := range messages {
			require.EqualValues(t, i+1, msg.Varints[2],
				"stream sequence must be contiguous")
		}
		t.Logf("server streaming OK: %d messages relayed through gateway", len(messages))
	})

	t.Run("bidi streaming through gateway", func(t *testing.T) {
		values := []int{7, 21, 100}
		responses, err := bidiStreamThroughGateway(ctx, conn, values, "double")
		require.NoError(t, err, "bidi stream through gateway failed")
		require.Len(t, responses, len(values))
		for i, resp := range responses {
			require.EqualValues(t, values[i], resp.Varints[1],
				"original_value must echo the sent value")
			require.EqualValues(t, values[i]*2, resp.Varints[2],
				"transformed_value must be doubled")
			require.Equal(t, "double", resp.Strings[3])
		}
		t.Logf("bidi streaming OK: %d exchanges relayed through gateway", len(responses))
	})
}

// TestIntegration_LiveGRPCBackend_MTLS_VaultPKI verifies gateway grpcRoute
// -> grpc_3 with backend mTLS using a client certificate issued by the LIVE
// Vault PKI, covering unary + server streaming + bidi streaming.
func TestIntegration_LiveGRPCBackend_MTLS_VaultPKI(t *testing.T) {
	live := helpers.GetLiveAuthBackendConfig()
	helpers.SkipIfVaultUnavailable(t)
	helpers.SkipIfTCPUnreachable(t, live.MTLSGRPCAddr, "grpc_3 (mTLS)")

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	clientCert := helpers.IssueVaultClientCert(
		t, vaultSetup, live.VaultClientCertRole, "avapigw-live-grpc-client")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Pre-flight: prove grpc_3 accepts EXACTLY this material directly, so
	// a gateway-path failure below is a gateway bug, not environment drift.
	if pfErr := helpers.PreflightDirectGRPCMTLS(ctx, live.MTLSGRPCAddr, clientCert); pfErr != nil {
		t.Skipf("backend mTLS contract not satisfied: direct gRPC handshake failed (%v) — "+
			"CA generation mismatch, stale backend certs, or a non-mTLS service on the port "+
			"(run setup-vault.sh + make test-env-restart-auth-backends); environment drift; skipping", pfErr)
	}

	host, port := splitHostPortOrFatal(t, live.MTLSGRPCAddr)

	backendCfg := config.GRPCBackend{
		Name:  "grpc-mtls-backend",
		Hosts: []config.BackendHost{{Address: host, Port: port, Weight: 1}},
		TLS: &config.TLSConfig{
			Enabled:  true,
			Mode:     config.TLSModeMutual,
			CertFile: clientCert.CertFile,
			KeyFile:  clientCert.KeyFile,
			// The compose server cert (CN=grpc_3) carries SANs
			// localhost/127.0.0.1, so default hostname verification against
			// the dialed address passes.
			CAFile: clientCert.CAFile,
		},
	}

	gatewayPort, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	gi, err := helpers.StartGRPCGatewayWithBackends(
		ctx, buildLiveGRPCGatewayConfig(gatewayPort, backendCfg), nil)
	require.NoError(t, err, "failed to start gRPC gateway with mTLS backend")
	t.Cleanup(func() { _ = gi.Stop(ctx) })

	require.NoError(t, helpers.WaitForGRPCReady(gi.Address, 10*time.Second))

	runGRPCStreamingSuite(t, ctx, gi.Address)

	t.Run("without client cert the backend rejects the dial", func(t *testing.T) {
		noCert := backendCfg
		noCert.Name = "grpc-mtls-nocert"
		noCert.TLS = &config.TLSConfig{
			Enabled: true,
			Mode:    config.TLSModeSimple,
			CAFile:  clientCert.CAFile,
		}

		port2, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		gi2, err := helpers.StartGRPCGatewayWithBackends(
			ctx, buildLiveGRPCGatewayConfig(port2, noCert), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = gi2.Stop(ctx) })
		require.NoError(t, helpers.WaitForGRPCReady(gi2.Address, 10*time.Second))

		conn := dialGateway(t, ctx, gi2.Address)
		_, callErr := invokeUnaryThroughGateway(ctx, conn, "must-fail")
		require.Error(t, callErr,
			"backend must reject the gateway connection without a client cert")
		st, ok := status.FromError(callErr)
		require.True(t, ok)
		require.Equal(t, codes.Unavailable, st.Code(),
			"TLS rejection surfaces as UNAVAILABLE from the gateway")
		t.Logf("no-client-cert rejection (expected): %v", callErr)
	})
}

// TestIntegration_LiveGRPCBackend_OIDC_S2S verifies gateway grpcRoute ->
// grpc_4 with backend OIDC service-to-service auth (client_credentials
// against the LIVE Keycloak backend-test realm), covering unary + server
// streaming + bidi streaming.
//
// The issuer-rewrite proxy bridges the host.docker.internal DNS gap (see
// helpers.StartIssuerRewriteProxy).
func TestIntegration_LiveGRPCBackend_OIDC_S2S(t *testing.T) {
	live := helpers.GetLiveAuthBackendConfig()
	helpers.SkipIfKeycloakUnavailable(t)
	helpers.SkipIfKeycloakRealmMissing(t, live.KeycloakURL, live.BackendRealm)
	helpers.SkipIfTCPUnreachable(t, live.OIDCGRPCAddr, "grpc_4 (OIDC)")

	issuerProxy := helpers.StartIssuerRewriteProxy(t, live.KeycloakURL, live.BackendIssuerHost)
	issuerURL := fmt.Sprintf("%s/realms/%s", issuerProxy, live.BackendRealm)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Pre-flight the backend OIDC contract directly (bypassing the
	// gateway): no-token calls must be UNAUTHENTICATED and a live-minted
	// client_credentials token must be accepted.
	if pfErr := helpers.PreflightDirectGRPCUnauthenticated(ctx, live.OIDCGRPCAddr); pfErr != nil {
		t.Skipf("backend OIDC contract not satisfied: %v — "+
			"auth mode/image drift on grpc_4; environment drift; skipping", pfErr)
	}
	token, tokenErr := helpers.MintClientCredentialsToken(
		ctx, issuerURL, live.BackendClientID, live.BackendClientSecret)
	if tokenErr != nil {
		t.Skipf("backend OIDC contract not satisfied: cannot mint client_credentials token (%v) — "+
			"run test/docker-compose/scripts/setup-keycloak.sh; environment drift; skipping", tokenErr)
	}
	if pfErr := helpers.PreflightDirectGRPCAuthorized(ctx, live.OIDCGRPCAddr, token); pfErr != nil {
		t.Skipf("backend OIDC contract not satisfied: %v — "+
			"issuer/audience drift between Keycloak and grpc_4; environment drift; skipping", pfErr)
	}

	host, port := splitHostPortOrFatal(t, live.OIDCGRPCAddr)

	backendCfg := config.GRPCBackend{
		Name:  "grpc-oidc-backend",
		Hosts: []config.BackendHost{{Address: host, Port: port, Weight: 1}},
		Authentication: &config.BackendAuthConfig{
			Type: "jwt",
			JWT: &config.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &config.BackendOIDCConfig{
					IssuerURL:    issuerURL,
					ClientID:     live.BackendClientID,
					ClientSecret: live.BackendClientSecret,
				},
			},
		},
	}

	gatewayPort, err := helpers.GetFreeGRPCPort()
	require.NoError(t, err)

	gi, err := helpers.StartGRPCGatewayWithBackends(
		ctx, buildLiveGRPCGatewayConfig(gatewayPort, backendCfg), nil)
	require.NoError(t, err, "failed to start gRPC gateway with OIDC backend auth")
	t.Cleanup(func() { _ = gi.Stop(ctx) })

	require.NoError(t, helpers.WaitForGRPCReady(gi.Address, 10*time.Second))

	runGRPCStreamingSuite(t, ctx, gi.Address)

	t.Run("without backend auth the backend rejects", func(t *testing.T) {
		noAuth := backendCfg
		noAuth.Name = "grpc-oidc-noauth"
		noAuth.Authentication = nil

		port2, err := helpers.GetFreeGRPCPort()
		require.NoError(t, err)

		gi2, err := helpers.StartGRPCGatewayWithBackends(
			ctx, buildLiveGRPCGatewayConfig(port2, noAuth), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = gi2.Stop(ctx) })
		require.NoError(t, helpers.WaitForGRPCReady(gi2.Address, 10*time.Second))

		conn := dialGateway(t, ctx, gi2.Address)
		_, callErr := invokeUnaryThroughGateway(ctx, conn, "must-fail")
		require.Error(t, callErr,
			"backend must reject calls without an OIDC token")
		st, ok := status.FromError(callErr)
		require.True(t, ok)
		require.Equal(t, codes.Unauthenticated, st.Code(),
			"missing token must surface as UNAUTHENTICATED")
		t.Logf("no-token rejection (expected): %v", callErr)
	})
}
