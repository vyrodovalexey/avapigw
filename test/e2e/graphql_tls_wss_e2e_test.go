//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the API Gateway.
//
// TLS-GraphQL + WSS E2E tests verify the secure GraphQL user journey
// through a REAL gateway with an HTTPS listener: queries over HTTPS and
// graphql-transport-ws subscriptions over wss://, both TLS-terminated at
// the gateway and relayed to the backend GraphQL WebSocket.
//
// NOTE ON THE LIVE BACKEND: the reference restapi-example image does NOT
// serve /graphql (verified live), so the gateway targets an in-process
// graphql-ws mock backend — the documented fallback exercising the full
// TLS listener + GraphQL routing + subscription upgrade path.
package e2e

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// gqlTLSTestPort is the listener port base for TLS GraphQL e2e gateways.
// (18461-18445 are taken by the aggregate e2e suites.)
const gqlTLSTestPort = 18491

// startGraphQLTLSGateway starts a gateway with an HTTPS listener and the
// embedded GraphQL pipeline against a graphql-ws mock backend.
func startGraphQLTLSGateway(
	t *testing.T, ctx context.Context, port int, origins []string,
) (*helpers.GraphQLGatewayInstance, *helpers.TestCertificates) {
	t.Helper()

	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err, "Failed to generate test certificates")
	require.NoError(t, certs.WriteToFiles(), "Failed to write certificates")
	t.Cleanup(certs.Cleanup)

	mock := helpers.NewMockGraphQLWSBackend(t)
	backendInfo := helpers.GetGraphQLBackendInfo(mock.Listener.Addr().String())

	cfg := helpers.BuildGraphQLGatewayConfig(
		port, certs, backendInfo.Host, backendInfo.Port, origins)
	gi, err := helpers.StartGraphQLGatewayWithConfig(ctx, cfg)
	require.NoError(t, err, "Failed to start TLS GraphQL gateway")
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = gi.Stop(stopCtx)
	})

	// Readiness: /graphql with an empty POST body answers 400 over TLS.
	err = helpers.WaitForReadyTLS(gi.BaseURL+"/graphql", 10*time.Second, certs)
	require.NoError(t, err, "TLS GraphQL gateway did not become ready")

	return gi, certs
}

// TestE2E_GraphQLTLS_QueryOverHTTPS verifies GraphQL query routing through
// the HTTPS listener.
func TestE2E_GraphQLTLS_QueryOverHTTPS(t *testing.T) {
	ctx := context.Background()
	gi, certs := startGraphQLTLSGateway(t, ctx, gqlTLSTestPort, nil)

	client := helpers.HTTPSClientForCerts(certs)
	resp, err := client.Post(gi.BaseURL+"/graphql", "application/json",
		strings.NewReader(`{"query":"query { items { id name } }"}`))
	require.NoError(t, err, "HTTPS GraphQL query failed")

	gqlResp, err := helpers.ReadGraphQLResponse(resp)
	require.NoError(t, err)
	assert.Empty(t, gqlResp.Errors, "HTTPS query must succeed through the gateway")
	assert.NotNil(t, gqlResp.Data)
	t.Log("GraphQL query over HTTPS succeeded")
}

// TestE2E_GraphQLTLS_SubscriptionOverWSS verifies the full secure
// subscription journey: wss:// upgrade on the HTTPS listener, graphql-ws
// lifecycle relayed to the backend, TLS-verified transport.
func TestE2E_GraphQLTLS_SubscriptionOverWSS(t *testing.T) {
	ctx := context.Background()
	gi, certs := startGraphQLTLSGateway(t, ctx, gqlTLSTestPort+1, nil)

	wssURL := helpers.WSSURL(gi.BaseURL, "/graphql")
	t.Logf("Dialing subscription over TLS: %s", wssURL)

	client, resp, err := helpers.DialGraphQLWS(helpers.WSSDialer(certs), wssURL, nil)
	require.NoError(t, err, "graphql-ws upgrade over wss failed")
	defer client.Close()
	if resp != nil {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	}

	// The transport under the relay must be TLS.
	_, isTLS := client.Conn.UnderlyingConn().(*tls.Conn)
	assert.True(t, isTLS, "graphql-ws transport must be TLS")

	_, err = client.InitHandshake(5 * time.Second)
	require.NoError(t, err, "connection_init/ack must relay over wss")

	subID := "tls-sub-1"
	require.NoError(t, client.Subscribe(subID,
		`subscription { itemUpdated { id sequence } }`))

	payloads, terminal, err := client.CollectSubscription(subID, 3, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, helpers.GQLWSMsgComplete, terminal)
	assert.Len(t, payloads, 3, "wss subscription must deliver all events")
	t.Logf("wss subscription delivered %d events, terminal=%s", len(payloads), terminal)
}

// TestE2E_GraphQLTLS_WSSFailureModes verifies TLS trust and origin failures
// on the secure subscription path.
func TestE2E_GraphQLTLS_WSSFailureModes(t *testing.T) {
	ctx := context.Background()
	gi, certs := startGraphQLTLSGateway(t, ctx, gqlTLSTestPort+2,
		[]string{"https://app.example.com"})

	wssURL := helpers.WSSURL(gi.BaseURL, "/graphql")

	t.Run("untrusted CA fails wss handshake", func(t *testing.T) {
		dialer := &websocket.Dialer{
			HandshakeTimeout: 5 * time.Second,
			TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
		}
		client, resp, err := helpers.DialGraphQLWS(dialer, wssURL, nil)
		if client != nil {
			client.Close()
		}
		if resp != nil {
			resp.Body.Close()
		}
		require.Error(t, err, "untrusted certificate must fail the wss upgrade")
		assert.Contains(t, err.Error(), "certificate")
	})

	t.Run("disallowed origin rejected over wss", func(t *testing.T) {
		header := http.Header{"Origin": []string{"https://evil.example.org"}}
		client, resp, err := helpers.DialGraphQLWS(helpers.WSSDialer(certs), wssURL, header)
		if client != nil {
			client.Close()
		}
		require.Error(t, err, "disallowed origin must be rejected over wss")
		if resp != nil {
			defer resp.Body.Close()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	})

	t.Run("allowed origin subscribes over wss", func(t *testing.T) {
		header := http.Header{"Origin": []string{"https://app.example.com"}}
		client, resp, err := helpers.DialGraphQLWS(helpers.WSSDialer(certs), wssURL, header)
		require.NoError(t, err, "allowed origin must upgrade over wss")
		defer client.Close()
		if resp != nil {
			resp.Body.Close()
		}
		_, err = client.InitHandshake(5 * time.Second)
		require.NoError(t, err)
	})
}
