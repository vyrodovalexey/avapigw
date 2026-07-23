//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the API Gateway.
//
// GraphQL-over-WebSocket E2E tests verify the full subscription user
// journey through a REAL running gateway (listener -> gin engine ->
// GraphQLHandler -> subscription relay): the client POSTs queries to
// /graphql and opens graphql-transport-ws subscriptions on the same
// endpoint.
//
// NOTE ON THE LIVE BACKEND: the reference restapi-example image does NOT
// serve /graphql (verified live: POST and WS upgrade return 404), so the
// gateway is exercised against an in-process mock backend implementing the
// graphql-transport-ws protocol — the documented fallback that still runs
// the gateway's complete graphql-ws pipeline end-to-end.
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// gqlWSTestPort is the listener port base for GraphQL-WS e2e gateways.
const gqlWSTestPort = 18451

// startGraphQLWSGateway starts a full gateway with the embedded GraphQL
// pipeline against a graphql-ws mock backend and waits for readiness.
func startGraphQLWSGateway(
	t *testing.T, ctx context.Context, port int, origins []string,
) (*helpers.GraphQLGatewayInstance, *helpers.MockGraphQLWSBackend) {
	t.Helper()

	mock := helpers.NewMockGraphQLWSBackend(t)
	backendInfo := helpers.GetGraphQLBackendInfo(mock.Listener.Addr().String())

	cfg := helpers.BuildGraphQLGatewayConfig(port, nil, backendInfo.Host, backendInfo.Port, origins)
	gi, err := helpers.StartGraphQLGatewayWithConfig(ctx, cfg)
	require.NoError(t, err, "Failed to start GraphQL gateway")
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = gi.Stop(stopCtx)
	})

	// /graphql with an empty body answers 400 (parse error) once the
	// listener is up — sufficient as a readiness signal (<500).
	err = helpers.WaitForReady(gi.BaseURL+"/graphql", 10*time.Second)
	require.NoError(t, err, "GraphQL gateway did not become ready")

	return gi, mock
}

// TestE2E_GraphQLWS_QueryAndSubscription runs the primary user journey:
// query over HTTP, then a subscription over the graphql-ws WebSocket, both
// through the same running gateway endpoint.
func TestE2E_GraphQLWS_QueryAndSubscription(t *testing.T) {
	ctx := context.Background()
	gi, _ := startGraphQLWSGateway(t, ctx, gqlWSTestPort, nil)

	t.Run("HTTP query through gateway", func(t *testing.T) {
		resp, err := helpers.MakeGraphQLRequest(
			gi.BaseURL+"/graphql", `query { items { id name } }`, nil)
		require.NoError(t, err)

		gqlResp, err := helpers.ReadGraphQLResponse(resp)
		require.NoError(t, err)
		assert.Empty(t, gqlResp.Errors, "query must succeed through the gateway")
		assert.NotNil(t, gqlResp.Data)
	})

	t.Run("subscription lifecycle over ws through gateway", func(t *testing.T) {
		wsURL := strings.Replace(gi.BaseURL, "http://", "ws://", 1) + "/graphql"

		client, resp, err := helpers.DialGraphQLWS(nil, wsURL, nil)
		require.NoError(t, err, "graphql-ws upgrade through running gateway failed")
		defer client.Close()
		if resp != nil {
			defer resp.Body.Close()
			assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
		}

		_, err = client.InitHandshake(5 * time.Second)
		require.NoError(t, err, "connection_init/connection_ack must relay")

		subID := "e2e-sub-1"
		require.NoError(t, client.Subscribe(subID,
			`subscription { itemUpdated { id sequence } }`))

		payloads, terminal, err := client.CollectSubscription(subID, 3, 5*time.Second)
		require.NoError(t, err)
		assert.Equal(t, helpers.GQLWSMsgComplete, terminal)
		assert.Len(t, payloads, 3, "subscription must deliver all events")
		t.Logf("subscription delivered %d events, terminal=%s", len(payloads), terminal)
	})
}

// TestE2E_GraphQLWS_ConcurrentSubscriptions verifies multiple concurrent
// graphql-ws subscription tunnels through one running gateway.
func TestE2E_GraphQLWS_ConcurrentSubscriptions(t *testing.T) {
	ctx := context.Background()
	gi, _ := startGraphQLWSGateway(t, ctx, gqlWSTestPort+1, nil)

	wsURL := strings.Replace(gi.BaseURL, "http://", "ws://", 1) + "/graphql"

	const numSubs = 4
	var wg sync.WaitGroup
	var completed atomic.Int64

	for i := 0; i < numSubs; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			client, resp, err := helpers.DialGraphQLWS(nil, wsURL, nil)
			if err != nil {
				t.Logf("sub %d: dial failed: %v", id, err)
				return
			}
			defer client.Close()
			if resp != nil {
				resp.Body.Close()
			}

			if _, err := client.InitHandshake(5 * time.Second); err != nil {
				t.Logf("sub %d: init failed: %v", id, err)
				return
			}

			subID := fmt.Sprintf("conc-sub-%d", id)
			if err := client.Subscribe(subID,
				`subscription { itemUpdated { id } }`); err != nil {
				t.Logf("sub %d: subscribe failed: %v", id, err)
				return
			}

			payloads, terminal, err := client.CollectSubscription(subID, 3, 5*time.Second)
			if err != nil {
				t.Logf("sub %d: collect failed: %v", id, err)
				return
			}
			if terminal == helpers.GQLWSMsgComplete && len(payloads) == 3 {
				completed.Add(1)
			}
		}(i)
	}
	wg.Wait()

	assert.EqualValues(t, numSubs, completed.Load(),
		"all concurrent subscriptions must complete with full event streams")
}

// TestE2E_GraphQLWS_OriginPolicy verifies the CSWSH origin allowlist on the
// running gateway's graphql-ws upgrade (spec.websocket.allowedOrigins).
func TestE2E_GraphQLWS_OriginPolicy(t *testing.T) {
	ctx := context.Background()
	gi, _ := startGraphQLWSGateway(t, ctx, gqlWSTestPort+2,
		[]string{"https://app.example.com"})

	wsURL := strings.Replace(gi.BaseURL, "http://", "ws://", 1) + "/graphql"

	t.Run("allowed origin subscribes", func(t *testing.T) {
		header := http.Header{"Origin": []string{"https://app.example.com"}}
		client, resp, err := helpers.DialGraphQLWS(nil, wsURL, header)
		require.NoError(t, err)
		defer client.Close()
		if resp != nil {
			resp.Body.Close()
		}
		_, err = client.InitHandshake(5 * time.Second)
		require.NoError(t, err)
	})

	t.Run("disallowed origin rejected", func(t *testing.T) {
		header := http.Header{"Origin": []string{"https://evil.example.org"}}
		client, resp, err := helpers.DialGraphQLWS(nil, wsURL, header)
		if client != nil {
			client.Close()
		}
		require.Error(t, err, "disallowed origin must be rejected on upgrade")
		if resp != nil {
			defer resp.Body.Close()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	})
}

// TestE2E_GraphQLWS_ErrorPropagation verifies backend subscription errors
// reach the client through the running gateway.
func TestE2E_GraphQLWS_ErrorPropagation(t *testing.T) {
	ctx := context.Background()
	gi, _ := startGraphQLWSGateway(t, ctx, gqlWSTestPort+3, nil)

	wsURL := strings.Replace(gi.BaseURL, "http://", "ws://", 1) + "/graphql"
	client, resp, err := helpers.DialGraphQLWS(nil, wsURL, nil)
	require.NoError(t, err)
	defer client.Close()
	if resp != nil {
		resp.Body.Close()
	}

	_, err = client.InitHandshake(5 * time.Second)
	require.NoError(t, err)

	subID := "e2e-err-sub"
	require.NoError(t, client.Subscribe(subID, `subscription { failNow }`))

	payloads, terminal, err := client.CollectSubscription(subID, 1, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, helpers.GQLWSMsgError, terminal,
		"backend subscription error must relay to the client")
	assert.Empty(t, payloads)
}
