//go:build integration
// +build integration

// Package integration contains integration tests for the API Gateway.
//
// GraphQL-over-WebSocket subscription tests verify the gateway's graphql-ws
// (graphql-transport-ws) handling: the GraphQLHandler matches the upgrade
// request to a route, upgrades the client connection, dials the backend
// /graphql WebSocket, and relays protocol frames in both directions.
//
// NOTE ON THE LIVE BACKEND: the reference restapi-example image does NOT
// serve /graphql (verified live: POST and WS upgrade both return 404), so
// subscription relaying is exercised against an in-process mock backend
// implementing the graphql-transport-ws protocol. This is the documented
// fallback: the gateway's own graphql-ws pipeline (route match -> middleware
// -> upgrade -> relay) is fully exercised; only the terminal backend is
// simulated.
package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	graphqlproxy "github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// newGraphQLWSGatewayHandler builds the production GraphQLHandler wired to a
// router+proxy targeting the given backend, and serves it on an httptest
// server. Subscription origins are optional.
func newGraphQLWSGatewayHandler(
	t *testing.T, backendHost string, backendPort int, origins []string,
) *httptest.Server {
	t.Helper()

	logger := observability.NopLogger()

	rt := graphqlrouter.New(graphqlrouter.WithRouterLogger(logger))
	err := rt.LoadRoutes([]config.GraphQLRoute{
		{
			Name: "subscription-route",
			Match: []config.GraphQLRouteMatch{
				{Path: &config.StringMatch{Exact: "/graphql"}},
			},
			Route: []config.RouteDestination{
				{
					Destination: config.Destination{Host: backendHost, Port: backendPort},
					Weight:      100,
				},
			},
			Timeout: config.Duration(30 * time.Second),
		},
	})
	require.NoError(t, err)

	px := graphqlproxy.New(
		graphqlproxy.WithLogger(logger),
		graphqlproxy.WithTimeout(30*time.Second),
	)
	px.UpdateBackends([]config.GraphQLBackend{
		{
			Name: backendHost,
			Hosts: []config.BackendHost{
				{Address: backendHost, Port: backendPort},
			},
		},
	})
	t.Cleanup(func() { px.Close() })

	opts := []gateway.GraphQLHandlerOption{
		gateway.WithGraphQLHandlerLogger(logger),
	}
	if len(origins) > 0 {
		opts = append(opts, gateway.WithGraphQLHandlerSubscriptionOrigins(origins))
	}
	handler, err := gateway.NewGraphQLHandler(rt, px, opts...)
	require.NoError(t, err)
	t.Cleanup(handler.Close)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// wsURLFromHTTP rewrites an http:// URL to ws://.
func wsURLFromHTTP(httpURL string) string {
	return strings.Replace(httpURL, "http://", "ws://", 1)
}

// TestIntegration_GraphQLWS_SubscriptionLifecycle verifies the full
// graphql-transport-ws lifecycle through the gateway relay:
// connection_init -> connection_ack -> subscribe -> next xN -> complete.
func TestIntegration_GraphQLWS_SubscriptionLifecycle(t *testing.T) {
	mock := helpers.NewMockGraphQLWSBackend(t)
	backendInfo := helpers.GetGraphQLBackendInfo(mock.Listener.Addr().String())

	srv := newGraphQLWSGatewayHandler(t, backendInfo.Host, backendInfo.Port, nil)

	client, resp, err := helpers.DialGraphQLWS(nil, wsURLFromHTTP(srv.URL)+"/graphql", nil)
	require.NoError(t, err, "graphql-ws upgrade through gateway failed")
	defer client.Close()
	if resp != nil {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	}

	t.Run("connection init handshake", func(t *testing.T) {
		ack, ackErr := client.InitHandshake(5 * time.Second)
		require.NoError(t, ackErr, "connection_init must be answered with connection_ack")
		assert.Equal(t, helpers.GQLWSMsgConnectionAck, ack.Type)
		t.Log("connection_ack received through gateway relay")
	})

	t.Run("subscribe receives events and completion", func(t *testing.T) {
		subID := "sub-1"
		require.NoError(t, client.Subscribe(subID,
			`subscription { itemUpdated { id sequence } }`))

		payloads, terminal, collErr := client.CollectSubscription(subID, 3, 5*time.Second)
		require.NoError(t, collErr, "failed to collect subscription events")
		assert.Equal(t, helpers.GQLWSMsgComplete, terminal,
			"subscription must end with complete")
		require.Len(t, payloads, 3, "expected 3 next events")

		// Verify event payload shape survived the relay byte-for-byte.
		var first struct {
			Data struct {
				ItemUpdated struct {
					ID       string `json:"id"`
					Sequence int    `json:"sequence"`
				} `json:"itemUpdated"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(payloads[0], &first))
		assert.Equal(t, "1", first.Data.ItemUpdated.ID)
		assert.Equal(t, 0, first.Data.ItemUpdated.Sequence)
		t.Logf("received %d relayed events, terminal=%s", len(payloads), terminal)
	})

	t.Run("ping answered with pong through relay", func(t *testing.T) {
		require.NoError(t, client.Send(helpers.GraphQLWSMessage{Type: helpers.GQLWSMsgPing}))
		msg, recvErr := client.Recv(5 * time.Second)
		require.NoError(t, recvErr)
		assert.Equal(t, helpers.GQLWSMsgPong, msg.Type, "ping must be answered with pong")
	})
}

// TestIntegration_GraphQLWS_ErrorMessage verifies that a backend error
// message for a failing subscription is relayed to the client.
func TestIntegration_GraphQLWS_ErrorMessage(t *testing.T) {
	mock := helpers.NewMockGraphQLWSBackend(t)
	backendInfo := helpers.GetGraphQLBackendInfo(mock.Listener.Addr().String())

	srv := newGraphQLWSGatewayHandler(t, backendInfo.Host, backendInfo.Port, nil)

	client, resp, err := helpers.DialGraphQLWS(nil, wsURLFromHTTP(srv.URL)+"/graphql", nil)
	require.NoError(t, err)
	defer client.Close()
	if resp != nil {
		resp.Body.Close()
	}

	_, err = client.InitHandshake(5 * time.Second)
	require.NoError(t, err)

	subID := "sub-err"
	require.NoError(t, client.Subscribe(subID, `subscription { failNow }`))

	payloads, terminal, err := client.CollectSubscription(subID, 1, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, helpers.GQLWSMsgError, terminal,
		"failing subscription must terminate with an error message")
	assert.Empty(t, payloads, "no next events expected for failing subscription")
}

// TestIntegration_GraphQLWS_ProtocolNegotiation verifies the subprotocol
// path through the relay: the client requests graphql-transport-ws and the
// backend leg negotiates it (the client header is forwarded on the backend
// dial).
func TestIntegration_GraphQLWS_ProtocolNegotiation(t *testing.T) {
	// A protocol-recording backend: accepts the upgrade only when the
	// graphql-transport-ws subprotocol was requested, and echoes it.
	var requestedProtocols []string
	upgrader := websocket.Upgrader{
		Subprotocols: []string{helpers.GraphQLWSProtocol},
		CheckOrigin:  func(*http.Request) bool { return true },
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			http.NotFound(w, r)
			return
		}
		requestedProtocols = websocket.Subprotocols(r)
		conn, upErr := upgrader.Upgrade(w, r, nil)
		if upErr != nil {
			return
		}
		defer conn.Close()
		// Answer one init to keep the session alive briefly.
		var msg helpers.GraphQLWSMessage
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := conn.ReadJSON(&msg); err == nil && msg.Type == helpers.GQLWSMsgConnectionInit {
			_ = conn.WriteJSON(helpers.GraphQLWSMessage{Type: helpers.GQLWSMsgConnectionAck})
		}
	}))
	t.Cleanup(backend.Close)

	backendInfo := helpers.GetGraphQLBackendInfo(backend.Listener.Addr().String())
	srv := newGraphQLWSGatewayHandler(t, backendInfo.Host, backendInfo.Port, nil)

	client, resp, err := helpers.DialGraphQLWS(nil, wsURLFromHTTP(srv.URL)+"/graphql", nil)
	require.NoError(t, err, "upgrade requesting graphql-transport-ws must succeed")
	defer client.Close()
	if resp != nil {
		resp.Body.Close()
	}

	// The relay forwards Sec-WebSocket-Protocol to the backend dial, so the
	// backend must have observed the requested protocol.
	_, err = client.InitHandshake(5 * time.Second)
	require.NoError(t, err, "protocol frames must relay after negotiation")
	assert.Contains(t, requestedProtocols, helpers.GraphQLWSProtocol,
		"backend must receive the client-requested graphql-transport-ws subprotocol")

	// The gateway's client-side upgrader negotiates the graphql-ws
	// subprotocols and echoes the selection in the 101 response, as
	// required by RFC 6455 and strict graphql-ws clients.
	assert.Equal(t, helpers.GraphQLWSProtocol, client.Conn.Subprotocol(),
		"gateway must echo the negotiated graphql-transport-ws subprotocol")
}

// TestIntegration_GraphQLWS_OriginAllowlist verifies the CSWSH origin
// allowlist on the graphql-ws upgrade path.
func TestIntegration_GraphQLWS_OriginAllowlist(t *testing.T) {
	mock := helpers.NewMockGraphQLWSBackend(t)
	backendInfo := helpers.GetGraphQLBackendInfo(mock.Listener.Addr().String())

	srv := newGraphQLWSGatewayHandler(t, backendInfo.Host, backendInfo.Port,
		[]string{"https://app.example.com"})

	t.Run("allowed origin upgrades", func(t *testing.T) {
		header := http.Header{"Origin": []string{"https://app.example.com"}}
		client, resp, err := helpers.DialGraphQLWS(nil, wsURLFromHTTP(srv.URL)+"/graphql", header)
		require.NoError(t, err, "allowed origin must upgrade")
		defer client.Close()
		if resp != nil {
			resp.Body.Close()
		}
		_, err = client.InitHandshake(5 * time.Second)
		require.NoError(t, err)
	})

	t.Run("disallowed origin rejected", func(t *testing.T) {
		header := http.Header{"Origin": []string{"https://evil.example.org"}}
		client, resp, err := helpers.DialGraphQLWS(nil, wsURLFromHTTP(srv.URL)+"/graphql", header)
		if client != nil {
			client.Close()
		}
		require.Error(t, err, "disallowed origin must be rejected")
		if resp != nil {
			defer resp.Body.Close()
			// The gorilla upgrader answers 403 for origin rejections.
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	})
}

// TestIntegration_GraphQLWS_RouteAndBackendFailureModes verifies the failure
// paths of the subscription pipeline: unmatched route and unreachable
// backend.
func TestIntegration_GraphQLWS_RouteAndBackendFailureModes(t *testing.T) {
	t.Run("no matching route rejects the upgrade with 404", func(t *testing.T) {
		mock := helpers.NewMockGraphQLWSBackend(t)
		backendInfo := helpers.GetGraphQLBackendInfo(mock.Listener.Addr().String())
		srv := newGraphQLWSGatewayHandler(t, backendInfo.Host, backendInfo.Port, nil)

		client, resp, err := helpers.DialGraphQLWS(nil, wsURLFromHTTP(srv.URL)+"/not-graphql", nil)
		if client != nil {
			client.Close()
		}
		require.Error(t, err, "upgrade on unmatched path must fail")
		if resp != nil {
			defer resp.Body.Close()
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		}
	})

	t.Run("unreachable backend closes the upgraded connection", func(t *testing.T) {
		// Point the route at a dead backend port.
		srv := newGraphQLWSGatewayHandler(t, "127.0.0.1", 1, nil)

		client, resp, err := helpers.DialGraphQLWS(nil, wsURLFromHTTP(srv.URL)+"/graphql", nil)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			// Acceptable: the handler may fail the handshake outright.
			t.Logf("upgrade failed fast (accepted failure mode): %v", err)
			return
		}
		defer client.Close()

		// The client upgrade succeeded but the backend dial fails; the
		// relay must close the client connection promptly.
		_, recvErr := client.Recv(5 * time.Second)
		require.Error(t, recvErr,
			"client connection must be closed when the backend dial fails")
		t.Logf("connection closed after backend failure (expected): %v", recvErr)
	})
}
