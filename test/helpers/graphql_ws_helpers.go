// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// GraphQLWSProtocol is the graphql-transport-ws WebSocket subprotocol name
// (the modern graphql-ws protocol, https://github.com/enisdenjo/graphql-ws).
const GraphQLWSProtocol = "graphql-transport-ws"

// graphql-transport-ws message types.
const (
	GQLWSMsgConnectionInit = "connection_init"
	GQLWSMsgConnectionAck  = "connection_ack"
	GQLWSMsgPing           = "ping"
	GQLWSMsgPong           = "pong"
	GQLWSMsgSubscribe      = "subscribe"
	GQLWSMsgNext           = "next"
	GQLWSMsgError          = "error"
	GQLWSMsgComplete       = "complete"
)

// GraphQLWSMessage is a graphql-transport-ws protocol frame.
type GraphQLWSMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// GraphQLWSSubscribePayload is the payload of a subscribe message.
type GraphQLWSSubscribePayload struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// MockGraphQLWSBackend is a mock GraphQL backend implementing the
// graphql-transport-ws subscription protocol on /graphql plus plain
// HTTP POST /graphql queries and GET /health.
type MockGraphQLWSBackend struct {
	*httptest.Server

	// EventsPerSubscription is the number of "next" events emitted per
	// subscription before "complete" is sent (default 3).
	EventsPerSubscription int

	// EventInterval is the delay between "next" events (default 50ms).
	EventInterval time.Duration
}

// NewMockGraphQLWSBackend starts a mock GraphQL backend that supports
// subscriptions over the graphql-transport-ws protocol:
//
//	client                            backend
//	  |-- connection_init ------------->|
//	  |<-- connection_ack --------------|
//	  |-- subscribe {id, query} ------->|
//	  |<-- next {id, payload} x N ------|   (N = EventsPerSubscription)
//	  |<-- complete {id} ---------------|
//
// A subscription whose query contains "failNow" produces an "error"
// message instead of next/complete, exercising the error path. Ping
// messages are answered with pong.
func NewMockGraphQLWSBackend(t *testing.T) *MockGraphQLWSBackend {
	t.Helper()

	mock := &MockGraphQLWSBackend{
		EventsPerSubscription: 3,
		EventInterval:         50 * time.Millisecond,
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		Subprotocols:    []string{GraphQLWSProtocol},
		CheckOrigin:     func(*http.Request) bool { return true },
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		if isWSUpgrade(r) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			mock.serveGraphQLWS(conn)
			return
		}

		// Plain HTTP GraphQL query handling.
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var gqlReq mockGraphQLRequest
		if err := json.NewDecoder(r.Body).Decode(&gqlReq); err != nil {
			writeJSONResponse(w, http.StatusBadRequest, `{"errors":[{"message":"invalid JSON"}]}`)
			return
		}
		writeJSONResponse(w, http.StatusOK, resolveGraphQLMockResponse(gqlReq.Query))
	})

	mock.Server = httptest.NewServer(mux)
	t.Cleanup(mock.Server.Close)

	return mock
}

// serveGraphQLWS drives one graphql-transport-ws server-side session.
func (m *MockGraphQLWSBackend) serveGraphQLWS(conn *websocket.Conn) {
	defer conn.Close()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}
		var msg GraphQLWSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}

		switch msg.Type {
		case GQLWSMsgConnectionInit:
			if err := conn.WriteJSON(GraphQLWSMessage{Type: GQLWSMsgConnectionAck}); err != nil {
				return
			}
		case GQLWSMsgPing:
			if err := conn.WriteJSON(GraphQLWSMessage{Type: GQLWSMsgPong}); err != nil {
				return
			}
		case GQLWSMsgSubscribe:
			if !m.handleSubscribe(conn, msg) {
				return
			}
		case GQLWSMsgComplete:
			// Client-initiated completion: nothing to emit.
		default:
			// Unknown types are ignored to keep the relay flowing.
		}
	}
}

// handleSubscribe emits the event stream for one subscription. Returns false
// when the connection is no longer writable.
func (m *MockGraphQLWSBackend) handleSubscribe(conn *websocket.Conn, msg GraphQLWSMessage) bool {
	var payload GraphQLWSSubscribePayload
	_ = json.Unmarshal(msg.Payload, &payload)

	if strings.Contains(payload.Query, "failNow") {
		errPayload, _ := json.Marshal([]map[string]string{
			{"message": "subscription failed by request"},
		})
		return conn.WriteJSON(GraphQLWSMessage{
			ID: msg.ID, Type: GQLWSMsgError, Payload: errPayload,
		}) == nil
	}

	for i := 0; i < m.EventsPerSubscription; i++ {
		nextPayload, _ := json.Marshal(map[string]interface{}{
			"data": map[string]interface{}{
				"itemUpdated": map[string]interface{}{
					"id":       fmt.Sprintf("%d", i+1),
					"sequence": i,
				},
			},
		})
		if err := conn.WriteJSON(GraphQLWSMessage{
			ID: msg.ID, Type: GQLWSMsgNext, Payload: nextPayload,
		}); err != nil {
			return false
		}
		time.Sleep(m.EventInterval)
	}

	return conn.WriteJSON(GraphQLWSMessage{ID: msg.ID, Type: GQLWSMsgComplete}) == nil
}

// isWSUpgrade reports whether the request is a WebSocket upgrade handshake.
func isWSUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// GraphQLWSClient wraps a client-side graphql-transport-ws session with
// deadline-guarded helpers for test assertions.
type GraphQLWSClient struct {
	Conn *websocket.Conn
}

// DialGraphQLWS dials a graphql-transport-ws endpoint (ws:// or wss://)
// requesting the graphql-transport-ws subprotocol.
func DialGraphQLWS(dialer *websocket.Dialer, wsURL string, header http.Header) (*GraphQLWSClient, *http.Response, error) {
	if dialer == nil {
		dialer = &websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	}
	d := *dialer
	d.Subprotocols = []string{GraphQLWSProtocol}

	conn, resp, err := d.Dial(wsURL, header)
	if err != nil {
		return nil, resp, err
	}
	return &GraphQLWSClient{Conn: conn}, resp, nil
}

// Close closes the underlying connection.
func (c *GraphQLWSClient) Close() {
	_ = c.Conn.Close()
}

// Send writes a protocol message with a write deadline.
func (c *GraphQLWSClient) Send(msg GraphQLWSMessage) error {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	return c.Conn.WriteJSON(msg)
}

// Recv reads the next protocol message with the given deadline.
func (c *GraphQLWSClient) Recv(timeout time.Duration) (GraphQLWSMessage, error) {
	var msg GraphQLWSMessage
	if err := c.Conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return msg, err
	}
	err := c.Conn.ReadJSON(&msg)
	return msg, err
}

// InitHandshake performs connection_init -> connection_ack and returns the
// ack message.
func (c *GraphQLWSClient) InitHandshake(timeout time.Duration) (GraphQLWSMessage, error) {
	if err := c.Send(GraphQLWSMessage{Type: GQLWSMsgConnectionInit}); err != nil {
		return GraphQLWSMessage{}, err
	}
	msg, err := c.Recv(timeout)
	if err != nil {
		return msg, err
	}
	if msg.Type != GQLWSMsgConnectionAck {
		return msg, fmt.Errorf("expected %s, got %s", GQLWSMsgConnectionAck, msg.Type)
	}
	return msg, nil
}

// Subscribe sends a subscribe message for the given query.
func (c *GraphQLWSClient) Subscribe(id, query string) error {
	payload, err := json.Marshal(GraphQLWSSubscribePayload{Query: query})
	if err != nil {
		return err
	}
	return c.Send(GraphQLWSMessage{ID: id, Type: GQLWSMsgSubscribe, Payload: payload})
}

// CollectSubscription reads messages until a complete or error message for
// the subscription id arrives (or the per-read timeout fires). It returns
// the received next payloads and the terminal message type.
func (c *GraphQLWSClient) CollectSubscription(
	id string, maxEvents int, perReadTimeout time.Duration,
) (nextPayloads []json.RawMessage, terminal string, err error) {
	for i := 0; i < maxEvents+2; i++ {
		msg, recvErr := c.Recv(perReadTimeout)
		if recvErr != nil {
			return nextPayloads, "", recvErr
		}
		if msg.ID != "" && msg.ID != id {
			continue
		}
		switch msg.Type {
		case GQLWSMsgNext:
			nextPayloads = append(nextPayloads, msg.Payload)
		case GQLWSMsgComplete, GQLWSMsgError:
			return nextPayloads, msg.Type, nil
		}
	}
	return nextPayloads, "", fmt.Errorf("no terminal message after %d reads", maxEvents+2)
}
