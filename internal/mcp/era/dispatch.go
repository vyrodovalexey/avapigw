package era

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// EventDispatcher is the single per-upstream sink installed on a pooled legacy
// session's SSE pump. It classifies each upstream server event and routes it:
//
//   - a server-initiated REQUEST (has an id and a known server method such as
//     sampling/createMessage) → the MRTR bridge (HUB-704);
//   - a NOTIFICATION (resources/updated, *_list_changed, no id) → every
//     registered subscription relay for the upstream (HUB-703).
//
// It never forwards logging/setLevel, ping or notifications/roots/list_changed
// downstream (HUB-707): those are dropped here.
type EventDispatcher struct {
	upstreamID string
	logger     observability.Logger

	// serverRequest handles a server-initiated request event (HUB-704). Nil
	// disables the MRTR bridge for the upstream.
	serverRequest func(ctx context.Context, upstreamID string, req *jsonrpc.Request) error

	mu       sync.RWMutex
	relays   map[int]mcpproxy.SSEEventHandler
	nextID   int
	dispatch context.Context //nolint:containedctx // pump-scoped ctx for request routing
}

// newEventDispatcher constructs a dispatcher for an upstream. serverRequest may
// be nil when no MRTR bridge is wired.
func newEventDispatcher(
	upstreamID string,
	logger observability.Logger,
	serverRequest func(ctx context.Context, upstreamID string, req *jsonrpc.Request) error,
) *EventDispatcher {
	return &EventDispatcher{
		upstreamID:    upstreamID,
		logger:        logger,
		serverRequest: serverRequest,
		relays:        make(map[int]mcpproxy.SSEEventHandler),
		dispatch:      context.Background(),
	}
}

// registerRelay adds a subscription relay handler and returns a token used to
// remove it. Concurrent subscriptions to the same upstream share the session's
// single SSE pump this way (HUB-703).
func (d *EventDispatcher) registerRelay(h mcpproxy.SSEEventHandler) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.nextID
	d.nextID++
	d.relays[id] = h
	return id
}

// unregisterRelay removes a previously registered relay handler.
func (d *EventDispatcher) unregisterRelay(token int) {
	d.mu.Lock()
	delete(d.relays, token)
	d.mu.Unlock()
}

// handle is the mcpproxy.SSEEventHandler installed on the session pump. It
// classifies the event and routes it. Unparseable events are dropped with a
// debug log rather than tearing down the pump.
func (d *EventDispatcher) handle(ev mcpproxy.SSEEvent) error {
	msg, err := parseEventMessage(ev.Data)
	if err != nil {
		d.logger.Debug("era: drop unparseable legacy SSE event",
			observability.String("upstream", d.upstreamID), observability.Error(err))
		return nil
	}
	if isServerInitiatedRequest(msg) {
		return d.routeServerRequest(msg)
	}
	if shouldDropDownstream(msg.Method) {
		// HUB-707: never forward these semantics downstream.
		return nil
	}
	d.fanOutNotification(ev)
	return nil
}

// routeServerRequest forwards a server-initiated request to the MRTR bridge
// (HUB-704). When no bridge is wired the request is dropped (the hub cannot
// satisfy it).
func (d *EventDispatcher) routeServerRequest(msg *eventMessage) error {
	if d.serverRequest == nil {
		return nil
	}
	req := &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		ID:      msg.ID,
		Method:  msg.Method,
		Params:  msg.Params,
	}
	d.mu.RLock()
	ctx := d.dispatch
	d.mu.RUnlock()
	return d.serverRequest(ctx, d.upstreamID, req)
}

// fanOutNotification relays a notification event to every registered relay.
// A relay error is logged but does not stop other relays or the pump.
func (d *EventDispatcher) fanOutNotification(ev mcpproxy.SSEEvent) {
	d.mu.RLock()
	handlers := make([]mcpproxy.SSEEventHandler, 0, len(d.relays))
	for _, h := range d.relays {
		handlers = append(handlers, h)
	}
	d.mu.RUnlock()
	for _, h := range handlers {
		if err := h(ev); err != nil {
			d.logger.Debug("era: subscription relay error",
				observability.String("upstream", d.upstreamID), observability.Error(err))
		}
	}
}

// eventMessage is the parsed shape of a legacy SSE JSON-RPC message.
type eventMessage struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// parseEventMessage decodes the SSE event data as a JSON-RPC message.
func parseEventMessage(data []byte) (*eventMessage, error) {
	var msg eventMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// isServerInitiatedRequest reports whether a message is a server-initiated
// request the hub must broker via MRTR (HUB-704): it carries an id (so it
// expects a response) and a recognized server-initiated method.
func isServerInitiatedRequest(msg *eventMessage) bool {
	if len(msg.ID) == 0 {
		return false
	}
	return legacyServerMethods[msg.Method]
}

// legacyServerMethods is the set of legacy server-initiated request methods the
// hub converts to an InputRequiredResult (HUB-704).
var legacyServerMethods = map[string]bool{
	LegacyMethodSamplingCreate:    true,
	LegacyMethodElicitationCreate: true,
	LegacyMethodRootsList:         true,
}

// Legacy server-initiated request methods (HUB-704).
const (
	// LegacyMethodSamplingCreate is the legacy sampling request.
	LegacyMethodSamplingCreate = "sampling/createMessage"
	// LegacyMethodElicitationCreate is the legacy elicitation request.
	LegacyMethodElicitationCreate = "elicitation/create"
	// LegacyMethodRootsList is the legacy roots request.
	LegacyMethodRootsList = "roots/list"
)

// downstreamSuppressedMethods is the set of legacy methods whose semantics the
// hub must NOT forward downstream (HUB-707). They may still be used upstream.
var downstreamSuppressedMethods = map[string]bool{
	"logging/setLevel":                 true,
	"ping":                             true,
	"notifications/roots/list_changed": true,
}

// shouldDropDownstream reports whether a method's event must not be relayed
// downstream (HUB-707).
func shouldDropDownstream(method string) bool {
	return downstreamSuppressedMethods[method]
}
