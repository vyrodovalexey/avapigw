// Package subscription implements the hub's subscriptions/listen fan-out
// (HUB-221..229). A downstream client opens one SSE stream per subscription;
// the hub acknowledges it, fans the honored filter out to the upstreams that
// own the requested resource URIs / primitive types, fans the resulting
// notifications back in (rewriting subscriptionId to the downstream value and
// re-namespacing URIs), coalesces duplicate list_changed within a debounce
// window, keeps the stream alive with SSE comments, and — on graceful shutdown
// or upstream teardown — answers the original request with a complete result
// before closing.
package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Notification method-name constants (HUB-221..229).
const (
	// MethodAcknowledged is the first message sent on a subscription stream.
	MethodAcknowledged = "notifications/subscriptions/acknowledged"
	// MethodToolsListChanged notifies that the tool list changed.
	MethodToolsListChanged = "notifications/tools/list_changed"
	// MethodPromptsListChanged notifies that the prompt list changed.
	MethodPromptsListChanged = "notifications/prompts/list_changed"
	// MethodResourcesListChanged notifies that the resource list changed.
	MethodResourcesListChanged = "notifications/resources/list_changed"
	// MethodResourcesUpdated notifies that a subscribed resource changed.
	MethodResourcesUpdated = "notifications/resources/updated"
)

// filterField/kind constants for invalidation and coalescing.
const (
	kindTools     = "tools"
	kindPrompts   = "prompts"
	kindResources = "resources"
)

// DefaultKeepAlive is the SSE keep-alive interval used when unconfigured
// (HUB-225: default ≤30s).
const DefaultKeepAlive = 25 * time.Second

// DefaultDebounce coalesces duplicate list_changed from a single upstream
// (HUB-229) when unconfigured.
const DefaultDebounce = 500 * time.Millisecond

// Filter is the honored subset of a subscriptions/listen request (HUB-221).
type Filter struct {
	// ToolsListChanged requests tool list_changed notifications.
	ToolsListChanged bool
	// PromptsListChanged requests prompt list_changed notifications.
	PromptsListChanged bool
	// ResourcesListChanged requests resource list_changed notifications.
	ResourcesListChanged bool
	// ResourceSubscriptions is the set of (namespaced) resource URIs the
	// client subscribed to for resources/updated.
	ResourceSubscriptions []string
}

// ParseFilter extracts the honored filter from subscriptions/listen params
// (HUB-221). Unknown fields are ignored; unrequested types are never honored.
func ParseFilter(params map[string]any) Filter {
	f := Filter{
		ToolsListChanged:     boolField(params, "toolsListChanged"),
		PromptsListChanged:   boolField(params, "promptsListChanged"),
		ResourcesListChanged: boolField(params, "resourcesListChanged"),
	}
	if raw, ok := params["resourceSubscriptions"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				f.ResourceSubscriptions = append(f.ResourceSubscriptions, s)
			}
		}
	}
	return f
}

// boolField returns a bool param value, defaulting to false.
func boolField(params map[string]any, key string) bool {
	v, _ := params[key].(bool)
	return v
}

// Namespacer resolves namespaced⇄upstream names/URIs for fan-out/fan-in
// (HUB-223). It is satisfied by namespace.Mapper.
type Namespacer interface {
	// Namespace returns the hub-visible name for an upstream primitive.
	Namespace(upstreamID, name string) (string, error)
	// Denamespace resolves a hub-visible name to its upstream id and
	// original name.
	Denamespace(nsName string) (upstreamID, name string, ok bool)
}

// UpstreamStreamer opens an upstream subscription stream and relays its events.
// It is the subset of the proxy HubClient the subscription manager needs; the
// resolver supplies the concrete backend.
type UpstreamStreamer interface {
	// StreamUpstream opens a subscriptions/listen stream to upstreamID and
	// invokes handler for each relayed SSE event until ctx is canceled.
	StreamUpstream(
		ctx context.Context, upstreamID string, req *jsonrpc.Request, handler mcpproxy.SSEEventHandler,
	) error
}

// CacheInvalidator is the M3 cache invalidation hook called on list_changed /
// resources/updated fan-in (HUB-185).
type CacheInvalidator interface {
	// InvalidateCache drops cached entries affected by an upstream change.
	InvalidateCache(ctx context.Context, upstream, kind, uri string)
}

// Config configures the subscription manager.
type Config struct {
	// KeepAlive is the SSE keep-alive comment interval (HUB-225).
	KeepAlive time.Duration
	// Debounce coalesces duplicate list_changed within this window
	// (HUB-229).
	Debounce time.Duration
}

func (c Config) withDefaults() Config {
	if c.KeepAlive <= 0 {
		c.KeepAlive = DefaultKeepAlive
	}
	if c.Debounce <= 0 {
		c.Debounce = DefaultDebounce
	}
	return c
}

// Manager coordinates all active subscription streams so graceful shutdown can
// close them per HUB-226.
type Manager struct {
	streamer    UpstreamStreamer
	mapper      Namespacer
	invalidator CacheInvalidator
	cfg         Config
	metrics     *mcpmetrics.Metrics
	logger      observability.Logger

	mu     sync.Mutex
	active map[*subscription]struct{}
	closed bool
}

// Option configures a Manager.
type Option func(*Manager)

// WithMetrics sets the metrics recorder.
func WithMetrics(m *mcpmetrics.Metrics) Option {
	return func(mgr *Manager) {
		if m != nil {
			mgr.metrics = m
		}
	}
}

// WithLogger sets the manager logger.
func WithLogger(l observability.Logger) Option {
	return func(mgr *Manager) {
		if l != nil {
			mgr.logger = l
		}
	}
}

// WithInvalidator sets the cache invalidation hook (HUB-185).
func WithInvalidator(inv CacheInvalidator) Option {
	return func(mgr *Manager) {
		mgr.invalidator = inv
	}
}

// NewManager constructs a Manager.
func NewManager(streamer UpstreamStreamer, mapper Namespacer, cfg Config, opts ...Option) (*Manager, error) {
	if streamer == nil {
		return nil, errors.New("subscription: nil streamer")
	}
	if mapper == nil {
		return nil, errors.New("subscription: nil mapper")
	}
	m := &Manager{
		streamer: streamer,
		mapper:   mapper,
		cfg:      cfg.withDefaults(),
		metrics:  mcpmetrics.GetMetrics(),
		logger:   observability.NopLogger(),
		active:   make(map[*subscription]struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// ListenParams carries the inputs to open a downstream subscription.
type ListenParams struct {
	// SubscriptionID is the JSON-RPC id of the client's subscriptions/listen
	// request, used as the downstream subscriptionId (HUB-222).
	SubscriptionID json.RawMessage
	// RequestID echoes the JSON-RPC id for the terminal complete result.
	RequestID json.RawMessage
	// Filter is the parsed subscription filter.
	Filter Filter
	// Upstreams is the set of upstream ids the route fans out to.
	Upstreams []string
	// UpstreamMeta is the JSON of the _meta object to send upstream.
	UpstreamMeta json.RawMessage
}

// Listen opens a downstream subscription: it registers the stream, sends the
// acknowledged message (HUB-222), fans out to upstreams (HUB-223), pumps
// notifications and keep-alives until ctx is canceled (client disconnect,
// HUB-241) or the manager shuts down, and — on graceful shutdown — answers the
// original request with a complete result before returning (HUB-226). It blocks
// until the subscription ends.
func (m *Manager) Listen(ctx context.Context, w mcpproxy.SSEWriter, p ListenParams) error {
	sub := newSubscription(m, w, p)
	if err := m.register(sub); err != nil {
		return err
	}
	defer m.unregister(sub)

	m.metrics.SubscriptionsOpen.WithLabelValues("").Inc()
	defer m.metrics.SubscriptionsOpen.WithLabelValues("").Dec()

	return sub.run(ctx)
}

// register adds a subscription to the active set, rejecting when the manager is
// shutting down.
func (m *Manager) register(sub *subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("subscription: manager is shutting down")
	}
	m.active[sub] = struct{}{}
	return nil
}

// unregister removes a subscription from the active set.
func (m *Manager) unregister(sub *subscription) {
	m.mu.Lock()
	delete(m.active, sub)
	m.mu.Unlock()
}

// Shutdown signals every active subscription to complete gracefully (HUB-226):
// each answers its original subscriptions/listen request with a complete result
// then closes. It marks the manager closed so no new subscriptions register.
// Shutdown returns once all active subscriptions have observed the signal; each
// stream drains on its own goroutine.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	subs := make([]*subscription, 0, len(m.active))
	for sub := range m.active {
		subs = append(subs, sub)
	}
	m.mu.Unlock()

	for _, sub := range subs {
		sub.gracefulComplete()
	}
}

// invalidate calls the cache invalidation hook when configured (HUB-185).
func (m *Manager) invalidate(ctx context.Context, upstream, kind, uri string) {
	if m.invalidator != nil {
		m.invalidator.InvalidateCache(ctx, upstream, kind, uri)
	}
}

// buildAcknowledged assembles the notifications/subscriptions/acknowledged
// message reflecting only the honored filter subset (HUB-222).
func buildAcknowledged(subscriptionID json.RawMessage, f Filter) (json.RawMessage, error) {
	honored := map[string]any{
		"toolsListChanged":     f.ToolsListChanged,
		"promptsListChanged":   f.PromptsListChanged,
		"resourcesListChanged": f.ResourcesListChanged,
	}
	if len(f.ResourceSubscriptions) > 0 {
		honored["resourceSubscriptions"] = f.ResourceSubscriptions
	}
	msg := jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		Method:  MethodAcknowledged,
		Params: mustMarshal(map[string]any{
			"_meta":  map[string]any{protocol.MetaSubscriptionID: rawOrNull(subscriptionID)},
			"filter": honored,
		}),
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("subscription: encode acknowledged: %w", err)
	}
	return raw, nil
}

// buildComplete assembles the terminal complete result carrying the
// subscriptionId (HUB-226).
func buildComplete(requestID, subscriptionID json.RawMessage) (json.RawMessage, error) {
	result := map[string]any{
		"resultType": protocol.ResultComplete,
		"_meta":      map[string]any{protocol.MetaSubscriptionID: rawOrNull(subscriptionID)},
	}
	resp := jsonrpc.Response{
		JSONRPC: jsonrpc.Version,
		ID:      rawOrNull(requestID),
		Result:  mustMarshal(result),
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("subscription: encode complete: %w", err)
	}
	return raw, nil
}

// mustMarshal marshals v, returning an empty object on failure so callers keep
// small signatures; inputs here are always marshalable maps.
func mustMarshal(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// rawOrNull returns raw or a JSON null when raw is empty.
func rawOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}
