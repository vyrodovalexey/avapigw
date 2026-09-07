// Package discovery implements the MCP hub's discovery and capability
// aggregation (HUB-161..169, HUB-145). Given the set of upstreams for a route
// and a HubClient, it fetches each upstream's server/discover (or the relevant
// */list method), merges the results into a single hub-visible catalog,
// namespaces every primitive name and resource URI, resolves collisions by
// namespacing, preserves upstream schemas byte-for-byte except for name
// rewriting, rejects tools whose x-mcp-header annotations violate the schema
// constraints, and serves degraded results when an upstream is unavailable.
//
// Ordering is deterministic and stable across requests and replicas (sorted by
// namespaced name), so the same underlying set always produces the same output
// regardless of upstream response order or the replica serving the request
// (HUB-164).
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/headers"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/meta"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/mcp/security"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// degradedTTLMs is the shortened cache TTL (in milliseconds) applied to a
// degraded discovery/list result so clients re-discover sooner once an
// upstream recovers (HUB-167).
const degradedTTLMs int64 = 5000

// defaultCompleteTTLMs is the TTL emitted on a complete aggregated result when
// no upstream contributes a TTL of its own (HUB-181).
const defaultCompleteTTLMs int64 = 60000

// cacheScopePublic / cacheScopePrivate are the two cacheScope values the hub
// emits (HUB-182).
const (
	cacheScopePublic  = "public"
	cacheScopePrivate = "private"
)

// listItemKeys maps an MCP list method to the JSON array key that carries its
// primitives in the upstream result.
var listItemKeys = map[string]string{
	protocol.MethodToolsList:             "tools",
	protocol.MethodPromptsList:           "prompts",
	protocol.MethodResourcesList:         "resources",
	protocol.MethodResourceTemplatesList: "resourceTemplates",
}

// nameFields lists the JSON object keys, in priority order, that carry the
// primitive's identifying name/uri which the hub re-namespaces.
var nameFields = []string{"name", "uri", "uriTemplate"}

// ErrNilHub indicates the aggregator was constructed without a HubClient.
var ErrNilHub = errors.New("discovery: nil hub client")

// UpstreamResolver resolves a configured MCP upstream id to its runtime
// ServiceBackend and static config. It is satisfied by the MCP handler which
// already owns the backend registry and the upstream config map.
type UpstreamResolver interface {
	// Resolve returns the ServiceBackend, its MCP config and whether the
	// upstream exists and is usable.
	Resolve(upstreamID string) (*backend.ServiceBackend, config.MCPBackend, bool)
}

// DiscoverResult is the merged, hub-visible discovery/list result.
type DiscoverResult struct {
	// Method is the MCP method this result answers.
	Method string
	// Items is the ordered, namespaced set of primitives (for */list).
	Items []json.RawMessage
	// SupportedVersions is the hub's own supported version set (server/discover).
	SupportedVersions []string
	// Capabilities is the policy-filtered union of upstream capabilities.
	Capabilities map[string]json.RawMessage
	// Instructions is the merged instructions text (server/discover).
	Instructions string
	// TTLMs is the aggregated cache TTL in milliseconds (HUB-182).
	TTLMs int64
	// CacheScope is the aggregated cache scope, "public" or "private".
	CacheScope string
	// Degraded is true when at least one upstream was unavailable (HUB-167).
	Degraded bool
	// NextCursor, when non-empty, is the opaque hub cursor for the next page.
	NextCursor string
}

// Aggregator merges discovery and list results across upstreams.
type Aggregator interface {
	// Discover aggregates server/discover across the given upstreams.
	Discover(ctx context.Context, upstreams []string, principalScopes []string) (*DiscoverResult, error)
	// ListTools aggregates tools/list with pagination.
	ListTools(ctx context.Context, upstreams []string, cursor string, scopes []string) (*DiscoverResult, error)
	// ListPrompts aggregates prompts/list with pagination.
	ListPrompts(ctx context.Context, upstreams []string, cursor string, scopes []string) (*DiscoverResult, error)
	// ListResources aggregates resources/list with pagination.
	ListResources(ctx context.Context, upstreams []string, cursor string, scopes []string) (*DiscoverResult, error)
	// ListResourceTemplates aggregates resources/templates/list with pagination.
	ListResourceTemplates(
		ctx context.Context, upstreams []string, cursor string, scopes []string,
	) (*DiscoverResult, error)
}

// hubCaller is the subset of the proxy HubClient the aggregator needs. It is
// satisfied by proxy.HubClient (http.Header is map[string][]string).
type hubCaller interface {
	Call(
		ctx context.Context,
		up *backend.ServiceBackend,
		upstreamPath string,
		req *jsonrpc.Request,
		upstreamHeaders http.Header,
	) (*jsonrpc.Response, error)
}

// DefaultAggregator is the default Aggregator implementation.
type DefaultAggregator struct {
	hub       hubCaller
	resolver  UpstreamResolver
	mapper    namespace.Mapper
	cursors   *CursorCodec
	metrics   *mcpmetrics.Metrics
	logger    observability.Logger
	pageLimit int

	// Security hardening (M5). Each is optional: a nil/zero component leaves
	// the corresponding check disabled (additive).
	drift        *security.DriftStore
	schemaLimits security.SchemaLimits
	trustPolicy  string

	// Upstream _meta construction (HUB-124). hubClientInfo is the hub's own
	// identity sent upstream as clientInfo; brokerableCaps is the capability
	// set the hub can broker, sent (narrowed) as clientCapabilities. For
	// discovery there is no downstream client-capability context, so the
	// brokerable set is advertised directly (an empty set yields {}).
	hubClientInfo  meta.Info
	brokerableCaps map[string]bool
}

// AggregatorOption is a functional option for DefaultAggregator.
type AggregatorOption func(*DefaultAggregator)

// WithAggregatorLogger sets the aggregator logger.
func WithAggregatorLogger(logger observability.Logger) AggregatorOption {
	return func(a *DefaultAggregator) {
		if logger != nil {
			a.logger = logger
		}
	}
}

// WithAggregatorMetrics sets the metrics recorder.
func WithAggregatorMetrics(m *mcpmetrics.Metrics) AggregatorOption {
	return func(a *DefaultAggregator) {
		if m != nil {
			a.metrics = m
		}
	}
}

// WithAggregatorPageLimit sets the per-upstream page size requested upstream.
// Non-positive values are ignored.
func WithAggregatorPageLimit(limit int) AggregatorOption {
	return func(a *DefaultAggregator) {
		if limit > 0 {
			a.pageLimit = limit
		}
	}
}

// WithAggregatorDriftStore sets the tool-definition drift detector (HUB-402).
func WithAggregatorDriftStore(d *security.DriftStore) AggregatorOption {
	return func(a *DefaultAggregator) {
		a.drift = d
	}
}

// WithAggregatorSchemaLimits sets the bounded schema-validation limits
// (HUB-403/404).
func WithAggregatorSchemaLimits(l security.SchemaLimits) AggregatorOption {
	return func(a *DefaultAggregator) {
		a.schemaLimits = l
	}
}

// WithAggregatorTrustPolicy sets the untrusted-upstream trust policy (HUB-401):
// "strip" or "flag".
func WithAggregatorTrustPolicy(policy string) AggregatorOption {
	return func(a *DefaultAggregator) {
		a.trustPolicy = policy
	}
}

// WithAggregatorClientInfo sets the hub's clientInfo sent upstream in every
// forwarded discovery/list request's _meta (HUB-124).
func WithAggregatorClientInfo(info meta.Info) AggregatorOption {
	return func(a *DefaultAggregator) {
		a.hubClientInfo = info
	}
}

// WithAggregatorBrokerableCapabilities sets the capability set the hub can
// broker, advertised (as-is) as clientCapabilities in every forwarded
// discovery/list request's _meta (HUB-124/125). A nil/empty set yields an
// empty capabilities object.
func WithAggregatorBrokerableCapabilities(caps map[string]bool) AggregatorOption {
	return func(a *DefaultAggregator) {
		a.brokerableCaps = caps
	}
}

// NewDefaultAggregator constructs a DefaultAggregator. hub, resolver, mapper
// and cursors are required; the logger and metrics default to safe values.
func NewDefaultAggregator(
	hub hubCaller,
	resolver UpstreamResolver,
	mapper namespace.Mapper,
	cursors *CursorCodec,
	opts ...AggregatorOption,
) (*DefaultAggregator, error) {
	if hub == nil {
		return nil, ErrNilHub
	}
	a := &DefaultAggregator{
		hub:      hub,
		resolver: resolver,
		mapper:   mapper,
		cursors:  cursors,
		metrics:  mcpmetrics.GetMetrics(),
		logger:   observability.NopLogger(),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Discover aggregates server/discover across upstreams (HUB-161).
func (a *DefaultAggregator) Discover(
	ctx context.Context, upstreams []string, principalScopes []string,
) (*DiscoverResult, error) {
	agg := newAggregation(protocol.MethodServerDiscover)
	for _, id := range upstreams {
		a.discoverOne(ctx, id, agg)
	}
	result := agg.finalizeDiscover()
	result.SupportedVersions = append([]string(nil), protocol.HubSupportedVersions...)
	// principalScopes are reserved for capability policy filtering in authz;
	// discovery marks the result private when a scope filter is applied.
	if len(principalScopes) > 0 {
		result.CacheScope = cacheScopePrivate
	}
	return result, nil
}

// ListTools aggregates tools/list.
func (a *DefaultAggregator) ListTools(
	ctx context.Context, upstreams []string, cursor string, scopes []string,
) (*DiscoverResult, error) {
	return a.list(ctx, protocol.MethodToolsList, upstreams, cursor, scopes)
}

// ListPrompts aggregates prompts/list.
func (a *DefaultAggregator) ListPrompts(
	ctx context.Context, upstreams []string, cursor string, scopes []string,
) (*DiscoverResult, error) {
	return a.list(ctx, protocol.MethodPromptsList, upstreams, cursor, scopes)
}

// ListResources aggregates resources/list.
func (a *DefaultAggregator) ListResources(
	ctx context.Context, upstreams []string, cursor string, scopes []string,
) (*DiscoverResult, error) {
	return a.list(ctx, protocol.MethodResourcesList, upstreams, cursor, scopes)
}

// ListResourceTemplates aggregates resources/templates/list.
func (a *DefaultAggregator) ListResourceTemplates(
	ctx context.Context, upstreams []string, cursor string, scopes []string,
) (*DiscoverResult, error) {
	return a.list(ctx, protocol.MethodResourceTemplatesList, upstreams, cursor, scopes)
}

// list is the shared aggregation path for every */list method. It decodes the
// inbound hub cursor (if any) into per-upstream upstream cursors, fetches each
// upstream's page, merges and namespaces the items, and re-issues an opaque
// hub cursor when any upstream reports more pages (HUB-164/166/167).
func (a *DefaultAggregator) list(
	ctx context.Context, method string, upstreams []string, cursor string, scopes []string,
) (*DiscoverResult, error) {
	state, err := a.decodeCursor(ctx, cursor, method)
	if err != nil {
		return nil, err
	}

	agg := newAggregation(method)
	nextState := &CursorState{Method: method}
	for _, id := range upstreams {
		upCursor := state.cursorFor(id)
		a.listOne(ctx, id, method, upCursor, agg, nextState)
	}

	result := agg.finalizeList()
	if len(scopes) > 0 {
		result.CacheScope = cacheScopePrivate
	}
	if err := a.encodeNextCursor(ctx, result, nextState); err != nil {
		return nil, err
	}
	return result, nil
}

// decodeCursor opens an inbound hub cursor, verifying it belongs to the same
// method. An empty cursor yields an empty state (first page).
func (a *DefaultAggregator) decodeCursor(ctx context.Context, cursor, method string) (*CursorState, error) {
	if cursor == "" {
		return &CursorState{Method: method}, nil
	}
	if a.cursors == nil {
		return nil, ErrCursorRestart
	}
	state, err := a.cursors.Decode(ctx, cursor)
	if err != nil {
		return nil, err
	}
	if state.Method != method {
		return nil, ErrCursorRestart
	}
	return state, nil
}

// encodeNextCursor seals the next-page state onto the result when at least one
// upstream reported a further page.
func (a *DefaultAggregator) encodeNextCursor(
	ctx context.Context, result *DiscoverResult, nextState *CursorState,
) error {
	if len(nextState.Upstreams) == 0 {
		return nil
	}
	if a.cursors == nil {
		return nil
	}
	token, err := a.cursors.Encode(ctx, nextState)
	if err != nil {
		return err
	}
	result.NextCursor = token
	return nil
}

// discoverOne fetches and merges a single upstream's server/discover.
func (a *DefaultAggregator) discoverOne(ctx context.Context, id string, agg *aggregation) {
	sb, cfg, ok := a.resolve(id)
	if !ok {
		agg.markDegraded()
		return
	}
	resp, err := a.callUpstream(ctx, id, cfg, sb, protocol.MethodServerDiscover, "")
	if err != nil {
		a.metrics.RecordUpstreamFailure(id, protocol.MethodServerDiscover)
		a.logger.Warn("mcp discovery: upstream server/discover failed",
			observability.String("upstream", id), observability.Error(err))
		agg.markDegraded()
		return
	}
	a.mergeDiscover(id, cfg, resp, agg)
}

// listOne fetches and merges a single upstream's */list page.
func (a *DefaultAggregator) listOne(
	ctx context.Context, id, method, upCursor string, agg *aggregation, nextState *CursorState,
) {
	sb, cfg, ok := a.resolve(id)
	if !ok {
		agg.markDegraded()
		return
	}
	resp, err := a.callUpstream(ctx, id, cfg, sb, method, upCursor)
	if err != nil {
		a.metrics.RecordUpstreamFailure(id, method)
		a.logger.Warn("mcp discovery: upstream list failed",
			observability.String("upstream", id),
			observability.String("method", method),
			observability.Error(err))
		agg.markDegraded()
		return
	}
	a.mergeList(id, cfg, method, resp, agg, nextState)
}

// resolve looks up an upstream, returning ok=false when it is not configured.
func (a *DefaultAggregator) resolve(
	id string,
) (*backend.ServiceBackend, config.MCPBackend, bool) {
	if a.resolver == nil {
		return nil, config.MCPBackend{}, false
	}
	return a.resolver.Resolve(id)
}

// callUpstream builds and forwards a discovery/list request to one upstream.
// It resolves the protocol version negotiated with THAT upstream and threads
// it into both the request _meta (HUB-124) and the MCP-Protocol-Version header
// so the header and body agree (HUB-122).
func (a *DefaultAggregator) callUpstream(
	ctx context.Context,
	id string,
	cfg config.MCPBackend,
	sb *backend.ServiceBackend,
	method, upCursor string,
) (*jsonrpc.Response, error) {
	negotiated := a.negotiatedVersion(cfg)
	req, err := a.buildRequest(method, upCursor, negotiated)
	if err != nil {
		return nil, err
	}
	hdrs := headers.DeriveUpstreamHeaders(method, "", nil, nil)
	// HUB-122: keep the MCP-Protocol-Version header consistent with the
	// _meta protocolVersion carried in the body.
	hdrs.Set(headers.HeaderMcpProtocolVersion, negotiated)
	resp, err := a.hub.Call(ctx, sb, cfg.GetEffectivePath(), req, hdrs)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Error != nil {
		return nil, fmt.Errorf("discovery: upstream %s returned error: %w", id, resp.Error)
	}
	return resp, nil
}

// negotiatedVersion resolves the protocol version to send to an upstream: the
// upstream's pinned version when set, otherwise the hub's latest supported
// version (HUB-124).
func (a *DefaultAggregator) negotiatedVersion(cfg config.MCPBackend) string {
	if cfg.PinnedVersion != "" {
		return cfg.PinnedVersion
	}
	return protocol.LatestVersion
}

// buildRequest constructs the JSON-RPC request for a discovery/list method,
// including the per-upstream cursor and page limit when set, and the fresh
// per-request `_meta` mandated for every upstream request (HUB-124): the
// negotiated protocol version, the hub's brokerable clientCapabilities and the
// hub's own clientInfo.
func (a *DefaultAggregator) buildRequest(method, upCursor, negotiated string) (*jsonrpc.Request, error) {
	params := map[string]any{}
	if upCursor != "" {
		params["cursor"] = upCursor
	}
	if a.pageLimit > 0 {
		params["limit"] = a.pageLimit
	}
	rawMeta, err := a.buildUpstreamMeta(negotiated)
	if err != nil {
		return nil, err
	}
	params["_meta"] = rawMeta

	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("discovery: encode params: %w", err)
	}
	return &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		ID:      json.RawMessage(`1`),
		Method:  method,
		Params:  raw,
	}, nil
}

// buildUpstreamMeta constructs the fresh `_meta` object for a forwarded
// discovery/list request (HUB-124). Discovery carries no downstream client
// context, so the hub's brokerable capability set is advertised directly as
// clientCapabilities; the meta package narrows it against itself, yielding the
// hub's brokerable set (an empty object when the hub brokers nothing).
func (a *DefaultAggregator) buildUpstreamMeta(negotiated string) (json.RawMessage, error) {
	upMeta, err := meta.BuildUpstreamMeta(a.brokerableDownstreamMeta(), meta.BuildUpstreamOptions{
		NegotiatedUpstreamVersion: negotiated,
		HubClientInfo:             a.hubClientInfo,
		BrokerableCaps:            a.brokerableCaps,
	})
	if err != nil {
		return nil, err
	}
	return upMeta.Encode()
}

// brokerableDownstreamMeta synthesizes a downstream `_meta` whose
// clientCapabilities is the hub's full brokerable set, so BuildUpstreamMeta
// narrows it to exactly that set for the discovery path.
func (a *DefaultAggregator) brokerableDownstreamMeta() meta.Meta {
	caps := make(map[string]json.RawMessage, len(a.brokerableCaps))
	for name := range a.brokerableCaps {
		caps[name] = json.RawMessage(`{}`)
	}
	m := make(meta.Meta)
	if raw, err := json.Marshal(caps); err == nil {
		m[protocol.MetaClientCapabilities] = raw
	}
	return m
}

// mergeDiscover merges one upstream's server/discover result into agg.
func (a *DefaultAggregator) mergeDiscover(
	id string, cfg config.MCPBackend, resp *jsonrpc.Response, agg *aggregation,
) {
	obj := decodeResultObject(resp.Result)
	if obj == nil {
		return
	}
	a.mergeCapabilities(obj, agg)
	mergeInstructions(obj, agg)
	agg.absorbCacheHints(obj)

	// Merge each embedded primitive list carried in the discover result.
	for method, key := range listItemKeys {
		if raw, ok := obj[key]; ok {
			a.mergeItems(id, cfg, method, raw, agg)
		}
	}
}

// mergeCapabilities unions the upstream capabilities into the aggregate.
func (a *DefaultAggregator) mergeCapabilities(obj map[string]json.RawMessage, agg *aggregation) {
	raw, ok := obj["capabilities"]
	if !ok {
		return
	}
	var caps map[string]json.RawMessage
	if err := json.Unmarshal(raw, &caps); err != nil {
		return
	}
	for k, v := range caps {
		if _, exists := agg.capabilities[k]; !exists {
			agg.capabilities[k] = v
		}
	}
}

// mergeList merges one upstream's */list page into agg and records the next
// per-upstream cursor when the upstream reports more pages.
func (a *DefaultAggregator) mergeList(
	id string,
	cfg config.MCPBackend,
	method string,
	resp *jsonrpc.Response,
	agg *aggregation,
	nextState *CursorState,
) {
	obj := decodeResultObject(resp.Result)
	if obj == nil {
		return
	}
	agg.absorbCacheHints(obj)
	if raw, ok := obj[listItemKeys[method]]; ok {
		a.mergeItems(id, cfg, method, raw, agg)
	}
	if nc := decodeStringField(obj, "nextCursor"); nc != "" {
		nextState.set(id, nc)
	}
}

// mergeItems namespaces and appends the primitives from one upstream list,
// applying the upstream allow/deny policy and rejecting tools whose
// x-mcp-header annotations violate the schema constraints (HUB-145).
func (a *DefaultAggregator) mergeItems(
	id string, cfg config.MCPBackend, method string, raw json.RawMessage, agg *aggregation,
) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return
	}
	for _, item := range items {
		a.mergeItem(id, cfg, method, item, agg)
	}
}

// mergeItem processes a single primitive: policy filtering, x-mcp-header
// validation (tools only), schema-safety validation, drift detection, trust
// policy, name/uri re-namespacing, then appends it.
func (a *DefaultAggregator) mergeItem(
	id string, cfg config.MCPBackend, method string, item json.RawMessage, agg *aggregation,
) {
	obj := decodeResultObject(item)
	if obj == nil {
		return
	}
	original := firstNameField(obj)
	if !policyAllows(cfg, original) {
		return
	}
	if method == protocol.MethodToolsList && !a.validateTool(id, original, obj) {
		return
	}
	if a.driftExcludes(id, original, item) {
		return
	}
	item = security.ApplyTrustPolicy(cfg, a.effectiveTrustPolicy(), item)
	if obj = decodeResultObject(item); obj == nil {
		return
	}
	rewritten, nsName, err := a.namespaceItem(id, obj)
	if err != nil {
		a.logger.Warn("mcp discovery: namespace item failed",
			observability.String("upstream", id), observability.Error(err))
		return
	}
	agg.add(nsName, rewritten)
}

// validateTool enforces the x-mcp-header annotation rules and the bounded
// schema-safety checks for a tool (HUB-403/404/145). It returns false when the
// tool must be rejected, recording the rejection metric and a WARN.
func (a *DefaultAggregator) validateTool(id, tool string, obj map[string]json.RawMessage) bool {
	if reason := validateXMcpHeader(obj); reason != "" {
		a.metrics.RecordSchemaRejection(protocol.MethodToolsList)
		a.logger.Warn("mcp discovery: rejected tool with invalid x-mcp-header",
			observability.String("upstream", id),
			observability.String("tool", tool),
			observability.String("reason", reason))
		return false
	}
	if err := a.validateToolSchemas(obj); err != nil {
		a.metrics.RecordSchemaRejection(protocol.MethodToolsList)
		a.logger.Warn("mcp discovery: rejected tool with unsafe schema",
			observability.String("upstream", id),
			observability.String("tool", tool),
			observability.Error(err))
		return false
	}
	return true
}

// validateToolSchemas walks a tool's input/output schemas under the configured
// cost bounds, rejecting network $refs (HUB-403/404). It is a no-op when no
// schema limits are configured.
func (a *DefaultAggregator) validateToolSchemas(obj map[string]json.RawMessage) error {
	if a.schemaLimits.MaxDepth == 0 && a.schemaLimits.MaxNodes == 0 && a.schemaLimits.Budget == 0 {
		return nil
	}
	for _, field := range []string{"inputSchema", "outputSchema"} {
		raw, ok := obj[field]
		if !ok {
			continue
		}
		if err := security.ValidateSchema(raw, a.schemaLimits); err != nil {
			return err
		}
	}
	return nil
}

// driftExcludes records a tool-definition drift observation and reports whether
// the primitive must be excluded pending re-approval (HUB-402). When drift is
// detected it emits a WARN and increments the drift metric.
func (a *DefaultAggregator) driftExcludes(id, name string, item json.RawMessage) bool {
	if a.drift == nil {
		return false
	}
	res := a.drift.Observe(id, name, item)
	if !res.Changed {
		return false
	}
	a.metrics.RecordDrift(id, name)
	a.logger.Warn("mcp discovery: tool definition drift detected",
		observability.String("upstream", id),
		observability.String("tool", name),
		observability.String("hash", res.Hash),
		observability.Bool("excluded", res.Exclude))
	return res.Exclude
}

// effectiveTrustPolicy returns the configured trust policy or the strip default.
func (a *DefaultAggregator) effectiveTrustPolicy() string {
	if a.trustPolicy == "" {
		return config.MCPTrustPolicyStrip
	}
	return a.trustPolicy
}

// namespaceItem re-namespaces the identifying name/uri fields of a primitive
// object, preserving every other field (schemas) byte-for-byte (HUB-169), and
// returns the re-encoded object plus the namespaced name used for ordering.
func (a *DefaultAggregator) namespaceItem(
	id string, obj map[string]json.RawMessage,
) (encoded json.RawMessage, nsSortKey string, err error) {
	nsName := ""
	for _, field := range nameFields {
		raw, ok := obj[field]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		ns, nsErr := a.mapper.Namespace(id, s)
		if nsErr != nil {
			return nil, "", nsErr
		}
		fieldRaw, mErr := json.Marshal(ns)
		if mErr != nil {
			return nil, "", fmt.Errorf("discovery: encode namespaced field: %w", mErr)
		}
		obj[field] = fieldRaw
		if nsName == "" {
			nsName = ns
		}
	}
	out, mErr := json.Marshal(obj)
	if mErr != nil {
		return nil, "", fmt.Errorf("discovery: encode item: %w", mErr)
	}
	return out, nsName, nil
}

// ── aggregation state ────────────────────────────────────────────────────

// aggregation accumulates merged primitives, capabilities, instructions and
// cache hints across upstreams for a single discovery/list operation.
type aggregation struct {
	method       string
	items        []orderedItem
	capabilities map[string]json.RawMessage
	instructions []string
	minTTLMs     int64
	haveTTL      bool
	private      bool
	degraded     bool
}

// orderedItem pairs a namespaced sort key with its encoded primitive.
type orderedItem struct {
	key  string
	item json.RawMessage
}

// newAggregation constructs an empty aggregation for a method.
func newAggregation(method string) *aggregation {
	return &aggregation{
		method:       method,
		capabilities: make(map[string]json.RawMessage),
	}
}

// add records a namespaced primitive for later stable ordering.
func (g *aggregation) add(key string, item json.RawMessage) {
	g.items = append(g.items, orderedItem{key: key, item: item})
}

// markDegraded records that an upstream was unavailable (HUB-167).
func (g *aggregation) markDegraded() { g.degraded = true }

// absorbCacheHints folds an upstream result's ttlMs / cacheScope into the
// aggregate: TTL becomes the minimum across contributors and the scope becomes
// private if any contributor is private (HUB-182).
func (g *aggregation) absorbCacheHints(obj map[string]json.RawMessage) {
	if raw, ok := obj["ttlMs"]; ok {
		var ttl int64
		if err := json.Unmarshal(raw, &ttl); err == nil && ttl >= 0 {
			if !g.haveTTL || ttl < g.minTTLMs {
				g.minTTLMs = ttl
				g.haveTTL = true
			}
		}
	}
	if scope := decodeStringField(obj, "cacheScope"); scope == cacheScopePrivate {
		g.private = true
	}
}

// ordered returns the items sorted by namespaced key for deterministic,
// replica-stable output (HUB-164).
func (g *aggregation) ordered() []json.RawMessage {
	sort.SliceStable(g.items, func(i, j int) bool {
		return g.items[i].key < g.items[j].key
	})
	out := make([]json.RawMessage, 0, len(g.items))
	for _, it := range g.items {
		out = append(out, it.item)
	}
	return out
}

// ttlAndScope resolves the emitted ttlMs and cacheScope, applying the degraded
// TTL shortening (HUB-167) and the private/public determination (HUB-182).
func (g *aggregation) ttlAndScope() (ttlMs int64, scopeName string) {
	ttl := defaultCompleteTTLMs
	if g.haveTTL {
		ttl = g.minTTLMs
	}
	if g.degraded && ttl > degradedTTLMs {
		ttl = degradedTTLMs
	}
	scope := cacheScopePublic
	if g.private {
		scope = cacheScopePrivate
	}
	return ttl, scope
}

// finalizeList produces the DiscoverResult for a */list operation.
func (g *aggregation) finalizeList() *DiscoverResult {
	ttl, scope := g.ttlAndScope()
	return &DiscoverResult{
		Method:     g.method,
		Items:      g.ordered(),
		TTLMs:      ttl,
		CacheScope: scope,
		Degraded:   g.degraded,
	}
}

// finalizeDiscover produces the DiscoverResult for server/discover.
func (g *aggregation) finalizeDiscover() *DiscoverResult {
	ttl, scope := g.ttlAndScope()
	return &DiscoverResult{
		Method:       g.method,
		Items:        g.ordered(),
		Capabilities: g.capabilities,
		Instructions: strings.Join(g.instructions, "\n\n"),
		TTLMs:        ttl,
		CacheScope:   scope,
		Degraded:     g.degraded,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────

// mergeInstructions appends an upstream's instructions text to the aggregate.
func mergeInstructions(obj map[string]json.RawMessage, agg *aggregation) {
	if s := decodeStringField(obj, "instructions"); s != "" {
		agg.instructions = append(agg.instructions, s)
	}
}

// decodeResultObject decodes a JSON object into a raw-valued map, returning nil
// when the input is empty or not an object.
func decodeResultObject(raw json.RawMessage) map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	obj := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	return obj
}

// decodeStringField returns the string value at key, or "" when absent or not
// a JSON string.
func decodeStringField(obj map[string]json.RawMessage, key string) string {
	raw, ok := obj[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// firstNameField returns the first present name/uri field value.
func firstNameField(obj map[string]json.RawMessage) string {
	for _, field := range nameFields {
		if s := decodeStringField(obj, field); s != "" {
			return s
		}
	}
	return ""
}

// policyAllows applies the upstream allow/deny lists to a primitive name. An
// empty allow list allows everything not denied (HUB-165 policy filtering).
func policyAllows(cfg config.MCPBackend, name string) bool {
	for _, d := range cfg.Deny {
		if d == name {
			return false
		}
	}
	if len(cfg.Allow) == 0 {
		return true
	}
	for _, a := range cfg.Allow {
		if a == name {
			return true
		}
	}
	return false
}
