// Package helpers provides common test utilities for the API Gateway tests.
//
// This file provides MCP-hub (Model Context Protocol) test helpers shared by
// the functional, integration and e2e suites. Like the other helper files in
// this package it carries no build tag so it compiles under every test tag.
//
// The helpers here reuse the production MCP wiring from cmd/gateway
// (initMCPHandler / initMCPSubsystem) as closely as practical: a dedicated MCP
// upstream backend.Registry, an mcpproxy.HTTPHubClient, a namespace mapper, an
// optional discovery aggregator (with an in-process AEAD cursor codec), and the
// shared per-route middleware manager. The composed MCP path dispatcher is
// installed as the gateway's route handler via gateway.WithRouteHandler, which
// is exactly how the dispatcher is threaded into the global middleware chain in
// production.
package helpers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/mcp/discovery"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/mcp/meta"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// MCP mirrored-header names and the hub protocol constants surfaced here so
// tests do not have to import the internal mcp packages directly.
const (
	// MCPHeaderMethod mirrors the JSON-RPC method (HUB-141).
	MCPHeaderMethod = "Mcp-Method"
	// MCPHeaderName mirrors params.name / params.uri (HUB-141).
	MCPHeaderName = "Mcp-Name"
	// MCPHeaderProtocolVersion carries the protocol revision (HUB-122).
	MCPHeaderProtocolVersion = "MCP-Protocol-Version"

	// MCPProtocolVersion is the hub's target protocol revision (HUB-123).
	MCPProtocolVersion = protocol.LatestVersion

	// MCP `_meta` keys (vendor-prefixed per the MCP specification).
	metaProtocolVersionKey    = protocol.MetaProtocolVersion
	metaClientCapabilitiesKey = protocol.MetaClientCapabilities

	// MCP JSON-RPC method names.
	MCPMethodToolsList      = protocol.MethodToolsList
	MCPMethodToolsCall      = protocol.MethodToolsCall
	MCPMethodServerDiscover = protocol.MethodServerDiscover

	// MCP error codes surfaced downstream.
	MCPErrHeaderMismatch             = protocol.HeaderMismatch             // -32020
	MCPErrUnsupportedProtocolVersion = protocol.UnsupportedProtocolVersion // -32022
	MCPErrInvalidParams              = protocol.InvalidParams              // -32602
)

// MCPTestConfig holds MCP mock upstream endpoints resolved from environment
// variables with defaults for the docker-compose test ENV.
type MCPTestConfig struct {
	// Backend1URL / Backend2URL are the downstream MCP mock POST endpoints.
	Backend1URL string
	Backend2URL string
	// Backend1MetricsURL / Backend2MetricsURL are the mock /metrics endpoints.
	Backend1MetricsURL string
	Backend2MetricsURL string
}

// GetMCPTestConfig returns MCP test configuration from environment variables.
// Defaults mirror the docker-compose ENV (mcp_mock_1/2).
func GetMCPTestConfig() MCPTestConfig {
	return MCPTestConfig{
		Backend1URL:        getEnvOrDefault("TEST_MCP_BACKEND1_URL", "http://127.0.0.1:8821/mcp"),
		Backend2URL:        getEnvOrDefault("TEST_MCP_BACKEND2_URL", "http://127.0.0.1:8822/mcp"),
		Backend1MetricsURL: getEnvOrDefault("TEST_MCP_BACKEND1_METRICS_URL", "http://127.0.0.1:9095"),
		Backend2MetricsURL: getEnvOrDefault("TEST_MCP_BACKEND2_METRICS_URL", "http://127.0.0.1:9096"),
	}
}

// MCPHostPort splits a mock MCP URL (e.g. http://127.0.0.1:8821/mcp) into its
// host, port and path components, applying the default MCP path when absent.
func MCPHostPort(rawURL string) (host string, port int, path string, err error) {
	u, perr := url.Parse(rawURL)
	if perr != nil {
		return "", 0, "", fmt.Errorf("parse mcp url %q: %w", rawURL, perr)
	}
	host = u.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}
	portStr := u.Port()
	if portStr == "" {
		portStr = "80"
	}
	port, perr = strconv.Atoi(portStr)
	if perr != nil {
		return "", 0, "", fmt.Errorf("parse mcp port from %q: %w", rawURL, perr)
	}
	path = u.Path
	if path == "" {
		path = config.DefaultMCPUpstreamPath
	}
	return host, port, path, nil
}

// IsMCPMockAvailable reports whether an MCP mock is reachable at its POST /mcp
// endpoint. It sends a GET (which the mock answers with 405 by design) so a
// non-connection error is treated as available.
func IsMCPMockAvailable(mcpURL string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(mcpURL)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// SkipIfMCPMockUnavailable skips the test when the MCP mock is not reachable.
func SkipIfMCPMockUnavailable(t interface{ Skip(...interface{}) }, mcpURL string) {
	if !IsMCPMockAvailable(mcpURL) {
		t.Skip("MCP mock not available at", mcpURL, "- skipping test")
	}
}

// ----------------------------------------------------------------------------
// Config builders
// ----------------------------------------------------------------------------

// MCPBackendFromURL builds an MCPBackend pointing at the given mock URL. The
// namespace prefix defaults to the backend name so a namespaced tool
// "<name>.<tool>" de-namespaces back to the upstream tool.
func MCPBackendFromURL(name, rawURL string) (config.MCPBackend, error) {
	host, port, path, err := MCPHostPort(rawURL)
	if err != nil {
		return config.MCPBackend{}, err
	}
	return config.MCPBackend{
		Name:            name,
		NamespacePrefix: name,
		Transport:       config.MCPBackendTransportStreamableHTTP,
		Path:            path,
		Hosts:           []config.BackendHost{{Address: host, Port: port}},
	}, nil
}

// MCPBackendToDeadPort builds an MCPBackend whose single host points at a port
// with no listener, used to exercise degraded operation (one upstream down).
func MCPBackendToDeadPort(name string, deadPort int) config.MCPBackend {
	return config.MCPBackend{
		Name:            name,
		NamespacePrefix: name,
		Transport:       config.MCPBackendTransportStreamableHTTP,
		Path:            config.DefaultMCPUpstreamPath,
		Hosts:           []config.BackendHost{{Address: "127.0.0.1", Port: deadPort}},
	}
}

// MCPGatewayConfigOptions customizes BuildMCPGatewayConfig.
type MCPGatewayConfigOptions struct {
	// Name is the gateway metadata name.
	Name string
	// Port is the listener port.
	Port int
	// Certs, when non-nil, installs an HTTPS listener terminating TLS.
	Certs *TestCertificates
	// Backends are the MCP upstreams.
	Backends []config.MCPBackend
	// WeightedUpstreams, when non-empty, configures the MCP route with weighted
	// upstream references (canary / A-B) instead of the legacy equal-weight
	// Upstreams list derived from Backends. Mutually exclusive with the legacy
	// list at the config level, so when this is set the route's Upstreams is
	// left empty.
	WeightedUpstreams []config.MCPUpstreamRef
	// RouteName is the MCP route name.
	RouteName string
	// AllowedOrigins installs the downstream Origin allowlist (HUB-106).
	AllowedOrigins []string
	// Authentication is the route-level authentication (OIDC/JWT) applied via
	// the projected middleware route (ToMiddlewareRoute).
	Authentication *config.AuthenticationConfig
	// RateLimit is the route-level rate limit applied via the middleware route.
	RateLimit *config.RateLimitConfig
	// DryRun enables shadow mode on the MCP config (HUB-507).
	DryRun bool
	// MCPPath overrides the downstream MCP endpoint path (default /mcp).
	MCPPath string
}

// BuildMCPGatewayConfig builds a gateway config with a single listener (HTTP,
// or HTTPS when Certs is set) and one MCP route fanning out to the provided
// upstreams. It mirrors BuildGraphQLGatewayConfig for the MCP hub.
func BuildMCPGatewayConfig(opts MCPGatewayConfigOptions) *config.GatewayConfig {
	listener := config.Listener{
		Name:     "http",
		Port:     opts.Port,
		Protocol: config.ProtocolHTTP,
		Bind:     "127.0.0.1",
	}
	if opts.Certs != nil {
		listener.Name = "https"
		listener.Protocol = config.ProtocolHTTPS
		listener.TLS = &config.ListenerTLSConfig{
			Mode:       "SIMPLE",
			MinVersion: "TLS12",
			CertFile:   opts.Certs.ServerCertPath(),
			KeyFile:    opts.Certs.ServerKeyPath(),
		}
	}

	upstreamNames := make([]string, 0, len(opts.Backends))
	for i := range opts.Backends {
		upstreamNames = append(upstreamNames, opts.Backends[i].Name)
	}

	routeName := opts.RouteName
	if routeName == "" {
		routeName = "mcp-route"
	}
	name := opts.Name
	if name == "" {
		name = "mcp-test-gateway"
	}

	mcpCfg := &config.MCPConfig{
		AllowedOrigins: opts.AllowedOrigins,
		DryRun:         opts.DryRun,
	}
	if opts.MCPPath != "" {
		mcpCfg.Path = opts.MCPPath
	}

	route := config.MCPRoute{
		Name:           routeName,
		Timeout:        config.Duration(30 * time.Second),
		Authentication: opts.Authentication,
		RateLimit:      opts.RateLimit,
	}
	// WeightedUpstreams and Upstreams are mutually exclusive at the config
	// level: prefer the weighted form when supplied so weighted-routing tests
	// exercise the canary/A-B path, otherwise fall back to the legacy list.
	if len(opts.WeightedUpstreams) > 0 {
		route.WeightedUpstreams = opts.WeightedUpstreams
	} else {
		route.Upstreams = upstreamNames
	}

	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: name},
		Spec: config.GatewaySpec{
			Listeners:   []config.Listener{listener},
			MCPRoutes:   []config.MCPRoute{route},
			MCPBackends: opts.Backends,
			MCP:         mcpCfg,
		},
	}
}

// ----------------------------------------------------------------------------
// JSON-RPC body builders
// ----------------------------------------------------------------------------

// MCPRequestBody is a builder for a downstream JSON-RPC MCP request body
// carrying the required _meta (protocolVersion + clientCapabilities).
type MCPRequestBody struct {
	// Method is the JSON-RPC method (e.g. tools/call).
	Method string
	// Name is the primitive name (params.name); empty omits it.
	Name string
	// Arguments is placed under params.arguments for tools/call; nil omits it.
	Arguments map[string]any
	// Extra merges arbitrary keys into params.
	Extra map[string]any
	// ID is the JSON-RPC request id; defaults to 1.
	ID int

	// OmitMeta / OmitVersion / OmitCaps drive negative _meta tests.
	OmitMeta    bool
	OmitVersion bool
	OmitCaps    bool
	// Version overrides the _meta protocolVersion.
	Version string
}

// Build marshals the request body to JSON. It uses the vendor-prefixed _meta
// keys the hub requires downstream (HUB-121).
func (b MCPRequestBody) Build() ([]byte, error) {
	params := map[string]any{}
	if b.Name != "" {
		params["name"] = b.Name
	}
	if b.Arguments != nil {
		params["arguments"] = b.Arguments
	}
	for k, v := range b.Extra {
		params[k] = v
	}
	if !b.OmitMeta {
		metaObj := map[string]any{}
		version := b.Version
		if version == "" {
			version = MCPProtocolVersion
		}
		if !b.OmitVersion {
			metaObj[metaProtocolVersionKey] = version
		}
		if !b.OmitCaps {
			metaObj[metaClientCapabilitiesKey] = map[string]any{}
		}
		params["_meta"] = metaObj
	}
	id := b.ID
	if id == 0 {
		id = 1
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  b.Method,
		"params":  json.RawMessage(rawParams),
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	return raw, nil
}

// MustBuild builds the body, panicking on error (test convenience).
func (b MCPRequestBody) MustBuild() []byte {
	raw, err := b.Build()
	if err != nil {
		panic(err)
	}
	return raw
}

// ----------------------------------------------------------------------------
// Request sending / response parsing
// ----------------------------------------------------------------------------

// MCPRequestOptions carries per-request options for PostMCP.
type MCPRequestOptions struct {
	// Method mirrors into the Mcp-Method header. Empty omits it.
	Method string
	// Name mirrors into the Mcp-Name header. Empty omits it.
	Name string
	// ProtocolVersion sets the MCP-Protocol-Version header. When empty the
	// hub default is sent; use OmitProtocolVersion to omit it entirely.
	ProtocolVersion string
	// OmitProtocolVersion omits the MCP-Protocol-Version header.
	OmitProtocolVersion bool
	// Authorization sets the Authorization header verbatim (e.g. "Bearer x").
	Authorization string
	// Origin sets the Origin header (HUB-106).
	Origin string
	// ExtraHeaders sets additional headers verbatim.
	ExtraHeaders map[string]string
	// Client overrides the HTTP client (e.g. a TLS client). Defaults to
	// HTTPClient().
	Client *http.Client
}

// PostMCP posts a JSON-RPC body to the MCP endpoint at baseURL+path with the
// mirrored MCP headers set from opts, returning the raw HTTP response.
func PostMCP(baseURL, path string, body []byte, opts MCPRequestOptions) (*http.Response, error) {
	if path == "" {
		path = config.DefaultMCPPath
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+path, bytesReader(body))
	if err != nil {
		return nil, fmt.Errorf("new mcp request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if !opts.OmitProtocolVersion {
		version := opts.ProtocolVersion
		if version == "" {
			version = MCPProtocolVersion
		}
		req.Header.Set(MCPHeaderProtocolVersion, version)
	}
	if opts.Method != "" {
		req.Header.Set(MCPHeaderMethod, opts.Method)
	}
	if opts.Name != "" {
		req.Header.Set(MCPHeaderName, opts.Name)
	}
	if opts.Authorization != "" {
		req.Header.Set("Authorization", opts.Authorization)
	}
	if opts.Origin != "" {
		req.Header.Set("Origin", opts.Origin)
	}
	for k, v := range opts.ExtraHeaders {
		req.Header.Set(k, v)
	}

	client := opts.Client
	if client == nil {
		client = HTTPClient()
	}
	return client.Do(req)
}

// MCPResponse is a decoded JSON-RPC response with helpers for assertions.
type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPRPCError    `json:"error,omitempty"`
}

// MCPRPCError is a JSON-RPC error object.
type MCPRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// DecodeMCPResponse reads and decodes the JSON-RPC response body.
func DecodeMCPResponse(resp *http.Response) (*MCPResponse, error) {
	defer resp.Body.Close()
	var out MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode mcp response: %w", err)
	}
	return &out, nil
}

// ResultTools decodes result.tools into a slice of tool objects. It is used to
// assert namespacing on tools/list and server/discover results.
func (r *MCPResponse) ResultTools() ([]map[string]any, error) {
	if r == nil || len(r.Result) == 0 {
		return nil, fmt.Errorf("no result")
	}
	var wrapper struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &wrapper); err != nil {
		return nil, fmt.Errorf("decode tools: %w", err)
	}
	return wrapper.Tools, nil
}

// ToolNames returns the sorted-as-received list of namespaced tool names in the
// result.
func (r *MCPResponse) ToolNames() ([]string, error) {
	tools, err := r.ResultTools()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		if n, ok := t["name"].(string); ok {
			names = append(names, n)
		}
	}
	return names, nil
}

// ----------------------------------------------------------------------------
// Full-gateway MCP harness (mirrors cmd/gateway initMCPSubsystem)
// ----------------------------------------------------------------------------

// MCPGatewayInstance represents a running gateway serving the MCP hub endpoint.
type MCPGatewayInstance struct {
	Gateway         *gateway.Gateway
	Config          *config.GatewayConfig
	Handler         *gateway.MCPHandler
	Registry        *backend.Registry
	RouteMiddleware *gateway.RouteMiddlewareManager
	CacheFactory    *gateway.CacheFactory
	BaseURL         string
	// MCPPath is the resolved downstream MCP endpoint path.
	MCPPath string
}

// MCPGatewayOption customizes StartMCPGateway.
type MCPGatewayOption func(*mcpGatewayOptions)

type mcpGatewayOptions struct {
	withAggregator     bool
	withRouteMiddlware bool
	vaultClient        vault.Client
}

// WithMCPAggregator enables the discovery aggregator (server/discover +
// tools/list aggregation across upstreams) using an in-process AEAD cursor
// codec. Without it discovery/list fall through to single-upstream passthrough.
func WithMCPAggregator() MCPGatewayOption {
	return func(o *mcpGatewayOptions) { o.withAggregator = true }
}

// WithMCPRouteMiddleware enables the shared per-route middleware manager so the
// MCP route's Authentication / RateLimit are enforced (OIDC + rate limiting).
func WithMCPRouteMiddleware() MCPGatewayOption {
	return func(o *mcpGatewayOptions) { o.withRouteMiddlware = true }
}

// StartMCPGateway starts a gateway whose route handler is the MCP path
// dispatcher, mirroring the production wiring in cmd/gateway.initMCPSubsystem.
func StartMCPGateway(
	ctx context.Context, cfg *config.GatewayConfig, opts ...MCPGatewayOption,
) (*MCPGatewayInstance, error) {
	o := &mcpGatewayOptions{}
	for _, opt := range opts {
		opt(o)
	}

	logger := observability.NopLogger()

	// Dedicated MCP upstream registry (mirrors initMCPBackendRegistry).
	registry := backend.NewRegistry(logger)
	if err := registry.LoadFromConfig(config.MCPBackendsToBackends(cfg.Spec.MCPBackends)); err != nil {
		return nil, fmt.Errorf("load mcp backends: %w", err)
	}
	if err := registry.StartAll(ctx); err != nil {
		return nil, fmt.Errorf("start mcp backends: %w", err)
	}

	// Namespace mapper.
	sep := ""
	if cfg.Spec.MCP != nil {
		sep = cfg.Spec.MCP.GetEffectiveNamespaceSep()
	}
	mapper, err := namespace.NewDefaultMapper(sep)
	if err != nil {
		_ = registry.StopAll(ctx)
		return nil, fmt.Errorf("build mcp mapper: %w", err)
	}

	hub := mcpproxy.NewHTTPHubClient(mcpproxy.WithHubClientLogger(logger))

	upstreams := mcpUpstreamMap(cfg.Spec.MCPBackends)

	handlerOpts := []gateway.MCPHandlerOption{
		gateway.WithMCPHandlerLogger(logger),
		gateway.WithMCPHandlerBackendRegistry(registry),
		gateway.WithMCPHandlerHub(hub),
		gateway.WithMCPHandlerMapper(mapper),
		gateway.WithMCPHandlerConfig(cfg.Spec.MCPRoutes, upstreams, cfg.Spec.MCP),
		gateway.WithMCPHandlerClientInfo(mcpHubInfo()),
		gateway.WithMCPHandlerServerInfo(mcpHubInfo()),
	}
	if cfg.Spec.MCP != nil && cfg.Spec.MCP.DryRun {
		handlerOpts = append(handlerOpts, gateway.WithMCPHandlerDryRun(true))
	}

	var routeMwMgr *gateway.RouteMiddlewareManager
	var cacheFactory *gateway.CacheFactory
	if o.withRouteMiddlware {
		cacheFactory = gateway.NewCacheFactory(logger, o.vaultClient)
		mwOpts := []gateway.RouteMiddlewareOption{
			gateway.WithRouteMiddlewareCacheFactory(cacheFactory),
		}
		if o.vaultClient != nil {
			mwOpts = append(mwOpts, gateway.WithRouteMiddlewareVaultClient(o.vaultClient))
		}
		routeMwMgr = gateway.NewRouteMiddlewareManager(&cfg.Spec, logger, mwOpts...)
		handlerOpts = append(handlerOpts, gateway.WithMCPHandlerRouteMiddleware(routeMwMgr))
	}

	if o.withAggregator {
		agg, aerr := buildTestMCPAggregator(registry, mapper, hub, upstreams, logger)
		if aerr != nil {
			cleanupMCP(ctx, registry, routeMwMgr, cacheFactory)
			return nil, fmt.Errorf("build mcp aggregator: %w", aerr)
		}
		handlerOpts = append(handlerOpts, gateway.WithMCPHandlerAggregator(agg))
	}

	handler, err := gateway.NewMCPHandler(handlerOpts...)
	if err != nil {
		cleanupMCP(ctx, registry, routeMwMgr, cacheFactory)
		return nil, fmt.Errorf("build mcp handler: %w", err)
	}

	mcpPath := gateway.MCPPathFromConfig(cfg)
	dispatcher := gateway.NewMCPPathDispatcher(mcpPath, handler, http.NotFoundHandler())

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(dispatcher),
	)
	if err != nil {
		handler.Close()
		cleanupMCP(ctx, registry, routeMwMgr, cacheFactory)
		return nil, fmt.Errorf("create gateway: %w", err)
	}
	if err := gw.Start(ctx); err != nil {
		handler.Close()
		cleanupMCP(ctx, registry, routeMwMgr, cacheFactory)
		return nil, fmt.Errorf("start gateway: %w", err)
	}

	port := 8080
	scheme := "http"
	if len(cfg.Spec.Listeners) > 0 {
		port = cfg.Spec.Listeners[0].Port
		if cfg.Spec.Listeners[0].Protocol == config.ProtocolHTTPS {
			scheme = "https"
		}
	}

	return &MCPGatewayInstance{
		Gateway:         gw,
		Config:          cfg,
		Handler:         handler,
		Registry:        registry,
		RouteMiddleware: routeMwMgr,
		CacheFactory:    cacheFactory,
		BaseURL:         fmt.Sprintf("%s://127.0.0.1:%d", scheme, port),
		MCPPath:         mcpPath,
	}, nil
}

// Stop stops the MCP gateway instance and releases handler / middleware / cache
// resources.
func (gi *MCPGatewayInstance) Stop(ctx context.Context) error {
	if gi.Handler != nil {
		gi.Handler.Close()
	}
	if gi.Registry != nil {
		_ = gi.Registry.StopAll(ctx)
	}
	if gi.RouteMiddleware != nil {
		gi.RouteMiddleware.Stop()
	}
	if gi.CacheFactory != nil {
		_ = gi.CacheFactory.Close()
	}
	if gi.Gateway != nil {
		return gi.Gateway.Stop(ctx)
	}
	return nil
}

// cleanupMCP releases partially-constructed MCP resources on a start failure.
func cleanupMCP(
	ctx context.Context,
	registry *backend.Registry,
	routeMw *gateway.RouteMiddlewareManager,
	cacheFactory *gateway.CacheFactory,
) {
	if registry != nil {
		_ = registry.StopAll(ctx)
	}
	if routeMw != nil {
		routeMw.Stop()
	}
	if cacheFactory != nil {
		_ = cacheFactory.Close()
	}
}

// mcpUpstreamMap builds a name-keyed, defaulted map of MCP upstreams
// (mirrors cmd/gateway.mcpUpstreamMap).
func mcpUpstreamMap(backends []config.MCPBackend) map[string]config.MCPBackend {
	m := make(map[string]config.MCPBackend, len(backends))
	for i := range backends {
		b := backends[i]
		b.SetDefaults()
		m[b.Name] = b
	}
	return m
}

// mcpHubInfo returns the hub participant identity used as clientInfo/serverInfo.
func mcpHubInfo() meta.Info {
	return meta.Info{Name: "avapigw-mcp-hub", Version: "test"}
}

// buildTestMCPAggregator builds the discovery aggregator over an in-process
// AEAD cursor codec (single-replica), mirroring cmd/gateway.buildMCPAggregator.
func buildTestMCPAggregator(
	registry *backend.Registry,
	mapper namespace.Mapper,
	hub mcpproxy.HubClient,
	upstreams map[string]config.MCPBackend,
	logger observability.Logger,
) (discovery.Aggregator, error) {
	key := make([]byte, envelope.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate aead key: %w", err)
	}
	sealer, err := envelope.NewAEADSealer(key)
	if err != nil {
		return nil, fmt.Errorf("build sealer: %w", err)
	}
	cursors, err := discovery.NewCursorCodec(sealer)
	if err != nil {
		return nil, fmt.Errorf("build cursor codec: %w", err)
	}
	resolver := gateway.NewMCPUpstreamResolver(registry, upstreams)
	agg, err := discovery.NewDefaultAggregator(hub, resolver, mapper, cursors,
		discovery.WithAggregatorLogger(logger),
	)
	if err != nil {
		return nil, fmt.Errorf("build aggregator: %w", err)
	}
	return agg, nil
}

// bytesReader returns an io.Reader over body, or nil for an empty body.
func bytesReader(body []byte) io.Reader {
	if len(body) == 0 {
		return nil
	}
	return bytes.NewReader(body)
}

// GetFreeTCPPort returns an OS-assigned free TCP port for test listeners.
func GetFreeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
