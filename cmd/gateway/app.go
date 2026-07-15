package main

import (
	"net/http"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	aggregategraphql "github.com/vyrodovalexey/avapigw/internal/aggregate/graphqladapter"
	aggregategrpc "github.com/vyrodovalexey/avapigw/internal/aggregate/grpcadapter"
	aggregaterest "github.com/vyrodovalexey/avapigw/internal/aggregate/rest"
	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	authjwt "github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
	"github.com/vyrodovalexey/avapigw/internal/authz"
	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	backendauth "github.com/vyrodovalexey/avapigw/internal/backend/auth"
	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/encoding"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	graphqlmetrics "github.com/vyrodovalexey/avapigw/internal/graphql/metrics"
	graphqlproxy "github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/health"
	backendmetricspkg "github.com/vyrodovalexey/avapigw/internal/metrics/backend"
	routepkg "github.com/vyrodovalexey/avapigw/internal/metrics/route"
	"github.com/vyrodovalexey/avapigw/internal/metrics/streaming"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/openapi"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/internal/security"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/transform"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// application holds all application components.
type application struct {
	gateway             *gateway.Gateway
	backendRegistry     *backend.Registry
	grpcBackendRegistry *backend.Registry
	router              *router.Router
	healthChecker       *health.Checker
	metrics             *observability.Metrics
	reloadMetrics       *reloadMetrics
	metricsServer       *http.Server
	tracer              *observability.Tracer
	config              *config.GatewayConfig
	rateLimiter         middleware.RateLimiterHandle
	maxSessionsLimiter  *middleware.MaxSessionsLimiter
	auditLogger         *audit.AtomicAuditLogger
	auditMetrics        *audit.Metrics
	vaultClient         vault.Client
	authMetrics         *auth.Metrics
	cacheFactory        *gateway.CacheFactory
	routeMiddlewareMgr  *gateway.RouteMiddlewareManager
	graphqlRouter       *graphqlrouter.Router
	graphqlProxy        *graphqlproxy.Proxy
	graphqlHandler      *gateway.GraphQLHandler
}

// initApplication initializes all application components.
func initApplication(cfg *config.GatewayConfig, logger observability.Logger) *application {
	metrics := observability.NewMetrics("gateway")
	metrics.InitVecMetrics()
	metrics.SetBuildInfo(version, gitCommit, buildTime)
	tracer := initTracer(cfg, logger)
	healthChecker := health.NewChecker(version, logger)

	// Create audit metrics once and share across reloads. This avoids
	// Prometheus duplicate-registration errors when the audit logger is
	// hot-reloaded — the same counter instance remains in the registry.
	auditMetrics := audit.NewMetricsWithRegisterer("gateway", metrics.Registry())
	rawAuditLogger := initAuditLogger(cfg, logger,
		audit.WithLoggerMetrics(auditMetrics),
	)
	auditLogger := audit.NewAtomicAuditLogger(rawAuditLogger)

	// Initialize subsystem metric singletons and register them with the
	// gateway's custom Prometheus registry. These singletons use promauto
	// which auto-registers with the default global registry, but the
	// gateway serves /metrics from its own custom registry. Without this
	// explicit registration, cache, encoding, transform, and vault metrics
	// would be invisible on the /metrics endpoint.
	registerSubsystemMetrics(metrics, logger)

	// Initialize Vault client before the backend registry so that backends
	// requiring Vault (mTLS certs, KV credentials, OIDC tokens) receive
	// the client at creation time.
	var vaultClient vault.Client
	var vaultFactory tlspkg.VaultProviderFactory
	if needsVault(cfg) {
		vaultClient = initVaultClient(logger)
		if needsVaultTLS(cfg) {
			vaultFactory = createVaultProviderFactory(vaultClient)
			logger.Info("vault provider factory created for TLS certificate management")
		}
	}

	backendRegistry := initBackendRegistry(cfg.Spec.Backends, logger, metrics, vaultClient)
	if backendRegistry == nil {
		return nil
	}
	grpcBackendRegistry := initGRPCBackendRegistry(cfg.Spec.GRPCBackends, logger, metrics, vaultClient)
	if grpcBackendRegistry == nil {
		return nil
	}

	gqlRouter, gqlProxy := initGraphQLComponents(cfg, logger)

	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		fatalWithSync(logger, "failed to load routes", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	// Create auth metrics registered with the gateway's custom registry
	// so they appear on the gateway's /metrics endpoint. This shared
	// instance is passed to authenticators via WithAuthenticatorMetrics
	// to avoid the fallback to prometheus.DefaultRegisterer.
	authMetrics := auth.NewMetricsWithRegisterer("gateway", metrics.Registry())
	authMetrics.Init()

	// Create authz metrics registered with the gateway's custom registry
	// so they appear on the gateway's /metrics endpoint.
	authzMetrics := authz.NewMetricsWithRegisterer("gateway", metrics.Registry())
	authzMetrics.Init()

	// Create per-route middleware manager with cache factory
	cacheFactory := gateway.NewCacheFactory(logger, vaultClient)
	routeMiddlewareOpts := []gateway.RouteMiddlewareOption{
		gateway.WithRouteMiddlewareCacheFactory(cacheFactory),
		gateway.WithRouteMiddlewareAuthMetrics(authMetrics),
		gateway.WithRouteMiddlewareAuthzMetrics(authzMetrics),
	}
	if vaultClient != nil {
		routeMiddlewareOpts = append(routeMiddlewareOpts, gateway.WithRouteMiddlewareVaultClient(vaultClient))
	}
	routeMiddlewareMgr := gateway.NewRouteMiddlewareManager(
		&cfg.Spec, logger,
		routeMiddlewareOpts...,
	)

	// Build the shared aggregate (fan-out) handlers. The REST handler is wired
	// into the reverse proxy so routes declaring aggregate.enabled=true fan out
	// to their configured targets, merge/envelope the responses, and emit the
	// gateway_aggregate_* metrics. The same engine backs the GraphQL handler.
	restAggregateHandler, graphqlAggregateHandler, grpcAggregateHandler := initAggregateHandlers(metrics, logger)

	reverseProxy := proxy.NewReverseProxy(r, backendRegistry,
		proxy.WithProxyLogger(logger),
		proxy.WithMetricsRegistry(metrics.Registry()),
		proxy.WithRouteMiddleware(routeMiddlewareMgr),
		proxy.WithAggregateHandler(restAggregateHandler),
		// Wire the WebSocket origin allowlist (CSWSH protection) into the
		// data plane; nil/empty config keeps the permissive legacy behavior.
		proxy.WithWebSocketConfig(cfg.Spec.WebSocket),
	)

	// Compose the GraphQL endpoint INSIDE the global middleware chain via
	// the path dispatcher, so /graphql traffic passes global middleware
	// (auth, rate limits, recovery, metrics, tracing) AND each matched
	// GraphQL route's own middleware chain (auth, authz, rate limit, CORS,
	// headers) through the shared RouteMiddlewareManager. Registering
	// GraphQL directly on the gin engine bypassed both layers.
	gqlHandler := initGraphQLHandler(
		cfg, gqlRouter, gqlProxy, graphqlAggregateHandler, routeMiddlewareMgr, logger,
	)
	dispatcher := gateway.NewGraphQLPathDispatcher(
		gateway.GraphQLPathFromConfig(cfg), graphqlDispatchHandler(gqlHandler), reverseProxy,
	)

	middlewareResult, mwErr := buildMiddlewareChain(
		dispatcher, cfg, logger, metrics, tracer, auditLogger,
		cfg.Spec.Authentication, authMetrics, vaultClient,
	)
	if mwErr != nil {
		fatalWithSync(logger, "failed to build middleware chain", observability.Error(mwErr))
		return nil // unreachable in production; allows test to continue
	}

	// Create TLS metrics registered with the gateway's custom registry
	// so they appear on the gateway's /metrics endpoint.
	tlsMetrics := tlspkg.NewMetrics("gateway", tlspkg.WithRegistry(metrics.Registry()))
	tlsMetrics.Init()

	gwOpts := []gateway.Option{
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(middlewareResult.handler),
		gateway.WithShutdownTimeout(shutdownTimeout),
		gateway.WithAuditLogger(auditLogger),
		gateway.WithMetricsRegistry(metrics.Registry()),
		gateway.WithGatewayTLSMetrics(tlsMetrics),
		gateway.WithGatewayAuthMetrics(authMetrics),
		gateway.WithGatewayGRPCAggregateHandler(grpcAggregateHandler),
	}
	if vaultFactory != nil {
		gwOpts = append(gwOpts, gateway.WithGatewayVaultProviderFactory(vaultFactory))
	}
	if vaultClient != nil {
		gwOpts = append(gwOpts, gateway.WithGatewayVaultClient(vaultClient))
	}
	if grpcBackendRegistry != nil {
		gwOpts = append(gwOpts, gateway.WithGatewayGRPCBackendRegistry(grpcBackendRegistry))
	}
	// GraphQL components are intentionally NOT passed to the gateway: the
	// GraphQL endpoint is served through the dispatcher inside the global
	// middleware chain above. Passing them here would additionally register
	// the endpoint on the gin engine, which bypasses the global chain.

	gw, err := gateway.New(cfg, gwOpts...)
	if err != nil {
		fatalWithSync(logger, "failed to create gateway", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	return &application{
		gateway:             gw,
		backendRegistry:     backendRegistry,
		grpcBackendRegistry: grpcBackendRegistry,
		router:              r,
		healthChecker:       healthChecker,
		metrics:             metrics,
		reloadMetrics:       newReloadMetrics(metrics),
		tracer:              tracer,
		config:              cfg,
		rateLimiter:         middlewareResult.rateLimiter,
		maxSessionsLimiter:  middlewareResult.maxSessionsLimiter,
		auditLogger:         auditLogger,
		auditMetrics:        auditMetrics,
		vaultClient:         vaultClient,
		authMetrics:         authMetrics,
		cacheFactory:        cacheFactory,
		routeMiddlewareMgr:  routeMiddlewareMgr,
		graphqlRouter:       gqlRouter,
		graphqlProxy:        gqlProxy,
		graphqlHandler:      gqlHandler,
	}
}

// initGraphQLHandler builds the shared GraphQL endpoint handler wired with
// the per-route middleware manager, the aggregate handler, and the GraphQL
// body/WS origin settings. Returns nil when the GraphQL components are
// unavailable (disabled GraphQL pipeline).
func initGraphQLHandler(
	cfg *config.GatewayConfig,
	gqlRouter *graphqlrouter.Router,
	gqlProxy *graphqlproxy.Proxy,
	aggregator *aggregategraphql.Handler,
	routeMiddlewareMgr *gateway.RouteMiddlewareManager,
	logger observability.Logger,
) *gateway.GraphQLHandler {
	if gqlRouter == nil || gqlProxy == nil {
		return nil
	}

	opts := []gateway.GraphQLHandlerOption{
		gateway.WithGraphQLHandlerLogger(logger),
		gateway.WithGraphQLHandlerRouteMiddleware(routeMiddlewareMgr),
	}
	// Guard against a typed-nil pointer becoming a non-nil interface.
	if aggregator != nil {
		opts = append(opts, gateway.WithGraphQLHandlerAggregator(aggregator))
	}
	if cfg.Spec.GraphQL != nil && cfg.Spec.GraphQL.MaxBodySize > 0 {
		opts = append(opts, gateway.WithGraphQLHandlerMaxBodySize(cfg.Spec.GraphQL.MaxBodySize))
	}
	if cfg.Spec.WebSocket != nil && len(cfg.Spec.WebSocket.AllowedOrigins) > 0 {
		opts = append(opts, gateway.WithGraphQLHandlerSubscriptionOrigins(cfg.Spec.WebSocket.AllowedOrigins))
	}

	handler, err := gateway.NewGraphQLHandler(gqlRouter, gqlProxy, opts...)
	if err != nil {
		// Defensive: only reachable with nil router/proxy, both checked above.
		logger.Error("failed to build GraphQL handler; GraphQL endpoint disabled",
			observability.Error(err),
		)
		return nil
	}

	logger.Info("GraphQL endpoint composed into global middleware chain",
		observability.String("path", gateway.GraphQLPathFromConfig(cfg)),
	)
	return handler
}

// graphqlDispatchHandler converts the concrete handler into the dispatcher's
// http.Handler dependency, preserving nil-ness (a typed nil pointer inside a
// non-nil interface would defeat the dispatcher's nil check).
func graphqlDispatchHandler(h *gateway.GraphQLHandler) http.Handler {
	if h == nil {
		return nil
	}
	return h
}

// registerSubsystemMetrics initializes and registers all subsystem
// metric singletons with the gateway's custom Prometheus registry.
// Many packages use promauto which registers metrics with the default
// global registry, but the gateway's /metrics endpoint is served from
// its own custom registry. Without this explicit registration the
// subsystem metrics would be invisible on the /metrics endpoint even
// though they are being recorded at runtime.
//
//nolint:funlen // registering many subsystems requires many statements
func registerSubsystemMetrics(metrics *observability.Metrics, logger observability.Logger) {
	registry := metrics.Registry()

	cacheMetrics := cache.GetCacheMetrics()
	cacheMetrics.MustRegister(registry)
	cacheMetrics.Init()

	encodingMetrics := encoding.GetEncodingMetrics()
	encodingMetrics.MustRegister(registry)
	encodingMetrics.Init()

	transformMetrics := transform.GetTransformMetrics()
	transformMetrics.MustRegister(registry)
	transformMetrics.Init()

	// Vault metrics singleton implements prometheus.Collector.
	// Initialize it (idempotent via sync.Once) and register the
	// collector with the custom registry so vault metrics appear
	// on the gateway's /metrics endpoint.
	vaultMetrics := vault.NewMetrics("gateway")
	registry.MustRegister(vaultMetrics)
	vaultMetrics.Init()

	// Backend auth metrics singleton. Register with the gateway's
	// custom registry so backend auth metrics (OIDC, mTLS, Basic)
	// appear on the /metrics endpoint.
	backendAuthMetrics := backendauth.GetSharedMetrics()
	backendAuthMetrics.MustRegister(registry)
	backendAuthMetrics.Init()

	// Middleware metrics singleton (rate limiter, circuit breaker,
	// timeouts, retries, body limit, max sessions, panics, CORS).
	mwMetrics := middleware.GetMiddlewareMetrics()
	mwMetrics.MustRegister(registry)
	mwMetrics.Init()

	// Security headers metrics singleton (security headers, HSTS,
	// CSP applied/violations).
	secMetrics := security.GetSecurityMetrics()
	secMetrics.MustRegister(registry)
	secMetrics.Init()

	// Health check metrics singleton (checks total, check status).
	hlMetrics := health.GetHealthMetrics()
	hlMetrics.MustRegister(registry)
	hlMetrics.Init()

	// Router regex cache metrics singleton (cache hits, misses,
	// evictions, size).
	routerMetrics := router.GetRouterMetrics()
	routerMetrics.MustRegister(registry)
	routerMetrics.Init()

	// Auth provider metrics singletons. Each provider creates its own
	// private prometheus.Registry internally; registering the shared
	// singleton with the gateway's custom registry makes these metrics
	// visible on the /metrics endpoint.
	apikeyMetrics := apikey.GetSharedMetrics()
	apikeyMetrics.MustRegister(registry)
	apikeyMetrics.Init()

	jwtMetrics := authjwt.GetSharedMetrics()
	jwtMetrics.MustRegister(registry)
	jwtMetrics.Init()

	oidcMetrics := oidc.GetSharedMetrics()
	oidcMetrics.MustRegister(registry)
	oidcMetrics.Init()

	mtlsMetrics := mtls.GetSharedMetrics()
	mtlsMetrics.MustRegister(registry)
	mtlsMetrics.Init()

	// Authz provider metrics singletons. Same pattern as auth providers.
	rbacMetrics := rbac.GetSharedMetrics()
	rbacMetrics.MustRegister(registry)
	rbacMetrics.Init()

	abacMetrics := abac.GetSharedMetrics()
	abacMetrics.MustRegister(registry)
	abacMetrics.Init()

	externalMetrics := external.GetSharedMetrics()
	externalMetrics.MustRegister(registry)
	externalMetrics.Init()

	// Route-level metrics singleton. Register with the gateway's
	// custom registry so route metrics appear on the /metrics endpoint.
	rm := routepkg.GetRouteMetrics()
	rm.MustRegister(registry)
	rm.Init()

	// Backend-level metrics singleton. Register with the gateway's
	// custom registry so backend metrics (requests, connections,
	// health checks, LB, circuit breaker, auth, TLS, pool) appear
	// on the /metrics endpoint.
	bm := backendmetricspkg.GetBackendMetrics()
	bm.MustRegister(registry)
	bm.Init()

	// WebSocket streaming metrics singleton. Register with the
	// gateway's custom registry so WebSocket streaming metrics
	// (connections, messages, errors, duration) appear on the
	// /metrics endpoint.
	wsm := streaming.GetWSMetrics()
	wsm.MustRegister(registry)
	wsm.Init()

	// gRPC streaming metrics singleton. Register with the gateway's
	// custom registry so gRPC streaming metrics (messages, active
	// streams, duration) appear on the /metrics endpoint.
	gsm := streaming.GetGRPCStreamMetrics()
	gsm.MustRegister(registry)
	gsm.Init()

	// GraphQL metrics singleton. Register with the gateway's custom
	// registry so GraphQL metrics (requests, errors, depth, complexity,
	// subscriptions) appear on the /metrics endpoint.
	graphqlmetrics.InitMetrics(registry)
	graphqlmetrics.InitVecMetrics()

	// OpenAPI validation metrics singleton. Register with the gateway's
	// custom registry so validation successes/failures recorded by the
	// route middleware path appear on the /metrics endpoint.
	openapi.InitSharedMetrics(registry)

	subsystems := []string{
		"cache", "encoding", "transform", "vault", "backend_auth",
		"middleware", "security", "health", "router",
		"apikey", "jwt", "oidc", "mtls",
		"rbac", "abac", "external_authz",
		"route", "backend", "ws_streaming", "grpc_streaming", "graphql",
		"openapi_validation",
	}
	logger.Info("subsystem metrics registered with gateway registry",
		observability.Int("subsystem_count", len(subsystems)),
	)
}

// initGraphQLComponents creates and initializes the GraphQL router and proxy.
// The router matches incoming GraphQL requests to configured routes, and the
// proxy forwards matched requests to the appropriate backend.
func initGraphQLComponents(
	cfg *config.GatewayConfig,
	logger observability.Logger,
) (*graphqlrouter.Router, *graphqlproxy.Proxy) {
	gqlRouter := graphqlrouter.New(
		graphqlrouter.WithRouterLogger(logger),
	)
	if err := gqlRouter.LoadRoutes(cfg.Spec.GraphQLRoutes); err != nil {
		fatalWithSync(logger, "failed to load GraphQL routes", observability.Error(err))
		return nil, nil
	}

	gqlProxy := graphqlproxy.New(
		graphqlproxy.WithLogger(logger),
	)
	gqlProxy.UpdateBackends(cfg.Spec.GraphQLBackends)

	logger.Info("GraphQL components initialized",
		observability.Int("routes", len(cfg.Spec.GraphQLRoutes)),
		observability.Int("backends", len(cfg.Spec.GraphQLBackends)),
	)

	return gqlRouter, gqlProxy
}

// initAggregateHandlers builds the REST, GraphQL and gRPC aggregate (fan-out)
// handlers backed by a shared engine. All handlers share a single
// aggregate.Metrics registered on the gateway's custom Prometheus registry so
// the gateway_aggregate_* series appear on the /metrics endpoint, and a single
// OTLP tracer (B3/Jaeger propagation is configured at process startup).
//
// The REST and GraphQL handlers use REST invokers (reusing internal/backend for
// per-target TLS/mTLS and per-target authentication). The gRPC handler is a
// transport-level ProxyHandler: it builds a pool-backed gRPC invoker per call
// (reusing the proxy's connection pool and per-target mTLS) and treats the call
// as UNARY. All handlers are injected via decoupling interfaces to avoid import
// cycles.
func initAggregateHandlers(
	metrics *observability.Metrics,
	logger observability.Logger,
) (
	restHandler *aggregaterest.Handler,
	graphqlHandler *aggregategraphql.Handler,
	grpcHandler *aggregategrpc.ProxyHandler,
) {
	aggMetrics := aggregate.NewMetricsWith(metrics.Registry())
	aggTracer := aggregate.NewTracer()
	restHandler = aggregaterest.NewHandler(
		aggregaterest.NewInvoker(aggregaterest.WithLogger(logger)),
		logger, aggMetrics, aggTracer,
	)
	graphqlHandler = aggregategraphql.NewHandler(
		aggregaterest.NewInvoker(aggregaterest.WithLogger(logger)),
		logger, aggMetrics, aggTracer,
	)
	grpcHandler = aggregategrpc.NewProxyHandler(
		logger,
		aggregategrpc.WithProxyHandlerMetrics(aggMetrics),
		aggregategrpc.WithProxyHandlerTracer(aggTracer),
	)
	return restHandler, graphqlHandler, grpcHandler
}

// initBackendRegistry creates and loads the HTTP backend registry.
func initBackendRegistry(
	backends []config.Backend,
	logger observability.Logger,
	metrics *observability.Metrics,
	vaultClient vault.Client,
) *backend.Registry {
	opts := []backend.RegistryOption{backend.WithRegistryMetrics(metrics)}
	if vaultClient != nil {
		opts = append(opts, backend.WithRegistryVaultClient(vaultClient))
	}
	reg := backend.NewRegistry(logger, opts...)
	if err := reg.LoadFromConfig(backends); err != nil {
		fatalWithSync(logger, "failed to load backends", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}
	return reg
}

// initGRPCBackendRegistry creates and loads the gRPC backend registry.
// Uses the same infrastructure as HTTP backends (load balancing, health checking).
func initGRPCBackendRegistry(
	grpcBackends []config.GRPCBackend,
	logger observability.Logger,
	metrics *observability.Metrics,
	vaultClient vault.Client,
) *backend.Registry {
	opts := []backend.RegistryOption{backend.WithRegistryMetrics(metrics)}
	if vaultClient != nil {
		opts = append(opts, backend.WithRegistryVaultClient(vaultClient))
	}
	reg := backend.NewRegistry(logger, opts...)
	if err := reg.LoadFromConfig(config.GRPCBackendsToBackends(grpcBackends)); err != nil {
		fatalWithSync(logger, "failed to load gRPC backends", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}
	return reg
}

// initClientIPExtractor creates and sets the global ClientIPExtractor
// from the gateway configuration's trusted proxies list.
func initClientIPExtractor(
	cfg *config.GatewayConfig,
	logger observability.Logger,
) {
	proxies := cfg.Spec.TrustedProxies
	extractor := middleware.NewClientIPExtractor(proxies)
	middleware.SetGlobalIPExtractor(extractor)

	if len(proxies) > 0 {
		logger.Info("client IP extraction configured with trusted proxies",
			observability.Int("trusted_proxy_count", len(proxies)),
		)
	} else {
		logger.Info("client IP extraction using RemoteAddr only (no trusted proxies)")
	}
}
