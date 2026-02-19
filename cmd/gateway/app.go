package main

import (
	"net/http"
	"time"

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
	"github.com/vyrodovalexey/avapigw/internal/health"
	backendmetricspkg "github.com/vyrodovalexey/avapigw/internal/metrics/backend"
	routepkg "github.com/vyrodovalexey/avapigw/internal/metrics/route"
	"github.com/vyrodovalexey/avapigw/internal/metrics/streaming"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/internal/security"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/transform"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// application holds all application components.
type application struct {
	gateway            *gateway.Gateway
	backendRegistry    *backend.Registry
	router             *router.Router
	healthChecker      *health.Checker
	metrics            *observability.Metrics
	reloadMetrics      *reloadMetrics
	metricsServer      *http.Server
	tracer             *observability.Tracer
	config             *config.GatewayConfig
	rateLimiter        *middleware.RateLimiter
	maxSessionsLimiter *middleware.MaxSessionsLimiter
	auditLogger        audit.Logger
	vaultClient        vault.Client
	authMetrics        *auth.Metrics
	cacheFactory       *gateway.CacheFactory
	routeMiddlewareMgr *gateway.RouteMiddlewareManager
}

// initApplication initializes all application components.
func initApplication(cfg *config.GatewayConfig, logger observability.Logger) *application {
	metrics := observability.NewMetrics("gateway")
	metrics.InitVecMetrics()
	metrics.SetBuildInfo(version, gitCommit, buildTime)
	tracer := initTracer(cfg, logger)
	healthChecker := health.NewChecker(version, logger)
	auditLogger := initAuditLogger(cfg, logger,
		audit.WithLoggerRegisterer(metrics.Registry()),
	)

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

	registryOpts := []backend.RegistryOption{backend.WithRegistryMetrics(metrics)}
	if vaultClient != nil {
		registryOpts = append(registryOpts, backend.WithRegistryVaultClient(vaultClient))
	}
	backendRegistry := backend.NewRegistry(logger, registryOpts...)
	if err := backendRegistry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		fatalWithSync(logger, "failed to load backends", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

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

	reverseProxy := proxy.NewReverseProxy(r, backendRegistry,
		proxy.WithProxyLogger(logger),
		proxy.WithMetricsRegistry(metrics.Registry()),
		proxy.WithRouteMiddleware(routeMiddlewareMgr),
	)
	middlewareResult, mwErr := buildMiddlewareChain(
		reverseProxy, cfg, logger, metrics, tracer, auditLogger,
		cfg.Spec.Authentication, authMetrics,
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
		gateway.WithShutdownTimeout(30 * time.Second),
		gateway.WithAuditLogger(auditLogger),
		gateway.WithMetricsRegistry(metrics.Registry()),
		gateway.WithGatewayTLSMetrics(tlsMetrics),
		gateway.WithGatewayAuthMetrics(authMetrics),
	}
	if vaultFactory != nil {
		gwOpts = append(gwOpts, gateway.WithGatewayVaultProviderFactory(vaultFactory))
	}
	if vaultClient != nil {
		gwOpts = append(gwOpts, gateway.WithGatewayVaultClient(vaultClient))
	}

	gw, err := gateway.New(cfg, gwOpts...)
	if err != nil {
		fatalWithSync(logger, "failed to create gateway", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	return &application{
		gateway:            gw,
		backendRegistry:    backendRegistry,
		router:             r,
		healthChecker:      healthChecker,
		metrics:            metrics,
		reloadMetrics:      newReloadMetrics(metrics),
		tracer:             tracer,
		config:             cfg,
		rateLimiter:        middlewareResult.rateLimiter,
		maxSessionsLimiter: middlewareResult.maxSessionsLimiter,
		auditLogger:        auditLogger,
		vaultClient:        vaultClient,
		authMetrics:        authMetrics,
		cacheFactory:       cacheFactory,
		routeMiddlewareMgr: routeMiddlewareMgr,
	}
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

	logger.Info("subsystem metrics registered with gateway registry",
		observability.Bool("cache", true),
		observability.Bool("encoding", true),
		observability.Bool("transform", true),
		observability.Bool("vault", vaultMetrics != nil),
		observability.Bool("backend_auth", true),
		observability.Bool("middleware", true),
		observability.Bool("security", true),
		observability.Bool("health", true),
		observability.Bool("router", true),
		observability.Bool("apikey", true),
		observability.Bool("jwt", true),
		observability.Bool("oidc", true),
		observability.Bool("mtls", true),
		observability.Bool("rbac", true),
		observability.Bool("abac", true),
		observability.Bool("external_authz", true),
		observability.Bool("route", true),
		observability.Bool("backend", true),
		observability.Bool("ws_streaming", true),
		observability.Bool("grpc_streaming", true),
	)
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
