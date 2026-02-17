package main

import (
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/encoding"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
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
}

// initApplication initializes all application components.
func initApplication(cfg *config.GatewayConfig, logger observability.Logger) *application {
	metrics := observability.NewMetrics("gateway")
	metrics.SetBuildInfo(version, gitCommit, buildTime)
	tracer := initTracer(cfg, logger)
	healthChecker := health.NewChecker(version, logger)
	auditLogger := initAuditLogger(cfg, logger,
		audit.WithLoggerRegisterer(metrics.Registry()),
	)

	backendRegistry := backend.NewRegistry(
		logger, backend.WithRegistryMetrics(metrics),
	)
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

	// Initialize subsystem metric singletons and register them with the
	// gateway's custom Prometheus registry. These singletons use promauto
	// which auto-registers with the default global registry, but the
	// gateway serves /metrics from its own custom registry. Without this
	// explicit registration, cache, encoding, transform, and vault metrics
	// would be invisible on the /metrics endpoint.
	registerSubsystemMetrics(metrics, logger)

	// Initialize Vault client if any listener/route needs Vault TLS
	var vaultClient vault.Client
	var vaultFactory tlspkg.VaultProviderFactory
	if needsVaultTLS(cfg) {
		vaultClient = initVaultClient(logger)
		vaultFactory = createVaultProviderFactory(vaultClient)
		logger.Info("vault provider factory created for TLS certificate management")
	}

	reverseProxy := proxy.NewReverseProxy(r, backendRegistry,
		proxy.WithProxyLogger(logger),
		proxy.WithMetricsRegistry(metrics.Registry()),
	)
	middlewareResult := buildMiddlewareChain(reverseProxy, cfg, logger, metrics, tracer, auditLogger)

	// Create TLS metrics registered with the gateway's custom registry
	// so they appear on the gateway's /metrics endpoint.
	tlsMetrics := tlspkg.NewMetrics("gateway", tlspkg.WithRegistry(metrics.Registry()))

	gwOpts := []gateway.Option{
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(middlewareResult.handler),
		gateway.WithShutdownTimeout(30 * time.Second),
		gateway.WithAuditLogger(auditLogger),
		gateway.WithMetricsRegistry(metrics.Registry()),
		gateway.WithGatewayTLSMetrics(tlsMetrics),
	}
	if vaultFactory != nil {
		gwOpts = append(gwOpts, gateway.WithGatewayVaultProviderFactory(vaultFactory))
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
	}
}

// registerSubsystemMetrics initializes and registers cache, encoding,
// transform, and vault metric singletons with the gateway's custom
// Prometheus registry. These packages use promauto which registers
// metrics with the default global registry, but the gateway's /metrics
// endpoint is served from its own custom registry. Without this
// explicit registration the subsystem metrics would be invisible on
// the /metrics endpoint even though they are being recorded at runtime.
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

	logger.Info("subsystem metrics registered with gateway registry",
		observability.Bool("cache", true),
		observability.Bool("encoding", true),
		observability.Bool("transform", true),
		observability.Bool("vault", vaultMetrics != nil),
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
