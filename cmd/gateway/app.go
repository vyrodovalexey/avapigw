package main

import (
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// application holds all application components.
type application struct {
	gateway            *gateway.Gateway
	backendRegistry    *backend.Registry
	router             *router.Router
	healthChecker      *health.Checker
	metrics            *observability.Metrics
	metricsServer      *http.Server
	tracer             *observability.Tracer
	config             *config.GatewayConfig
	rateLimiter        *middleware.RateLimiter
	maxSessionsLimiter *middleware.MaxSessionsLimiter
	auditLogger        audit.Logger
	vaultClient        vault.Client
}

// initApplication initializes all application components.
func initApplication(cfg *config.GatewayConfig, logger observability.Logger) *application {
	metrics := observability.NewMetrics("gateway")
	tracer := initTracer(cfg, logger)
	healthChecker := health.NewChecker(version, logger)
	auditLogger := initAuditLogger(cfg, logger)

	backendRegistry := backend.NewRegistry(logger)
	if err := backendRegistry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		fatalWithSync(logger, "failed to load backends", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		fatalWithSync(logger, "failed to load routes", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	// Initialize Vault client if any listener/route needs Vault TLS
	var vaultClient vault.Client
	var vaultFactory tlspkg.VaultProviderFactory
	if needsVaultTLS(cfg) {
		vaultClient = initVaultClient(logger)
		vaultFactory = createVaultProviderFactory(vaultClient)
		logger.Info("vault provider factory created for TLS certificate management")
	}

	reverseProxy := proxy.NewReverseProxy(r, backendRegistry, proxy.WithProxyLogger(logger))
	middlewareResult := buildMiddlewareChain(reverseProxy, cfg, logger, metrics, tracer, auditLogger)

	gwOpts := []gateway.Option{
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(middlewareResult.handler),
		gateway.WithShutdownTimeout(30 * time.Second),
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
		tracer:             tracer,
		config:             cfg,
		rateLimiter:        middlewareResult.rateLimiter,
		maxSessionsLimiter: middlewareResult.maxSessionsLimiter,
		auditLogger:        auditLogger,
		vaultClient:        vaultClient,
	}
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
