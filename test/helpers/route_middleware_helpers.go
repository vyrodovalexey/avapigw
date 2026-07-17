// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"context"
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// RouteMiddlewareGatewayOption customizes StartGatewayWithRouteMiddleware.
type RouteMiddlewareGatewayOption func(*routeMiddlewareGatewayOptions)

// routeMiddlewareGatewayOptions holds optional dependencies for the
// route-middleware-enabled gateway.
type routeMiddlewareGatewayOptions struct {
	vaultClient vault.Client
}

// WithRouteMiddlewareGatewayVaultClient supplies a Vault client to the
// per-route middleware manager and cache factory, enabling Vault-resolved
// Redis passwords for route-level caches and rate limiters.
func WithRouteMiddlewareGatewayVaultClient(client vault.Client) RouteMiddlewareGatewayOption {
	return func(o *routeMiddlewareGatewayOptions) {
		o.vaultClient = client
	}
}

// StartGatewayWithRouteMiddleware starts a gateway with the per-route
// middleware chain (authentication, authorization, rate limiting, security
// headers, CORS, body limits, OpenAPI validation, headers, cache, transform,
// encoding) wired the same way initApplication does in cmd/gateway. Tests
// using this helper exercise the production route chain, including the
// redis-backed distributed rate limiter and route-level redis caches.
func StartGatewayWithRouteMiddleware(
	ctx context.Context,
	cfg *config.GatewayConfig,
	opts ...RouteMiddlewareGatewayOption,
) (*GatewayInstance, error) {
	logger := observability.NopLogger()

	o := &routeMiddlewareGatewayOptions{}
	for _, opt := range opts {
		opt(o)
	}

	// Create router
	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		return nil, fmt.Errorf("failed to load routes: %w", err)
	}

	// Create backend registry
	registry := backend.NewRegistry(logger)
	if err := registry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		return nil, fmt.Errorf("failed to load backends: %w", err)
	}

	// Start backends
	if err := registry.StartAll(ctx); err != nil {
		return nil, fmt.Errorf("failed to start backends: %w", err)
	}

	// Create the per-route middleware manager with a cache factory,
	// mirroring the production wiring in cmd/gateway initApplication.
	cacheFactory := gateway.NewCacheFactory(logger, o.vaultClient)
	mwOpts := []gateway.RouteMiddlewareOption{
		gateway.WithRouteMiddlewareCacheFactory(cacheFactory),
	}
	if o.vaultClient != nil {
		mwOpts = append(mwOpts, gateway.WithRouteMiddlewareVaultClient(o.vaultClient))
	}
	routeMiddlewareMgr := gateway.NewRouteMiddlewareManager(&cfg.Spec, logger, mwOpts...)

	// Create proxy with per-route middleware and WebSocket config wired the
	// same way initApplication does in cmd/gateway.
	p := proxy.NewReverseProxy(r, registry,
		proxy.WithProxyLogger(logger),
		proxy.WithRouteMiddleware(routeMiddlewareMgr),
		proxy.WithWebSocketConfig(cfg.Spec.WebSocket),
	)

	// Create gateway
	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(p),
	)
	if err != nil {
		routeMiddlewareMgr.Stop()
		_ = cacheFactory.Close()
		return nil, fmt.Errorf("failed to create gateway: %w", err)
	}

	// Start gateway
	if err := gw.Start(ctx); err != nil {
		routeMiddlewareMgr.Stop()
		_ = cacheFactory.Close()
		return nil, fmt.Errorf("failed to start gateway: %w", err)
	}

	// Determine base URL
	port := 8080
	if len(cfg.Spec.Listeners) > 0 {
		port = cfg.Spec.Listeners[0].Port
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	return &GatewayInstance{
		Gateway:         gw,
		Config:          cfg,
		Router:          r,
		Registry:        registry,
		Proxy:           p,
		BaseURL:         baseURL,
		RouteMiddleware: routeMiddlewareMgr,
		CacheFactory:    cacheFactory,
	}, nil
}
