package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// reloadMetrics holds Prometheus metrics for configuration reload
// operations. All collectors are registered with the gateway's custom
// registry so they appear on the /metrics endpoint.
type reloadMetrics struct {
	configReloadTotal          *prometheus.CounterVec
	configReloadDuration       prometheus.Histogram
	configReloadLastSuccess    prometheus.Gauge
	configWatcherStatus        prometheus.Gauge
	configReloadComponentTotal *prometheus.CounterVec
}

// newReloadMetrics creates reload metrics and registers them with the
// provided gateway Metrics instance's custom registry.
func newReloadMetrics(m *observability.Metrics) *reloadMetrics {
	rm := &reloadMetrics{
		configReloadTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Name:      "config_reload_total",
				Help: "Total number of " +
					"configuration reloads",
			},
			[]string{"result"},
		),
		configReloadDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: "gateway",
				Name: "config_reload_" +
					"duration_seconds",
				Help: "Duration of configuration " +
					"reload operations",
				Buckets: []float64{
					.01, .05, .1, .25, .5, 1, 2.5, 5,
				},
			},
		),
		configReloadLastSuccess: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "gateway",
				Name: "config_reload_" +
					"last_success_timestamp",
				Help: "Timestamp of last successful " +
					"config reload",
			},
		),
		configWatcherStatus: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "gateway",
				Name:      "config_watcher_running",
				Help: "Whether the config file " +
					"watcher is running (1=running, 0=stopped)",
			},
		),
		configReloadComponentTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gateway",
				Name: "config_reload_" +
					"component_total",
				Help: "Total number of component " +
					"reload operations by component and result",
			},
			[]string{"component", "result"},
		),
	}

	// Register all reload metrics with the custom registry so they
	// appear on the gateway's /metrics endpoint.
	collectors := []prometheus.Collector{
		rm.configReloadTotal,
		rm.configReloadDuration,
		rm.configReloadLastSuccess,
		rm.configWatcherStatus,
		rm.configReloadComponentTotal,
	}
	for _, c := range collectors {
		// Ignore duplicate registration errors (safe because descriptors
		// are identical when re-registered).
		_ = m.RegisterCollector(c)
	}

	return rm
}

// ensureReloadMetrics returns the application's reload metrics,
// lazily initializing them with a standalone registry when the
// application was created without an observability.Metrics instance
// (e.g. in tests).
func ensureReloadMetrics(app *application) *reloadMetrics {
	if app.reloadMetrics != nil {
		return app.reloadMetrics
	}
	// Create a standalone metrics instance for the reload metrics.
	// This path is only hit in tests that construct application
	// structs without calling initApplication.
	m := observability.NewMetrics("gateway")
	app.reloadMetrics = newReloadMetrics(m)
	return app.reloadMetrics
}

// startConfigWatcher starts the configuration watcher.
func startConfigWatcher(
	ctx context.Context,
	app *application,
	configPath string,
	logger observability.Logger,
) *config.Watcher {
	rm := ensureReloadMetrics(app)

	watcher, err := config.NewWatcher(configPath, func(newCfg *config.GatewayConfig) {
		logger.Info("configuration changed, reloading")
		reloadComponents(ctx, app, newCfg, logger)
	}, config.WithLogger(logger))

	if err != nil {
		logger.Warn("failed to create config watcher", observability.Error(err))
		rm.configWatcherStatus.Set(0)
		return nil
	}

	if err := watcher.Start(ctx); err != nil {
		logger.Warn("failed to start config watcher", observability.Error(err))
		rm.configWatcherStatus.Set(0)
		return watcher
	}

	rm.configWatcherStatus.Set(1)
	return watcher
}

// reloadComponents reloads all gateway components with new config.
// Circuit breaker from sony/gobreaker does not support runtime
// reconfiguration; a gateway restart is required to change its
// threshold or timeout settings.
//
// NOTE: gRPC routes and backends are NOT hot-reloaded. gRPC connections
// are long-lived and streaming must be drained, so changes to gRPC
// configuration require a full gateway restart. Only HTTP routes and
// backends are reloaded here.
func reloadComponents(
	ctx context.Context,
	app *application,
	newCfg *config.GatewayConfig,
	logger observability.Logger,
) {
	start := time.Now()
	rm := ensureReloadMetrics(app)

	// Reload gateway config (atomic pointer swap)
	if err := app.gateway.Reload(newCfg); err != nil {
		logger.Error("failed to reload gateway config",
			observability.Error(err),
		)
		rm.configReloadTotal.WithLabelValues("error").Inc()
		rm.configReloadDuration.Observe(
			time.Since(start).Seconds(),
		)
		return
	}

	// Warn if gRPC configuration has changed — gRPC routes/backends are NOT hot-reloaded
	if grpcConfigChanged(app.config, newCfg) {
		logger.Warn("gRPC configuration has changed but gRPC routes/backends are NOT hot-reloaded; "+
			"restart the gateway to apply gRPC changes",
			observability.Int("old_grpc_routes", len(app.config.Spec.GRPCRoutes)),
			observability.Int("new_grpc_routes", len(newCfg.Spec.GRPCRoutes)),
			observability.Int("old_grpc_backends", len(app.config.Spec.GRPCBackends)),
			observability.Int("new_grpc_backends", len(newCfg.Spec.GRPCBackends)),
		)
	}

	// Update rate limiter
	if app.rateLimiter != nil && newCfg.Spec.RateLimit != nil {
		app.rateLimiter.UpdateConfig(newCfg.Spec.RateLimit)
		rm.configReloadComponentTotal.WithLabelValues("rate_limiter", "success").Inc()
	}

	// Update max sessions limiter
	if app.maxSessionsLimiter != nil && newCfg.Spec.MaxSessions != nil {
		app.maxSessionsLimiter.UpdateConfig(newCfg.Spec.MaxSessions)
		rm.configReloadComponentTotal.WithLabelValues("max_sessions", "success").Inc()
	}

	// Reload HTTP routes (gRPC routes are NOT reloaded — see function comment)
	if app.router != nil {
		if err := app.router.LoadRoutes(newCfg.Spec.Routes); err != nil {
			logger.Error("failed to reload routes",
				observability.Error(err),
			)
			rm.configReloadComponentTotal.WithLabelValues("routes", "error").Inc()
		} else {
			rm.configReloadComponentTotal.WithLabelValues("routes", "success").Inc()
		}
	}

	// Clear HTTP route middleware cache so the next request rebuilds
	// middleware chains from the updated route configuration.
	if app.routeMiddlewareMgr != nil {
		app.routeMiddlewareMgr.ClearCache()
		logger.Debug("HTTP route middleware cache cleared after config reload")
	}

	// Reload HTTP backends (gRPC backends are NOT reloaded — see function comment)
	if app.backendRegistry != nil {
		timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		if err := app.backendRegistry.ReloadFromConfig(
			timeoutCtx, newCfg.Spec.Backends,
		); err != nil {
			logger.Error("failed to reload backends",
				observability.Error(err),
			)
			rm.configReloadComponentTotal.WithLabelValues("backends", "error").Inc()
		} else {
			rm.configReloadComponentTotal.WithLabelValues("backends", "success").Inc()
		}
	}

	// Reload audit logger if audit configuration changed
	reloadAuditLogger(app, newCfg, logger)

	// Warn if CORS configuration has changed — CORS middleware is part of the
	// static handler chain and cannot be hot-reloaded without a restart.
	if corsConfigChanged(app.config, newCfg) {
		logger.Warn("CORS configuration has changed but CORS middleware is NOT hot-reloaded; " +
			"restart the gateway to apply CORS changes")
	}

	// Warn if security headers configuration has changed — security headers
	// middleware is part of the static handler chain and cannot be hot-reloaded.
	if securityConfigChanged(app.config, newCfg) {
		logger.Warn("security configuration has changed but security middleware is NOT hot-reloaded; " +
			"restart the gateway to apply security changes")
	}

	app.config = newCfg

	rm.configReloadTotal.WithLabelValues("success").Inc()
	rm.configReloadDuration.Observe(
		time.Since(start).Seconds(),
	)
	rm.configReloadLastSuccess.SetToCurrentTime()

	logger.Info("all components reloaded successfully")
}

// reloadAuditLogger replaces the audit logger if audit configuration has changed.
func reloadAuditLogger(
	app *application,
	newCfg *config.GatewayConfig,
	logger observability.Logger,
) {
	if !auditConfigChanged(app.config, newCfg) {
		return
	}

	logger.Info("audit configuration changed, reloading audit logger")

	// Close the old audit logger to flush pending events
	if app.auditLogger != nil {
		if err := app.auditLogger.Close(); err != nil {
			logger.Error("failed to close old audit logger", observability.Error(err))
		}
	}

	// Create a new audit logger with the updated configuration,
	// registering audit metrics with the gateway's custom registry
	// when available.
	var auditOpts []audit.LoggerOption
	if app.metrics != nil {
		auditOpts = append(auditOpts,
			audit.WithLoggerRegisterer(app.metrics.Registry()),
		)
	}
	app.auditLogger = initAuditLogger(newCfg, logger, auditOpts...)
	ensureReloadMetrics(app).configReloadComponentTotal.WithLabelValues("audit", "success").Inc()
}

// configSectionHash computes a SHA-256 hash of a configuration section
// for fast change detection. Falls back to reflect.DeepEqual when JSON
// marshaling fails (e.g. for types with unexported fields).
func configSectionHash(v interface{}) ([sha256.Size]byte, bool) {
	data, err := json.Marshal(v)
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256(data), true
}

// configSectionChanged compares two configuration sections using a
// SHA-256 hash for O(n) performance instead of reflect.DeepEqual's
// recursive comparison. Falls back to reflect.DeepEqual when hashing
// is not possible.
func configSectionChanged(oldSection, newSection interface{}) bool {
	oldHash, oldOK := configSectionHash(oldSection)
	newHash, newOK := configSectionHash(newSection)
	if oldOK && newOK {
		return oldHash != newHash
	}
	// Fallback to reflect.DeepEqual when hashing fails
	return !reflect.DeepEqual(oldSection, newSection)
}

// grpcConfigChanged checks if gRPC routes or backends have changed between configs.
func grpcConfigChanged(oldCfg, newCfg *config.GatewayConfig) bool {
	if oldCfg == nil || newCfg == nil {
		return oldCfg != newCfg
	}
	if configSectionChanged(oldCfg.Spec.GRPCRoutes, newCfg.Spec.GRPCRoutes) {
		return true
	}
	return configSectionChanged(oldCfg.Spec.GRPCBackends, newCfg.Spec.GRPCBackends)
}

// corsConfigChanged checks if CORS configuration has changed between configs.
func corsConfigChanged(oldCfg, newCfg *config.GatewayConfig) bool {
	if oldCfg == nil || newCfg == nil {
		return oldCfg != newCfg
	}
	return configSectionChanged(oldCfg.Spec.CORS, newCfg.Spec.CORS)
}

// securityConfigChanged checks if security configuration has changed between configs.
func securityConfigChanged(oldCfg, newCfg *config.GatewayConfig) bool {
	if oldCfg == nil || newCfg == nil {
		return oldCfg != newCfg
	}
	return configSectionChanged(oldCfg.Spec.Security, newCfg.Spec.Security)
}

// auditConfigChanged checks if audit configuration has changed between configs.
func auditConfigChanged(oldCfg, newCfg *config.GatewayConfig) bool {
	if oldCfg == nil || newCfg == nil {
		return oldCfg != newCfg
	}
	return configSectionChanged(oldCfg.Spec.Audit, newCfg.Spec.Audit)
}
