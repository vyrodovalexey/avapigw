package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// defaultMetricsPort is the default port for the metrics HTTP server
// when not explicitly configured.
const defaultMetricsPort = 9090

// securityHeadersMiddleware wraps an http.Handler and adds security
// headers to every response. This hardens the metrics/health endpoints
// against content-type sniffing, click-jacking, and caching of
// sensitive data.
//
// NOTE: This intentionally does NOT reuse the internal/security package's
// SecurityHeadersMiddleware because the metrics server is a separate
// http.Server with its own mux, independent of the gateway's middleware
// chain. The security package middleware is designed for the gateway's
// configurable pipeline (with HSTS, CSP, etc.), while the metrics
// server only needs a minimal, static set of hardening headers.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// createMetricsServer creates the metrics HTTP server.
func createMetricsServer(
	port int,
	path string,
	metrics *observability.Metrics,
	healthChecker *health.Checker,
	logger observability.Logger,
) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(path, metrics.Handler())
	mux.HandleFunc("/health", healthChecker.HealthHandler())
	mux.HandleFunc("/ready", healthChecker.ReadinessHandler())
	mux.HandleFunc("/live", healthChecker.LivenessHandler())

	addr := fmt.Sprintf(":%d", port)
	logger.Info("starting metrics server",
		observability.String("address", addr),
		observability.String("metrics_path", path),
	)

	return &http.Server{
		Addr:              addr,
		Handler:           securityHeadersMiddleware(mux),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// runMetricsServer runs the metrics HTTP server.
func runMetricsServer(server *http.Server, logger observability.Logger) {
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("metrics server error", observability.Error(err))
	}
}

// startMetricsServerIfEnabled starts the metrics server if enabled.
func startMetricsServerIfEnabled(app *application, logger observability.Logger) {
	obs := app.config.Spec.Observability
	if obs == nil || obs.Metrics == nil || !obs.Metrics.Enabled {
		return
	}

	metricsPath := obs.Metrics.Path
	if metricsPath == "" {
		metricsPath = "/metrics"
	}

	metricsPort := obs.Metrics.Port
	if metricsPort == 0 {
		metricsPort = defaultMetricsPort
	}

	app.metricsServer = createMetricsServer(metricsPort, metricsPath, app.metrics, app.healthChecker, logger)
	go runMetricsServer(app.metricsServer, logger)
}
