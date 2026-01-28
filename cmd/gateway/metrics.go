package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

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
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
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
		metricsPort = 9090
	}

	app.metricsServer = createMetricsServer(metricsPort, metricsPath, app.metrics, app.healthChecker, logger)
	go runMetricsServer(app.metricsServer, logger)
}
