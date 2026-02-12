package main

import (
	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// loadAndValidateConfig loads and validates the configuration.
func loadAndValidateConfig(configPath string, logger observability.Logger) *config.GatewayConfig {
	logger.Info("starting avapigw",
		observability.String("version", version),
		observability.String("config", configPath),
	)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fatalWithSync(logger, "failed to load configuration", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	// Apply Redis Sentinel environment variable overrides before validation.
	// ENV values take priority over file-based configuration.
	applyRedisSentinelEnvToConfig(cfg)

	warnings, err := config.ValidateConfigWithWarnings(cfg)
	if err != nil {
		fatalWithSync(logger, "invalid configuration", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	for _, w := range warnings {
		logger.Warn("configuration warning",
			observability.String("path", w.Path),
			observability.String("message", w.Message),
		)
	}

	// Count gRPC and HTTP listeners
	grpcListenerCount := 0
	httpListenerCount := 0
	for _, l := range cfg.Spec.Listeners {
		if l.Protocol == config.ProtocolGRPC {
			grpcListenerCount++
		} else {
			httpListenerCount++
		}
	}

	logger.Info("configuration loaded",
		observability.String("name", cfg.Metadata.Name),
		observability.Int("http_listeners", httpListenerCount),
		observability.Int("grpc_listeners", grpcListenerCount),
		observability.Int("routes", len(cfg.Spec.Routes)),
		observability.Int("grpc_routes", len(cfg.Spec.GRPCRoutes)),
		observability.Int("backends", len(cfg.Spec.Backends)),
		observability.Int("grpc_backends", len(cfg.Spec.GRPCBackends)),
	)

	return cfg
}

// initAuditLogger creates an audit logger from the gateway configuration.
// If audit is not configured or disabled, a no-op logger is returned.
func initAuditLogger(cfg *config.GatewayConfig, logger observability.Logger) audit.Logger {
	if cfg.Spec.Audit == nil || !cfg.Spec.Audit.Enabled {
		logger.Info("audit logging disabled")
		return audit.NewNoopLogger()
	}

	auditCfg := &audit.Config{
		Enabled:      cfg.Spec.Audit.Enabled,
		Level:        audit.Level(cfg.Spec.Audit.Level),
		Output:       cfg.Spec.Audit.Output,
		Format:       cfg.Spec.Audit.Format,
		SkipPaths:    cfg.Spec.Audit.SkipPaths,
		RedactFields: cfg.Spec.Audit.RedactFields,
	}

	// Default output to stdout when not specified
	if auditCfg.Output == "" {
		auditCfg.Output = "stdout"
	}

	// Convert events configuration
	if cfg.Spec.Audit.Events != nil {
		auditCfg.Events = &audit.EventsConfig{
			Authentication: cfg.Spec.Audit.Events.Authentication,
			Authorization:  cfg.Spec.Audit.Events.Authorization,
			Request:        cfg.Spec.Audit.Events.Request,
			Response:       cfg.Spec.Audit.Events.Response,
			Configuration:  cfg.Spec.Audit.Events.Configuration,
			Security:       cfg.Spec.Audit.Events.Security,
		}
	}

	auditLogger, err := audit.NewLogger(auditCfg, audit.WithLoggerLogger(logger))
	if err != nil {
		logger.Warn("failed to create audit logger, using noop", observability.Error(err))
		return audit.NewNoopLogger()
	}

	logger.Info("audit logging enabled",
		observability.String("output", auditCfg.Output),
		observability.String("format", auditCfg.GetEffectiveFormat()),
		observability.String("level", string(auditCfg.GetEffectiveLevel())),
	)

	return auditLogger
}

// initTracer initializes the tracer.
func initTracer(cfg *config.GatewayConfig, logger observability.Logger) *observability.Tracer {
	tracerCfg := observability.TracerConfig{
		ServiceName:  "avapigw",
		Enabled:      false,
		SamplingRate: 1.0,
	}

	if cfg.Spec.Observability != nil && cfg.Spec.Observability.Tracing != nil {
		tracerCfg.Enabled = cfg.Spec.Observability.Tracing.Enabled
		tracerCfg.SamplingRate = cfg.Spec.Observability.Tracing.SamplingRate
		tracerCfg.OTLPEndpoint = cfg.Spec.Observability.Tracing.OTLPEndpoint
		if cfg.Spec.Observability.Tracing.ServiceName != "" {
			tracerCfg.ServiceName = cfg.Spec.Observability.Tracing.ServiceName
		}
	}

	tracer, err := observability.NewTracer(tracerCfg)
	if err != nil {
		fatalWithSync(logger, "failed to initialize tracer", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	return tracer
}
