// Package main is the entry point for the avapigw-operator.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
	"github.com/vyrodovalexey/avapigw/internal/operator/controller"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
	operatorwebhook "github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(avapigwv1alpha1.AddToScheme(scheme))
}

// Config holds the operator configuration.
type Config struct {
	// MetricsAddr is the address the metric endpoint binds to.
	MetricsAddr string

	// ProbeAddr is the address the probe endpoint binds to.
	ProbeAddr string

	// EnableLeaderElection enables leader election for controller manager.
	EnableLeaderElection bool

	// LeaderElectionID is the name of the resource that leader election will use for holding the leader lock.
	LeaderElectionID string

	// WebhookPort is the port that the webhook server serves at.
	WebhookPort int

	// GRPCPort is the port that the gRPC server serves at.
	GRPCPort int

	// CertProvider is the certificate provider (selfsigned, vault).
	CertProvider string

	// VaultAddr is the Vault server address.
	VaultAddr string

	// VaultPKIMount is the Vault PKI mount path.
	VaultPKIMount string

	// VaultPKIRole is the Vault PKI role name.
	VaultPKIRole string

	// LogLevel is the log level (debug, info, warn, error).
	LogLevel string

	// LogFormat is the log format (json, console).
	LogFormat string

	// EnableWebhooks enables admission webhooks.
	EnableWebhooks bool

	// EnableGRPCServer enables the gRPC configuration server.
	EnableGRPCServer bool

	// EnableTracing enables OpenTelemetry tracing.
	EnableTracing bool

	// OTLPEndpoint is the OTLP exporter endpoint.
	OTLPEndpoint string

	// TracingSamplingRate is the sampling rate for tracing (0.0 to 1.0).
	TracingSamplingRate float64

	// VaultInitTimeout is the timeout for Vault certificate manager initialization.
	VaultInitTimeout time.Duration

	// CertDNSNames is the list of DNS names for the server certificate.
	CertDNSNames []string

	// CertServiceName is the service name for generating default DNS names.
	CertServiceName string

	// CertNamespace is the namespace for generating default DNS names.
	CertNamespace string
}

func main() {
	if err := run(); err != nil {
		setupLog.Error(err, "operator failed")
		os.Exit(1)
	}
}

func run() error {
	cfg := parseFlags()

	// Setup logging
	logger := setupLogger(cfg.LogLevel, cfg.LogFormat)
	ctrl.SetLogger(logger)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	setupSignalHandler(cancel)

	// Setup tracing if enabled
	tracerShutdown, err := setupTracingIfEnabled(cfg)
	if err != nil {
		return err
	}
	if tracerShutdown != nil {
		defer tracerShutdown()
	}

	// Create manager
	mgr, err := createManager(cfg)
	if err != nil {
		return err
	}

	// Setup certificate manager
	certManager, err := setupCertManager(ctx, cfg)
	if err != nil {
		return fmt.Errorf("unable to setup certificate manager: %w", err)
	}

	// Setup gRPC server
	grpcServer, err := setupGRPCServerIfEnabled(ctx, cfg, certManager)
	if err != nil {
		return err
	}

	// Setup controllers
	if err := setupControllers(mgr, grpcServer); err != nil {
		return fmt.Errorf("unable to setup controllers: %w", err)
	}

	// Setup webhooks if enabled
	if err := setupWebhooksIfEnabled(mgr, cfg); err != nil {
		return err
	}

	// Add health checks
	if err := setupHealthChecks(mgr); err != nil {
		return err
	}

	// Start gRPC server in background
	startGRPCServerBackground(ctx, grpcServer)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}

	return nil
}

// setupTracingIfEnabled sets up tracing if enabled and returns a shutdown function.
func setupTracingIfEnabled(cfg *Config) (func(), error) {
	if !cfg.EnableTracing {
		return nil, nil
	}

	tracer, err := setupTracing(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to setup tracing: %w", err)
	}

	setupLog.Info("tracing enabled", "endpoint", cfg.OTLPEndpoint, "sampling_rate", cfg.TracingSamplingRate)

	return func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := tracer.Shutdown(shutdownCtx); err != nil {
			setupLog.Error(err, "failed to shutdown tracer")
		}
	}, nil
}

// createManager creates the controller-runtime manager.
func createManager(cfg *Config) (ctrl.Manager, error) {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: cfg.MetricsAddr,
		},
		HealthProbeBindAddress: cfg.ProbeAddr,
		LeaderElection:         cfg.EnableLeaderElection,
		LeaderElectionID:       cfg.LeaderElectionID,
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: cfg.WebhookPort,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create manager: %w", err)
	}
	return mgr, nil
}

// setupGRPCServerIfEnabled sets up the gRPC server if enabled.
func setupGRPCServerIfEnabled(
	ctx context.Context,
	cfg *Config,
	certManager cert.Manager,
) (*operatorgrpc.Server, error) {
	if !cfg.EnableGRPCServer {
		return nil, nil
	}

	grpcServer, err := setupGRPCServer(ctx, cfg, certManager)
	if err != nil {
		return nil, fmt.Errorf("unable to setup gRPC server: %w", err)
	}
	return grpcServer, nil
}

// setupWebhooksIfEnabled sets up webhooks if enabled.
func setupWebhooksIfEnabled(mgr ctrl.Manager, cfg *Config) error {
	if !cfg.EnableWebhooks {
		return nil
	}
	if err := setupWebhooks(mgr); err != nil {
		return fmt.Errorf("unable to setup webhooks: %w", err)
	}
	return nil
}

// setupHealthChecks adds health and ready checks to the manager.
func setupHealthChecks(mgr ctrl.Manager) error {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}
	return nil
}

// startGRPCServerBackground starts the gRPC server in a background goroutine.
func startGRPCServerBackground(ctx context.Context, grpcServer *operatorgrpc.Server) {
	if grpcServer == nil {
		return
	}
	go func() {
		if err := grpcServer.Start(ctx); err != nil {
			setupLog.Error(err, "gRPC server error")
		}
	}()
}

func parseFlags() *Config {
	cfg := &Config{}

	defineFlags(cfg)
	flag.Parse()
	applyEnvOverrides(cfg)

	return cfg
}

func defineFlags(cfg *Config) {
	flag.StringVar(&cfg.MetricsAddr, "metrics-bind-address", ":8080",
		"The address the metric endpoint binds to.")
	flag.StringVar(&cfg.ProbeAddr, "health-probe-bind-address", ":8081",
		"The address the probe endpoint binds to.")
	flag.BoolVar(&cfg.EnableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager.")
	flag.StringVar(&cfg.LeaderElectionID, "leader-election-id",
		"avapigw-operator-leader.avapigw.io",
		"The name of the resource that leader election will use for holding the leader lock.")
	flag.IntVar(&cfg.WebhookPort, "webhook-port", 9443,
		"The port that the webhook server serves at.")
	flag.IntVar(&cfg.GRPCPort, "grpc-port", 9444,
		"The port that the gRPC server serves at.")
	flag.StringVar(&cfg.CertProvider, "cert-provider", "selfsigned",
		"The certificate provider (selfsigned, vault).")
	flag.StringVar(&cfg.VaultAddr, "vault-addr", "",
		"The Vault server address.")
	flag.StringVar(&cfg.VaultPKIMount, "vault-pki-mount", "pki",
		"The Vault PKI mount path.")
	flag.StringVar(&cfg.VaultPKIRole, "vault-pki-role", "operator",
		"The Vault PKI role name.")
	flag.StringVar(&cfg.LogLevel, "log-level", "info",
		"The log level (debug, info, warn, error).")
	flag.StringVar(&cfg.LogFormat, "log-format", "json",
		"The log format (json, console).")
	flag.BoolVar(&cfg.EnableWebhooks, "enable-webhooks", true,
		"Enable admission webhooks.")
	flag.BoolVar(&cfg.EnableGRPCServer, "enable-grpc-server", true,
		"Enable the gRPC configuration server.")
	flag.BoolVar(&cfg.EnableTracing, "enable-tracing", false,
		"Enable OpenTelemetry tracing.")
	flag.StringVar(&cfg.OTLPEndpoint, "otlp-endpoint", "",
		"The OTLP exporter endpoint (e.g., localhost:4317).")
	flag.Float64Var(&cfg.TracingSamplingRate, "tracing-sampling-rate", 1.0,
		"The sampling rate for tracing (0.0 to 1.0).")
	flag.DurationVar(&cfg.VaultInitTimeout, "vault-init-timeout", 30*time.Second,
		"The timeout for Vault certificate manager initialization.")
	flag.StringVar(&cfg.CertServiceName, "cert-service-name", "avapigw-operator",
		"The service name for generating default certificate DNS names.")
	flag.StringVar(&cfg.CertNamespace, "cert-namespace", "avapigw-system",
		"The namespace for generating default certificate DNS names.")
}

func applyEnvOverrides(cfg *Config) {
	// String overrides
	applyStringEnv(&cfg.MetricsAddr, "METRICS_BIND_ADDRESS")
	applyStringEnv(&cfg.ProbeAddr, "HEALTH_PROBE_BIND_ADDRESS")
	applyStringEnv(&cfg.LeaderElectionID, "LEADER_ELECTION_ID")
	applyStringEnv(&cfg.CertProvider, "CERT_PROVIDER")
	applyStringEnv(&cfg.VaultAddr, "VAULT_ADDR")
	applyStringEnv(&cfg.VaultPKIMount, "VAULT_PKI_MOUNT")
	applyStringEnv(&cfg.VaultPKIRole, "VAULT_PKI_ROLE")
	applyStringEnv(&cfg.LogLevel, "LOG_LEVEL")
	applyStringEnv(&cfg.LogFormat, "LOG_FORMAT")
	applyStringEnv(&cfg.OTLPEndpoint, "OTLP_ENDPOINT")

	// Int overrides
	applyIntEnv(&cfg.WebhookPort, "WEBHOOK_PORT")
	applyIntEnv(&cfg.GRPCPort, "GRPC_PORT")

	// Float overrides
	applyFloat64Env(&cfg.TracingSamplingRate, "TRACING_SAMPLING_RATE")

	// Duration overrides
	applyDurationEnv(&cfg.VaultInitTimeout, "VAULT_INIT_TIMEOUT")

	// Certificate DNS names override
	applyStringEnv(&cfg.CertServiceName, "CERT_SERVICE_NAME")
	applyStringEnv(&cfg.CertNamespace, "CERT_NAMESPACE")
	applyCertDNSNamesEnv(cfg)

	// Bool overrides
	if os.Getenv("LEADER_ELECT") == "true" {
		cfg.EnableLeaderElection = true
	}
	if os.Getenv("ENABLE_WEBHOOKS") == "false" {
		cfg.EnableWebhooks = false
	}
	if os.Getenv("ENABLE_GRPC_SERVER") == "false" {
		cfg.EnableGRPCServer = false
	}
	if os.Getenv("ENABLE_TRACING") == "true" {
		cfg.EnableTracing = true
	}
}

func applyStringEnv(target *string, envKey string) {
	if v := os.Getenv(envKey); v != "" {
		*target = v
	}
}

func applyIntEnv(target *int, envKey string) {
	if v := os.Getenv(envKey); v != "" {
		var port int
		if err := parseIntEnv(v, &port); err == nil {
			*target = port
		}
	}
}

func applyFloat64Env(target *float64, envKey string) {
	if v := os.Getenv(envKey); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			*target = f
		}
	}
}

func applyDurationEnv(target *time.Duration, envKey string) {
	if v := os.Getenv(envKey); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			*target = d
		}
	}
}

// applyCertDNSNamesEnv applies the CERT_DNS_NAMES environment variable override.
// The value should be a comma-separated list of DNS names.
func applyCertDNSNamesEnv(cfg *Config) {
	if v := os.Getenv("CERT_DNS_NAMES"); v != "" {
		cfg.CertDNSNames = splitAndTrim(v, ",")
	}
}

// splitAndTrim splits a string by separator and trims whitespace from each part.
func splitAndTrim(s, sep string) []string {
	parts := make([]string, 0)
	for _, part := range splitString(s, sep) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// splitString splits a string by separator without using strings package.
func splitString(s, sep string) []string {
	if s == "" {
		return nil
	}
	if sep == "" {
		return []string{s}
	}

	var result []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

// trimSpace trims leading and trailing whitespace from a string.
func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func parseIntEnv(s string, v *int) error {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return fmt.Errorf("invalid integer: %s", s)
		}
		n = n*10 + int(c-'0')
	}
	*v = n
	return nil
}

func setupLogger(level, format string) logr.Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var encoder zapcore.Encoder
	if format == "console" {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	core := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapLevel)

	opts := []ctrlzap.Opts{
		ctrlzap.UseDevMode(level == "debug"),
		ctrlzap.RawZapOpts(zap.WrapCore(func(_ zapcore.Core) zapcore.Core {
			return core
		})),
	}
	return ctrlzap.New(opts...)
}

func setupSignalHandler(cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		setupLog.Info("received signal, shutting down", "signal", sig.String())
		cancel()

		// Give some time for graceful shutdown
		time.Sleep(5 * time.Second)

		sig = <-sigCh
		setupLog.Info("received second signal, forcing shutdown", "signal", sig.String())
		os.Exit(1)
	}()
}

func setupTracing(cfg *Config) (*observability.Tracer, error) {
	return observability.NewTracer(observability.TracerConfig{
		ServiceName:  "avapigw-operator",
		OTLPEndpoint: cfg.OTLPEndpoint,
		SamplingRate: cfg.TracingSamplingRate,
		Enabled:      cfg.EnableTracing,
	})
}

func setupCertManager(ctx context.Context, cfg *Config) (cert.Manager, error) {
	switch cfg.CertProvider {
	case "vault":
		// Create a context with timeout for Vault initialization
		vaultCtx, cancel := context.WithTimeout(ctx, cfg.VaultInitTimeout)
		defer cancel()

		setupLog.Info("initializing Vault certificate manager",
			"address", cfg.VaultAddr,
			"timeout", cfg.VaultInitTimeout.String(),
		)

		manager, err := cert.NewVaultProvider(vaultCtx, &cert.VaultProviderConfig{
			Address:  cfg.VaultAddr,
			PKIMount: cfg.VaultPKIMount,
			Role:     cfg.VaultPKIRole,
		})
		if err != nil {
			// Check if the error is due to context timeout
			if vaultCtx.Err() != nil {
				return nil, fmt.Errorf(
					"vault certificate manager initialization timed out after %s: %w",
					cfg.VaultInitTimeout, err,
				)
			}
			return nil, fmt.Errorf("failed to initialize vault certificate manager: %w", err)
		}
		return manager, nil
	default:
		return cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
			CACommonName:    cert.DefaultCACommonName,
			CAValidity:      cert.DefaultCAValidity,
			CertValidity:    cert.DefaultCertValidity,
			RotateBefore:    cert.DefaultRotateBefore,
			KeySize:         cert.DefaultKeySize,
			Organization:    []string{cert.DefaultOrganization},
			SecretName:      cert.DefaultSecretName,
			SecretNamespace: cert.DefaultSecretNamespace,
		})
	}
}

// defaultCertDNSNames generates the default DNS names for the server certificate.
// It creates a list of DNS names based on the service name and namespace:
// - serviceName
// - serviceName.namespace
// - serviceName.namespace.svc
// - serviceName.namespace.svc.cluster.local
func defaultCertDNSNames(serviceName, namespace string) []string {
	return []string{
		serviceName,
		serviceName + "." + namespace,
		serviceName + "." + namespace + ".svc",
		serviceName + "." + namespace + ".svc.cluster.local",
	}
}

// getCertDNSNames returns the DNS names for the server certificate.
// If custom DNS names are configured, they are used; otherwise, default names are generated.
func getCertDNSNames(cfg *Config) []string {
	if len(cfg.CertDNSNames) > 0 {
		return cfg.CertDNSNames
	}
	return defaultCertDNSNames(cfg.CertServiceName, cfg.CertNamespace)
}

func setupGRPCServer(ctx context.Context, cfg *Config, certManager cert.Manager) (*operatorgrpc.Server, error) {
	dnsNames := getCertDNSNames(cfg)

	setupLog.Info("requesting server certificate",
		"service_name", cfg.CertServiceName,
		"namespace", cfg.CertNamespace,
		"dns_names", dnsNames,
	)

	serverCert, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: cfg.CertServiceName,
		DNSNames:   dnsNames,
	})
	if err != nil {
		return nil, err
	}

	return operatorgrpc.NewServer(&operatorgrpc.ServerConfig{
		Port:        cfg.GRPCPort,
		Certificate: serverCert,
		CertManager: certManager,
	})
}

func setupControllers(mgr ctrl.Manager, grpcServer *operatorgrpc.Server) error {
	// Setup APIRoute controller
	if err := (&controller.APIRouteReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
		Recorder:   mgr.GetEventRecorderFor("apiroute-controller"),
		GRPCServer: grpcServer,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	// Setup GRPCRoute controller
	if err := (&controller.GRPCRouteReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
		Recorder:   mgr.GetEventRecorderFor("grpcroute-controller"),
		GRPCServer: grpcServer,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	// Setup Backend controller
	if err := (&controller.BackendReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
		Recorder:   mgr.GetEventRecorderFor("backend-controller"),
		GRPCServer: grpcServer,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	// Setup GRPCBackend controller
	if err := (&controller.GRPCBackendReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
		Recorder:   mgr.GetEventRecorderFor("grpcbackend-controller"),
		GRPCServer: grpcServer,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	return nil
}

func setupWebhooks(mgr ctrl.Manager) error {
	// Setup APIRoute webhook
	if err := operatorwebhook.SetupAPIRouteWebhook(mgr); err != nil {
		return err
	}

	// Setup GRPCRoute webhook
	if err := operatorwebhook.SetupGRPCRouteWebhook(mgr); err != nil {
		return err
	}

	// Setup Backend webhook
	if err := operatorwebhook.SetupBackendWebhook(mgr); err != nil {
		return err
	}

	// Setup GRPCBackend webhook
	if err := operatorwebhook.SetupGRPCBackendWebhook(mgr); err != nil {
		return err
	}

	return nil
}
