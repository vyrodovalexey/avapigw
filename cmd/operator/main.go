// Package main is the entry point for the avapigw-operator.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
	"github.com/vyrodovalexey/avapigw/internal/operator/controller"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
	operatorwebhook "github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// tracerShutdowner is an interface for shutting down a tracer.
// It is satisfied by *observability.Tracer and can be replaced in tests.
type tracerShutdowner interface {
	Shutdown(ctx context.Context) error
}

// setupTracingFunc is the function used to create a tracer.
// It is a package-level variable to allow overriding in tests
// where OpenTelemetry schema URL conflicts prevent real tracer creation.
// Version information (set at build time).
var (
	operatorVersion   = "dev"
	operatorBuildTime = "unknown"
	operatorGitCommit = "unknown"
)

// defaultWebhookConfigName is the default name of the ValidatingWebhookConfiguration resource.
const defaultWebhookConfigName = "avapigw-operator-validating-webhook-configuration"

var setupTracingFunc = defaultSetupTracing

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

var (
	operatorBuildInfo     *prometheus.GaugeVec
	operatorBuildInfoOnce sync.Once
)

// initializeMetrics initializes all operator metrics modules with the given
// Prometheus registerer so they appear on the correct /metrics endpoint.
// This must be called early in runWithConfig, after the controller manager
// is created but before any component that records metrics is started.
func initializeMetrics(registerer prometheus.Registerer) {
	initOperatorBuildInfo(registerer)
	controller.InitControllerMetrics(registerer)
	controller.InitControllerVecMetrics()
	controller.InitStatusUpdateMetrics(registerer)
	controller.InitStatusUpdateVecMetrics()
	operatorwebhook.InitWebhookMetrics(registerer)
	operatorwebhook.InitWebhookVecMetrics()
	operatorwebhook.InitDuplicateMetrics(registerer)
	operatorwebhook.InitDuplicateVecMetrics()
	cert.InitCertMetrics(registerer)
	cert.InitCertVecMetrics()
	cert.InitVaultAuthMetrics(registerer)
	cert.InitVaultAuthVecMetrics()
	cert.InitWebhookInjectorMetrics(registerer)
	cert.InitWebhookInjectorVecMetrics()
}

// initOperatorBuildInfo initializes the singleton operator build info metric with
// the given Prometheus registerer. If registerer is nil, metrics are registered with
// the default registerer. Must be called before using operatorBuildInfo for the metric
// to appear on the correct registry; subsequent calls are no-ops (sync.Once).
func initOperatorBuildInfo(registerer prometheus.Registerer) {
	operatorBuildInfoOnce.Do(func() {
		if registerer == nil {
			registerer = prometheus.DefaultRegisterer
		}
		factory := promauto.With(registerer)
		operatorBuildInfo = factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "avapigw_operator",
				Name:      "build_info",
				Help: "Build information for " +
					"the operator",
			},
			[]string{"version", "commit", "build_time"},
		)
	})
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(avapigwv1alpha1.AddToScheme(scheme))
	utilruntime.Must(networkingv1.AddToScheme(scheme))
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

	// WebhookCertDir is the directory containing TLS certificates for the webhook server.
	// When set, the webhook server uses tls.crt and tls.key from this directory.
	// If empty, the controller-runtime default cert directory is used.
	WebhookCertDir string

	// WebhookConfigName is the name of the ValidatingWebhookConfiguration resource.
	// Defaults to "avapigw-operator-validating-webhook-configuration".
	WebhookConfigName string

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

	// VaultK8sRole is the Vault role for Kubernetes authentication.
	VaultK8sRole string

	// VaultK8sMountPath is the mount path for the Kubernetes auth method.
	// Defaults to "kubernetes".
	VaultK8sMountPath string

	// LogLevel is the log level (debug, info, warn, error).
	LogLevel string

	// LogFormat is the log format (json, console).
	LogFormat string

	// EnableWebhooks enables admission webhooks.
	EnableWebhooks bool

	// EnableGRPCServer enables the gRPC configuration server.
	EnableGRPCServer bool

	// GRPCRequireClientCert requires client certificates for gRPC connections (mTLS).
	// When false, the gRPC server uses server-side TLS only.
	GRPCRequireClientCert bool

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

	// EnableIngressController enables the Kubernetes Ingress controller.
	EnableIngressController bool

	// IngressClassName is the IngressClass name this controller handles.
	IngressClassName string

	// IngressLBAddress is the load balancer address (IP or hostname) to set on Ingress status.
	IngressLBAddress string

	// EnableClusterWideDuplicateCheck enables cluster-wide duplicate detection for webhooks.
	// When false (default), duplicate detection is namespace-scoped for better performance.
	EnableClusterWideDuplicateCheck bool

	// DuplicateCacheEnabled enables caching for duplicate detection.
	DuplicateCacheEnabled bool

	// DuplicateCacheTTL is the TTL for duplicate detection cache entries.
	DuplicateCacheTTL time.Duration
}

func main() {
	if err := run(); err != nil {
		setupLog.Error(err, "operator failed")
		os.Exit(1)
	}
}

func run() error {
	cfg := parseFlags()
	return runWithConfig(cfg, nil)
}

// runWithConfig is the main orchestration function that accepts a REST config.
// When restConfig is nil, it uses ctrl.GetConfigOrDie() (production mode).
// This separation enables unit testing without a real Kubernetes cluster.
func runWithConfig(cfg *Config, restConfig *rest.Config) error {
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

	// Setup certificate manager and create controller manager
	certManager, mgr, err := setupCertManagerAndControllerManager(ctx, cfg, restConfig)
	if err != nil {
		return err
	}

	// Schedule cleanup of temporary webhook certificate directory after the
	// manager stops. The cert dir may contain private key material that must
	// not persist on disk beyond the operator's lifetime.
	if cfg.WebhookCertDir != "" && strings.HasPrefix(cfg.WebhookCertDir, os.TempDir()) {
		defer func() {
			setupLog.Info("cleaning up temporary webhook certificate directory",
				"cert_dir", cfg.WebhookCertDir,
			)
			if removeErr := os.RemoveAll(cfg.WebhookCertDir); removeErr != nil {
				setupLog.Error(removeErr, "failed to remove temporary webhook certificate directory",
					"cert_dir", cfg.WebhookCertDir,
				)
			}
		}()
	}

	// Initialize all operator metrics with controller-runtime's registry
	// so they appear on the /metrics endpoint served by the manager.
	initializeMetrics(metrics.Registry)

	// Set build info metric
	operatorBuildInfo.WithLabelValues(
		operatorVersion, operatorGitCommit,
		operatorBuildTime,
	).Set(1)

	// Setup all operator components (gRPC, controllers, webhooks, health checks)
	caInjector, err := setupOperatorComponents(ctx, cfg, mgr, certManager)
	if err != nil {
		return err
	}
	if caInjector != nil {
		defer caInjector.Stop()
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}

	return nil
}

// setupCertManagerAndControllerManager initializes the certificate manager,
// writes webhook TLS certificates if needed, and creates the controller-runtime manager.
func setupCertManagerAndControllerManager(
	ctx context.Context,
	cfg *Config,
	restConfig *rest.Config,
) (cert.Manager, ctrl.Manager, error) {
	certManager, err := setupCertManager(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to setup certificate manager: %w", err)
	}

	// Write webhook TLS certificates from the cert manager when webhooks are enabled.
	// This wires the cert manager's certificates to the webhook server's TLS configuration.
	if cfg.EnableWebhooks {
		certDir, certErr := writeWebhookCertificates(ctx, cfg, certManager)
		if certErr != nil {
			return nil, nil, fmt.Errorf("unable to write webhook certificates: %w", certErr)
		}
		if certDir != "" {
			cfg.WebhookCertDir = certDir
		}
	}

	var mgr ctrl.Manager
	if restConfig != nil {
		mgr, err = createManagerWithConfig(restConfig, cfg)
	} else {
		mgr, err = createManager(cfg)
	}
	if err != nil {
		return nil, nil, err
	}

	return certManager, mgr, nil
}

// setupOperatorComponents sets up gRPC server, controllers, webhooks, CA injector,
// health checks, and starts the gRPC server in the background.
func setupOperatorComponents(
	ctx context.Context,
	cfg *Config,
	mgr ctrl.Manager,
	certManager cert.Manager,
) (*cert.WebhookCAInjector, error) {
	grpcServer, err := setupGRPCServerIfEnabled(ctx, cfg, certManager)
	if err != nil {
		return nil, err
	}

	if err := setupControllers(mgr, grpcServer, cfg); err != nil {
		return nil, fmt.Errorf("unable to setup controllers: %w", err)
	}

	// Setup webhooks if enabled (pass ctx for DuplicateChecker lifecycle management)
	if err := setupWebhooksIfEnabled(ctx, mgr, cfg); err != nil {
		return nil, err
	}

	caInjector, err := setupWebhookCAInjectorIfEnabled(ctx, mgr, cfg, certManager)
	if err != nil {
		return nil, err
	}

	if err := setupHealthChecks(mgr); err != nil {
		return nil, err
	}

	startGRPCServerBackground(ctx, grpcServer)

	return caInjector, nil
}

// setupTracingIfEnabled sets up tracing if enabled and returns a shutdown function.
func setupTracingIfEnabled(cfg *Config) (func(), error) {
	if !cfg.EnableTracing {
		return nil, nil
	}

	tracer, err := setupTracingFunc(cfg)
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
	return createManagerWithConfig(ctrl.GetConfigOrDie(), cfg)
}

// createManagerWithConfig creates the controller-runtime manager using the provided REST config.
// This is separated from createManager to enable unit testing with a fake API server.
func createManagerWithConfig(restConfig *rest.Config, cfg *Config) (ctrl.Manager, error) {
	webhookOpts := webhook.Options{
		Port: cfg.WebhookPort,
	}

	// Configure TLS certificate paths for the webhook server if cert directory is set.
	// The cert manager writes certificates to this directory, and the webhook server
	// reads them for TLS termination.
	if cfg.WebhookCertDir != "" {
		webhookOpts.CertDir = cfg.WebhookCertDir
		webhookOpts.CertName = "tls.crt"
		webhookOpts.KeyName = "tls.key"
	}

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: cfg.MetricsAddr,
		},
		HealthProbeBindAddress: cfg.ProbeAddr,
		LeaderElection:         cfg.EnableLeaderElection,
		LeaderElectionID:       cfg.LeaderElectionID,
		WebhookServer:          webhook.NewServer(webhookOpts),
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

// setupWebhookCAInjectorIfEnabled creates and starts the WebhookCAInjector when webhooks are enabled.
// It injects the CA bundle from the cert manager into ValidatingWebhookConfiguration resources
// so that the API server can verify the webhook server's TLS certificate.
func setupWebhookCAInjectorIfEnabled(
	ctx context.Context,
	mgr ctrl.Manager,
	cfg *Config,
	certManager cert.Manager,
) (*cert.WebhookCAInjector, error) {
	if !cfg.EnableWebhooks {
		return nil, nil
	}

	webhookConfigName := cfg.WebhookConfigName
	if webhookConfigName == "" {
		webhookConfigName = defaultWebhookConfigName
	}

	injector, err := cert.NewWebhookCAInjector(&cert.WebhookInjectorConfig{
		WebhookConfigName: webhookConfigName,
		CertManager:       certManager,
		Client:            mgr.GetClient(),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create webhook CA injector: %w", err)
	}

	// Start the injector in a background goroutine; it will stop when ctx is canceled
	go func() {
		if startErr := injector.Start(ctx); startErr != nil {
			setupLog.Error(startErr, "webhook CA injector error")
		}
	}()

	setupLog.Info("webhook CA injector started",
		"webhook_config", webhookConfigName,
	)

	return injector, nil
}

// setupWebhooksIfEnabled sets up webhooks if enabled.
// The context is used for DuplicateChecker lifecycle management to prevent goroutine leaks.
func setupWebhooksIfEnabled(ctx context.Context, mgr ctrl.Manager, cfg *Config) error {
	if !cfg.EnableWebhooks {
		return nil
	}
	if err := setupWebhooks(ctx, mgr, cfg); err != nil {
		return fmt.Errorf("unable to setup webhooks: %w", err)
	}
	return nil
}

// healthCheckAdder is an interface for adding health and readiness checks.
// It is satisfied by ctrl.Manager and can be mocked in tests.
type healthCheckAdder interface {
	AddHealthzCheck(name string, check healthz.Checker) error
	AddReadyzCheck(name string, check healthz.Checker) error
}

// setupHealthChecks adds health and ready checks to the manager.
func setupHealthChecks(mgr healthCheckAdder) error {
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
	flag.StringVar(&cfg.WebhookCertDir, "webhook-cert-dir", "",
		"The directory containing TLS certificates for the webhook server. "+
			"If empty, certificates are generated from the cert manager.")
	flag.StringVar(&cfg.WebhookConfigName, "webhook-config-name", defaultWebhookConfigName,
		"The name of the ValidatingWebhookConfiguration resource.")
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
	flag.StringVar(&cfg.VaultK8sRole, "vault-k8s-role", "",
		"The Vault role for Kubernetes authentication.")
	flag.StringVar(&cfg.VaultK8sMountPath, "vault-k8s-mount-path", "kubernetes",
		"The mount path for the Kubernetes auth method.")
	flag.StringVar(&cfg.LogLevel, "log-level", "info",
		"The log level (debug, info, warn, error).")
	flag.StringVar(&cfg.LogFormat, "log-format", "json",
		"The log format (json, console).")
	flag.BoolVar(&cfg.EnableWebhooks, "enable-webhooks", true,
		"Enable admission webhooks.")
	flag.BoolVar(&cfg.EnableGRPCServer, "enable-grpc-server", true,
		"Enable the gRPC configuration server.")
	flag.BoolVar(&cfg.GRPCRequireClientCert, "grpc-require-client-cert", false,
		"Require client certificates for gRPC connections (mTLS). When false, uses server-side TLS only.")
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
	flag.BoolVar(&cfg.EnableIngressController, "enable-ingress-controller", false,
		"Enable the Kubernetes Ingress controller.")
	flag.StringVar(&cfg.IngressClassName, "ingress-class-name", controller.DefaultIngressClassName,
		"The IngressClass name this controller handles.")
	flag.StringVar(&cfg.IngressLBAddress, "ingress-lb-address", "",
		"The load balancer address (IP or hostname) to set on Ingress status.")
	flag.BoolVar(&cfg.EnableClusterWideDuplicateCheck, "enable-cluster-wide-duplicate-check", false,
		"Enable cluster-wide duplicate detection for webhooks (default: namespace-scoped).")
	flag.BoolVar(&cfg.DuplicateCacheEnabled, "duplicate-cache-enabled", true,
		"Enable caching for duplicate detection.")
	flag.DurationVar(&cfg.DuplicateCacheTTL, "duplicate-cache-ttl", 30*time.Second,
		"TTL for duplicate detection cache entries.")
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
	applyStringEnv(&cfg.VaultK8sRole, "VAULT_K8S_ROLE")
	applyStringEnv(&cfg.VaultK8sMountPath, "VAULT_K8S_MOUNT_PATH")
	applyStringEnv(&cfg.LogLevel, "LOG_LEVEL")
	applyStringEnv(&cfg.LogFormat, "LOG_FORMAT")
	applyStringEnv(&cfg.OTLPEndpoint, "OTLP_ENDPOINT")

	// Int overrides
	applyIntEnv(&cfg.WebhookPort, "WEBHOOK_PORT")
	applyStringEnv(&cfg.WebhookCertDir, "WEBHOOK_CERT_DIR")
	applyStringEnv(&cfg.WebhookConfigName, "WEBHOOK_CONFIG_NAME")
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
	applyBoolEnv(&cfg.EnableLeaderElection, "LEADER_ELECT")
	applyBoolEnv(&cfg.EnableWebhooks, "ENABLE_WEBHOOKS")
	applyBoolEnv(&cfg.EnableGRPCServer, "ENABLE_GRPC_SERVER")
	applyBoolEnv(&cfg.GRPCRequireClientCert, "GRPC_REQUIRE_CLIENT_CERT")
	applyBoolEnv(&cfg.EnableTracing, "ENABLE_TRACING")
	applyBoolEnv(&cfg.EnableIngressController, "ENABLE_INGRESS_CONTROLLER")
	applyStringEnv(&cfg.IngressClassName, "INGRESS_CLASS_NAME")
	applyStringEnv(&cfg.IngressLBAddress, "INGRESS_LB_ADDRESS")

	// Duplicate detection configuration
	applyBoolEnv(&cfg.EnableClusterWideDuplicateCheck, "ENABLE_CLUSTER_WIDE_DUPLICATE_CHECK")
	applyBoolEnv(&cfg.DuplicateCacheEnabled, "DUPLICATE_CACHE_ENABLED")
	applyDurationEnv(&cfg.DuplicateCacheTTL, "DUPLICATE_CACHE_TTL")
}

// applyBoolEnv applies a boolean environment variable override.
// It handles both true and false values symmetrically.
func applyBoolEnv(target *bool, envKey string) {
	if v := os.Getenv(envKey); v != "" {
		switch strings.ToLower(v) {
		case "true", "1", "yes":
			*target = true
		case "false", "0", "no":
			*target = false
		}
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
	for _, part := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func parseIntEnv(s string, v *int) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid integer: %s", s)
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

		// Wait for a second signal to force shutdown; context cancellation
		// drives graceful shutdown so no fixed sleep is needed.
		sig = <-sigCh
		setupLog.Info("received second signal, forcing shutdown", "signal", sig.String())
		os.Exit(1)
	}()
}

// defaultSetupTracing is the default implementation of setupTracingFunc.
// It delegates to setupTracing and adapts the return type to tracerShutdowner.
func defaultSetupTracing(cfg *Config) (tracerShutdowner, error) {
	return setupTracing(cfg)
}

func setupTracing(cfg *Config) (*observability.Tracer, error) {
	return observability.NewTracer(observability.TracerConfig{
		ServiceName:  "avapigw-operator",
		OTLPEndpoint: cfg.OTLPEndpoint,
		SamplingRate: cfg.TracingSamplingRate,
		Enabled:      cfg.EnableTracing,
		OTLPInsecure: true, // Default insecure for backward compatibility
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
			Address:             cfg.VaultAddr,
			PKIMount:            cfg.VaultPKIMount,
			Role:                cfg.VaultPKIRole,
			KubernetesRole:      cfg.VaultK8sRole,
			KubernetesMountPath: cfg.VaultK8sMountPath,
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

// writeWebhookCertificates obtains a TLS certificate from the cert manager and
// writes it to a temporary directory so the webhook server can load it.
// Returns the directory path containing the certificate files.
func writeWebhookCertificates(
	ctx context.Context,
	cfg *Config,
	certManager cert.Manager,
) (string, error) {
	dnsNames := getCertDNSNames(cfg)

	setupLog.Info("requesting webhook server certificate",
		"service_name", cfg.CertServiceName,
		"namespace", cfg.CertNamespace,
		"dns_names", dnsNames,
	)

	serverCert, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: cfg.CertServiceName,
		DNSNames:   dnsNames,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get webhook certificate: %w", err)
	}

	// Create a temporary directory for webhook certificates
	certDir, err := os.MkdirTemp("", "avapigw-webhook-certs-*")
	if err != nil {
		return "", fmt.Errorf("failed to create webhook cert directory: %w", err)
	}

	// Write certificate file
	certPath := filepath.Join(certDir, "tls.crt")
	if err := os.WriteFile(certPath, serverCert.CertificatePEM, 0o600); err != nil {
		return "", fmt.Errorf("failed to write webhook certificate: %w", err)
	}

	// Write private key file
	keyPath := filepath.Join(certDir, "tls.key")
	if err := os.WriteFile(keyPath, serverCert.PrivateKeyPEM, 0o600); err != nil {
		return "", fmt.Errorf("failed to write webhook private key: %w", err)
	}

	setupLog.Info("webhook TLS certificates written",
		"cert_dir", certDir,
		"expiration", serverCert.Expiration,
	)

	return certDir, nil
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

	serverConfig := &operatorgrpc.ServerConfig{
		Port:              cfg.GRPCPort,
		Certificate:       serverCert,
		MetricsRegisterer: metrics.Registry,
	}
	// Only enable mTLS (client cert verification) when explicitly requested
	if cfg.GRPCRequireClientCert {
		serverConfig.CertManager = certManager
	}
	server, err := operatorgrpc.NewServer(serverConfig)
	if err != nil {
		return nil, err
	}
	operatorgrpc.InitServerVecMetrics()
	return server, nil
}

// controllerSetup defines a controller setup operation with a name for error reporting.
type controllerSetup struct {
	name  string
	setup func() error
}

func setupControllers(mgr ctrl.Manager, grpcServer *operatorgrpc.Server, cfg *Config) error {
	setups := []controllerSetup{
		{
			name: "APIRoute",
			setup: func() error {
				return (&controller.APIRouteReconciler{
					Client: mgr.GetClient(),
					Scheme: mgr.GetScheme(),
					//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
					Recorder:   mgr.GetEventRecorderFor("apiroute-controller"),
					GRPCServer: grpcServer,
				}).SetupWithManager(mgr)
			},
		},
		{
			name: "GRPCRoute",
			setup: func() error {
				return (&controller.GRPCRouteReconciler{
					Client: mgr.GetClient(),
					Scheme: mgr.GetScheme(),
					//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
					Recorder:   mgr.GetEventRecorderFor("grpcroute-controller"),
					GRPCServer: grpcServer,
				}).SetupWithManager(mgr)
			},
		},
		{
			name: "Backend",
			setup: func() error {
				return (&controller.BackendReconciler{
					Client: mgr.GetClient(),
					Scheme: mgr.GetScheme(),
					//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
					Recorder:   mgr.GetEventRecorderFor("backend-controller"),
					GRPCServer: grpcServer,
				}).SetupWithManager(mgr)
			},
		},
		{
			name: "GRPCBackend",
			setup: func() error {
				return (&controller.GRPCBackendReconciler{
					Client: mgr.GetClient(),
					Scheme: mgr.GetScheme(),
					//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
					Recorder:   mgr.GetEventRecorderFor("grpcbackend-controller"),
					GRPCServer: grpcServer,
				}).SetupWithManager(mgr)
			},
		},
		{
			name: "GraphQLRoute",
			setup: func() error {
				return (&controller.GraphQLRouteReconciler{
					Client: mgr.GetClient(),
					Scheme: mgr.GetScheme(),
					//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
					Recorder:   mgr.GetEventRecorderFor("graphqlroute-controller"),
					GRPCServer: grpcServer,
				}).SetupWithManager(mgr)
			},
		},
		{
			name: "GraphQLBackend",
			setup: func() error {
				return (&controller.GraphQLBackendReconciler{
					Client: mgr.GetClient(),
					Scheme: mgr.GetScheme(),
					//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
					Recorder:   mgr.GetEventRecorderFor("graphqlbackend-controller"),
					GRPCServer: grpcServer,
				}).SetupWithManager(mgr)
			},
		},
	}

	for _, s := range setups {
		if err := s.setup(); err != nil {
			return fmt.Errorf("unable to setup %s controller: %w", s.name, err)
		}
	}

	// Setup Ingress controller if enabled
	if cfg.EnableIngressController {
		if err := setupIngressController(mgr, grpcServer, cfg); err != nil {
			return fmt.Errorf("unable to setup Ingress controller: %w", err)
		}
	}

	return nil
}

func setupIngressController(
	mgr ctrl.Manager,
	grpcServer *operatorgrpc.Server,
	cfg *Config,
) error {
	setupLog.Info("setting up Ingress controller",
		"ingress_class", cfg.IngressClassName,
		"lb_address", cfg.IngressLBAddress,
	)

	statusUpdater := controller.NewIngressStatusUpdater(mgr.GetClient(), cfg.IngressLBAddress)

	return (&controller.IngressReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		//nolint:staticcheck // Using deprecated API for compatibility with record.EventRecorder
		Recorder:            mgr.GetEventRecorderFor("ingress-controller"),
		GRPCServer:          grpcServer,
		IngressStatusUpdate: statusUpdater,
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    cfg.IngressClassName,
	}).SetupWithManager(mgr)
}

func setupWebhooks(ctx context.Context, mgr ctrl.Manager, cfg *Config) error {
	// Create a single shared DuplicateChecker for all webhooks.
	// This avoids creating multiple instances (and cleanup goroutines) per webhook.
	duplicateCheckerCfg := operatorwebhook.DuplicateCheckerConfig{
		ClusterWide:  cfg.EnableClusterWideDuplicateCheck,
		CacheEnabled: cfg.DuplicateCacheEnabled,
		CacheTTL:     cfg.DuplicateCacheTTL,
	}

	sharedChecker := operatorwebhook.NewDuplicateCheckerFromConfigWithContext(
		ctx, mgr.GetClient(), duplicateCheckerCfg,
	)

	setupLog.Info("configuring webhook duplicate detection",
		"cluster_wide", duplicateCheckerCfg.ClusterWide,
		"cache_enabled", duplicateCheckerCfg.CacheEnabled,
		"cache_ttl", duplicateCheckerCfg.CacheTTL,
		"shared_checker", true,
	)

	webhookSetups := []controllerSetup{
		{
			name: "APIRoute",
			setup: func() error {
				return operatorwebhook.SetupAPIRouteWebhookWithChecker(mgr, sharedChecker)
			},
		},
		{
			name: "GRPCRoute",
			setup: func() error {
				return operatorwebhook.SetupGRPCRouteWebhookWithChecker(mgr, sharedChecker)
			},
		},
		{
			name: "Backend",
			setup: func() error {
				return operatorwebhook.SetupBackendWebhookWithChecker(mgr, sharedChecker)
			},
		},
		{
			name: "GRPCBackend",
			setup: func() error {
				return operatorwebhook.SetupGRPCBackendWebhookWithChecker(mgr, sharedChecker)
			},
		},
		{
			name: "GraphQLRoute",
			setup: func() error {
				return operatorwebhook.SetupGraphQLRouteWebhookWithChecker(mgr, sharedChecker)
			},
		},
		{
			name: "GraphQLBackend",
			setup: func() error {
				return operatorwebhook.SetupGraphQLBackendWebhookWithChecker(mgr, sharedChecker)
			},
		},
	}

	for _, s := range webhookSetups {
		if err := s.setup(); err != nil {
			return fmt.Errorf("unable to setup %s webhook: %w", s.name, err)
		}
	}

	// Setup Ingress webhook if Ingress controller is enabled, sharing the same DuplicateChecker
	if cfg.EnableIngressController {
		setupLog.Info("setting up Ingress validating webhook",
			"ingress_class", cfg.IngressClassName,
		)
		if err := operatorwebhook.SetupIngressWebhookWithChecker(mgr, sharedChecker, cfg.IngressClassName); err != nil {
			return fmt.Errorf("unable to setup Ingress webhook: %w", err)
		}
	}

	return nil
}
