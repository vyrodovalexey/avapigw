// Package main is the entry point for the avapigw-operator.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	"sigs.k8s.io/controller-runtime/pkg/client"
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

// defaultCertManagerCertDir is controller-runtime's default webhook
// serving-certs directory, where cert-manager-provisioned Secrets are
// mounted by convention.
const defaultCertManagerCertDir = "/tmp/k8s-webhook-server/serving-certs"

// defaultString returns s, or fallback when s is empty.
func defaultString(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

var setupTracingFunc = defaultSetupTracing

// setupSignalHandlerFunc is the function used to create the signal-handling context.
// It defaults to ctrl.SetupSignalHandler and can be overridden in tests to avoid
// the panic that occurs when ctrl.SetupSignalHandler is called more than once.
var setupSignalHandlerFunc = defaultSetupSignalHandler

// defaultSetupSignalHandler delegates to controller-runtime's signal handler.
func defaultSetupSignalHandler() context.Context {
	return ctrl.SetupSignalHandler()
}

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

	// WebhookCertName is the certificate file name inside WebhookCertDir
	// (default "tls.crt"). Set automatically for the file provider when the
	// webhook cert dir is derived from --cert-file.
	WebhookCertName string

	// WebhookKeyName is the key file name inside WebhookCertDir
	// (default "tls.key").
	WebhookKeyName string

	// WebhookConfigName is the name of the ValidatingWebhookConfiguration resource.
	// Defaults to "avapigw-operator-validating-webhook-configuration".
	WebhookConfigName string

	// GRPCPort is the port that the gRPC server serves at.
	GRPCPort int

	// CertProvider is the certificate provider (selfsigned, vault, file, cert-manager).
	CertProvider string

	// CertFile is the path to a PEM serving certificate (file provider).
	CertFile string

	// KeyFile is the path to the PEM private key (file provider).
	KeyFile string

	// CACertFile is the path to the PEM CA bundle (file provider, optional).
	CACertFile string

	// CertSecretName is the Kubernetes Secret used by the selfsigned
	// provider to persist its CA and serving certificate so the CA is
	// stable across operator restarts and the gateway can mount ca.crt
	// for TLS verification. Empty disables persistence.
	CertSecretName string

	// CertSecretNamespace is the namespace of CertSecretName. Defaults to
	// the POD_NAMESPACE environment variable, then CertNamespace.
	CertSecretNamespace string

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

	// envWarnings collects environment variables whose values failed to
	// parse during applyEnvOverrides. Parsing happens before the logger is
	// configured, so the warnings are recorded here and logged by
	// logEnvWarnings once logging is set up.
	envWarnings []envWarning
}

// envWarning describes an environment variable override that was ignored
// because its value could not be parsed.
type envWarning struct {
	key    string
	value  string
	reason string
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

	// Surface environment variable parse failures collected before the
	// logger was available (parity with the gateway's env warnings).
	logEnvWarnings(cfg)

	// Use controller-runtime's signal handler as the base context.
	// It handles SIGINT/SIGTERM and cancels the context on the first signal.
	ctx := setupSignalHandlerFunc()

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
	// Resolve the REST config once: it is shared by the certificate
	// manager (Secret persistence client) and the controller manager.
	if restConfig == nil {
		restConfig = ctrl.GetConfigOrDie()
	}

	certManager, err := setupCertManager(ctx, cfg, restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to setup certificate manager: %w", err)
	}

	// Configure webhook serving certificates (internal provisioning or
	// externally mounted cert dir) when webhooks are enabled.
	if cfg.EnableWebhooks {
		if err := configureWebhookCertificates(ctx, cfg, certManager); err != nil {
			return nil, nil, err
		}
	}

	mgr, err := createManagerWithConfig(restConfig, cfg)
	if err != nil {
		return nil, nil, err
	}

	return certManager, mgr, nil
}

// configureWebhookCertificates wires the webhook server's TLS certificates.
// With the cert-manager and file providers the certificates are provisioned
// externally into the (mounted) webhook cert dir, which controller-runtime
// watches for rotation natively — internal provisioning must not override
// it. Otherwise the cert manager's certificates are written to a temp dir.
func configureWebhookCertificates(ctx context.Context, cfg *Config, certManager cert.Manager) error {
	if usesExternalWebhookCerts(cfg) {
		return resolveExternalWebhookCertDir(cfg)
	}

	certDir, err := writeWebhookCertificates(ctx, cfg, certManager)
	if err != nil {
		return fmt.Errorf("unable to write webhook certificates: %w", err)
	}
	if certDir != "" {
		cfg.WebhookCertDir = certDir
	}
	return nil
}

// usesExternalWebhookCerts reports whether webhook serving certificates are
// provisioned externally (mounted into the cert dir) rather than written by
// the operator's certificate manager.
func usesExternalWebhookCerts(cfg *Config) bool {
	switch cert.CertificateMode(cfg.CertProvider) {
	case cert.CertModeCertManager, cert.CertModeFile:
		return true
	default:
		return false
	}
}

// resolveExternalWebhookCertDir determines the webhook certificate
// directory (and file names) for externally provisioned certificates.
// Precedence: an explicitly configured WebhookCertDir is honored as-is
// (cert-manager convention: tls.crt/tls.key inside it); otherwise the file
// provider's cert/key paths are used when they share a directory; otherwise
// the cert-manager default mount path is assumed.
func resolveExternalWebhookCertDir(cfg *Config) error {
	if cfg.WebhookCertDir == "" {
		switch {
		case cfg.CertFile != "" && cfg.KeyFile != "":
			certDir := filepath.Dir(cfg.CertFile)
			if filepath.Dir(cfg.KeyFile) != certDir {
				return fmt.Errorf(
					"webhook certificates require cert-file and key-file in the same directory "+
						"(got %q and %q); set --webhook-cert-dir explicitly",
					cfg.CertFile, cfg.KeyFile,
				)
			}
			cfg.WebhookCertDir = certDir
			cfg.WebhookCertName = filepath.Base(cfg.CertFile)
			cfg.WebhookKeyName = filepath.Base(cfg.KeyFile)
		default:
			cfg.WebhookCertDir = defaultCertManagerCertDir
		}
	}

	setupLog.Info("using externally provisioned webhook certificates",
		"cert_provider", cfg.CertProvider,
		"cert_dir", cfg.WebhookCertDir,
	)
	return nil
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

	// SetupWithManager follows the standard kubebuilder signature (no ctx);
	// its ConfigMap field-index registration uses a Background context
	// because indexer setup is synchronous and manager-lifetime scoped.
	//nolint:contextcheck // kubebuilder SetupWithManager convention has no context parameter
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

	// Wire the store readiness gate (leadership signal + seeding goroutine)
	// BEFORE the gRPC server starts serving, so no early RPC can observe the
	// gate without its leadership signal.
	startStoreSeedingBackground(ctx, grpcServer, mgr)
	startGRPCServerBackground(ctx, grpcServer)

	// Start the serving-certificate rotation loop (selfsigned/vault
	// providers): re-issues before expiry and swaps the certificate into
	// the running gRPC server and the webhook cert dir.
	startCertRotationForComponents(ctx, cfg, certManager, grpcServer)

	return caInjector, nil
}

// startCertRotationForComponents resolves the current serving certificate
// (a cache hit on the certificate manager) and starts the rotation loop for
// internally provisioned certificates.
func startCertRotationForComponents(
	ctx context.Context,
	cfg *Config,
	certManager cert.Manager,
	grpcServer *operatorgrpc.Server,
) {
	if usesExternalWebhookCerts(cfg) || (grpcServer == nil && !cfg.EnableWebhooks) {
		return
	}

	currentCert, err := certManager.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: cfg.CertServiceName,
		DNSNames:   getCertDNSNames(cfg),
	})
	if err != nil {
		setupLog.Error(err, "unable to resolve current serving certificate; rotation loop not started")
		return
	}

	startCertRotationIfNeeded(ctx, cfg, certManager, grpcServer, currentCert)
}

// Store seeding constants for the gRPC configuration store readiness gate.
const (
	// storeSeedReconcileTimeout bounds the wait for the controllers' initial
	// reconcile pass to populate the gRPC store after the caches have synced.
	storeSeedReconcileTimeout = 30 * time.Second

	// storeSeedPollInterval is the poll interval while waiting for the store
	// to reach the expected resource count.
	storeSeedPollInterval = 100 * time.Millisecond
)

// cacheSyncWaiter is the subset of the manager cache used for store seeding.
// It is satisfied by cache.Cache and can be mocked in tests.
type cacheSyncWaiter interface {
	WaitForCacheSync(ctx context.Context) bool
}

// startStoreSeedingBackground wires the manager's leader-election signal into
// the gRPC server's store readiness gate and launches a goroutine that marks
// the gRPC configuration store as seeded once this replica has been ELECTED
// LEADER, the manager's informer caches have synced, and the controllers'
// initial reconcile pass has populated the store (bounded wait). Until then,
// the gRPC server parks initial-snapshot RPCs so a gateway connecting right
// after an operator restart does not receive an empty FULL_SYNC that would
// wipe its running configuration.
//
// Multi-replica behavior: controllers only run on the elected leader, so a
// NON-LEADER replica's store stays empty for its whole lifetime. Gating both
// the seed mark and the server-side seed-timeout clock on mgr.Elected()
// guarantees non-leaders never open the gate (and never hit the timeout
// fallback) with an empty store — connecting gateways park or retry until
// they reach the leader. With leader election disabled, Elected() closes as
// soon as the manager starts, preserving single-replica behavior.
//
// Leadership loss/regain: controller-runtime managers never un-elect — on
// leadership loss the manager terminates and the process restarts, so the
// elected → seeded transition happens at most once per process and needs no
// reset handling. See Server.SetLeadershipSignal.
func startStoreSeedingBackground(ctx context.Context, grpcServer *operatorgrpc.Server, mgr ctrl.Manager) {
	if grpcServer == nil {
		return
	}
	elected := mgr.Elected()
	grpcServer.SetLeadershipSignal(elected)
	go seedGRPCStore(ctx, grpcServer, elected, mgr.GetCache(), mgr.GetClient())
}

// seedGRPCStore waits for leader election, cache sync, and the initial
// reconcile pass, then releases the gRPC store readiness gate. The
// reconcile-pass wait is bounded: on timeout the store is marked seeded
// anyway (with a logged decision) so gateways are never blocked indefinitely
// by resources that cannot reconcile. The timeout clock starts at election —
// a replica that is never elected parks here and never marks the (empty)
// store seeded. On shutdown the seed mark is skipped entirely.
func seedGRPCStore(
	ctx context.Context,
	grpcServer *operatorgrpc.Server,
	elected <-chan struct{},
	cacheSync cacheSyncWaiter,
	reader client.Reader,
) {
	// Leadership gate: park until this replica is elected leader (immediate
	// when leader election is disabled). Controllers never run on
	// non-leaders, so proceeding here would time out against a permanently
	// empty store and open the gate for empty snapshots.
	select {
	case <-ctx.Done():
		setupLog.Info("shutdown before leader election; skipping gRPC store seed mark")
		return
	case <-elected:
	}

	if !cacheSync.WaitForCacheSync(ctx) {
		setupLog.Info("cache sync canceled before gRPC store seeding; skipping seed mark")
		return
	}

	expected := countExpectedConfigResources(ctx, reader)
	reached := waitForStoreCount(ctx, grpcServer, expected)
	if !reached && ctx.Err() != nil {
		setupLog.Info("shutdown while waiting for initial reconcile; skipping gRPC store seed mark")
		return
	}

	grpcServer.MarkStoreSeeded()
	setupLog.Info("gRPC configuration store marked seeded",
		"expected_resources", expected,
		"store_resources", grpcServer.StoreResourceCount(),
		"initial_reconcile_complete", reached,
	)
}

// countExpectedConfigResources counts all avapigw configuration resources
// visible in the (synced) cache. List errors are logged and treated as zero
// for that resource type so seeding is never blocked by a transient failure.
func countExpectedConfigResources(ctx context.Context, reader client.Reader) int {
	total := 0

	countList := func(name string, list client.ObjectList, lenFn func() int) {
		if err := reader.List(ctx, list); err != nil {
			setupLog.Error(err, "failed to list resources for store seeding", "resource", name)
			return
		}
		total += lenFn()
	}

	apiRoutes := &avapigwv1alpha1.APIRouteList{}
	countList("APIRoute", apiRoutes, func() int { return len(apiRoutes.Items) })
	grpcRoutes := &avapigwv1alpha1.GRPCRouteList{}
	countList("GRPCRoute", grpcRoutes, func() int { return len(grpcRoutes.Items) })
	graphqlRoutes := &avapigwv1alpha1.GraphQLRouteList{}
	countList("GraphQLRoute", graphqlRoutes, func() int { return len(graphqlRoutes.Items) })
	backends := &avapigwv1alpha1.BackendList{}
	countList("Backend", backends, func() int { return len(backends.Items) })
	grpcBackends := &avapigwv1alpha1.GRPCBackendList{}
	countList("GRPCBackend", grpcBackends, func() int { return len(grpcBackends.Items) })
	graphqlBackends := &avapigwv1alpha1.GraphQLBackendList{}
	countList("GraphQLBackend", graphqlBackends, func() int { return len(graphqlBackends.Items) })

	return total
}

// waitForStoreCount polls until the gRPC store holds at least the expected
// number of resources, the bounded timeout elapses, or the context is
// canceled. It returns whether the expected count was reached.
func waitForStoreCount(ctx context.Context, grpcServer *operatorgrpc.Server, expected int) bool {
	if expected <= 0 {
		return true
	}

	deadline := time.NewTimer(storeSeedReconcileTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(storeSeedPollInterval)
	defer ticker.Stop()

	for {
		if grpcServer.StoreResourceCount() >= expected {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-ticker.C:
		}
	}
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

// createManagerWithConfig creates the controller-runtime manager using the provided REST config.
// The REST config is resolved by setupCertManagerAndControllerManager (production:
// ctrl.GetConfigOrDie; tests: a fake API server config).
func createManagerWithConfig(restConfig *rest.Config, cfg *Config) (ctrl.Manager, error) {
	webhookOpts := webhook.Options{
		Port: cfg.WebhookPort,
	}

	// Configure TLS certificate paths for the webhook server if cert directory is set.
	// The certificates are either written by the cert manager (selfsigned/vault) or
	// mounted externally (file/cert-manager); controller-runtime watches the files
	// and reloads them on rotation.
	if cfg.WebhookCertDir != "" {
		webhookOpts.CertDir = cfg.WebhookCertDir
		webhookOpts.CertName = defaultString(cfg.WebhookCertName, "tls.crt")
		webhookOpts.KeyName = defaultString(cfg.WebhookKeyName, "tls.key")
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

// startGRPCServerBackground starts the gRPC server in a background goroutine
// and launches the gateway registry staleness reaper alongside it, so
// registrations of gateways that disappeared without unregistering are
// removed after three missed heartbeats.
func startGRPCServerBackground(ctx context.Context, grpcServer *operatorgrpc.Server) {
	if grpcServer == nil {
		return
	}
	grpcServer.StartGatewayReaper(ctx, 0, 0) // 0,0 = default interval and TTL
	go func() {
		if err := grpcServer.Start(ctx); err != nil {
			// Start returns ctx.Err() when the shutdown context is
			// canceled; that is a clean shutdown, not a server error.
			if errors.Is(err, context.Canceled) {
				setupLog.Info("gRPC server stopped")
				return
			}
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
		"The certificate provider (selfsigned, vault, file, cert-manager).")
	flag.StringVar(&cfg.CertFile, "cert-file", "",
		"Path to the PEM serving certificate (file provider).")
	flag.StringVar(&cfg.KeyFile, "key-file", "",
		"Path to the PEM private key (file provider).")
	flag.StringVar(&cfg.CACertFile, "ca-file", "",
		"Path to the PEM CA bundle (file provider, optional).")
	flag.StringVar(&cfg.CertSecretName, "cert-secret-name", "",
		"Kubernetes Secret used by the selfsigned provider to persist its CA and "+
			"serving certificate (empty disables persistence).")
	flag.StringVar(&cfg.CertSecretNamespace, "cert-secret-namespace", "",
		"Namespace of the certificate persistence Secret "+
			"(defaults to POD_NAMESPACE, then the cert namespace).")
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
	// collect records a parse warning; parse failures keep the flag/default
	// value in effect and are logged by logEnvWarnings after logger setup.
	collect := func(w *envWarning) {
		if w != nil {
			cfg.envWarnings = append(cfg.envWarnings, *w)
		}
	}

	// String overrides
	applyStringEnv(&cfg.MetricsAddr, "METRICS_BIND_ADDRESS")
	applyStringEnv(&cfg.ProbeAddr, "HEALTH_PROBE_BIND_ADDRESS")
	applyStringEnv(&cfg.LeaderElectionID, "LEADER_ELECTION_ID")
	applyStringEnv(&cfg.CertProvider, "CERT_PROVIDER")
	applyStringEnv(&cfg.CertFile, "CERT_FILE")
	applyStringEnv(&cfg.KeyFile, "KEY_FILE")
	applyStringEnv(&cfg.CACertFile, "CA_FILE")
	applyStringEnv(&cfg.CertSecretName, "CERT_SECRET_NAME")
	applyStringEnv(&cfg.CertSecretNamespace, "CERT_SECRET_NAMESPACE")
	applyStringEnv(&cfg.VaultAddr, "VAULT_ADDR")
	applyStringEnv(&cfg.VaultPKIMount, "VAULT_PKI_MOUNT")
	applyStringEnv(&cfg.VaultPKIRole, "VAULT_PKI_ROLE")
	applyStringEnv(&cfg.VaultK8sRole, "VAULT_K8S_ROLE")
	applyStringEnv(&cfg.VaultK8sMountPath, "VAULT_K8S_MOUNT_PATH")
	applyStringEnv(&cfg.LogLevel, "LOG_LEVEL")
	applyStringEnv(&cfg.LogFormat, "LOG_FORMAT")
	applyStringEnv(&cfg.OTLPEndpoint, "OTLP_ENDPOINT")

	// Int overrides
	collect(applyIntEnv(&cfg.WebhookPort, "WEBHOOK_PORT"))
	applyStringEnv(&cfg.WebhookCertDir, "WEBHOOK_CERT_DIR")
	applyStringEnv(&cfg.WebhookConfigName, "WEBHOOK_CONFIG_NAME")
	collect(applyIntEnv(&cfg.GRPCPort, "GRPC_PORT"))

	// Float overrides
	collect(applyFloat64Env(&cfg.TracingSamplingRate, "TRACING_SAMPLING_RATE"))

	// Duration overrides
	collect(applyDurationEnv(&cfg.VaultInitTimeout, "VAULT_INIT_TIMEOUT"))

	// Certificate DNS names override
	applyStringEnv(&cfg.CertServiceName, "CERT_SERVICE_NAME")
	applyStringEnv(&cfg.CertNamespace, "CERT_NAMESPACE")
	applyCertDNSNamesEnv(cfg)

	// Bool overrides
	collect(applyBoolEnv(&cfg.EnableLeaderElection, "LEADER_ELECT"))
	collect(applyBoolEnv(&cfg.EnableWebhooks, "ENABLE_WEBHOOKS"))
	collect(applyBoolEnv(&cfg.EnableGRPCServer, "ENABLE_GRPC_SERVER"))
	collect(applyBoolEnv(&cfg.GRPCRequireClientCert, "GRPC_REQUIRE_CLIENT_CERT"))
	collect(applyBoolEnv(&cfg.EnableTracing, "ENABLE_TRACING"))
	collect(applyBoolEnv(&cfg.EnableIngressController, "ENABLE_INGRESS_CONTROLLER"))
	applyStringEnv(&cfg.IngressClassName, "INGRESS_CLASS_NAME")
	applyStringEnv(&cfg.IngressLBAddress, "INGRESS_LB_ADDRESS")

	// Duplicate detection configuration
	collect(applyBoolEnv(&cfg.EnableClusterWideDuplicateCheck, "ENABLE_CLUSTER_WIDE_DUPLICATE_CHECK"))
	collect(applyBoolEnv(&cfg.DuplicateCacheEnabled, "DUPLICATE_CACHE_ENABLED"))
	collect(applyDurationEnv(&cfg.DuplicateCacheTTL, "DUPLICATE_CACHE_TTL"))
}

// logEnvWarnings logs environment variables whose values failed to parse and
// were ignored during applyEnvOverrides. It runs after the logger is
// configured because env parsing happens before logging setup. The values
// logged here are operational settings (ports, durations, booleans), never
// secrets.
func logEnvWarnings(cfg *Config) {
	for _, w := range cfg.envWarnings {
		setupLog.Info("WARNING: ignoring invalid environment variable value; keeping current setting",
			"env", w.key,
			"value", w.value,
			"reason", w.reason,
		)
	}
}

// applyBoolEnv applies a boolean environment variable override.
// It handles both true and false values symmetrically. An unrecognized
// value keeps the current setting and returns a warning instead of being
// silently ignored.
func applyBoolEnv(target *bool, envKey string) *envWarning {
	v := os.Getenv(envKey)
	if v == "" {
		return nil
	}
	switch strings.ToLower(v) {
	case "true", "1", "yes":
		*target = true
	case "false", "0", "no":
		*target = false
	default:
		return &envWarning{key: envKey, value: v,
			reason: "not a valid boolean (use true/false, 1/0, or yes/no)"}
	}
	return nil
}

func applyStringEnv(target *string, envKey string) {
	if v := os.Getenv(envKey); v != "" {
		*target = v
	}
}

// applyIntEnv applies an integer environment variable override. An
// unparsable value keeps the current setting and returns a warning.
func applyIntEnv(target *int, envKey string) *envWarning {
	v := os.Getenv(envKey)
	if v == "" {
		return nil
	}
	var parsed int
	if err := parseIntEnv(v, &parsed); err != nil {
		return &envWarning{key: envKey, value: v, reason: "not a valid integer"}
	}
	*target = parsed
	return nil
}

// applyFloat64Env applies a float environment variable override. An
// unparsable value keeps the current setting and returns a warning.
func applyFloat64Env(target *float64, envKey string) *envWarning {
	v := os.Getenv(envKey)
	if v == "" {
		return nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return &envWarning{key: envKey, value: v, reason: "not a valid number"}
	}
	*target = f
	return nil
}

// applyDurationEnv applies a duration environment variable override. An
// unparsable value keeps the current setting and returns a warning.
func applyDurationEnv(target *time.Duration, envKey string) *envWarning {
	v := os.Getenv(envKey)
	if v == "" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return &envWarning{key: envKey, value: v, reason: "not a valid duration (e.g. 30s, 5m)"}
	}
	*target = d
	return nil
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

func setupCertManager(ctx context.Context, cfg *Config, restConfig *rest.Config) (cert.Manager, error) {
	switch cert.CertificateMode(cfg.CertProvider) {
	case cert.CertModeVault:
		return setupVaultCertManager(ctx, cfg)
	case cert.CertModeFile, cert.CertModeCertManager:
		return setupFileCertManager(cfg)
	default:
		return setupSelfSignedCertManager(ctx, cfg, restConfig)
	}
}

// setupVaultCertManager initializes the Vault PKI certificate manager.
func setupVaultCertManager(ctx context.Context, cfg *Config) (cert.Manager, error) {
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
}

// setupFileCertManager initializes the file-based certificate manager used
// by the file and cert-manager providers. When explicit cert/key paths are
// not configured (cert-manager convention), the certificates are loaded
// from the webhook cert dir (default: the cert-manager mount path).
func setupFileCertManager(cfg *Config) (cert.Manager, error) {
	certFile, keyFile, caFile := cfg.CertFile, cfg.KeyFile, cfg.CACertFile

	if certFile == "" && keyFile == "" {
		certDir := defaultString(cfg.WebhookCertDir, defaultCertManagerCertDir)
		certFile = filepath.Join(certDir, "tls.crt")
		keyFile = filepath.Join(certDir, "tls.key")
		if caFile == "" {
			// cert-manager includes ca.crt for CA/self-signed issuers;
			// when absent the CA chain falls back to the cert bundle.
			candidate := filepath.Join(certDir, "ca.crt")
			if _, err := os.Stat(candidate); err == nil {
				caFile = candidate
			}
		}
	}

	setupLog.Info("initializing file certificate manager",
		"provider", cfg.CertProvider,
		"cert_file", certFile,
		"key_file", keyFile,
		"ca_file", caFile,
	)

	return cert.NewFileProvider(&cert.FileProviderConfig{
		CertFile:     certFile,
		KeyFile:      keyFile,
		CAFile:       caFile,
		RotateBefore: cert.DefaultRotateBefore,
	})
}

// setupSelfSignedCertManager initializes the self-signed certificate
// manager. When a persistence Secret is configured, the CA (and serving
// certificate) are stored in it so the CA is stable across operator
// restarts and the gateway can mount ca.crt for verified TLS.
func setupSelfSignedCertManager(
	ctx context.Context,
	cfg *Config,
	restConfig *rest.Config,
) (cert.Manager, error) {
	providerCfg := &cert.SelfSignedProviderConfig{
		CACommonName: cert.DefaultCACommonName,
		CAValidity:   cert.DefaultCAValidity,
		CertValidity: cert.DefaultCertValidity,
		RotateBefore: cert.DefaultRotateBefore,
		KeySize:      cert.DefaultKeySize,
		Organization: []string{cert.DefaultOrganization},
	}

	if cfg.CertSecretName != "" {
		secretClient, err := newSecretClient(restConfig)
		if err != nil {
			// Persistence is best-effort: fall back to the in-memory CA
			// (legacy behavior) instead of failing operator startup.
			setupLog.Error(err, "unable to create client for certificate secret persistence; "+
				"continuing with in-memory CA (CA will NOT survive restarts)")
		} else {
			providerCfg.SecretName = cfg.CertSecretName
			providerCfg.SecretNamespace = resolveCertSecretNamespace(cfg)
			providerCfg.SecretClient = secretClient
			setupLog.Info("self-signed CA persistence enabled",
				"secret", providerCfg.SecretName,
				"namespace", providerCfg.SecretNamespace,
			)
		}
	}

	return cert.NewSelfSignedProviderWithContext(ctx, providerCfg)
}

// newSecretClient creates a lightweight Kubernetes client for Secret
// persistence. It is separate from the manager's cached client because the
// certificate manager starts BEFORE the controller manager.
var newSecretClient = func(restConfig *rest.Config) (cert.SecretStore, error) {
	if restConfig == nil {
		return nil, fmt.Errorf("kubernetes REST config is required for secret persistence")
	}
	c, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	return c, nil
}

// resolveCertSecretNamespace resolves the namespace for the certificate
// persistence Secret: explicit flag/env, then the pod's own namespace
// (POD_NAMESPACE, injected via the downward API), then the cert namespace.
func resolveCertSecretNamespace(cfg *Config) string {
	if cfg.CertSecretNamespace != "" {
		return cfg.CertSecretNamespace
	}
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	return cfg.CertNamespace
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
	// Arm the store readiness gate: initial-snapshot RPCs are parked (bounded)
	// until the controllers' initial reconcile pass seeds the store, preventing
	// empty FULL_SYNC responses right after operator restart (the gate is
	// released by seedGRPCStore once the manager caches have synced).
	server.EnableStoreReadinessGate()
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
