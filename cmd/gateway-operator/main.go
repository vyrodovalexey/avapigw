/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	uberzap "go.uber.org/zap"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/controller"
	avapigwwebhook "github.com/vyrodovalexey/avapigw/internal/webhook"
	"github.com/vyrodovalexey/avapigw/internal/webhook/cert"
	//+kubebuilder:scaffold:imports
)

const (
	// gracefulShutdownTimeout is the maximum time to wait for graceful shutdown
	gracefulShutdownTimeout = 30 * time.Second
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(avapigwv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

// operatorConfig holds all configuration for the operator
type operatorConfig struct {
	metricsAddr                 string
	probeAddr                   string
	enableLeaderElection        bool
	webhookPort                 int
	enableWebhooks              bool
	webhookSelfSignedCert       bool
	webhookCertDir              string
	webhookCertValidity         time.Duration
	webhookCertRotation         time.Duration
	webhookCertSecretName       string
	webhookServiceName          string
	webhookServiceNamespace     string
	webhookValidatingConfigName string
	webhookMutatingConfigName   string
}

func main() {
	cfg := parseFlags()

	mgr, err := createManager(cfg)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	certManager, err := setupCertManagerIfNeeded(cfg)
	if err != nil {
		setupLog.Error(err, "unable to setup certificate manager")
		os.Exit(1)
	}

	if err = initializeManager(mgr, cfg); err != nil {
		setupLog.Error(err, "unable to initialize manager")
		os.Exit(1)
	}

	runManager(mgr, certManager)
}

// parseFlags parses command line flags and returns the operator configuration
func parseFlags() *operatorConfig {
	cfg := &operatorConfig{}

	registerServerFlags(cfg)
	registerWebhookFlags(cfg)
	registerWebhookCertFlags(cfg)

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	return cfg
}

// registerServerFlags registers server-related command line flags.
func registerServerFlags(cfg *operatorConfig) {
	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&cfg.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
}

// registerWebhookFlags registers webhook-related command line flags.
func registerWebhookFlags(cfg *operatorConfig) {
	flag.IntVar(&cfg.webhookPort, "webhook-port", 9443, "The port the webhook server binds to.")
	flag.BoolVar(&cfg.enableWebhooks, "enable-webhooks", true, "Enable admission webhooks.")
	flag.BoolVar(&cfg.webhookSelfSignedCert, "webhook-self-signed-cert", false,
		"Enable self-signed certificate generation for webhooks.")
	flag.StringVar(&cfg.webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs",
		"Directory to store webhook certificates.")
	flag.StringVar(&cfg.webhookServiceName, "webhook-service-name", "avapigw-webhook-service",
		"Name of the webhook service.")
	flag.StringVar(&cfg.webhookServiceNamespace, "webhook-service-namespace",
		getEnvOrDefault("POD_NAMESPACE", "avapigw-system"), "Namespace of the webhook service.")
}

// registerWebhookCertFlags registers webhook certificate-related command line flags.
func registerWebhookCertFlags(cfg *operatorConfig) {
	flag.DurationVar(&cfg.webhookCertValidity, "webhook-cert-validity", 365*24*time.Hour,
		"Webhook certificate validity period.")
	flag.DurationVar(&cfg.webhookCertRotation, "webhook-cert-rotation", 30*24*time.Hour,
		"Time before expiry to rotate webhook certificates.")
	flag.StringVar(&cfg.webhookCertSecretName, "webhook-cert-secret-name", "avapigw-webhook-certs",
		"Name of the Kubernetes secret for webhook certificates.")
	flag.StringVar(&cfg.webhookValidatingConfigName, "webhook-validating-config-name",
		"avapigw-validating-webhook-configuration", "Name of the ValidatingWebhookConfiguration.")
	flag.StringVar(&cfg.webhookMutatingConfigName, "webhook-mutating-config-name",
		"avapigw-mutating-webhook-configuration", "Name of the MutatingWebhookConfiguration.")
}

// createManager creates and configures the controller manager
func createManager(cfg *operatorConfig) (ctrl.Manager, error) {
	webhookOpts := webhook.Options{
		Port: cfg.webhookPort,
	}

	if cfg.webhookSelfSignedCert {
		webhookOpts.CertDir = cfg.webhookCertDir
	}

	return ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: cfg.metricsAddr,
		},
		WebhookServer:          webhook.NewServer(webhookOpts),
		HealthProbeBindAddress: cfg.probeAddr,
		LeaderElection:         cfg.enableLeaderElection,
		LeaderElectionID:       "avapigw.vyrodovalexey.github.com",
	})
}

// setupCertManagerIfNeeded sets up the certificate manager if self-signed certs are enabled
func setupCertManagerIfNeeded(cfg *operatorConfig) (*cert.Manager, error) {
	if !cfg.webhookSelfSignedCert || !cfg.enableWebhooks {
		return nil, nil
	}

	setupLog.Info("setting up self-signed certificate manager for webhooks")

	zapLogger, err := uberzap.NewProduction()
	if err != nil {
		return nil, err
	}

	directClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	certManagerConfig := &cert.ManagerConfig{
		ServiceName:                 cfg.webhookServiceName,
		ServiceNamespace:            cfg.webhookServiceNamespace,
		SecretName:                  cfg.webhookCertSecretName,
		CertDir:                     cfg.webhookCertDir,
		Validity:                    cfg.webhookCertValidity,
		RotationThreshold:           cfg.webhookCertRotation,
		CheckInterval:               1 * time.Hour,
		ValidatingWebhookConfigName: cfg.webhookValidatingConfigName,
		MutatingWebhookConfigName:   cfg.webhookMutatingConfigName,
	}

	certManager, err := cert.NewManager(certManagerConfig, directClient, zapLogger)
	if err != nil {
		return nil, err
	}

	if err := certManager.Start(context.Background()); err != nil {
		return nil, err
	}

	setupLog.Info("certificate manager started successfully",
		"certDir", cfg.webhookCertDir,
		"secretName", cfg.webhookCertSecretName,
	)

	return certManager, nil
}

// initializeManager sets up indexers, controllers, webhooks, and health checks
func initializeManager(mgr ctrl.Manager, cfg *operatorConfig) error {
	if err := controller.SetupIndexers(context.Background(), mgr); err != nil {
		return err
	}

	if err := setupControllers(mgr); err != nil {
		return err
	}

	if cfg.enableWebhooks {
		if err := setupWebhooks(mgr); err != nil {
			return err
		}
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}

	return nil
}

// runManager starts the manager and handles graceful shutdown
func runManager(mgr ctrl.Manager, certManager *cert.Manager) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go handleShutdownSignal(sigChan, certManager, cancel)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		cancel()
		os.Exit(1) //nolint:gocritic // exitAfterDefer: cancel() called explicitly above
	}

	stopCertManager(certManager)
	setupLog.Info("manager stopped gracefully")
}

// handleShutdownSignal handles OS shutdown signals
func handleShutdownSignal(sigChan <-chan os.Signal, certManager *cert.Manager, cancel context.CancelFunc) {
	sig := <-sigChan
	setupLog.Info("received shutdown signal", "signal", sig.String())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)

	stopCertManager(certManager)
	cancel()

	<-shutdownCtx.Done()
	shutdownCancel() // Call explicitly before potential exit
	if shutdownCtx.Err() == context.DeadlineExceeded {
		setupLog.Info("graceful shutdown timeout exceeded, forcing exit")
		os.Exit(1) //nolint:gocritic // exitAfterDefer: shutdownCancel called explicitly above
	}
}

// stopCertManager stops the certificate manager if it's running
func stopCertManager(certManager *cert.Manager) {
	if certManager == nil {
		return
	}
	setupLog.Info("stopping certificate manager")
	if err := certManager.Stop(); err != nil {
		setupLog.Error(err, "error stopping certificate manager")
	}
}

// setupRouteControllers sets up route-related controllers.
func setupRouteControllers(mgr ctrl.Manager) error {
	if err := (&controller.HTTPRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("httproute-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "HTTPRoute")
		return err
	}

	if err := (&controller.GRPCRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("grpcroute-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GRPCRoute")
		return err
	}

	if err := (&controller.TCPRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("tcproute-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TCPRoute")
		return err
	}

	if err := (&controller.TLSRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("tlsroute-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TLSRoute")
		return err
	}

	return nil
}

// setupPolicyControllers sets up policy-related controllers.
func setupPolicyControllers(mgr ctrl.Manager) error {
	if err := (&controller.RateLimitPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("ratelimitpolicy-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "RateLimitPolicy")
		return err
	}

	if err := (&controller.AuthPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("authpolicy-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AuthPolicy")
		return err
	}

	return nil
}

// setupSecurityControllers sets up security-related controllers.
func setupSecurityControllers(mgr ctrl.Manager) error {
	if err := (&controller.TLSConfigReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("tlsconfig-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TLSConfig")
		return err
	}

	if err := (&controller.VaultSecretReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("vaultsecret-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VaultSecret")
		return err
	}

	return nil
}

// setupControllers sets up all controllers with the manager
func setupControllers(mgr ctrl.Manager) error {
	if err := (&controller.GatewayReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("gateway-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Gateway")
		return err
	}

	if err := setupRouteControllers(mgr); err != nil {
		return err
	}

	if err := (&controller.BackendReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("backend-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Backend")
		return err
	}

	if err := setupPolicyControllers(mgr); err != nil {
		return err
	}

	if err := setupSecurityControllers(mgr); err != nil {
		return err
	}

	setupLog.Info("all controllers registered successfully")
	return nil
}

// getEnvOrDefault returns the value of an environment variable or a default value.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// webhookSetupFunc is a function type for setting up a webhook.
type webhookSetupFunc func(ctrl.Manager) error

// setupWebhookWithLogging sets up a webhook and logs any errors.
func setupWebhookWithLogging(mgr ctrl.Manager, name string, setupFn webhookSetupFunc) error {
	if err := setupFn(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", name)
		return err
	}
	return nil
}

// setupWebhooks sets up all webhooks with the manager
func setupWebhooks(mgr ctrl.Manager) error {
	webhooks := []struct {
		name    string
		setupFn webhookSetupFunc
	}{
		{"Gateway", avapigwwebhook.SetupGatewayWebhookWithManager},
		{"HTTPRoute", avapigwwebhook.SetupHTTPRouteWebhookWithManager},
		{"GRPCRoute", avapigwwebhook.SetupGRPCRouteWebhookWithManager},
		{"TCPRoute", avapigwwebhook.SetupTCPRouteWebhookWithManager},
		{"TLSRoute", avapigwwebhook.SetupTLSRouteWebhookWithManager},
		{"Backend", avapigwwebhook.SetupBackendWebhookWithManager},
		{"RateLimitPolicy", avapigwwebhook.SetupRateLimitPolicyWebhookWithManager},
		{"AuthPolicy", avapigwwebhook.SetupAuthPolicyWebhookWithManager},
		{"TLSConfig", avapigwwebhook.SetupTLSConfigWebhookWithManager},
		{"VaultSecret", avapigwwebhook.SetupVaultSecretWebhookWithManager},
	}

	for _, wh := range webhooks {
		if err := setupWebhookWithLogging(mgr, wh.name, wh.setupFn); err != nil {
			return err
		}
	}

	setupLog.Info("all webhooks registered successfully")
	return nil
}
