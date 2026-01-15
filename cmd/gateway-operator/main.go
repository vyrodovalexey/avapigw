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

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var webhookPort int
	var enableWebhooks bool
	var webhookSelfSignedCert bool
	var webhookCertDir string
	var webhookCertValidity time.Duration
	var webhookCertRotation time.Duration
	var webhookCertSecretName string
	var webhookServiceName string
	var webhookServiceNamespace string
	var webhookValidatingConfigName string
	var webhookMutatingConfigName string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "The port the webhook server binds to.")
	flag.BoolVar(&enableWebhooks, "enable-webhooks", true, "Enable admission webhooks.")

	// Webhook certificate flags
	flag.BoolVar(&webhookSelfSignedCert, "webhook-self-signed-cert", false, "Enable self-signed certificate generation for webhooks.")
	flag.StringVar(&webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs", "Directory to store webhook certificates.")
	flag.DurationVar(&webhookCertValidity, "webhook-cert-validity", 365*24*time.Hour, "Webhook certificate validity period.")
	flag.DurationVar(&webhookCertRotation, "webhook-cert-rotation", 30*24*time.Hour, "Time before expiry to rotate webhook certificates.")
	flag.StringVar(&webhookCertSecretName, "webhook-cert-secret-name", "avapigw-webhook-certs", "Name of the Kubernetes secret for webhook certificates.")
	flag.StringVar(&webhookServiceName, "webhook-service-name", "avapigw-webhook-service", "Name of the webhook service.")
	flag.StringVar(&webhookServiceNamespace, "webhook-service-namespace", getEnvOrDefault("POD_NAMESPACE", "avapigw-system"), "Namespace of the webhook service.")
	flag.StringVar(&webhookValidatingConfigName, "webhook-validating-config-name", "avapigw-validating-webhook-configuration", "Name of the ValidatingWebhookConfiguration.")
	flag.StringVar(&webhookMutatingConfigName, "webhook-mutating-config-name", "avapigw-mutating-webhook-configuration", "Name of the MutatingWebhookConfiguration.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Create webhook server options
	webhookOpts := webhook.Options{
		Port: webhookPort,
	}

	// If self-signed certs are enabled, set the cert directory
	if webhookSelfSignedCert {
		webhookOpts.CertDir = webhookCertDir
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer:          webhook.NewServer(webhookOpts),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "avapigw.vyrodovalexey.github.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader doesn't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, this program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or are intending to do any signal handling (e.g. graceful
		// shutdowns), then it is not safe to enable this option.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Setup certificate manager if self-signed certs are enabled
	var certManager *cert.Manager
	if webhookSelfSignedCert && enableWebhooks {
		setupLog.Info("setting up self-signed certificate manager for webhooks")

		// Create a zap logger for the cert manager
		zapLogger, err := uberzap.NewProduction()
		if err != nil {
			setupLog.Error(err, "unable to create zap logger for cert manager")
			os.Exit(1)
		}

		// Create a direct client for cert manager (before manager starts)
		directClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
		if err != nil {
			setupLog.Error(err, "unable to create direct client for cert manager")
			os.Exit(1)
		}

		certManagerConfig := &cert.ManagerConfig{
			ServiceName:                 webhookServiceName,
			ServiceNamespace:            webhookServiceNamespace,
			SecretName:                  webhookCertSecretName,
			CertDir:                     webhookCertDir,
			Validity:                    webhookCertValidity,
			RotationThreshold:           webhookCertRotation,
			CheckInterval:               1 * time.Hour,
			ValidatingWebhookConfigName: webhookValidatingConfigName,
			MutatingWebhookConfigName:   webhookMutatingConfigName,
		}

		certManager, err = cert.NewManager(certManagerConfig, directClient, zapLogger)
		if err != nil {
			setupLog.Error(err, "unable to create certificate manager")
			os.Exit(1)
		}

		// Start certificate manager to ensure certs exist before webhook server starts
		if err := certManager.Start(context.Background()); err != nil {
			setupLog.Error(err, "unable to start certificate manager")
			os.Exit(1)
		}

		setupLog.Info("certificate manager started successfully",
			"certDir", webhookCertDir,
			"secretName", webhookCertSecretName,
		)
	}

	// Setup field indexers for efficient lookups
	if err = controller.SetupIndexers(context.Background(), mgr); err != nil {
		setupLog.Error(err, "unable to setup field indexers")
		os.Exit(1)
	}

	// Setup Controllers
	if err = setupControllers(mgr); err != nil {
		setupLog.Error(err, "unable to setup controllers")
		os.Exit(1)
	}

	// Setup Webhooks
	if enableWebhooks {
		if err = setupWebhooks(mgr); err != nil {
			setupLog.Error(err, "unable to setup webhooks")
			os.Exit(1)
		}
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		setupLog.Info("received shutdown signal", "signal", sig.String())

		// Create a context with timeout for graceful shutdown
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
		defer shutdownCancel()

		// Stop certificate manager if running
		if certManager != nil {
			setupLog.Info("stopping certificate manager")
			if err := certManager.Stop(); err != nil {
				setupLog.Error(err, "error stopping certificate manager")
			}
		}

		// Cancel the main context to trigger shutdown
		cancel()

		// Wait for shutdown timeout
		<-shutdownCtx.Done()
		if shutdownCtx.Err() == context.DeadlineExceeded {
			setupLog.Info("graceful shutdown timeout exceeded, forcing exit")
			os.Exit(1)
		}
	}()

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		cancel()   // Ensure context cleanup before exit
		os.Exit(1) //nolint:gocritic // exitAfterDefer: cancel() called explicitly above
	}

	// Stop certificate manager on normal exit
	if certManager != nil {
		setupLog.Info("stopping certificate manager")
		if err := certManager.Stop(); err != nil {
			setupLog.Error(err, "error stopping certificate manager")
		}
	}

	setupLog.Info("manager stopped gracefully")
}

// setupControllers sets up all controllers with the manager
func setupControllers(mgr ctrl.Manager) error {
	// Gateway Controller
	if err := (&controller.GatewayReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("gateway-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Gateway")
		return err
	}

	// HTTPRoute Controller
	if err := (&controller.HTTPRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("httproute-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "HTTPRoute")
		return err
	}

	// GRPCRoute Controller
	if err := (&controller.GRPCRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("grpcroute-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GRPCRoute")
		return err
	}

	// TCPRoute Controller
	if err := (&controller.TCPRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("tcproute-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TCPRoute")
		return err
	}

	// TLSRoute Controller
	if err := (&controller.TLSRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("tlsroute-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TLSRoute")
		return err
	}

	// Backend Controller
	if err := (&controller.BackendReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("backend-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Backend")
		return err
	}

	// RateLimitPolicy Controller
	if err := (&controller.RateLimitPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("ratelimitpolicy-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "RateLimitPolicy")
		return err
	}

	// AuthPolicy Controller
	if err := (&controller.AuthPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("authpolicy-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AuthPolicy")
		return err
	}

	// TLSConfig Controller
	if err := (&controller.TLSConfigReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("tlsconfig-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TLSConfig")
		return err
	}

	// VaultSecret Controller
	if err := (&controller.VaultSecretReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("vaultsecret-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VaultSecret")
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

// setupWebhooks sets up all webhooks with the manager
func setupWebhooks(mgr ctrl.Manager) error {
	// Gateway Webhook
	if err := avapigwwebhook.SetupGatewayWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "Gateway")
		return err
	}

	// HTTPRoute Webhook
	if err := avapigwwebhook.SetupHTTPRouteWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "HTTPRoute")
		return err
	}

	// GRPCRoute Webhook
	if err := avapigwwebhook.SetupGRPCRouteWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "GRPCRoute")
		return err
	}

	// TCPRoute Webhook
	if err := avapigwwebhook.SetupTCPRouteWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "TCPRoute")
		return err
	}

	// TLSRoute Webhook
	if err := avapigwwebhook.SetupTLSRouteWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "TLSRoute")
		return err
	}

	// Backend Webhook
	if err := avapigwwebhook.SetupBackendWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "Backend")
		return err
	}

	// RateLimitPolicy Webhook
	if err := avapigwwebhook.SetupRateLimitPolicyWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "RateLimitPolicy")
		return err
	}

	// AuthPolicy Webhook
	if err := avapigwwebhook.SetupAuthPolicyWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "AuthPolicy")
		return err
	}

	// TLSConfig Webhook
	if err := avapigwwebhook.SetupTLSConfigWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "TLSConfig")
		return err
	}

	// VaultSecret Webhook
	if err := avapigwwebhook.SetupVaultSecretWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "VaultSecret")
		return err
	}

	setupLog.Info("all webhooks registered successfully")
	return nil
}
