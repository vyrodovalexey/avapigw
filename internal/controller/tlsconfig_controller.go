// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

const (
	tlsConfigFinalizer = "avapigw.vyrodovalexey.github.com/tlsconfig-finalizer"

	// tlsConfigReconcileTimeout is the maximum duration for a single TLSConfig reconciliation
	tlsConfigReconcileTimeout = 30 * time.Second
)

// Prometheus metrics for TLSConfig controller
var (
	tlsConfigReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "tlsconfig_reconcile_duration_seconds",
			Help:      "Duration of TLSConfig reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	tlsConfigReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "tlsconfig_reconcile_total",
			Help:      "Total number of TLSConfig reconciliations",
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(tlsConfigReconcileDuration, tlsConfigReconcileTotal)
}

// TLSConfigReconciler reconciles a TLSConfig object
type TLSConfigReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=vaultsecrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles TLSConfig reconciliation
func (r *TLSConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Add timeout to prevent hanging reconciliations
	ctx, cancel := context.WithTimeout(ctx, tlsConfigReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)

	// Track reconciliation metrics
	start := time.Now()
	var reconcileResult string = "success"
	defer func() {
		duration := time.Since(start).Seconds()
		tlsConfigReconcileDuration.WithLabelValues(reconcileResult).Observe(duration)
		tlsConfigReconcileTotal.WithLabelValues(reconcileResult).Inc()
	}()

	logger.Info("Reconciling TLSConfig", "name", req.Name, "namespace", req.Namespace)

	// Fetch the TLSConfig instance
	tlsConfig := &avapigwv1alpha1.TLSConfig{}
	if err := r.Get(ctx, req.NamespacedName, tlsConfig); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("TLSConfig not found, ignoring")
			return ctrl.Result{}, nil
		}
		reconcileResult = "error"
		logger.Error(err, "Failed to get TLSConfig")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !tlsConfig.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, tlsConfig)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(tlsConfig, tlsConfigFinalizer) {
		controllerutil.AddFinalizer(tlsConfig, tlsConfigFinalizer)
		if err := r.Update(ctx, tlsConfig); err != nil {
			reconcileResult = "error"
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the TLSConfig
	if err := r.reconcileTLSConfig(ctx, tlsConfig); err != nil {
		reconcileResult = "error"
		logger.Error(err, "Failed to reconcile TLSConfig")
		r.Recorder.Event(tlsConfig, corev1.EventTypeWarning, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// Determine requeue interval based on certificate expiration
	requeueAfter := 1 * time.Hour
	if tlsConfig.Spec.Rotation != nil && tlsConfig.Spec.Rotation.CheckInterval != nil {
		if interval, err := time.ParseDuration(string(*tlsConfig.Spec.Rotation.CheckInterval)); err == nil {
			requeueAfter = interval
		}
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// handleDeletion handles TLSConfig deletion
func (r *TLSConfigReconciler) handleDeletion(ctx context.Context, tlsConfig *avapigwv1alpha1.TLSConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(tlsConfig, tlsConfigFinalizer) {
		// Perform cleanup
		logger.Info("Performing cleanup for TLSConfig deletion")

		// Record event
		r.Recorder.Event(tlsConfig, corev1.EventTypeNormal, "Deleting", "TLSConfig is being deleted")

		// Remove finalizer
		controllerutil.RemoveFinalizer(tlsConfig, tlsConfigFinalizer)
		if err := r.Update(ctx, tlsConfig); err != nil {
			logger.Error(err, "Failed to remove finalizer")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// reconcileTLSConfig performs the main reconciliation logic
func (r *TLSConfigReconciler) reconcileTLSConfig(ctx context.Context, tlsConfig *avapigwv1alpha1.TLSConfig) error {
	logger := log.FromContext(ctx)

	// Update status
	tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	tlsConfig.Status.ObservedGeneration = tlsConfig.Generation
	tlsConfig.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}

	// Load and validate certificate
	certInfo, err := r.loadAndValidateCertificate(ctx, tlsConfig)
	if err != nil {
		logger.Error(err, "Failed to load and validate certificate")
		r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonNotReady), err.Error())
		tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusError
		return r.updateStatus(ctx, tlsConfig)
	}

	// Update certificate info in status
	tlsConfig.Status.Certificate = certInfo

	// Check certificate expiration
	if certInfo.NotAfter != nil {
		now := time.Now()
		expiresIn := certInfo.NotAfter.Time.Sub(now)

		// Default renew before is 30 days
		renewBefore := 30 * 24 * time.Hour
		if tlsConfig.Spec.Rotation != nil && tlsConfig.Spec.Rotation.RenewBefore != nil {
			if parsed, err := time.ParseDuration(*tlsConfig.Spec.Rotation.RenewBefore); err == nil {
				renewBefore = parsed
			}
		}

		if expiresIn <= 0 {
			r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
				string(avapigwv1alpha1.ReasonError), "Certificate has expired")
			tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusError
			r.Recorder.Event(tlsConfig, corev1.EventTypeWarning, "CertificateExpired", "Certificate has expired")
		} else if expiresIn <= renewBefore {
			r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
				string(avapigwv1alpha1.ReasonDegraded), fmt.Sprintf("Certificate expires in %s", expiresIn.Round(time.Hour)))
			tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusDegraded
			r.Recorder.Event(tlsConfig, corev1.EventTypeWarning, "CertificateExpiringSoon",
				fmt.Sprintf("Certificate expires in %s", expiresIn.Round(time.Hour)))
		} else {
			r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
				string(avapigwv1alpha1.ReasonReady), "Certificate is valid")
			tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusReady
		}
	} else {
		r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			string(avapigwv1alpha1.ReasonReady), "TLSConfig is ready")
		tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusReady
	}

	// Update status
	if err := r.updateStatus(ctx, tlsConfig); err != nil {
		return err
	}

	r.Recorder.Event(tlsConfig, corev1.EventTypeNormal, "Reconciled", "TLSConfig reconciled successfully")
	return nil
}

// loadAndValidateCertificate loads and validates the certificate from the configured source
func (r *TLSConfigReconciler) loadAndValidateCertificate(ctx context.Context, tlsConfig *avapigwv1alpha1.TLSConfig) (*avapigwv1alpha1.CertificateInfo, error) {
	source := tlsConfig.Spec.CertificateSource

	// Load from Secret
	if source.Secret != nil {
		return r.loadCertificateFromSecret(ctx, tlsConfig, source.Secret)
	}

	// Load from Vault
	if source.Vault != nil {
		return r.loadCertificateFromVault(ctx, tlsConfig, source.Vault)
	}

	return nil, fmt.Errorf("no certificate source specified")
}

// loadCertificateFromSecret loads certificate from a Kubernetes Secret
func (r *TLSConfigReconciler) loadCertificateFromSecret(ctx context.Context, tlsConfig *avapigwv1alpha1.TLSConfig, secretSource *avapigwv1alpha1.SecretCertificateSource) (*avapigwv1alpha1.CertificateInfo, error) {
	namespace := tlsConfig.Namespace
	if secretSource.Namespace != nil {
		namespace = *secretSource.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretSource.Name}, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("certificate secret %s/%s not found", namespace, secretSource.Name)
		}
		return nil, fmt.Errorf("failed to get certificate secret %s/%s: %w", namespace, secretSource.Name, err)
	}

	// Determine certificate key
	certKey := "tls.crt"
	if secretSource.CertKey != nil {
		certKey = *secretSource.CertKey
	}

	// Get certificate data
	certData, ok := secret.Data[certKey]
	if !ok {
		return nil, fmt.Errorf("certificate key %s not found in secret %s/%s", certKey, namespace, secretSource.Name)
	}

	// Determine private key
	keyKey := "tls.key"
	if secretSource.KeyKey != nil {
		keyKey = *secretSource.KeyKey
	}

	// Verify private key exists
	if _, ok := secret.Data[keyKey]; !ok {
		return nil, fmt.Errorf("private key %s not found in secret %s/%s", keyKey, namespace, secretSource.Name)
	}

	// Parse and validate certificate
	return r.parseCertificate(certData)
}

// loadCertificateFromVault loads certificate from Vault
func (r *TLSConfigReconciler) loadCertificateFromVault(ctx context.Context, tlsConfig *avapigwv1alpha1.TLSConfig, vaultSource *avapigwv1alpha1.VaultCertificateSource) (*avapigwv1alpha1.CertificateInfo, error) {
	// If VaultSecretRef is provided, get the synced secret
	if vaultSource.VaultSecretRef != nil {
		vaultSecret := &avapigwv1alpha1.VaultSecret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: tlsConfig.Namespace, Name: vaultSource.VaultSecretRef.Name}, vaultSecret); err != nil {
			if errors.IsNotFound(err) {
				return nil, fmt.Errorf("VaultSecret %s not found", vaultSource.VaultSecretRef.Name)
			}
			return nil, fmt.Errorf("failed to get VaultSecret %s: %w", vaultSource.VaultSecretRef.Name, err)
		}

		// Check if VaultSecret has synced a target secret
		if vaultSecret.Status.TargetSecretName == nil {
			return nil, fmt.Errorf("VaultSecret %s has not synced a target secret yet", vaultSource.VaultSecretRef.Name)
		}

		targetNamespace := tlsConfig.Namespace
		if vaultSecret.Status.TargetSecretNamespace != nil {
			targetNamespace = *vaultSecret.Status.TargetSecretNamespace
		}

		// Load from the synced secret
		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: targetNamespace, Name: *vaultSecret.Status.TargetSecretName}, secret); err != nil {
			if errors.IsNotFound(err) {
				return nil, fmt.Errorf("target secret %s/%s not found", targetNamespace, *vaultSecret.Status.TargetSecretName)
			}
			return nil, fmt.Errorf("failed to get target secret %s/%s: %w", targetNamespace, *vaultSecret.Status.TargetSecretName, err)
		}

		// Determine certificate key
		certKey := "certificate"
		if vaultSource.CertKey != nil {
			certKey = *vaultSource.CertKey
		}

		certData, ok := secret.Data[certKey]
		if !ok {
			return nil, fmt.Errorf("certificate key %s not found in secret", certKey)
		}

		return r.parseCertificate(certData)
	}

	return nil, fmt.Errorf("Vault certificate source requires VaultSecretRef")
}

// parseCertificate parses a PEM-encoded certificate and extracts information
func (r *TLSConfigReconciler) parseCertificate(certData []byte) (*avapigwv1alpha1.CertificateInfo, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Calculate fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	// Build certificate info
	issuer := cert.Issuer.String()
	subject := cert.Subject.String()
	serialNumber := cert.SerialNumber.String()

	info := &avapigwv1alpha1.CertificateInfo{
		NotBefore:    &metav1.Time{Time: cert.NotBefore},
		NotAfter:     &metav1.Time{Time: cert.NotAfter},
		Issuer:       &issuer,
		Subject:      &subject,
		DNSNames:     cert.DNSNames,
		SerialNumber: &serialNumber,
		Fingerprint:  &fingerprintHex,
	}

	return info, nil
}

// setCondition sets a condition on the TLSConfig status
func (r *TLSConfigReconciler) setCondition(tlsConfig *avapigwv1alpha1.TLSConfig, conditionType avapigwv1alpha1.ConditionType, status metav1.ConditionStatus, reason, message string) {
	tlsConfig.Status.SetCondition(conditionType, status, reason, message)
}

// updateStatus updates the TLSConfig status
func (r *TLSConfigReconciler) updateStatus(ctx context.Context, tlsConfig *avapigwv1alpha1.TLSConfig) error {
	return r.Status().Update(ctx, tlsConfig)
}

// SetupWithManager sets up the controller with the Manager
func (r *TLSConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.TLSConfig{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findTLSConfigsForSecret),
		).
		Watches(
			&avapigwv1alpha1.VaultSecret{},
			handler.EnqueueRequestsFromMapFunc(r.findTLSConfigsForVaultSecret),
		).
		Complete(r)
}

// findTLSConfigsForSecret finds TLSConfigs that reference a Secret
func (r *TLSConfigReconciler) findTLSConfigsForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	secret := obj.(*corev1.Secret)
	var requests []reconcile.Request

	var tlsConfigs avapigwv1alpha1.TLSConfigList
	if err := r.List(ctx, &tlsConfigs); err != nil {
		return requests
	}

	for _, tlsConfig := range tlsConfigs.Items {
		if tlsConfig.Spec.CertificateSource.Secret != nil {
			namespace := tlsConfig.Namespace
			if tlsConfig.Spec.CertificateSource.Secret.Namespace != nil {
				namespace = *tlsConfig.Spec.CertificateSource.Secret.Namespace
			}
			if namespace == secret.Namespace && tlsConfig.Spec.CertificateSource.Secret.Name == secret.Name {
				requests = append(requests, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Namespace: tlsConfig.Namespace,
						Name:      tlsConfig.Name,
					},
				})
			}
		}
	}

	return requests
}

// findTLSConfigsForVaultSecret finds TLSConfigs that reference a VaultSecret
func (r *TLSConfigReconciler) findTLSConfigsForVaultSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	vaultSecret := obj.(*avapigwv1alpha1.VaultSecret)
	var requests []reconcile.Request

	var tlsConfigs avapigwv1alpha1.TLSConfigList
	if err := r.List(ctx, &tlsConfigs); err != nil {
		return requests
	}

	for _, tlsConfig := range tlsConfigs.Items {
		if tlsConfig.Spec.CertificateSource.Vault != nil &&
			tlsConfig.Spec.CertificateSource.Vault.VaultSecretRef != nil {
			if tlsConfig.Namespace == vaultSecret.Namespace &&
				tlsConfig.Spec.CertificateSource.Vault.VaultSecretRef.Name == vaultSecret.Name {
				requests = append(requests, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Namespace: tlsConfig.Namespace,
						Name:      tlsConfig.Name,
					},
				})
			}
		}
	}

	return requests
}
