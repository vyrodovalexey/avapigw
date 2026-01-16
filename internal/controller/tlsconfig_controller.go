// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/controller/base"
)

// Local aliases for constants to maintain backward compatibility.
// These reference the centralized constants from constants.go.
const (
	tlsConfigFinalizer        = TLSConfigFinalizerName
	tlsConfigReconcileTimeout = TLSConfigReconcileTimeout
)

// TLSConfigReconciler reconciles a TLSConfig object
type TLSConfigReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	RequeueStrategy     *RequeueStrategy
	requeueStrategyOnce sync.Once // Ensures thread-safe initialization of RequeueStrategy

	// Base reconciler components
	metrics          *base.ControllerMetrics
	finalizerHandler *base.FinalizerHandler
}

// getRequeueStrategy returns the requeue strategy, initializing with defaults if needed.
// Uses sync.Once to ensure thread-safe initialization and prevent race conditions
// when multiple goroutines access the strategy concurrently.
func (r *TLSConfigReconciler) getRequeueStrategy() *RequeueStrategy {
	r.requeueStrategyOnce.Do(func() {
		if r.RequeueStrategy == nil {
			r.RequeueStrategy = DefaultRequeueStrategy()
		}
	})
	return r.RequeueStrategy
}

// initBaseComponents initializes the base controller components.
// This is called automatically during reconciliation but can also be called
// explicitly for testing purposes.
func (r *TLSConfigReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("tlsconfig")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, tlsConfigFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *TLSConfigReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=tlsconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=vaultsecrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles TLSConfig reconciliation
func (r *TLSConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, tlsConfigReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling TLSConfig", "name", req.Name, "namespace", req.Namespace)

	tlsConfig, result, err := r.fetchTLSConfig(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if tlsConfig == nil {
		return result, nil
	}

	if !tlsConfig.DeletionTimestamp.IsZero() {
		result, delErr := r.handleDeletion(ctx, tlsConfig)
		if delErr == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, delErr
	}

	return r.ensureFinalizerAndReconcileTLSConfig(ctx, tlsConfig, strategy, resourceKey, &reconcileErr)
}

// fetchTLSConfig fetches the TLSConfig instance and handles not-found errors.
func (r *TLSConfigReconciler) fetchTLSConfig(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.TLSConfig, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	tlsConfig := &avapigwv1alpha1.TLSConfig{}
	if err := r.Get(ctx, req.NamespacedName, tlsConfig); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("TLSConfig not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getTLSConfig", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get TLSConfig",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return tlsConfig, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcileTLSConfig ensures the finalizer is present and performs reconciliation.
func (r *TLSConfigReconciler) ensureFinalizerAndReconcileTLSConfig(
	ctx context.Context,
	tlsConfig *avapigwv1alpha1.TLSConfig,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if !r.finalizerHandler.HasFinalizer(tlsConfig) {
		added, err := r.finalizerHandler.EnsureFinalizer(ctx, tlsConfig)
		if err != nil {
			*reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(*reconcileErr, "Failed to add finalizer", "errorType", (*reconcileErr).Type)
			r.Recorder.Event(tlsConfig, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	if err := r.reconcileTLSConfig(ctx, tlsConfig); err != nil {
		*reconcileErr = ClassifyError("reconcileTLSConfig", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile TLSConfig",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
		)
		r.Recorder.Event(tlsConfig, corev1.EventTypeWarning, "ReconcileError", err.Error())
		return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
	}

	strategy.ResetFailureCount(resourceKey)
	return strategy.ForCustomInterval(r.calculateRequeueInterval(tlsConfig)), nil
}

// calculateRequeueInterval determines the requeue interval based on certificate expiration.
func (r *TLSConfigReconciler) calculateRequeueInterval(tlsConfig *avapigwv1alpha1.TLSConfig) time.Duration {
	requeueAfter := 1 * time.Hour
	if tlsConfig.Spec.Rotation != nil && tlsConfig.Spec.Rotation.CheckInterval != nil {
		if interval, err := time.ParseDuration(string(*tlsConfig.Spec.Rotation.CheckInterval)); err == nil {
			requeueAfter = interval
		}
	}
	return requeueAfter
}

// handleDeletion handles TLSConfig deletion
func (r *TLSConfigReconciler) handleDeletion(
	ctx context.Context,
	tlsConfig *avapigwv1alpha1.TLSConfig,
) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(tlsConfig).String()

	if r.finalizerHandler.HasFinalizer(tlsConfig) {
		// Perform cleanup
		logger.Info("Performing cleanup for TLSConfig deletion")

		// Record event
		r.Recorder.Event(tlsConfig, corev1.EventTypeNormal, "Deleting", "TLSConfig is being deleted")

		// Remove finalizer
		if _, err := r.finalizerHandler.RemoveFinalizer(ctx, tlsConfig); err != nil {
			reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to remove finalizer",
				"errorType", reconcileErr.Type,
			)
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
	}

	return ctrl.Result{}, nil
}

// getRenewBeforeDuration returns the renew before duration from config or default.
func (r *TLSConfigReconciler) getRenewBeforeDuration(tlsConfig *avapigwv1alpha1.TLSConfig) time.Duration {
	renewBefore := 30 * 24 * time.Hour
	if tlsConfig.Spec.Rotation != nil && tlsConfig.Spec.Rotation.RenewBefore != nil {
		if parsed, err := time.ParseDuration(*tlsConfig.Spec.Rotation.RenewBefore); err == nil {
			renewBefore = parsed
		}
	}
	return renewBefore
}

// updateCertificateExpirationStatus updates the status based on certificate expiration.
func (r *TLSConfigReconciler) updateCertificateExpirationStatus(
	tlsConfig *avapigwv1alpha1.TLSConfig,
	certInfo *avapigwv1alpha1.CertificateInfo,
) {
	if certInfo.NotAfter == nil {
		r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			string(avapigwv1alpha1.ReasonReady), "TLSConfig is ready")
		tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusReady
		return
	}

	expiresIn := time.Until(certInfo.NotAfter.Time)
	renewBefore := r.getRenewBeforeDuration(tlsConfig)

	switch {
	case expiresIn <= 0:
		r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonError), "Certificate has expired")
		tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusError
		r.Recorder.Event(tlsConfig, corev1.EventTypeWarning, "CertificateExpired", "Certificate has expired")
	case expiresIn <= renewBefore:
		msg := fmt.Sprintf("Certificate expires in %s", expiresIn.Round(time.Hour))
		r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			string(avapigwv1alpha1.ReasonDegraded), msg)
		tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusDegraded
		r.Recorder.Event(tlsConfig, corev1.EventTypeWarning, "CertificateExpiringSoon",
			fmt.Sprintf("Certificate expires in %s", expiresIn.Round(time.Hour)))
	default:
		r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			string(avapigwv1alpha1.ReasonReady), "Certificate is valid")
		tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusReady
	}
}

// reconcileTLSConfig performs the main reconciliation logic
func (r *TLSConfigReconciler) reconcileTLSConfig(ctx context.Context, tlsConfig *avapigwv1alpha1.TLSConfig) error {
	logger := log.FromContext(ctx)
	resourceKey := client.ObjectKeyFromObject(tlsConfig).String()

	tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	tlsConfig.Status.ObservedGeneration = tlsConfig.Generation
	tlsConfig.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}

	certInfo, err := r.loadAndValidateCertificate(ctx, tlsConfig)
	if err != nil {
		reconcileErr := ClassifyError("loadAndValidateCertificate", resourceKey, err)
		logger.Error(reconcileErr, "Failed to load and validate certificate",
			"errorType", reconcileErr.Type,
		)
		r.setCondition(tlsConfig, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonNotReady), err.Error())
		tlsConfig.Status.Phase = avapigwv1alpha1.PhaseStatusError
		return r.updateStatus(ctx, tlsConfig)
	}

	tlsConfig.Status.Certificate = certInfo
	r.updateCertificateExpirationStatus(tlsConfig, certInfo)

	if err := r.updateStatus(ctx, tlsConfig); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update TLSConfig status",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	r.Recorder.Event(tlsConfig, corev1.EventTypeNormal, EventReasonReconciled, "TLSConfig reconciled successfully")
	return nil
}

// loadAndValidateCertificate loads and validates the certificate from the configured source
func (r *TLSConfigReconciler) loadAndValidateCertificate(
	ctx context.Context,
	tlsConfig *avapigwv1alpha1.TLSConfig,
) (*avapigwv1alpha1.CertificateInfo, error) {
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
func (r *TLSConfigReconciler) loadCertificateFromSecret(
	ctx context.Context,
	tlsConfig *avapigwv1alpha1.TLSConfig,
	secretSource *avapigwv1alpha1.SecretCertificateSource,
) (*avapigwv1alpha1.CertificateInfo, error) {
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
func (r *TLSConfigReconciler) loadCertificateFromVault(
	ctx context.Context,
	tlsConfig *avapigwv1alpha1.TLSConfig,
	vaultSource *avapigwv1alpha1.VaultCertificateSource,
) (*avapigwv1alpha1.CertificateInfo, error) {
	if vaultSource.VaultSecretRef == nil {
		return nil, fmt.Errorf("vault certificate source requires VaultSecretRef")
	}

	return r.loadCertificateFromVaultSecretRef(ctx, tlsConfig, vaultSource)
}

// loadCertificateFromVaultSecretRef loads certificate from a VaultSecret reference
func (r *TLSConfigReconciler) loadCertificateFromVaultSecretRef(
	ctx context.Context,
	tlsConfig *avapigwv1alpha1.TLSConfig,
	vaultSource *avapigwv1alpha1.VaultCertificateSource,
) (*avapigwv1alpha1.CertificateInfo, error) {
	vaultSecret, err := r.getVaultSecret(ctx, tlsConfig.Namespace, vaultSource.VaultSecretRef.Name)
	if err != nil {
		return nil, err
	}

	// Check if VaultSecret has synced a target secret
	if vaultSecret.Status.TargetSecretName == nil {
		return nil, fmt.Errorf("VaultSecret %s has not synced a target secret yet", vaultSource.VaultSecretRef.Name)
	}

	targetNamespace := tlsConfig.Namespace
	if vaultSecret.Status.TargetSecretNamespace != nil {
		targetNamespace = *vaultSecret.Status.TargetSecretNamespace
	}

	return r.loadCertificateFromTargetSecret(
		ctx, targetNamespace, *vaultSecret.Status.TargetSecretName, vaultSource.CertKey,
	)
}

// getVaultSecret retrieves a VaultSecret by namespace and name
func (r *TLSConfigReconciler) getVaultSecret(
	ctx context.Context,
	namespace, name string,
) (*avapigwv1alpha1.VaultSecret, error) {
	vaultSecret := &avapigwv1alpha1.VaultSecret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, vaultSecret); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("VaultSecret %s not found", name)
		}
		return nil, fmt.Errorf("failed to get VaultSecret %s: %w", name, err)
	}
	return vaultSecret, nil
}

// loadCertificateFromTargetSecret loads certificate data from a target secret
func (r *TLSConfigReconciler) loadCertificateFromTargetSecret(
	ctx context.Context,
	namespace, name string,
	certKeyPtr *string,
) (*avapigwv1alpha1.CertificateInfo, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("target secret %s/%s not found", namespace, name)
		}
		return nil, fmt.Errorf("failed to get target secret %s/%s: %w", namespace, name, err)
	}

	// Determine certificate key
	certKey := "certificate"
	if certKeyPtr != nil {
		certKey = *certKeyPtr
	}

	certData, ok := secret.Data[certKey]
	if !ok {
		return nil, fmt.Errorf("certificate key %s not found in secret", certKey)
	}

	return r.parseCertificate(certData)
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
//
//nolint:unparam // conditionType kept for API consistency with other controllers
func (r *TLSConfigReconciler) setCondition(
	tlsConfig *avapigwv1alpha1.TLSConfig,
	conditionType avapigwv1alpha1.ConditionType,
	status metav1.ConditionStatus,
	reason, message string,
) {
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
