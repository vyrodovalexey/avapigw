// Package controller provides Kubernetes controllers for CRD reconciliation.
package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/go-logr/logr"
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
	"github.com/vyrodovalexey/avapigw/internal/controller/base"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// vaultSecretReconcileTimeout is the maximum duration for a single VaultSecret reconciliation.
// Longer timeout for Vault operations which may involve network calls.
// This references the centralized constant from constants.go.
const vaultSecretReconcileTimeout = VaultSecretReconcileTimeout

// VaultClientCacheConfig holds configuration for the Vault client cache in the controller.
type VaultClientCacheConfig struct {
	// MaxSize is the maximum number of Vault clients to cache.
	MaxSize int

	// TTL is the time-to-live for unused clients.
	TTL time.Duration

	// CleanupInterval is how often to run the cleanup routine.
	CleanupInterval time.Duration
}

// DefaultVaultClientCacheConfig returns default configuration for the Vault client cache.
func DefaultVaultClientCacheConfig() *VaultClientCacheConfig {
	return &VaultClientCacheConfig{
		MaxSize:         100,
		TTL:             30 * time.Minute,
		CleanupInterval: 5 * time.Minute,
	}
}

// jitterRand is a thread-safe random number generator for jitter calculations
// Properly seeded with time-based seed to avoid predictable sequences
var jitterRand = rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // weak random is acceptable for jitter
var jitterMu sync.Mutex

// Local alias for the finalizer constant to maintain backward compatibility.
// This references the centralized constant from constants.go.
// G101: This is a finalizer name, not a credential
const vaultSecretFinalizer = VaultSecretFinalizerName //nolint:gosec // finalizer name, not a credential

// VaultSecretReconciler reconciles a VaultSecret object
type VaultSecretReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	RequeueStrategy     *RequeueStrategy
	requeueStrategyOnce sync.Once // Ensures thread-safe initialization of RequeueStrategy
	// map[string]*vault.Client - keyed by Vault address (legacy, for backward compatibility)
	vaultClients sync.Map

	// Base reconciler components
	metrics          *base.ControllerMetrics
	finalizerHandler *base.FinalizerHandler

	// vaultClientCache is the bounded LRU cache for Vault clients.
	// This replaces the unbounded sync.Map for better memory management.
	vaultClientCache *vault.VaultClientCache

	// vaultAddressTracker tracks the Vault address for each VaultSecret.
	// Key: namespace/name, Value: Vault address
	// Used to detect address changes and clean up old clients.
	vaultAddressTracker sync.Map

	// cacheConfig holds the configuration for the Vault client cache.
	cacheConfig *VaultClientCacheConfig

	// stopCh is used to signal shutdown of background routines.
	stopCh chan struct{}

	// stopOnce ensures Stop is only called once.
	stopOnce sync.Once

	// VaultEnabled indicates whether Vault integration is enabled.
	// When false, the controller will skip reconciliation gracefully.
	VaultEnabled bool

	// SecretsProviderType indicates the configured secrets provider type.
	// Used to determine if VaultSecret reconciliation should proceed.
	SecretsProviderType string
}

// getRequeueStrategy returns the requeue strategy, initializing with defaults if needed.
// Uses sync.Once to ensure thread-safe initialization and prevent race conditions
// when multiple goroutines access the strategy concurrently.
func (r *VaultSecretReconciler) getRequeueStrategy() *RequeueStrategy {
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
func (r *VaultSecretReconciler) initBaseComponents() {
	if r.metrics == nil {
		r.metrics = base.DefaultMetricsRegistry.RegisterController("vaultsecret")
	}
	if r.finalizerHandler == nil {
		r.finalizerHandler = base.NewFinalizerHandler(r.Client, vaultSecretFinalizer)
	}
}

// ensureInitialized ensures base components are initialized.
// This is a helper for methods that may be called directly in tests.
func (r *VaultSecretReconciler) ensureInitialized() {
	r.initBaseComponents()
}

//nolint:lll // kubebuilder RBAC marker cannot be shortened
//+kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=vaultsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=vaultsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=vaultsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// InitVaultClientCache initializes the Vault client cache with the given configuration.
// This should be called before starting the controller.
func (r *VaultSecretReconciler) InitVaultClientCache(ctx context.Context, config *VaultClientCacheConfig) {
	if config == nil {
		config = DefaultVaultClientCacheConfig()
	}
	r.cacheConfig = config
	r.stopCh = make(chan struct{})

	// Create the bounded LRU cache for Vault clients
	vaultCacheConfig := &vault.VaultClientCacheConfig{
		MaxSize:         config.MaxSize,
		TTL:             config.TTL,
		CleanupInterval: config.CleanupInterval,
	}
	r.vaultClientCache = vault.NewVaultClientCache(vaultCacheConfig, nil)

	// Start the cleanup routine
	r.vaultClientCache.Start(ctx, config.CleanupInterval)
}

// Stop stops the Vault client cache and cleans up resources.
// This should be called when the controller is shutting down.
func (r *VaultSecretReconciler) Stop() {
	r.stopOnce.Do(func() {
		if r.stopCh != nil {
			close(r.stopCh)
		}
		if r.vaultClientCache != nil {
			r.vaultClientCache.Stop()
		}
	})
}

// Reconcile handles VaultSecret reconciliation
func (r *VaultSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.initBaseComponents()

	ctx, cancel := context.WithTimeout(ctx, vaultSecretReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.String()

	// Check if Vault is enabled - skip reconciliation gracefully if not
	if !r.VaultEnabled && r.SecretsProviderType != "vault" {
		return r.handleVaultDisabled(ctx, req, logger)
	}

	// Track reconciliation metrics
	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		r.metrics.ObserveReconcile(time.Since(start).Seconds(), reconcileErr == nil)
	}()

	logger.Info("Reconciling VaultSecret",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the VaultSecret instance
	vaultSecret, result, err := r.fetchVaultSecret(ctx, req, strategy, resourceKey)
	if err != nil {
		reconcileErr = err
		return result, reconcileErr
	}
	if vaultSecret == nil {
		return result, nil
	}

	// Handle deletion
	if !vaultSecret.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, vaultSecret)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Ensure finalizer and reconcile
	return r.ensureFinalizerAndReconcileVaultSecret(ctx, vaultSecret, strategy, resourceKey, &reconcileErr)
}

// handleVaultDisabled handles reconciliation when Vault is disabled.
func (r *VaultSecretReconciler) handleVaultDisabled(
	ctx context.Context,
	req ctrl.Request,
	logger logr.Logger,
) (ctrl.Result, error) {
	logger.Info("Vault is disabled, skipping VaultSecret reconciliation",
		"name", req.Name,
		"namespace", req.Namespace,
		"secretsProvider", r.SecretsProviderType,
	)

	vaultSecret := &avapigwv1alpha1.VaultSecret{}
	if err := r.Get(ctx, req.NamespacedName, vaultSecret); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	disabledMsg := "Vault integration is disabled. " +
		"Set --vault-enabled=true or --secrets-provider=vault to enable."
	r.setCondition(vaultSecret, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
		"VaultDisabled", disabledMsg)
	vaultSecret.Status.Phase = avapigwv1alpha1.PhaseStatusPending
	if err := r.updateStatus(ctx, vaultSecret); err != nil {
		logger.Error(err, "Failed to update VaultSecret status")
	}
	r.Recorder.Event(vaultSecret, corev1.EventTypeWarning, "VaultDisabled",
		"Vault integration is disabled. VaultSecret will not be reconciled.")
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// fetchVaultSecret fetches the VaultSecret instance and handles not-found errors.
func (r *VaultSecretReconciler) fetchVaultSecret(
	ctx context.Context,
	req ctrl.Request,
	strategy *RequeueStrategy,
	resourceKey string,
) (*avapigwv1alpha1.VaultSecret, ctrl.Result, *ReconcileError) {
	logger := log.FromContext(ctx)
	vaultSecret := &avapigwv1alpha1.VaultSecret{}
	if err := r.Get(ctx, req.NamespacedName, vaultSecret); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("VaultSecret not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return nil, ctrl.Result{}, nil
		}
		reconcileErr := ClassifyError("getVaultSecret", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get VaultSecret",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return nil, strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
	return vaultSecret, ctrl.Result{}, nil
}

// ensureFinalizerAndReconcileVaultSecret ensures the finalizer is present and performs reconciliation.
func (r *VaultSecretReconciler) ensureFinalizerAndReconcileVaultSecret(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	strategy *RequeueStrategy,
	resourceKey string,
	reconcileErr **ReconcileError,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Add finalizer if not present
	if !r.finalizerHandler.HasFinalizer(vaultSecret) {
		added, err := r.finalizerHandler.EnsureFinalizer(ctx, vaultSecret)
		if err != nil {
			*reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(*reconcileErr, "Failed to add finalizer", "errorType", (*reconcileErr).Type)
			r.Recorder.Event(vaultSecret, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), *reconcileErr
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	// Reconcile the VaultSecret
	if err := r.reconcileVaultSecret(ctx, vaultSecret); err != nil {
		*reconcileErr = ClassifyError("reconcileVaultSecret", resourceKey, err)
		logger.Error(*reconcileErr, "Failed to reconcile VaultSecret",
			"errorType", (*reconcileErr).Type,
			"retryable", (*reconcileErr).Retryable,
			"userActionRequired", (*reconcileErr).UserActionRequired,
		)
		r.Recorder.Event(vaultSecret, corev1.EventTypeWarning, string((*reconcileErr).Type)+"Error", err.Error())
		return r.handleVaultSecretReconcileError(*reconcileErr, strategy, resourceKey)
	}

	return r.handleVaultSecretReconcileSuccess(ctx, vaultSecret, strategy, resourceKey, logger)
}

// handleVaultSecretReconcileError returns the appropriate result based on error type.
func (r *VaultSecretReconciler) handleVaultSecretReconcileError(
	reconcileErr *ReconcileError,
	strategy *RequeueStrategy,
	resourceKey string,
) (ctrl.Result, error) {
	switch reconcileErr.Type {
	case ErrorTypeValidation:
		return strategy.ForValidationError(), reconcileErr
	case ErrorTypePermanent:
		return strategy.ForPermanentError(), reconcileErr
	case ErrorTypeDependency:
		return strategy.ForDependencyErrorWithBackoff(resourceKey), reconcileErr
	default:
		return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}
}

// handleVaultSecretReconcileSuccess handles successful reconciliation.
func (r *VaultSecretReconciler) handleVaultSecretReconcileSuccess(
	_ context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	strategy *RequeueStrategy,
	resourceKey string,
	logger logr.Logger,
) (ctrl.Result, error) {
	strategy.ResetFailureCount(resourceKey)
	requeueAfter := r.calculateNextRefresh(vaultSecret)
	logger.Info("VaultSecret reconciled successfully",
		"name", vaultSecret.Name,
		"namespace", vaultSecret.Namespace,
		"nextRefresh", requeueAfter,
	)
	return strategy.ForCustomInterval(requeueAfter), nil
}

// handleDeletion handles VaultSecret deletion
func (r *VaultSecretReconciler) handleDeletion(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
) (ctrl.Result, error) {
	// Ensure base components are initialized (needed when called directly in tests)
	r.ensureInitialized()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(vaultSecret).String()

	if !r.finalizerHandler.HasFinalizer(vaultSecret) {
		return ctrl.Result{}, nil
	}

	// Perform cleanup - delete target secret if deletion policy is Delete
	r.cleanupTargetSecretIfNeeded(ctx, vaultSecret, resourceKey, logger)

	// Clean up cached Vault client to prevent memory leak
	r.cleanupVaultClient(vaultSecret)

	logger.Info("Performing cleanup for VaultSecret deletion",
		"name", vaultSecret.Name,
		"namespace", vaultSecret.Namespace,
	)

	// Record event
	r.Recorder.Event(vaultSecret, corev1.EventTypeNormal, "Deleting", "VaultSecret is being deleted")

	// Remove finalizer
	if _, err := r.finalizerHandler.RemoveFinalizer(ctx, vaultSecret); err != nil {
		reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
		logger.Error(reconcileErr, "Failed to remove finalizer",
			"errorType", reconcileErr.Type,
		)
		return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}

	return ctrl.Result{}, nil
}

// cleanupTargetSecretIfNeeded deletes the target secret if deletion policy requires it
func (r *VaultSecretReconciler) cleanupTargetSecretIfNeeded(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	resourceKey string,
	logger logr.Logger,
) {
	if vaultSecret.Spec.Target == nil {
		return
	}

	deletionPolicy := avapigwv1alpha1.SecretDeletionPolicyDelete
	if vaultSecret.Spec.Target.DeletionPolicy != nil {
		deletionPolicy = *vaultSecret.Spec.Target.DeletionPolicy
	}

	if deletionPolicy != avapigwv1alpha1.SecretDeletionPolicyDelete {
		return
	}

	if err := r.deleteTargetSecret(ctx, vaultSecret); err != nil {
		reconcileErr := ClassifyError("deleteTargetSecret", resourceKey, err)
		logger.Error(reconcileErr, "Failed to delete target secret",
			"errorType", reconcileErr.Type,
		)
		// Continue with finalizer removal even if deletion fails
	}
}

// cleanupVaultClient removes the cached Vault client for a VaultSecret.
// This prevents memory leaks when VaultSecrets are deleted.
func (r *VaultSecretReconciler) cleanupVaultClient(vaultSecret *avapigwv1alpha1.VaultSecret) {
	conn := vaultSecret.Spec.VaultConnection
	clientKey := fmt.Sprintf("%s-%s", conn.Address, vaultSecret.Namespace)

	// Remove from the legacy sync.Map (for backward compatibility)
	r.vaultClients.Delete(clientKey)

	// Remove from the bounded LRU cache if it exists
	if r.vaultClientCache != nil {
		r.vaultClientCache.Delete(clientKey)
	}

	// Remove from the address tracker
	trackerKey := fmt.Sprintf("%s/%s", vaultSecret.Namespace, vaultSecret.Name)
	r.vaultAddressTracker.Delete(trackerKey)
}

// handleVaultAddressChange detects if the Vault address has changed for a VaultSecret
// and cleans up the old client if necessary.
func (r *VaultSecretReconciler) handleVaultAddressChange(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
) {
	logger := log.FromContext(ctx)

	trackerKey := fmt.Sprintf("%s/%s", vaultSecret.Namespace, vaultSecret.Name)
	currentAddress := vaultSecret.Spec.VaultConnection.Address

	// Check if we have a previously tracked address
	if previousAddress, ok := r.vaultAddressTracker.Load(trackerKey); ok {
		prevAddr := previousAddress.(string)
		if prevAddr != currentAddress {
			// Address has changed - clean up the old client
			logger.Info("Vault address changed, cleaning up old client",
				"vaultSecret", trackerKey,
				"oldAddress", prevAddr,
				"newAddress", currentAddress,
			)

			oldClientKey := fmt.Sprintf("%s-%s", prevAddr, vaultSecret.Namespace)

			// Remove from the legacy sync.Map
			r.vaultClients.Delete(oldClientKey)

			// Remove from the bounded LRU cache if it exists
			if r.vaultClientCache != nil {
				r.vaultClientCache.Delete(oldClientKey)
			}
		}
	}

	// Update the tracker with the current address
	r.vaultAddressTracker.Store(trackerKey, currentAddress)
}

// reconcileVaultSecret performs the main reconciliation logic
func (r *VaultSecretReconciler) reconcileVaultSecret(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
) error {
	logger := log.FromContext(ctx)
	resourceKey := client.ObjectKeyFromObject(vaultSecret).String()

	r.initVaultSecretStatus(vaultSecret)
	r.handleVaultAddressChange(ctx, vaultSecret)

	if err := r.validateAndSyncVaultSecret(ctx, vaultSecret, resourceKey, logger); err != nil {
		return err
	}

	return r.finalizeVaultSecretReconcile(ctx, vaultSecret, resourceKey, logger)
}

// initVaultSecretStatus initializes the VaultSecret status for reconciliation.
func (r *VaultSecretReconciler) initVaultSecretStatus(vaultSecret *avapigwv1alpha1.VaultSecret) {
	vaultSecret.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	vaultSecret.Status.ObservedGeneration = vaultSecret.Generation
	vaultSecret.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}
}

// validateAndSyncVaultSecret validates the Vault connection and syncs the secret.
func (r *VaultSecretReconciler) validateAndSyncVaultSecret(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	resourceKey string,
	logger logr.Logger,
) error {
	if err := r.validateVaultConnection(ctx, vaultSecret); err != nil {
		return r.handleVaultValidationError(ctx, vaultSecret, resourceKey, err, logger)
	}

	if err := r.syncSecret(ctx, vaultSecret); err != nil {
		return r.handleVaultSyncError(ctx, vaultSecret, resourceKey, err, logger)
	}

	return nil
}

// handleVaultValidationError handles validation errors during VaultSecret reconciliation.
func (r *VaultSecretReconciler) handleVaultValidationError(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	resourceKey string,
	err error,
	logger logr.Logger,
) *ReconcileError {
	var reconcileErr *ReconcileError
	if errors.IsNotFound(err) {
		reconcileErr = NewDependencyError("validateVaultConnection", resourceKey, err)
	} else {
		reconcileErr = NewValidationError("validateVaultConnection", resourceKey, err)
	}

	logger.Error(reconcileErr, "Failed to validate Vault connection", "errorType", reconcileErr.Type)
	r.setVaultSecretErrorStatus(ctx, vaultSecret, err, logger)
	return reconcileErr
}

// handleVaultSyncError handles sync errors during VaultSecret reconciliation.
func (r *VaultSecretReconciler) handleVaultSyncError(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	resourceKey string,
	err error,
	logger logr.Logger,
) *ReconcileError {
	reconcileErr := ClassifyError("syncSecret", resourceKey, err)
	logger.Error(reconcileErr, "Failed to sync secret from Vault",
		"errorType", reconcileErr.Type,
		"retryable", reconcileErr.Retryable,
	)
	r.setVaultSecretErrorStatus(ctx, vaultSecret, err, logger)
	return reconcileErr
}

// setVaultSecretErrorStatus sets the error status on a VaultSecret.
func (r *VaultSecretReconciler) setVaultSecretErrorStatus(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	err error,
	logger logr.Logger,
) {
	r.setCondition(vaultSecret, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
		string(avapigwv1alpha1.ReasonNotReady), err.Error())
	vaultSecret.Status.Phase = avapigwv1alpha1.PhaseStatusError
	errMsg := err.Error()
	vaultSecret.Status.LastVaultError = &errMsg

	if statusErr := r.updateStatus(ctx, vaultSecret); statusErr != nil {
		logger.Error(statusErr, "Failed to update status after error")
	}
}

// finalizeVaultSecretReconcile completes the reconciliation by updating status and recording events.
func (r *VaultSecretReconciler) finalizeVaultSecretReconcile(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	resourceKey string,
	logger logr.Logger,
) error {
	vaultSecret.Status.LastVaultError = nil

	now := metav1.Now()
	vaultSecret.Status.LastRefreshTime = &now
	nextRefresh := metav1.NewTime(now.Add(r.calculateNextRefresh(vaultSecret)))
	vaultSecret.Status.NextRefreshTime = &nextRefresh

	r.setCondition(vaultSecret, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonReady), "Secret synced from Vault")
	vaultSecret.Status.Phase = avapigwv1alpha1.PhaseStatusReady

	if err := r.updateStatus(ctx, vaultSecret); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update VaultSecret status", "errorType", reconcileErr.Type)
		return reconcileErr
	}

	r.Recorder.Event(vaultSecret, corev1.EventTypeNormal, "Synced", "Secret synced from Vault successfully")
	return nil
}

// validateVaultConnection validates the Vault connection configuration
func (r *VaultSecretReconciler) validateVaultConnection(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
) error {
	conn := vaultSecret.Spec.VaultConnection

	// Validate address
	if conn.Address == "" {
		return fmt.Errorf("vault address is required")
	}

	// Validate authentication configuration
	auth := conn.Auth
	if auth.Kubernetes == nil && auth.Token == nil && auth.AppRole == nil {
		return fmt.Errorf("at least one authentication method must be configured")
	}

	// Validate Kubernetes auth
	if auth.Kubernetes != nil && auth.Kubernetes.Role == "" {
		return fmt.Errorf("kubernetes auth role is required")
	}

	// Validate Token auth
	if auth.Token != nil {
		if err := r.validateTokenAuth(ctx, vaultSecret.Namespace, auth.Token); err != nil {
			return err
		}
	}

	// Validate AppRole auth
	if auth.AppRole != nil {
		if err := r.validateAppRoleAuth(ctx, vaultSecret.Namespace, auth.AppRole); err != nil {
			return err
		}
	}

	// Validate TLS configuration
	if conn.TLS != nil {
		if err := r.validateTLSConfig(ctx, vaultSecret.Namespace, conn.TLS); err != nil {
			return err
		}
	}

	return nil
}

// validateTokenAuth validates the Token authentication configuration
func (r *VaultSecretReconciler) validateTokenAuth(
	ctx context.Context,
	defaultNamespace string,
	tokenAuth *avapigwv1alpha1.TokenAuthConfig,
) error {
	namespace := defaultNamespace
	if tokenAuth.SecretRef.Namespace != nil {
		namespace = *tokenAuth.SecretRef.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: tokenAuth.SecretRef.Name}, secret); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("token secret %s/%s not found", namespace, tokenAuth.SecretRef.Name)
		}
		return fmt.Errorf("failed to get token secret %s/%s: %w", namespace, tokenAuth.SecretRef.Name, err)
	}

	tokenKey := "token"
	if tokenAuth.TokenKey != nil {
		tokenKey = *tokenAuth.TokenKey
	}
	if _, ok := secret.Data[tokenKey]; !ok {
		return fmt.Errorf("token key %s not found in secret %s/%s", tokenKey, namespace, tokenAuth.SecretRef.Name)
	}

	return nil
}

// validateAppRoleAuth validates the AppRole authentication configuration
func (r *VaultSecretReconciler) validateAppRoleAuth(
	ctx context.Context,
	defaultNamespace string,
	appRole *avapigwv1alpha1.AppRoleAuthConfig,
) error {
	if appRole.RoleID == "" {
		return fmt.Errorf("AppRole role ID is required")
	}

	namespace := defaultNamespace
	if appRole.SecretIDRef.Namespace != nil {
		namespace = *appRole.SecretIDRef.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: appRole.SecretIDRef.Name}, secret); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("AppRole secret ID secret %s/%s not found", namespace, appRole.SecretIDRef.Name)
		}
		return fmt.Errorf("failed to get AppRole secret ID secret %s/%s: %w", namespace, appRole.SecretIDRef.Name, err)
	}

	secretIDKey := "secret-id"
	if appRole.SecretIDKey != nil {
		secretIDKey = *appRole.SecretIDKey
	}
	if _, ok := secret.Data[secretIDKey]; !ok {
		return fmt.Errorf(
			"secret ID key %s not found in secret %s/%s",
			secretIDKey, namespace, appRole.SecretIDRef.Name,
		)
	}

	return nil
}

// validateTLSConfig validates the TLS configuration for Vault connection
func (r *VaultSecretReconciler) validateTLSConfig(
	ctx context.Context,
	defaultNamespace string,
	tlsConfig *avapigwv1alpha1.VaultTLSConfig,
) error {
	if tlsConfig.CACertRef == nil {
		return nil
	}

	namespace := defaultNamespace
	if tlsConfig.CACertRef.Namespace != nil {
		namespace = *tlsConfig.CACertRef.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: tlsConfig.CACertRef.Name}, secret); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("TLS CA cert secret %s/%s not found", namespace, tlsConfig.CACertRef.Name)
		}
		return fmt.Errorf("failed to get TLS CA cert secret %s/%s: %w", namespace, tlsConfig.CACertRef.Name, err)
	}

	return nil
}

// getOrCreateVaultClient gets or creates a Vault client for the given VaultSecret
// Uses the bounded LRU cache if available, otherwise falls back to sync.Map.
// Uses LoadOrStore pattern to prevent race conditions between checking and creating clients.
func (r *VaultSecretReconciler) getOrCreateVaultClient(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
) (*vault.Client, error) {
	conn := vaultSecret.Spec.VaultConnection

	// Create a unique key for this Vault connection
	clientKey := fmt.Sprintf("%s-%s", conn.Address, vaultSecret.Namespace)

	// If the bounded LRU cache is available, use it
	if r.vaultClientCache != nil {
		return r.getOrCreateVaultClientWithCache(ctx, vaultSecret, clientKey)
	}

	// Fall back to the legacy sync.Map implementation
	return r.getOrCreateVaultClientLegacy(ctx, vaultSecret, clientKey)
}

// getOrCreateVaultClientWithCache uses the bounded LRU cache for Vault clients.
func (r *VaultSecretReconciler) getOrCreateVaultClientWithCache(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	clientKey string,
) (*vault.Client, error) {
	conn := vaultSecret.Spec.VaultConnection

	// Use GetOrCreate to atomically get or create the client
	return r.vaultClientCache.GetOrCreate(clientKey, conn.Address, func() (*vault.Client, error) {
		return r.createVaultClient(ctx, vaultSecret)
	})
}

// getOrCreateVaultClientLegacy uses the legacy sync.Map for backward compatibility.
func (r *VaultSecretReconciler) getOrCreateVaultClientLegacy(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	clientKey string,
) (*vault.Client, error) {
	// Try to load existing client first using LoadOrStore pattern to prevent race condition
	existing, loaded := r.vaultClients.Load(clientKey)
	if loaded {
		vaultClient := existing.(*vault.Client)
		if vaultClient.IsAuthenticated() {
			return vaultClient, nil
		}
		// Client exists but not authenticated, re-authenticate
		if err := vaultClient.Authenticate(ctx); err == nil {
			return vaultClient, nil
		}
		// Authentication failed, delete and create a new client
		// Use CompareAndDelete to avoid race with other goroutines
		r.vaultClients.CompareAndDelete(clientKey, existing)
	}

	// Create the client
	vaultClient, err := r.createVaultClient(ctx, vaultSecret)
	if err != nil {
		return nil, err
	}

	// Store the client using LoadOrStore to handle race condition
	// If another goroutine stored a client first, use that one instead
	actual, loaded := r.vaultClients.LoadOrStore(clientKey, vaultClient)
	if loaded {
		// Another goroutine created a client first, use that one
		return actual.(*vault.Client), nil
	}

	return vaultClient, nil
}

// createVaultClient creates a new Vault client for the given VaultSecret.
func (r *VaultSecretReconciler) createVaultClient(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
) (*vault.Client, error) {
	conn := vaultSecret.Spec.VaultConnection

	// Build TLS config if needed
	tlsConfig, err := r.buildVaultTLSConfig(ctx, vaultSecret.Namespace, conn.TLS)
	if err != nil {
		return nil, err
	}

	// Create Vault client config
	config := r.buildVaultClientConfig(conn, tlsConfig)

	// Create the client
	vaultClient, err := vault.NewClient(config, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set up authentication method
	authMethod, err := r.createAuthMethod(ctx, vaultSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth method: %w", err)
	}

	vaultClient.SetAuthMethod(authMethod)

	// Authenticate
	if err := vaultClient.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("failed to authenticate with Vault: %w", err)
	}

	return vaultClient, nil
}

// buildVaultTLSConfig builds the TLS configuration for Vault connection
func (r *VaultSecretReconciler) buildVaultTLSConfig(
	ctx context.Context,
	defaultNamespace string,
	tlsSpec *avapigwv1alpha1.VaultTLSConfig,
) (*vault.TLSConfig, error) {
	if tlsSpec == nil {
		return nil, nil
	}

	tlsConfig := &vault.TLSConfig{}

	if tlsSpec.InsecureSkipVerify != nil {
		tlsConfig.InsecureSkipVerify = *tlsSpec.InsecureSkipVerify
	}

	if tlsSpec.ServerName != nil {
		tlsConfig.ServerName = *tlsSpec.ServerName
	}

	// Load CA cert if specified
	if tlsSpec.CACertRef != nil {
		caCert, err := r.getSecretData(ctx, defaultNamespace, tlsSpec.CACertRef, "ca.crt")
		if err != nil {
			return nil, fmt.Errorf("failed to get CA cert: %w", err)
		}
		tlsConfig.CACert = caCert
	}

	// Load client cert if specified
	if tlsSpec.ClientCertRef != nil {
		clientCert, err := r.getSecretData(ctx, defaultNamespace, tlsSpec.ClientCertRef, "tls.crt")
		if err != nil {
			return nil, fmt.Errorf("failed to get client cert: %w", err)
		}
		tlsConfig.ClientCert = clientCert
	}

	// Load client key if specified
	if tlsSpec.ClientKeyRef != nil {
		clientKeyData, err := r.getSecretData(ctx, defaultNamespace, tlsSpec.ClientKeyRef, "tls.key")
		if err != nil {
			return nil, fmt.Errorf("failed to get client key: %w", err)
		}
		tlsConfig.ClientKey = clientKeyData
	}

	return tlsConfig, nil
}

// buildVaultClientConfig builds the Vault client configuration
func (r *VaultSecretReconciler) buildVaultClientConfig(
	conn avapigwv1alpha1.VaultConnectionConfig,
	tlsConfig *vault.TLSConfig,
) *vault.Config {
	config := &vault.Config{
		Address:      conn.Address,
		TLSConfig:    tlsConfig,
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryWaitMin: 500 * time.Millisecond,
		RetryWaitMax: 5 * time.Second,
	}

	if conn.Namespace != nil {
		config.Namespace = *conn.Namespace
	}

	return config
}

// createAuthMethod creates the appropriate authentication method
func (r *VaultSecretReconciler) createAuthMethod(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
) (vault.AuthMethod, error) {
	auth := vaultSecret.Spec.VaultConnection.Auth

	if auth.Kubernetes != nil {
		return r.createKubernetesAuthMethod(auth.Kubernetes)
	}

	if auth.Token != nil {
		return r.createTokenAuthMethod(ctx, vaultSecret.Namespace, auth.Token)
	}

	if auth.AppRole != nil {
		return r.createAppRoleAuthMethod(ctx, vaultSecret.Namespace, auth.AppRole)
	}

	return nil, fmt.Errorf("no authentication method configured")
}

// createKubernetesAuthMethod creates a Kubernetes authentication method
func (r *VaultSecretReconciler) createKubernetesAuthMethod(
	k8sAuth *avapigwv1alpha1.KubernetesAuthConfig,
) (vault.AuthMethod, error) {
	mountPath := "kubernetes"
	if k8sAuth.MountPath != nil {
		mountPath = *k8sAuth.MountPath
	}

	if k8sAuth.TokenPath != nil && *k8sAuth.TokenPath != "" {
		return vault.NewKubernetesAuthWithTokenPath(k8sAuth.Role, mountPath, *k8sAuth.TokenPath)
	}
	return vault.NewKubernetesAuth(k8sAuth.Role, mountPath)
}

// createTokenAuthMethod creates a Token authentication method
func (r *VaultSecretReconciler) createTokenAuthMethod(
	ctx context.Context,
	defaultNamespace string,
	tokenAuth *avapigwv1alpha1.TokenAuthConfig,
) (vault.AuthMethod, error) {
	namespace := defaultNamespace
	if tokenAuth.SecretRef.Namespace != nil {
		namespace = *tokenAuth.SecretRef.Namespace
	}

	tokenKey := "token"
	if tokenAuth.TokenKey != nil {
		tokenKey = *tokenAuth.TokenKey
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: tokenAuth.SecretRef.Name}, secret); err != nil {
		return nil, fmt.Errorf("failed to get token secret: %w", err)
	}

	token := string(secret.Data[tokenKey])
	return vault.NewTokenAuth(token)
}

// createAppRoleAuthMethod creates an AppRole authentication method
func (r *VaultSecretReconciler) createAppRoleAuthMethod(
	ctx context.Context,
	defaultNamespace string,
	appRole *avapigwv1alpha1.AppRoleAuthConfig,
) (vault.AuthMethod, error) {
	namespace := defaultNamespace
	if appRole.SecretIDRef.Namespace != nil {
		namespace = *appRole.SecretIDRef.Namespace
	}

	secretIDKey := "secret-id"
	if appRole.SecretIDKey != nil {
		secretIDKey = *appRole.SecretIDKey
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: appRole.SecretIDRef.Name}, secret); err != nil {
		return nil, fmt.Errorf("failed to get AppRole secret: %w", err)
	}

	secretID := string(secret.Data[secretIDKey])

	mountPath := "approle"
	if appRole.MountPath != nil {
		mountPath = *appRole.MountPath
	}

	return vault.NewAppRoleAuth(appRole.RoleID, secretID, mountPath)
}

// getSecretData retrieves data from a Kubernetes secret
func (r *VaultSecretReconciler) getSecretData(
	ctx context.Context,
	defaultNamespace string,
	ref *avapigwv1alpha1.SecretObjectReference,
	key string,
) ([]byte, error) {
	namespace := defaultNamespace
	if ref.Namespace != nil {
		namespace = *ref.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, secret); err != nil {
		return nil, err
	}

	// Try the specified key first, then common alternatives
	keys := []string{key, "ca.crt", "tls.crt", "tls.key", "cert", "key", "certificate"}
	for _, k := range keys {
		if data, ok := secret.Data[k]; ok {
			return data, nil
		}
	}

	return nil, fmt.Errorf("key %s not found in secret %s/%s", key, namespace, ref.Name)
}

// syncSecret syncs the secret from Vault to Kubernetes
func (r *VaultSecretReconciler) syncSecret(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) error {
	logger := log.FromContext(ctx)

	// Determine target secret configuration
	if vaultSecret.Spec.Target == nil {
		logger.Info("No target secret specified, skipping sync")
		return nil
	}

	target := vaultSecret.Spec.Target
	targetNamespace := r.resolveTargetNamespace(vaultSecret.Namespace, target.Namespace)

	// Read secret from Vault
	vaultSecretData, err := r.readVaultSecret(ctx, vaultSecret)
	if err != nil {
		return err
	}

	// Build the target Kubernetes secret
	secret := r.buildTargetSecret(vaultSecret, target, targetNamespace, vaultSecretData, logger)

	// Set owner reference if needed
	if err := r.setOwnerReferenceIfNeeded(vaultSecret, secret, target); err != nil {
		return err
	}

	// Create or update the secret
	if err := r.createOrUpdateSecret(ctx, secret, target, targetNamespace, logger); err != nil {
		return err
	}

	// Update status
	r.updateSyncStatus(vaultSecret, target, targetNamespace, vaultSecretData)

	return nil
}

// resolveTargetNamespace returns the target namespace, defaulting to the VaultSecret's namespace
func (r *VaultSecretReconciler) resolveTargetNamespace(defaultNamespace string, targetNamespace *string) string {
	if targetNamespace != nil {
		return *targetNamespace
	}
	return defaultNamespace
}

// readVaultSecret reads the secret from Vault
func (r *VaultSecretReconciler) readVaultSecret(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
) (*vault.Secret, error) {
	logger := log.FromContext(ctx)

	vaultClient, err := r.getOrCreateVaultClient(ctx, vaultSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get Vault client: %w", err)
	}

	mountPoint := "secret"
	if vaultSecret.Spec.MountPoint != nil {
		mountPoint = *vaultSecret.Spec.MountPoint
	}

	pathBuilder := vault.NewPathBuilder(mountPoint, "", "")
	secretPath := pathBuilder.BuildKV2(vaultSecret.Spec.Path)

	logger.Info("Reading secret from Vault", "path", secretPath)

	vaultSecretData, err := vaultClient.ReadSecret(ctx, secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from Vault: %w", err)
	}

	return vaultSecretData, nil
}

// buildTargetSecret builds the target Kubernetes secret from Vault data
func (r *VaultSecretReconciler) buildTargetSecret(
	vaultSecret *avapigwv1alpha1.VaultSecret,
	target *avapigwv1alpha1.VaultTargetConfig,
	targetNamespace string,
	vaultSecretData *vault.Secret,
	logger logr.Logger,
) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      target.Name,
			Namespace: targetNamespace,
		},
	}

	// Set secret type
	secret.Type = corev1.SecretTypeOpaque
	if target.Type != nil {
		secret.Type = corev1.SecretType(*target.Type)
	}

	// Set labels and annotations
	r.setSecretLabelsAndAnnotations(secret, vaultSecret, target, vaultSecretData)

	// Map Vault data to Kubernetes secret
	secret.Data = r.mapVaultDataToSecret(vaultSecret, vaultSecretData, logger)

	return secret
}

// setSecretLabelsAndAnnotations sets labels and annotations on the target secret
func (r *VaultSecretReconciler) setSecretLabelsAndAnnotations(
	secret *corev1.Secret,
	vaultSecret *avapigwv1alpha1.VaultSecret,
	target *avapigwv1alpha1.VaultTargetConfig,
	vaultSecretData *vault.Secret,
) {
	// Set labels
	if target.Labels != nil {
		secret.Labels = target.Labels
	}
	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}
	secret.Labels["app.kubernetes.io/managed-by"] = "avapigw"
	secret.Labels["avapigw.vyrodovalexey.github.com/vaultsecret"] = vaultSecret.Name

	// Set annotations
	if target.Annotations != nil {
		secret.Annotations = target.Annotations
	}
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}

	// Add Vault metadata to annotations
	if vaultSecretData.Metadata != nil {
		versionStr := strconv.Itoa(vaultSecretData.Metadata.Version)
		secret.Annotations["avapigw.vyrodovalexey.github.com/vault-version"] = versionStr
		createdTime := vaultSecretData.Metadata.CreatedTime.Format(time.RFC3339)
		secret.Annotations["avapigw.vyrodovalexey.github.com/vault-created-time"] = createdTime
	}
}

// mapVaultDataToSecret maps Vault secret data to Kubernetes secret data
func (r *VaultSecretReconciler) mapVaultDataToSecret(
	vaultSecret *avapigwv1alpha1.VaultSecret,
	vaultSecretData *vault.Secret,
	logger logr.Logger,
) map[string][]byte {
	data := make(map[string][]byte)

	if len(vaultSecret.Spec.Keys) > 0 {
		// Use explicit key mappings
		for _, keyMapping := range vaultSecret.Spec.Keys {
			value, ok := vaultSecretData.GetString(keyMapping.VaultKey)
			if !ok {
				logger.Info("Key not found in Vault secret", "key", keyMapping.VaultKey)
				continue
			}

			valueBytes := []byte(value)
			if keyMapping.Encoding != nil && *keyMapping.Encoding == avapigwv1alpha1.VaultValueEncodingBase64 {
				valueBytes = []byte(base64.StdEncoding.EncodeToString(valueBytes))
			}

			data[keyMapping.TargetKey] = valueBytes
		}
	} else {
		// Copy all keys from Vault secret
		for key, value := range vaultSecretData.Data {
			if strValue, ok := value.(string); ok {
				data[key] = []byte(strValue)
			}
		}
	}

	return data
}

// setOwnerReferenceIfNeeded sets the owner reference on the secret if the creation policy is Owner
func (r *VaultSecretReconciler) setOwnerReferenceIfNeeded(
	vaultSecret *avapigwv1alpha1.VaultSecret,
	secret *corev1.Secret,
	target *avapigwv1alpha1.VaultTargetConfig,
) error {
	creationPolicy := avapigwv1alpha1.SecretCreationPolicyOwner
	if target.CreationPolicy != nil {
		creationPolicy = *target.CreationPolicy
	}

	if creationPolicy == avapigwv1alpha1.SecretCreationPolicyOwner {
		if err := controllerutil.SetControllerReference(vaultSecret, secret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set owner reference: %w", err)
		}
	}

	return nil
}

// createOrUpdateSecret creates or updates the target secret in Kubernetes
func (r *VaultSecretReconciler) createOrUpdateSecret(
	ctx context.Context,
	secret *corev1.Secret,
	target *avapigwv1alpha1.VaultTargetConfig,
	targetNamespace string,
	logger logr.Logger,
) error {
	existingSecret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: targetNamespace, Name: target.Name}, existingSecret)
	secretExists := err == nil

	if secretExists {
		return r.updateExistingSecret(ctx, secret, existingSecret, target, targetNamespace, logger)
	}

	if err := r.Create(ctx, secret); err != nil {
		return fmt.Errorf("failed to create target secret: %w", err)
	}
	logger.Info("Created target secret", "secret", target.Name, "namespace", targetNamespace)
	return nil
}

// updateExistingSecret updates an existing secret, optionally merging data
func (r *VaultSecretReconciler) updateExistingSecret(
	ctx context.Context,
	secret *corev1.Secret,
	existingSecret *corev1.Secret,
	target *avapigwv1alpha1.VaultTargetConfig,
	targetNamespace string,
	logger logr.Logger,
) error {
	creationPolicy := avapigwv1alpha1.SecretCreationPolicyOwner
	if target.CreationPolicy != nil {
		creationPolicy = *target.CreationPolicy
	}

	if creationPolicy == avapigwv1alpha1.SecretCreationPolicyMerge {
		for k, v := range existingSecret.Data {
			if _, exists := secret.Data[k]; !exists {
				secret.Data[k] = v
			}
		}
	}

	secret.ResourceVersion = existingSecret.ResourceVersion
	if err := r.Update(ctx, secret); err != nil {
		return fmt.Errorf("failed to update target secret: %w", err)
	}
	logger.Info("Updated target secret", "secret", target.Name, "namespace", targetNamespace)
	return nil
}

// updateSyncStatus updates the VaultSecret status after a successful sync
func (r *VaultSecretReconciler) updateSyncStatus(
	vaultSecret *avapigwv1alpha1.VaultSecret,
	target *avapigwv1alpha1.VaultTargetConfig,
	targetNamespace string,
	vaultSecretData *vault.Secret,
) {
	vaultSecret.Status.TargetSecretName = &target.Name
	vaultSecret.Status.TargetSecretNamespace = &targetNamespace

	if vaultSecretData.Metadata != nil {
		version := strconv.Itoa(vaultSecretData.Metadata.Version)
		vaultSecret.Status.SecretVersion = &version
	}
}

// deleteTargetSecret deletes the target secret
func (r *VaultSecretReconciler) deleteTargetSecret(
	ctx context.Context,
	vaultSecret *avapigwv1alpha1.VaultSecret,
) error {
	if vaultSecret.Spec.Target == nil {
		return nil
	}

	target := vaultSecret.Spec.Target
	targetNamespace := vaultSecret.Namespace
	if target.Namespace != nil {
		targetNamespace = *target.Namespace
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      target.Name,
			Namespace: targetNamespace,
		},
	}

	if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete target secret: %w", err)
	}

	return nil
}

// calculateNextRefresh calculates the next refresh time with jitter
func (r *VaultSecretReconciler) calculateNextRefresh(vaultSecret *avapigwv1alpha1.VaultSecret) time.Duration {
	// Default refresh interval
	interval := 5 * time.Minute

	if vaultSecret.Spec.Refresh == nil {
		return interval
	}

	return r.calculateRefreshInterval(vaultSecret.Spec.Refresh, interval)
}

// calculateRefreshInterval calculates the refresh interval based on refresh configuration
func (r *VaultSecretReconciler) calculateRefreshInterval(
	refresh *avapigwv1alpha1.VaultRefreshConfig,
	defaultInterval time.Duration,
) time.Duration {
	// Check if refresh is enabled
	if refresh.Enabled != nil && !*refresh.Enabled {
		// Refresh disabled, use a long interval
		return 24 * time.Hour
	}

	interval := defaultInterval

	// Parse interval
	if refresh.Interval != nil {
		if parsed, err := time.ParseDuration(string(*refresh.Interval)); err == nil {
			interval = parsed
		}
	}

	// Apply jitter
	return r.applyJitter(interval, refresh.JitterPercent)
}

// applyJitter applies jitter to the given interval
func (r *VaultSecretReconciler) applyJitter(
	interval time.Duration,
	jitterPercentPtr *int32,
) time.Duration {
	jitterPercent := int32(10)
	if jitterPercentPtr != nil {
		jitterPercent = *jitterPercentPtr
	}

	if jitterPercent <= 0 {
		return interval
	}

	jitter := float64(interval) * float64(jitterPercent) / 100.0
	// Add random jitter between -jitter/2 and +jitter/2
	// Use thread-safe seeded random generator
	jitterMu.Lock()
	jitterValue := jitterRand.Float64()*jitter - jitter/2
	jitterMu.Unlock()

	return interval + time.Duration(jitterValue)
}

// setCondition sets a condition on the VaultSecret status
//
//nolint:unparam // conditionType kept for API consistency with other controllers
func (r *VaultSecretReconciler) setCondition(
	vaultSecret *avapigwv1alpha1.VaultSecret,
	conditionType avapigwv1alpha1.ConditionType,
	status metav1.ConditionStatus,
	reason, message string,
) {
	vaultSecret.Status.SetCondition(conditionType, status, reason, message)
}

// updateStatus updates the VaultSecret status
func (r *VaultSecretReconciler) updateStatus(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) error {
	return r.Status().Update(ctx, vaultSecret)
}

// SetupWithManager sets up the controller with the Manager
func (r *VaultSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&avapigwv1alpha1.VaultSecret{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findVaultSecretsForSecret),
		).
		Complete(r)
}

// findVaultSecretsForSecret finds VaultSecrets that reference a Secret
func (r *VaultSecretReconciler) findVaultSecretsForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	secret := obj.(*corev1.Secret)
	var requests []reconcile.Request

	var vaultSecrets avapigwv1alpha1.VaultSecretList
	if err := r.List(ctx, &vaultSecrets); err != nil {
		return requests
	}

	for _, vs := range vaultSecrets.Items {
		if r.vaultSecretReferencesSecret(&vs, secret.Namespace, secret.Name) {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKey{
					Namespace: vs.Namespace,
					Name:      vs.Name,
				},
			})
		}
	}

	return requests
}

// vaultSecretReferencesSecret checks if a VaultSecret references a specific secret.
// It checks all secret references in the VaultSecret spec including auth and TLS secrets.
func (r *VaultSecretReconciler) vaultSecretReferencesSecret(
	vs *avapigwv1alpha1.VaultSecret,
	secretNamespace, secretName string,
) bool {
	conn := vs.Spec.VaultConnection

	// Check auth-related secret references
	if r.authReferencesSecret(vs.Namespace, &conn.Auth, secretNamespace, secretName) {
		return true
	}

	// Check TLS-related secret references
	if r.tlsReferencesSecret(vs.Namespace, conn.TLS, secretNamespace, secretName) {
		return true
	}

	return false
}

// authReferencesSecret checks if any auth configuration references the specified secret.
func (r *VaultSecretReconciler) authReferencesSecret(
	defaultNamespace string,
	auth *avapigwv1alpha1.VaultAuthConfig,
	secretNamespace, secretName string,
) bool {
	// Check Token auth secret
	if auth.Token != nil {
		if secretRefMatches(defaultNamespace, &auth.Token.SecretRef, secretNamespace, secretName) {
			return true
		}
	}

	// Check AppRole secret
	if auth.AppRole != nil {
		if secretRefMatches(defaultNamespace, &auth.AppRole.SecretIDRef, secretNamespace, secretName) {
			return true
		}
	}

	return false
}

// tlsReferencesSecret checks if any TLS configuration references the specified secret.
func (r *VaultSecretReconciler) tlsReferencesSecret(
	defaultNamespace string,
	tls *avapigwv1alpha1.VaultTLSConfig,
	secretNamespace, secretName string,
) bool {
	if tls == nil {
		return false
	}

	// Check CA cert reference
	if tls.CACertRef != nil && secretRefMatches(defaultNamespace, tls.CACertRef, secretNamespace, secretName) {
		return true
	}

	// Check client cert reference
	if tls.ClientCertRef != nil && secretRefMatches(defaultNamespace, tls.ClientCertRef, secretNamespace, secretName) {
		return true
	}

	// Check client key reference
	if tls.ClientKeyRef != nil && secretRefMatches(defaultNamespace, tls.ClientKeyRef, secretNamespace, secretName) {
		return true
	}

	return false
}

// secretRefMatches checks if a secret reference matches the specified namespace and name.
func secretRefMatches(
	defaultNamespace string,
	ref *avapigwv1alpha1.SecretObjectReference,
	secretNamespace, secretName string,
) bool {
	ns := defaultNamespace
	if ref.Namespace != nil {
		ns = *ref.Namespace
	}
	return ns == secretNamespace && ref.Name == secretName
}
