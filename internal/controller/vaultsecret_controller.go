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
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// vaultSecretReconcileTimeout is the maximum duration for a single VaultSecret reconciliation
// Longer timeout for Vault operations which may involve network calls
const vaultSecretReconcileTimeout = 60 * time.Second

// Prometheus metrics for VaultSecret controller
var (
	vaultSecretReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "vaultsecret_reconcile_duration_seconds",
			Help:      "Duration of VaultSecret reconciliation in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"result"},
	)

	vaultSecretReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "controller",
			Name:      "vaultsecret_reconcile_total",
			Help:      "Total number of VaultSecret reconciliations",
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(vaultSecretReconcileDuration, vaultSecretReconcileTotal)
}

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

const (
	vaultSecretFinalizer = "avapigw.vyrodovalexey.github.com/vaultsecret-finalizer"
)

// VaultSecretReconciler reconciles a VaultSecret object
type VaultSecretReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	RequeueStrategy     *RequeueStrategy
	requeueStrategyOnce sync.Once // Ensures thread-safe initialization of RequeueStrategy
	vaultClients        sync.Map  // map[string]*vault.Client - keyed by Vault address (legacy, for backward compatibility)

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

// +kubebuilder:rbac:groups=avapigw.vyrodovalexey.github.com,resources=vaultsecrets,verbs=get;list;watch;create;update;patch;delete
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
	// Add timeout to prevent hanging reconciliations (longer for Vault operations)
	ctx, cancel := context.WithTimeout(ctx, vaultSecretReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := req.NamespacedName.String()

	// Check if Vault is enabled - skip reconciliation gracefully if not
	if !r.VaultEnabled && r.SecretsProviderType != "vault" {
		logger.Info("Vault is disabled, skipping VaultSecret reconciliation",
			"name", req.Name,
			"namespace", req.Namespace,
			"secretsProvider", r.SecretsProviderType,
		)
		// Still fetch the resource to update its status
		vaultSecret := &avapigwv1alpha1.VaultSecret{}
		if err := r.Get(ctx, req.NamespacedName, vaultSecret); err != nil {
			if errors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		// Update status to indicate Vault is disabled
		r.setCondition(vaultSecret, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			"VaultDisabled", "Vault integration is disabled. Set --vault-enabled=true or --secrets-provider=vault to enable.")
		vaultSecret.Status.Phase = avapigwv1alpha1.PhaseStatusPending
		if err := r.updateStatus(ctx, vaultSecret); err != nil {
			logger.Error(err, "Failed to update VaultSecret status")
		}
		r.Recorder.Event(vaultSecret, corev1.EventTypeWarning, "VaultDisabled",
			"Vault integration is disabled. VaultSecret will not be reconciled.")
		// Requeue after a long interval to check if Vault becomes enabled
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}

	// Track reconciliation metrics
	start := time.Now()
	var reconcileErr *ReconcileError
	defer func() {
		duration := time.Since(start).Seconds()
		result := "success"
		if reconcileErr != nil {
			result = "error"
		}
		vaultSecretReconcileDuration.WithLabelValues(result).Observe(duration)
		vaultSecretReconcileTotal.WithLabelValues(result).Inc()
	}()

	logger.Info("Reconciling VaultSecret",
		"name", req.Name,
		"namespace", req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the VaultSecret instance
	vaultSecret := &avapigwv1alpha1.VaultSecret{}
	if err := r.Get(ctx, req.NamespacedName, vaultSecret); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("VaultSecret not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return ctrl.Result{}, nil
		}
		reconcileErr = ClassifyError("getVaultSecret", resourceKey, err)
		logger.Error(reconcileErr, "Failed to get VaultSecret",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)
		return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
	}

	// Handle deletion
	if !vaultSecret.DeletionTimestamp.IsZero() {
		result, err := r.handleDeletion(ctx, vaultSecret)
		if err == nil {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(vaultSecret, vaultSecretFinalizer) {
		controllerutil.AddFinalizer(vaultSecret, vaultSecretFinalizer)
		if err := r.Update(ctx, vaultSecret); err != nil {
			reconcileErr = ClassifyError("addFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to add finalizer",
				"errorType", reconcileErr.Type,
			)
			r.Recorder.Event(vaultSecret, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
		return strategy.ForImmediateRequeue(), nil
	}

	// Reconcile the VaultSecret
	if err := r.reconcileVaultSecret(ctx, vaultSecret); err != nil {
		reconcileErr = ClassifyError("reconcileVaultSecret", resourceKey, err)
		logger.Error(reconcileErr, "Failed to reconcile VaultSecret",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
			"userActionRequired", reconcileErr.UserActionRequired,
		)
		r.Recorder.Event(vaultSecret, corev1.EventTypeWarning, string(reconcileErr.Type)+"Error", err.Error())

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

	// Success - reset failure count and use custom refresh interval
	strategy.ResetFailureCount(resourceKey)
	requeueAfter := r.calculateNextRefresh(vaultSecret)
	logger.Info("VaultSecret reconciled successfully",
		"name", req.Name,
		"namespace", req.Namespace,
		"nextRefresh", requeueAfter,
	)
	return strategy.ForCustomInterval(requeueAfter), nil
}

// handleDeletion handles VaultSecret deletion
func (r *VaultSecretReconciler) handleDeletion(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	strategy := r.getRequeueStrategy()
	resourceKey := client.ObjectKeyFromObject(vaultSecret).String()

	if controllerutil.ContainsFinalizer(vaultSecret, vaultSecretFinalizer) {
		// Perform cleanup - delete target secret if deletion policy is Delete
		if vaultSecret.Spec.Target != nil {
			deletionPolicy := avapigwv1alpha1.SecretDeletionPolicyDelete
			if vaultSecret.Spec.Target.DeletionPolicy != nil {
				deletionPolicy = *vaultSecret.Spec.Target.DeletionPolicy
			}

			if deletionPolicy == avapigwv1alpha1.SecretDeletionPolicyDelete {
				if err := r.deleteTargetSecret(ctx, vaultSecret); err != nil {
					reconcileErr := ClassifyError("deleteTargetSecret", resourceKey, err)
					logger.Error(reconcileErr, "Failed to delete target secret",
						"errorType", reconcileErr.Type,
					)
					// Continue with finalizer removal even if deletion fails
				}
			}
		}

		// Clean up cached Vault client to prevent memory leak
		r.cleanupVaultClient(vaultSecret)

		logger.Info("Performing cleanup for VaultSecret deletion",
			"name", vaultSecret.Name,
			"namespace", vaultSecret.Namespace,
		)

		// Record event
		r.Recorder.Event(vaultSecret, corev1.EventTypeNormal, "Deleting", "VaultSecret is being deleted")

		// Remove finalizer
		controllerutil.RemoveFinalizer(vaultSecret, vaultSecretFinalizer)
		if err := r.Update(ctx, vaultSecret); err != nil {
			reconcileErr := ClassifyError("removeFinalizer", resourceKey, err)
			logger.Error(reconcileErr, "Failed to remove finalizer",
				"errorType", reconcileErr.Type,
			)
			return strategy.ForTransientErrorWithBackoff(resourceKey), reconcileErr
		}
	}

	return ctrl.Result{}, nil
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
func (r *VaultSecretReconciler) handleVaultAddressChange(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) {
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
func (r *VaultSecretReconciler) reconcileVaultSecret(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) error {
	logger := log.FromContext(ctx)
	resourceKey := client.ObjectKeyFromObject(vaultSecret).String()

	// Update status to reconciling
	vaultSecret.Status.Phase = avapigwv1alpha1.PhaseStatusReconciling
	vaultSecret.Status.ObservedGeneration = vaultSecret.Generation
	vaultSecret.Status.LastReconciledTime = &metav1.Time{Time: time.Now()}

	// Check for Vault address changes and clean up old clients if needed
	r.handleVaultAddressChange(ctx, vaultSecret)

	// Validate Vault connection configuration
	if err := r.validateVaultConnection(ctx, vaultSecret); err != nil {
		// Determine error type based on the validation failure
		var reconcileErr *ReconcileError
		if errors.IsNotFound(err) {
			reconcileErr = NewDependencyError("validateVaultConnection", resourceKey, err)
		} else {
			reconcileErr = NewValidationError("validateVaultConnection", resourceKey, err)
		}

		logger.Error(reconcileErr, "Failed to validate Vault connection",
			"errorType", reconcileErr.Type,
		)

		r.setCondition(vaultSecret, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonNotReady), err.Error())
		vaultSecret.Status.Phase = avapigwv1alpha1.PhaseStatusError
		errMsg := err.Error()
		vaultSecret.Status.LastVaultError = &errMsg

		// Update status even on error
		if statusErr := r.updateStatus(ctx, vaultSecret); statusErr != nil {
			logger.Error(statusErr, "Failed to update status after validation error")
		}
		return reconcileErr
	}

	// Sync secret from Vault
	if err := r.syncSecret(ctx, vaultSecret); err != nil {
		// Classify the sync error - could be transient (network) or permanent (auth)
		reconcileErr := ClassifyError("syncSecret", resourceKey, err)
		logger.Error(reconcileErr, "Failed to sync secret from Vault",
			"errorType", reconcileErr.Type,
			"retryable", reconcileErr.Retryable,
		)

		r.setCondition(vaultSecret, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			string(avapigwv1alpha1.ReasonError), err.Error())
		vaultSecret.Status.Phase = avapigwv1alpha1.PhaseStatusError
		errMsg := err.Error()
		vaultSecret.Status.LastVaultError = &errMsg

		// Update status even on error
		if statusErr := r.updateStatus(ctx, vaultSecret); statusErr != nil {
			logger.Error(statusErr, "Failed to update status after sync error")
		}
		return reconcileErr
	}

	// Clear any previous error
	vaultSecret.Status.LastVaultError = nil

	// Update refresh times
	now := metav1.Now()
	vaultSecret.Status.LastRefreshTime = &now
	nextRefresh := metav1.NewTime(now.Add(r.calculateNextRefresh(vaultSecret)))
	vaultSecret.Status.NextRefreshTime = &nextRefresh

	// Set conditions
	r.setCondition(vaultSecret, avapigwv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		string(avapigwv1alpha1.ReasonReady), "Secret synced from Vault")

	vaultSecret.Status.Phase = avapigwv1alpha1.PhaseStatusReady

	// Update status
	if err := r.updateStatus(ctx, vaultSecret); err != nil {
		reconcileErr := ClassifyError("updateStatus", resourceKey, err)
		logger.Error(reconcileErr, "Failed to update VaultSecret status",
			"errorType", reconcileErr.Type,
		)
		return reconcileErr
	}

	r.Recorder.Event(vaultSecret, corev1.EventTypeNormal, "Synced", "Secret synced from Vault successfully")
	return nil
}

// validateVaultConnection validates the Vault connection configuration
func (r *VaultSecretReconciler) validateVaultConnection(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) error {
	conn := vaultSecret.Spec.VaultConnection

	// Validate address
	if conn.Address == "" {
		return fmt.Errorf("Vault address is required")
	}

	// Validate authentication configuration
	auth := conn.Auth
	if auth.Kubernetes == nil && auth.Token == nil && auth.AppRole == nil {
		return fmt.Errorf("at least one authentication method must be configured")
	}

	// Validate Kubernetes auth
	if auth.Kubernetes != nil {
		if auth.Kubernetes.Role == "" {
			return fmt.Errorf("Kubernetes auth role is required")
		}
	}

	// Validate Token auth
	if auth.Token != nil {
		namespace := vaultSecret.Namespace
		if auth.Token.SecretRef.Namespace != nil {
			namespace = *auth.Token.SecretRef.Namespace
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: auth.Token.SecretRef.Name}, secret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("token secret %s/%s not found", namespace, auth.Token.SecretRef.Name)
			}
			return fmt.Errorf("failed to get token secret %s/%s: %w", namespace, auth.Token.SecretRef.Name, err)
		}

		tokenKey := "token"
		if auth.Token.TokenKey != nil {
			tokenKey = *auth.Token.TokenKey
		}
		if _, ok := secret.Data[tokenKey]; !ok {
			return fmt.Errorf("token key %s not found in secret %s/%s", tokenKey, namespace, auth.Token.SecretRef.Name)
		}
	}

	// Validate AppRole auth
	if auth.AppRole != nil {
		if auth.AppRole.RoleID == "" {
			return fmt.Errorf("AppRole role ID is required")
		}

		namespace := vaultSecret.Namespace
		if auth.AppRole.SecretIDRef.Namespace != nil {
			namespace = *auth.AppRole.SecretIDRef.Namespace
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: auth.AppRole.SecretIDRef.Name}, secret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("AppRole secret ID secret %s/%s not found", namespace, auth.AppRole.SecretIDRef.Name)
			}
			return fmt.Errorf("failed to get AppRole secret ID secret %s/%s: %w", namespace, auth.AppRole.SecretIDRef.Name, err)
		}

		secretIDKey := "secret-id"
		if auth.AppRole.SecretIDKey != nil {
			secretIDKey = *auth.AppRole.SecretIDKey
		}
		if _, ok := secret.Data[secretIDKey]; !ok {
			return fmt.Errorf("secret ID key %s not found in secret %s/%s", secretIDKey, namespace, auth.AppRole.SecretIDRef.Name)
		}
	}

	// Validate TLS configuration
	if conn.TLS != nil {
		if conn.TLS.CACertRef != nil {
			namespace := vaultSecret.Namespace
			if conn.TLS.CACertRef.Namespace != nil {
				namespace = *conn.TLS.CACertRef.Namespace
			}

			secret := &corev1.Secret{}
			if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: conn.TLS.CACertRef.Name}, secret); err != nil {
				if errors.IsNotFound(err) {
					return fmt.Errorf("TLS CA cert secret %s/%s not found", namespace, conn.TLS.CACertRef.Name)
				}
				return fmt.Errorf("failed to get TLS CA cert secret %s/%s: %w", namespace, conn.TLS.CACertRef.Name, err)
			}
		}
	}

	return nil
}

// getOrCreateVaultClient gets or creates a Vault client for the given VaultSecret
// Uses the bounded LRU cache if available, otherwise falls back to sync.Map.
// Uses LoadOrStore pattern to prevent race conditions between checking and creating clients.
func (r *VaultSecretReconciler) getOrCreateVaultClient(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) (*vault.Client, error) {
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
func (r *VaultSecretReconciler) getOrCreateVaultClientWithCache(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret, clientKey string) (*vault.Client, error) {
	conn := vaultSecret.Spec.VaultConnection

	// Use GetOrCreate to atomically get or create the client
	return r.vaultClientCache.GetOrCreate(clientKey, conn.Address, func() (*vault.Client, error) {
		return r.createVaultClient(ctx, vaultSecret)
	})
}

// getOrCreateVaultClientLegacy uses the legacy sync.Map for backward compatibility.
func (r *VaultSecretReconciler) getOrCreateVaultClientLegacy(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret, clientKey string) (*vault.Client, error) {
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
func (r *VaultSecretReconciler) createVaultClient(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) (*vault.Client, error) {
	conn := vaultSecret.Spec.VaultConnection

	// Build TLS config if needed
	var tlsConfig *vault.TLSConfig
	if conn.TLS != nil {
		tlsConfig = &vault.TLSConfig{}

		if conn.TLS.InsecureSkipVerify != nil {
			tlsConfig.InsecureSkipVerify = *conn.TLS.InsecureSkipVerify
		}

		if conn.TLS.ServerName != nil {
			tlsConfig.ServerName = *conn.TLS.ServerName
		}

		// Load CA cert if specified
		if conn.TLS.CACertRef != nil {
			caCert, err := r.getSecretData(ctx, vaultSecret.Namespace, conn.TLS.CACertRef, "ca.crt")
			if err != nil {
				return nil, fmt.Errorf("failed to get CA cert: %w", err)
			}
			tlsConfig.CACert = caCert
		}

		// Load client cert if specified
		if conn.TLS.ClientCertRef != nil {
			clientCert, err := r.getSecretData(ctx, vaultSecret.Namespace, conn.TLS.ClientCertRef, "tls.crt")
			if err != nil {
				return nil, fmt.Errorf("failed to get client cert: %w", err)
			}
			tlsConfig.ClientCert = clientCert
		}

		// Load client key if specified
		if conn.TLS.ClientKeyRef != nil {
			clientKeyData, err := r.getSecretData(ctx, vaultSecret.Namespace, conn.TLS.ClientKeyRef, "tls.key")
			if err != nil {
				return nil, fmt.Errorf("failed to get client key: %w", err)
			}
			tlsConfig.ClientKey = clientKeyData
		}
	}

	// Create Vault client config
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

// createAuthMethod creates the appropriate authentication method
func (r *VaultSecretReconciler) createAuthMethod(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) (vault.AuthMethod, error) {
	auth := vaultSecret.Spec.VaultConnection.Auth

	// Kubernetes auth
	if auth.Kubernetes != nil {
		mountPath := "kubernetes"
		if auth.Kubernetes.MountPath != nil {
			mountPath = *auth.Kubernetes.MountPath
		}

		tokenPath := ""
		if auth.Kubernetes.TokenPath != nil {
			tokenPath = *auth.Kubernetes.TokenPath
		}

		if tokenPath != "" {
			return vault.NewKubernetesAuthWithTokenPath(auth.Kubernetes.Role, mountPath, tokenPath)
		}
		return vault.NewKubernetesAuth(auth.Kubernetes.Role, mountPath)
	}

	// Token auth
	if auth.Token != nil {
		namespace := vaultSecret.Namespace
		if auth.Token.SecretRef.Namespace != nil {
			namespace = *auth.Token.SecretRef.Namespace
		}

		tokenKey := "token"
		if auth.Token.TokenKey != nil {
			tokenKey = *auth.Token.TokenKey
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: auth.Token.SecretRef.Name}, secret); err != nil {
			return nil, fmt.Errorf("failed to get token secret: %w", err)
		}

		token := string(secret.Data[tokenKey])
		return vault.NewTokenAuth(token)
	}

	// AppRole auth
	if auth.AppRole != nil {
		namespace := vaultSecret.Namespace
		if auth.AppRole.SecretIDRef.Namespace != nil {
			namespace = *auth.AppRole.SecretIDRef.Namespace
		}

		secretIDKey := "secret-id"
		if auth.AppRole.SecretIDKey != nil {
			secretIDKey = *auth.AppRole.SecretIDKey
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: auth.AppRole.SecretIDRef.Name}, secret); err != nil {
			return nil, fmt.Errorf("failed to get AppRole secret: %w", err)
		}

		secretID := string(secret.Data[secretIDKey])

		mountPath := "approle"
		if auth.AppRole.MountPath != nil {
			mountPath = *auth.AppRole.MountPath
		}

		return vault.NewAppRoleAuth(auth.AppRole.RoleID, secretID, mountPath)
	}

	return nil, fmt.Errorf("no authentication method configured")
}

// getSecretData retrieves data from a Kubernetes secret
func (r *VaultSecretReconciler) getSecretData(ctx context.Context, defaultNamespace string, ref *avapigwv1alpha1.SecretObjectReference, key string) ([]byte, error) {
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
		// No target specified, nothing to sync
		logger.Info("No target secret specified, skipping sync")
		return nil
	}

	target := vaultSecret.Spec.Target
	targetNamespace := vaultSecret.Namespace
	if target.Namespace != nil {
		targetNamespace = *target.Namespace
	}

	// Get or create Vault client
	vaultClient, err := r.getOrCreateVaultClient(ctx, vaultSecret)
	if err != nil {
		return fmt.Errorf("failed to get Vault client: %w", err)
	}

	// Build the secret path
	mountPoint := "secret"
	if vaultSecret.Spec.MountPoint != nil {
		mountPoint = *vaultSecret.Spec.MountPoint
	}

	// Build path for KV v2
	pathBuilder := vault.NewPathBuilder(mountPoint, "", "")
	secretPath := pathBuilder.BuildKV2(vaultSecret.Spec.Path)

	logger.Info("Reading secret from Vault", "path", secretPath)

	// Read secret from Vault
	vaultSecretData, err := vaultClient.ReadSecret(ctx, secretPath)
	if err != nil {
		return fmt.Errorf("failed to read secret from Vault: %w", err)
	}

	// Create the target Kubernetes secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      target.Name,
			Namespace: targetNamespace,
		},
	}

	// Check if secret exists
	existingSecret := &corev1.Secret{}
	err = r.Get(ctx, client.ObjectKey{Namespace: targetNamespace, Name: target.Name}, existingSecret)
	secretExists := err == nil

	// Set secret type
	secretType := corev1.SecretTypeOpaque
	if target.Type != nil {
		secretType = corev1.SecretType(*target.Type)
	}
	secret.Type = secretType

	// Set labels and annotations
	if target.Labels != nil {
		secret.Labels = target.Labels
	}
	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}
	secret.Labels["app.kubernetes.io/managed-by"] = "avapigw"
	secret.Labels["avapigw.vyrodovalexey.github.com/vaultsecret"] = vaultSecret.Name

	if target.Annotations != nil {
		secret.Annotations = target.Annotations
	}
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}

	// Add Vault metadata to annotations
	if vaultSecretData.Metadata != nil {
		secret.Annotations["avapigw.vyrodovalexey.github.com/vault-version"] = strconv.Itoa(vaultSecretData.Metadata.Version)
		secret.Annotations["avapigw.vyrodovalexey.github.com/vault-created-time"] = vaultSecretData.Metadata.CreatedTime.Format(time.RFC3339)
	}

	// Map Vault data to Kubernetes secret
	secret.Data = make(map[string][]byte)

	if len(vaultSecret.Spec.Keys) > 0 {
		// Use explicit key mappings
		for _, keyMapping := range vaultSecret.Spec.Keys {
			value, ok := vaultSecretData.GetString(keyMapping.VaultKey)
			if !ok {
				logger.Info("Key not found in Vault secret", "key", keyMapping.VaultKey)
				continue
			}

			valueBytes := []byte(value)

			// Apply encoding if specified
			if keyMapping.Encoding != nil && *keyMapping.Encoding == avapigwv1alpha1.VaultValueEncodingBase64 {
				valueBytes = []byte(base64.StdEncoding.EncodeToString(valueBytes))
			}

			secret.Data[keyMapping.TargetKey] = valueBytes
		}
	} else {
		// Copy all keys from Vault secret
		for key, value := range vaultSecretData.Data {
			if strValue, ok := value.(string); ok {
				secret.Data[key] = []byte(strValue)
			}
		}
	}

	// Set owner reference if creation policy is Owner
	creationPolicy := avapigwv1alpha1.SecretCreationPolicyOwner
	if target.CreationPolicy != nil {
		creationPolicy = *target.CreationPolicy
	}

	if creationPolicy == avapigwv1alpha1.SecretCreationPolicyOwner {
		if err := controllerutil.SetControllerReference(vaultSecret, secret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set owner reference: %w", err)
		}
	}

	// Create or update the secret
	if secretExists {
		if creationPolicy == avapigwv1alpha1.SecretCreationPolicyMerge {
			// Merge with existing data
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
	} else {
		if err := r.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create target secret: %w", err)
		}
		logger.Info("Created target secret", "secret", target.Name, "namespace", targetNamespace)
	}

	// Update status with target secret info
	vaultSecret.Status.TargetSecretName = &target.Name
	vaultSecret.Status.TargetSecretNamespace = &targetNamespace

	// Update secret version in status
	if vaultSecretData.Metadata != nil {
		version := strconv.Itoa(vaultSecretData.Metadata.Version)
		vaultSecret.Status.SecretVersion = &version
	}

	return nil
}

// deleteTargetSecret deletes the target secret
func (r *VaultSecretReconciler) deleteTargetSecret(ctx context.Context, vaultSecret *avapigwv1alpha1.VaultSecret) error {
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

	if vaultSecret.Spec.Refresh != nil {
		// Check if refresh is enabled
		if vaultSecret.Spec.Refresh.Enabled != nil && !*vaultSecret.Spec.Refresh.Enabled {
			// Refresh disabled, use a long interval
			return 24 * time.Hour
		}

		// Parse interval
		if vaultSecret.Spec.Refresh.Interval != nil {
			if parsed, err := time.ParseDuration(string(*vaultSecret.Spec.Refresh.Interval)); err == nil {
				interval = parsed
			}
		}

		// Apply jitter
		jitterPercent := int32(10)
		if vaultSecret.Spec.Refresh.JitterPercent != nil {
			jitterPercent = *vaultSecret.Spec.Refresh.JitterPercent
		}

		if jitterPercent > 0 {
			jitter := float64(interval) * float64(jitterPercent) / 100.0
			// Add random jitter between -jitter/2 and +jitter/2
			// Use thread-safe seeded random generator
			jitterMu.Lock()
			jitterValue := jitterRand.Float64()*jitter - jitter/2
			jitterMu.Unlock()
			interval += time.Duration(jitterValue)
		}
	}

	return interval
}

// setCondition sets a condition on the VaultSecret status
func (r *VaultSecretReconciler) setCondition(vaultSecret *avapigwv1alpha1.VaultSecret, conditionType avapigwv1alpha1.ConditionType, status metav1.ConditionStatus, reason, message string) {
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

// vaultSecretReferencesSecret checks if a VaultSecret references a specific secret
func (r *VaultSecretReconciler) vaultSecretReferencesSecret(vs *avapigwv1alpha1.VaultSecret, secretNamespace, secretName string) bool {
	conn := vs.Spec.VaultConnection

	// Check Token auth secret
	if conn.Auth.Token != nil {
		ns := vs.Namespace
		if conn.Auth.Token.SecretRef.Namespace != nil {
			ns = *conn.Auth.Token.SecretRef.Namespace
		}
		if ns == secretNamespace && conn.Auth.Token.SecretRef.Name == secretName {
			return true
		}
	}

	// Check AppRole secret
	if conn.Auth.AppRole != nil {
		ns := vs.Namespace
		if conn.Auth.AppRole.SecretIDRef.Namespace != nil {
			ns = *conn.Auth.AppRole.SecretIDRef.Namespace
		}
		if ns == secretNamespace && conn.Auth.AppRole.SecretIDRef.Name == secretName {
			return true
		}
	}

	// Check TLS secrets
	if conn.TLS != nil {
		if conn.TLS.CACertRef != nil {
			ns := vs.Namespace
			if conn.TLS.CACertRef.Namespace != nil {
				ns = *conn.TLS.CACertRef.Namespace
			}
			if ns == secretNamespace && conn.TLS.CACertRef.Name == secretName {
				return true
			}
		}
		if conn.TLS.ClientCertRef != nil {
			ns := vs.Namespace
			if conn.TLS.ClientCertRef.Namespace != nil {
				ns = *conn.TLS.ClientCertRef.Namespace
			}
			if ns == secretNamespace && conn.TLS.ClientCertRef.Name == secretName {
				return true
			}
		}
		if conn.TLS.ClientKeyRef != nil {
			ns := vs.Namespace
			if conn.TLS.ClientKeyRef.Namespace != nil {
				ns = *conn.TLS.ClientKeyRef.Namespace
			}
			if ns == secretNamespace && conn.TLS.ClientKeyRef.Name == secretName {
				return true
			}
		}
	}

	return false
}
