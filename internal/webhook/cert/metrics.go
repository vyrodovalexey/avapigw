package cert

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// certGenerationsTotal counts total certificate generations.
	certGenerationsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "webhook_cert_generations_total",
			Help: "Total number of webhook certificate generations",
		},
	)

	// certRotationsTotal counts total certificate rotations.
	certRotationsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "webhook_cert_rotations_total",
			Help: "Total number of webhook certificate rotations",
		},
	)

	// certRotationErrorsTotal counts total certificate rotation errors.
	certRotationErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "webhook_cert_rotation_errors_total",
			Help: "Total number of webhook certificate rotation errors",
		},
	)

	// certExpiryTimestamp tracks the certificate expiry timestamp.
	certExpiryTimestamp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "webhook_cert_expiry_timestamp_seconds",
			Help: "Unix timestamp when the webhook certificate expires",
		},
	)

	// certValidDays tracks the number of days until certificate expiry.
	certValidDays = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "webhook_cert_valid_days",
			Help: "Number of days until the webhook certificate expires",
		},
	)

	// certInjectionTotal counts total CA bundle injections.
	certInjectionTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webhook_cert_injection_total",
			Help: "Total number of CA bundle injections into webhook configurations",
		},
		[]string{"webhook_type", "status"},
	)

	// certSecretOperationsTotal counts secret operations.
	certSecretOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webhook_cert_secret_operations_total",
			Help: "Total number of certificate secret operations",
		},
		[]string{"operation", "status"},
	)
)

const (
	statusSuccess = "success"
	statusError   = "error"

	webhookTypeValidating = "validating"
	webhookTypeMutating   = "mutating"

	operationCreate = "create"
	operationUpdate = "update"
	operationRead   = "read"
)

// recordCertGeneration records a certificate generation.
func recordCertGeneration() {
	defer recoverFromPanic()
	if certGenerationsTotal == nil {
		return
	}
	certGenerationsTotal.Inc()
}

// recordCertRotation records a certificate rotation.
func recordCertRotation() {
	defer recoverFromPanic()
	if certRotationsTotal == nil {
		return
	}
	certRotationsTotal.Inc()
}

// recordCertRotationError records a certificate rotation error.
func recordCertRotationError() {
	defer recoverFromPanic()
	if certRotationErrorsTotal == nil {
		return
	}
	certRotationErrorsTotal.Inc()
}

// updateCertExpiry updates the certificate expiry metrics.
func updateCertExpiry(expiresAt time.Time) {
	defer recoverFromPanic()
	if certExpiryTimestamp == nil || certValidDays == nil {
		return
	}

	if expiresAt.IsZero() {
		certExpiryTimestamp.Set(0)
		certValidDays.Set(0)
		return
	}

	certExpiryTimestamp.Set(float64(expiresAt.Unix()))

	// Calculate days until expiry
	daysUntilExpiry := time.Until(expiresAt).Hours() / 24
	if daysUntilExpiry < 0 {
		daysUntilExpiry = 0
	}
	certValidDays.Set(daysUntilExpiry)
}

// recordInjection records a CA bundle injection.
func recordInjection(webhookType string, success bool) {
	defer recoverFromPanic()
	if certInjectionTotal == nil {
		return
	}

	status := statusSuccess
	if !success {
		status = statusError
	}
	certInjectionTotal.WithLabelValues(webhookType, status).Inc()
}

// recordValidatingWebhookInjection records a validating webhook injection.
func recordValidatingWebhookInjection(success bool) {
	recordInjection(webhookTypeValidating, success)
}

// recordMutatingWebhookInjection records a mutating webhook injection.
func recordMutatingWebhookInjection(success bool) {
	recordInjection(webhookTypeMutating, success)
}

// recordSecretOperation records a secret operation.
func recordSecretOperation(operation string, success bool) {
	defer recoverFromPanic()
	if certSecretOperationsTotal == nil {
		return
	}

	status := statusSuccess
	if !success {
		status = statusError
	}
	certSecretOperationsTotal.WithLabelValues(operation, status).Inc()
}

// recoverFromPanic recovers from any panic in metrics recording.
func recoverFromPanic() {
	if r := recover(); r != nil {
		// Silently recover from any panic in metrics recording
		// This ensures metrics issues don't crash the application
	}
}
