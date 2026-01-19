package cert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRecordCertGeneration(t *testing.T) {
	// Test that recordCertGeneration doesn't panic
	t.Run("normal operation", func(t *testing.T) {
		assert.NotPanics(t, func() {
			recordCertGeneration()
		})
	})
}

func TestRecordCertRotation(t *testing.T) {
	// Test that recordCertRotation doesn't panic
	t.Run("normal operation", func(t *testing.T) {
		assert.NotPanics(t, func() {
			recordCertRotation()
		})
	})
}

func TestRecordCertRotationError(t *testing.T) {
	// Test that recordCertRotationError doesn't panic
	t.Run("normal operation", func(t *testing.T) {
		assert.NotPanics(t, func() {
			recordCertRotationError()
		})
	})
}

func TestUpdateCertExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
	}{
		{
			name:      "future expiry",
			expiresAt: time.Now().Add(365 * 24 * time.Hour),
		},
		{
			name:      "past expiry",
			expiresAt: time.Now().Add(-24 * time.Hour),
		},
		{
			name:      "zero time",
			expiresAt: time.Time{},
		},
		{
			name:      "near future expiry",
			expiresAt: time.Now().Add(1 * time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				updateCertExpiry(tt.expiresAt)
			})
		})
	}
}

func TestRecordInjection(t *testing.T) {
	tests := []struct {
		name        string
		webhookType string
		success     bool
	}{
		{
			name:        "validating webhook success",
			webhookType: webhookTypeValidating,
			success:     true,
		},
		{
			name:        "validating webhook error",
			webhookType: webhookTypeValidating,
			success:     false,
		},
		{
			name:        "mutating webhook success",
			webhookType: webhookTypeMutating,
			success:     true,
		},
		{
			name:        "mutating webhook error",
			webhookType: webhookTypeMutating,
			success:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				recordInjection(tt.webhookType, tt.success)
			})
		})
	}
}

func TestRecordValidatingWebhookInjection(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		assert.NotPanics(t, func() {
			recordValidatingWebhookInjection(true)
		})
	})

	t.Run("error", func(t *testing.T) {
		assert.NotPanics(t, func() {
			recordValidatingWebhookInjection(false)
		})
	})
}

func TestRecordMutatingWebhookInjection(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		assert.NotPanics(t, func() {
			recordMutatingWebhookInjection(true)
		})
	})

	t.Run("error", func(t *testing.T) {
		assert.NotPanics(t, func() {
			recordMutatingWebhookInjection(false)
		})
	})
}

func TestRecoverFromPanic(t *testing.T) {
	t.Run("recovers from panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			defer recoverFromPanic()
			panic("test panic")
		})
	})

	t.Run("no panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			defer recoverFromPanic()
			// No panic
		})
	})
}

func TestMetricsConstants(t *testing.T) {
	assert.Equal(t, "success", statusSuccess)
	assert.Equal(t, "error", statusError)
	assert.Equal(t, "validating", webhookTypeValidating)
	assert.Equal(t, "mutating", webhookTypeMutating)
}
