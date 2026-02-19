package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitServerVecMetrics_NoPanic(t *testing.T) {
	// InitServerVecMetrics uses the singleton. It should not panic.
	assert.NotPanics(t, func() {
		InitServerVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitServerVecMetrics()
	})
}
