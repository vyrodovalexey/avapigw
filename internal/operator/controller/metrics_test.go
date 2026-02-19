package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitControllerVecMetrics_NoPanic(t *testing.T) {
	// InitControllerVecMetrics uses the singleton, which is already initialized
	// by the time tests run. It should not panic.
	assert.NotPanics(t, func() {
		InitControllerVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitControllerVecMetrics()
	})
}

func TestInitStatusUpdateVecMetrics_NoPanic(t *testing.T) {
	// InitStatusUpdateVecMetrics uses the singleton, which is already initialized
	// by the time tests run. It should not panic.
	assert.NotPanics(t, func() {
		InitStatusUpdateVecMetrics()
	})

	// Idempotent - calling again should not panic
	assert.NotPanics(t, func() {
		InitStatusUpdateVecMetrics()
	})
}
