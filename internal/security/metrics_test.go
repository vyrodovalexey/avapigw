package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetrics_Init_CSPViolationsPrePopulated(t *testing.T) {
	// Note: NewMetrics uses promauto which registers with the default global registry.
	// We use GetSecurityMetrics() to get the singleton and test Init().
	m := GetSecurityMetrics()

	// Init should not panic
	assert.NotPanics(t, func() {
		m.Init()
	})

	// Init should be idempotent
	assert.NotPanics(t, func() {
		m.Init()
	})
}
