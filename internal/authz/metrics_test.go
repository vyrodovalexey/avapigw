package authz

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	// Note: We use a unique namespace to avoid metric registration conflicts
	metrics := NewMetrics("test_authz_metrics")

	require.NotNil(t, metrics)
	assert.NotNil(t, metrics.evaluationTotal)
	assert.NotNil(t, metrics.evaluationDuration)
	assert.NotNil(t, metrics.decisionTotal)
	assert.NotNil(t, metrics.cacheHits)
	assert.NotNil(t, metrics.cacheMisses)
	assert.NotNil(t, metrics.externalRequestTotal)
	assert.NotNil(t, metrics.externalRequestDuration)
	assert.NotNil(t, metrics.policyCount)
}

func TestMetrics_RecordEvaluation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metrics  *Metrics
		engine   string
		result   string
		duration time.Duration
	}{
		{
			name:     "nil metrics",
			metrics:  nil,
			engine:   "rbac",
			result:   "allow",
			duration: time.Millisecond,
		},
		{
			name:     "nil evaluationTotal",
			metrics:  &Metrics{},
			engine:   "rbac",
			result:   "allow",
			duration: time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Should not panic
			tt.metrics.RecordEvaluation(tt.engine, tt.result, tt.duration)
		})
	}
}

func TestMetrics_RecordDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metrics  *Metrics
		decision string
		policy   string
	}{
		{
			name:     "nil metrics",
			metrics:  nil,
			decision: "allow",
			policy:   "test-policy",
		},
		{
			name:     "nil decisionTotal",
			metrics:  &Metrics{},
			decision: "allow",
			policy:   "test-policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Should not panic
			tt.metrics.RecordDecision(tt.decision, tt.policy)
		})
	}
}

func TestMetrics_RecordCacheHit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		metrics *Metrics
	}{
		{
			name:    "nil metrics",
			metrics: nil,
		},
		{
			name:    "nil cacheHits",
			metrics: &Metrics{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Should not panic
			tt.metrics.RecordCacheHit()
		})
	}
}

func TestMetrics_RecordCacheMiss(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		metrics *Metrics
	}{
		{
			name:    "nil metrics",
			metrics: nil,
		},
		{
			name:    "nil cacheMisses",
			metrics: &Metrics{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Should not panic
			tt.metrics.RecordCacheMiss()
		})
	}
}

func TestMetrics_RecordExternalRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metrics  *Metrics
		provider string
		result   string
		duration time.Duration
	}{
		{
			name:     "nil metrics",
			metrics:  nil,
			provider: "opa",
			result:   "allow",
			duration: time.Millisecond,
		},
		{
			name:     "nil externalRequestTotal",
			metrics:  &Metrics{},
			provider: "opa",
			result:   "allow",
			duration: time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Should not panic
			tt.metrics.RecordExternalRequest(tt.provider, tt.result, tt.duration)
		})
	}
}

func TestMetrics_SetPolicyCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		metrics *Metrics
		engine  string
		count   int
	}{
		{
			name:    "nil metrics",
			metrics: nil,
			engine:  "rbac",
			count:   10,
		},
		{
			name:    "nil policyCount",
			metrics: &Metrics{},
			engine:  "rbac",
			count:   10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Should not panic
			tt.metrics.SetPolicyCount(tt.engine, tt.count)
		})
	}
}
