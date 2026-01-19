package circuitbreaker

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// CircuitBreakerState shows the current state of circuit breakers.
	CircuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "circuit_breaker_state",
			Help: "Current state of the circuit breaker (0=closed, 1=open, 2=half-open)",
		},
		[]string{"name"},
	)

	// CircuitBreakerRequestsTotal counts total requests through circuit breakers.
	CircuitBreakerRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "circuit_breaker_requests_total",
			Help: "Total number of requests through circuit breakers",
		},
		[]string{"name", "result"},
	)

	// CircuitBreakerFailuresTotal counts failures recorded by circuit breakers.
	CircuitBreakerFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "circuit_breaker_failures_total",
			Help: "Total number of failures recorded by circuit breakers",
		},
		[]string{"name"},
	)

	// CircuitBreakerSuccessesTotal counts successes recorded by circuit breakers.
	CircuitBreakerSuccessesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "circuit_breaker_successes_total",
			Help: "Total number of successes recorded by circuit breakers",
		},
		[]string{"name"},
	)

	// CircuitBreakerStateChangesTotal counts state changes.
	CircuitBreakerStateChangesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "circuit_breaker_state_changes_total",
			Help: "Total number of circuit breaker state changes",
		},
		[]string{"name", "from", "to"},
	)

	// CircuitBreakerRejectedTotal counts rejected requests due to open circuit.
	CircuitBreakerRejectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "circuit_breaker_rejected_total",
			Help: "Total number of requests rejected due to open circuit",
		},
		[]string{"name"},
	)
)

// RecordState records the current state of a circuit breaker.
func RecordState(name string, state State) {
	CircuitBreakerState.WithLabelValues(name).Set(float64(state))
}

// RecordRequest records a request through a circuit breaker.
func RecordRequest(name string, allowed bool) {
	result := "allowed"
	if !allowed {
		result = "rejected"
		CircuitBreakerRejectedTotal.WithLabelValues(name).Inc()
	}
	CircuitBreakerRequestsTotal.WithLabelValues(name, result).Inc()
}

// RecordFailure records a failure.
func RecordFailure(name string) {
	CircuitBreakerFailuresTotal.WithLabelValues(name).Inc()
}

// RecordSuccess records a success.
func RecordSuccess(name string) {
	CircuitBreakerSuccessesTotal.WithLabelValues(name).Inc()
}

// RecordStateChange records a state change.
func RecordStateChange(name string, from, to State) {
	CircuitBreakerStateChangesTotal.WithLabelValues(name, from.String(), to.String()).Inc()
	RecordState(name, to)
}

// MetricsOnStateChange returns a callback function for recording state changes.
func MetricsOnStateChange() func(name string, from, to State) {
	return func(name string, from, to State) {
		RecordStateChange(name, from, to)
	}
}
