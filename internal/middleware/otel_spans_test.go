package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestCircuitBreaker_OTELSpans verifies that OTEL spans are created
// during circuit breaker state changes. This test is NOT parallel
// because it modifies the global OTEL tracer provider.
func TestCircuitBreaker_OTELSpans(t *testing.T) {
	t.Run("state_change_creates_span", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() { _ = tp.Shutdown(context.Background()) }()

		oldTP := otel.GetTracerProvider()
		otel.SetTracerProvider(tp)
		defer otel.SetTracerProvider(oldTP)

		stateChanges := make([]string, 0)

		cb := NewCircuitBreaker(
			"test-otel-cb",
			2,                    // threshold
			100*time.Millisecond, // timeout
			WithCircuitBreakerLogger(observability.NopLogger()),
			WithCircuitBreakerStateCallback(func(name string, state int) {
				stateChanges = append(stateChanges, name)
			}),
		)

		// Force failures to trigger state change
		for i := 0; i < 10; i++ {
			_, _ = cb.Execute(func() (interface{}, error) {
				return nil, assert.AnError
			})
		}

		// Wait for timeout to allow half-open transition
		time.Sleep(200 * time.Millisecond)

		// Try one more request to trigger half-open -> closed or half-open -> open
		_, _ = cb.Execute(func() (interface{}, error) {
			return nil, assert.AnError
		})

		// Verify OTEL spans were created for state changes
		spans := exporter.GetSpans()

		// There should be at least one state change span
		stateChangeSpans := 0
		for _, s := range spans {
			if s.Name == "circuitbreaker.state_change" {
				stateChangeSpans++
				// Verify span has events
				require.NotEmpty(t, s.Events, "state change span should have events")
				event := s.Events[0]
				assert.Equal(t, "state_change", event.Name)

				// Verify event attributes
				attrs := make(map[string]interface{})
				for _, a := range event.Attributes {
					attrs[string(a.Key)] = a.Value.AsInterface()
				}
				assert.Contains(t, attrs, "circuitbreaker.name")
				assert.Contains(t, attrs, "circuitbreaker.from")
				assert.Contains(t, attrs, "circuitbreaker.to")
			}
		}

		// At least one state change should have occurred
		assert.Greater(t, stateChangeSpans, 0, "expected at least one circuit breaker state change span")
	})
}
