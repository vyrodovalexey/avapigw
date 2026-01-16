// Package tracing provides OpenTelemetry tracing for the API Gateway.
package tracing

import (
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// PropagatorType defines the type of context propagator.
type PropagatorType string

const (
	// PropagatorW3C uses W3C Trace Context propagation.
	PropagatorW3C PropagatorType = "w3c"
	// PropagatorB3 uses B3 propagation (Zipkin style).
	PropagatorB3 PropagatorType = "b3"
	// PropagatorB3Multi uses B3 multi-header propagation.
	PropagatorB3Multi PropagatorType = "b3-multi"
	// PropagatorJaeger uses Jaeger propagation.
	PropagatorJaeger PropagatorType = "jaeger"
	// PropagatorComposite uses multiple propagators.
	PropagatorComposite PropagatorType = "composite"
)

// PropagatorConfig holds configuration for context propagation.
type PropagatorConfig struct {
	// Types is the list of propagator types to use.
	Types []PropagatorType

	// EnableBaggage enables baggage propagation.
	EnableBaggage bool
}

// DefaultPropagatorConfig returns a PropagatorConfig with default values.
func DefaultPropagatorConfig() *PropagatorConfig {
	return &PropagatorConfig{
		Types:         []PropagatorType{PropagatorW3C},
		EnableBaggage: true,
	}
}

// SetupPropagators configures the global text map propagators.
func SetupPropagators(config *PropagatorConfig) {
	if config == nil {
		config = DefaultPropagatorConfig()
	}

	propagators := make([]propagation.TextMapPropagator, 0, len(config.Types)+1)

	for _, t := range config.Types {
		switch t {
		case PropagatorW3C:
			propagators = append(propagators, propagation.TraceContext{})
		case PropagatorB3:
			propagators = append(propagators, b3.New(b3.WithInjectEncoding(b3.B3SingleHeader)))
		case PropagatorB3Multi:
			propagators = append(propagators, b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader)))
		case PropagatorJaeger:
			propagators = append(propagators, jaeger.Jaeger{})
		default:
			propagators = append(propagators, propagation.TraceContext{})
		}
	}

	// Add baggage propagator if enabled
	if config.EnableBaggage {
		propagators = append(propagators, propagation.Baggage{})
	}

	// Set composite propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagators...))
}

// GetPropagator returns the current global text map propagator.
func GetPropagator() propagation.TextMapPropagator {
	return otel.GetTextMapPropagator()
}

// W3CTraceContextPropagator returns a W3C Trace Context propagator.
func W3CTraceContextPropagator() propagation.TextMapPropagator {
	return propagation.TraceContext{}
}

// BaggagePropagator returns a Baggage propagator.
func BaggagePropagator() propagation.TextMapPropagator {
	return propagation.Baggage{}
}

// CompositePropagator returns a composite propagator with W3C and Baggage.
func CompositePropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

// B3SingleHeaderPropagator returns a B3 single-header propagator.
func B3SingleHeaderPropagator() propagation.TextMapPropagator {
	return b3.New(b3.WithInjectEncoding(b3.B3SingleHeader))
}

// B3MultiHeaderPropagator returns a B3 multi-header propagator.
func B3MultiHeaderPropagator() propagation.TextMapPropagator {
	return b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader))
}

// JaegerPropagator returns a Jaeger propagator.
func JaegerPropagator() propagation.TextMapPropagator {
	return jaeger.Jaeger{}
}

// AllPropagators returns a composite propagator with W3C, B3, and Jaeger support.
func AllPropagators() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
		b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader|b3.B3SingleHeader)),
		jaeger.Jaeger{},
	)
}

// HeaderCarrier adapts http.Header to propagation.TextMapCarrier.
type HeaderCarrier map[string][]string

// Get returns the value associated with the passed key.
func (hc HeaderCarrier) Get(key string) string {
	vals := hc[key]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// Set stores the key-value pair.
func (hc HeaderCarrier) Set(key, value string) {
	hc[key] = []string{value}
}

// Keys lists the keys stored in this carrier.
func (hc HeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(hc))
	for k := range hc {
		keys = append(keys, k)
	}
	return keys
}

// MapCarrier adapts a map[string]string to propagation.TextMapCarrier.
type MapCarrier map[string]string

// Get returns the value associated with the passed key.
func (mc MapCarrier) Get(key string) string {
	return mc[key]
}

// Set stores the key-value pair.
func (mc MapCarrier) Set(key, value string) {
	mc[key] = value
}

// Keys lists the keys stored in this carrier.
func (mc MapCarrier) Keys() []string {
	keys := make([]string, 0, len(mc))
	for k := range mc {
		keys = append(keys, k)
	}
	return keys
}

// MetadataCarrier adapts gRPC metadata to propagation.TextMapCarrier.
type MetadataCarrier map[string][]string

// Get returns the value associated with the passed key.
func (mc MetadataCarrier) Get(key string) string {
	vals := mc[key]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// Set stores the key-value pair.
func (mc MetadataCarrier) Set(key, value string) {
	mc[key] = []string{value}
}

// Keys lists the keys stored in this carrier.
func (mc MetadataCarrier) Keys() []string {
	keys := make([]string, 0, len(mc))
	for k := range mc {
		keys = append(keys, k)
	}
	return keys
}
