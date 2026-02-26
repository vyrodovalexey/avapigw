// Package transform provides GraphQL response transformation capabilities.
package transform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// transformTracerName is the OpenTelemetry tracer name for transform operations.
const transformTracerName = "avapigw/graphql-transform"

// GraphQLResponse represents a standard GraphQL response.
type GraphQLResponse struct {
	Data       interface{}            `json:"data,omitempty"`
	Errors     []GraphQLError         `json:"errors,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// GraphQLError represents a GraphQL error.
type GraphQLError struct {
	Message    string                 `json:"message"`
	Locations  []ErrorLocation        `json:"locations,omitempty"`
	Path       []interface{}          `json:"path,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// ErrorLocation represents the location of an error in the query.
type ErrorLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Transformer applies transformations to GraphQL responses.
type Transformer struct {
	logger observability.Logger

	// Configuration
	stripExtensions bool
	addHeaders      map[string]string
	removeHeaders   []string
}

// Option is a functional option for configuring the transformer.
type Option func(*Transformer)

// WithTransformLogger sets the logger for the transformer.
func WithTransformLogger(logger observability.Logger) Option {
	return func(t *Transformer) {
		t.logger = logger
	}
}

// WithStripExtensions configures whether to strip extensions from responses.
func WithStripExtensions(strip bool) Option {
	return func(t *Transformer) {
		t.stripExtensions = strip
	}
}

// WithAddHeaders adds headers to the response.
func WithAddHeaders(headers map[string]string) Option {
	return func(t *Transformer) {
		t.addHeaders = headers
	}
}

// WithRemoveHeaders removes headers from the response.
func WithRemoveHeaders(headers []string) Option {
	return func(t *Transformer) {
		t.removeHeaders = headers
	}
}

// New creates a new GraphQL response transformer.
func New(opts ...Option) *Transformer {
	t := &Transformer{
		logger:     observability.NopLogger(),
		addHeaders: make(map[string]string),
	}

	for _, opt := range opts {
		opt(t)
	}

	return t
}

// TransformResponse applies transformations to a GraphQL HTTP response.
func (t *Transformer) TransformResponse(resp *http.Response) error {
	tracer := otel.Tracer(transformTracerName)
	_, span := tracer.Start(resp.Request.Context(), "graphql.transform.response",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	// Apply header transformations
	t.transformHeaders(resp)

	// Apply body transformations if needed
	if t.stripExtensions {
		if err := t.transformBody(resp); err != nil {
			span.RecordError(err)
			return err
		}
		span.SetAttributes(attribute.Bool("graphql.extensions_stripped", true))
	}

	return nil
}

// transformHeaders applies header transformations to the response.
func (t *Transformer) transformHeaders(resp *http.Response) {
	// Remove specified headers
	for _, header := range t.removeHeaders {
		resp.Header.Del(header)
	}

	// Add specified headers
	for key, value := range t.addHeaders {
		resp.Header.Set(key, value)
	}
}

// transformBody applies body transformations to the response.
func (t *Transformer) transformBody(resp *http.Response) error {
	if resp.Body == nil {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	_ = resp.Body.Close()

	var gqlResp GraphQLResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		// If the body is not valid JSON, return it as-is without transformation
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return err
	}

	// Strip extensions
	if t.stripExtensions {
		gqlResp.Extensions = nil
	}

	// Re-encode the response
	transformed, err := json.Marshal(gqlResp)
	if err != nil {
		return fmt.Errorf("failed to marshal transformed response: %w", err)
	}

	resp.Body = io.NopCloser(bytes.NewReader(transformed))
	resp.ContentLength = int64(len(transformed))

	t.logger.Debug("GraphQL response transformed",
		observability.Bool("extensions_stripped", t.stripExtensions),
	)

	return nil
}

// CreateErrorResponse creates a standard GraphQL error response.
func CreateErrorResponse(message string, statusCode int) ([]byte, error) {
	resp := GraphQLResponse{
		Errors: []GraphQLError{
			{
				Message: message,
				Extensions: map[string]interface{}{
					"code": statusCode,
				},
			},
		},
	}

	return json.Marshal(resp)
}
