// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"context"
	"fmt"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// requestTransformer implements the RequestTransformer interface.
type requestTransformer struct {
	logger         observability.Logger
	fieldMapper    FieldMapper
	templateEngine TemplateEngine
}

// RequestTransformerOption is a functional option for configuring the request transformer.
type RequestTransformerOption func(*requestTransformer)

// WithRequestLogger sets the logger for the request transformer.
func WithRequestLogger(logger observability.Logger) RequestTransformerOption {
	return func(rt *requestTransformer) {
		rt.logger = logger
	}
}

// WithRequestFieldMapper sets a custom field mapper.
func WithRequestFieldMapper(mapper FieldMapper) RequestTransformerOption {
	return func(rt *requestTransformer) {
		rt.fieldMapper = mapper
	}
}

// WithRequestTemplateEngine sets a custom template engine.
func WithRequestTemplateEngine(engine TemplateEngine) RequestTransformerOption {
	return func(rt *requestTransformer) {
		rt.templateEngine = engine
	}
}

// NewRequestTransformer creates a new RequestTransformer instance.
func NewRequestTransformer(logger observability.Logger, opts ...RequestTransformerOption) RequestTransformer {
	if logger == nil {
		logger = observability.NopLogger()
	}

	rt := &requestTransformer{
		logger:         logger,
		fieldMapper:    NewFieldMapper(logger),
		templateEngine: NewTemplateEngine(logger),
	}

	for _, opt := range opts {
		opt(rt)
	}

	return rt
}

// Transform applies the default transformation to the data.
func (rt *requestTransformer) Transform(ctx context.Context, data interface{}) (interface{}, error) {
	// No-op for default transformation
	return data, nil
}

// TransformRequest transforms request data using the provided configuration.
func (rt *requestTransformer) TransformRequest(
	ctx context.Context,
	request interface{},
	cfg *config.RequestTransformConfig,
) (interface{}, error) {
	if cfg == nil {
		return request, nil
	}

	// If passthrough is enabled, return the request as-is
	if cfg.PassthroughBody {
		rt.logger.Debug("passthrough mode enabled, returning request as-is")
		return request, nil
	}

	rt.logger.Debug("starting request transformation",
		observability.Bool("hasBodyTemplate", cfg.BodyTemplate != ""),
		observability.Bool("hasInjectFields", len(cfg.InjectFields) > 0),
		observability.Bool("hasRemoveFields", len(cfg.RemoveFields) > 0),
		observability.Bool("hasDefaultValues", len(cfg.DefaultValues) > 0))

	// If body template is specified, use it directly
	if cfg.BodyTemplate != "" {
		tc := TransformContextFromContext(ctx)
		templateData := map[string]interface{}{
			"request":  request,
			"context":  tc,
			"jwt":      tc.JWTClaims,
			"metadata": tc.Metadata,
			"headers":  tc.Headers,
		}
		return rt.templateEngine.Execute(cfg.BodyTemplate, templateData)
	}

	// Handle nil request
	if request == nil {
		if len(cfg.DefaultValues) > 0 || len(cfg.InjectFields) > 0 {
			request = make(map[string]interface{})
		} else {
			return nil, nil
		}
	}

	// Convert to map if possible
	data, ok := request.(map[string]interface{})
	if !ok {
		rt.logger.Debug("request is not a map, returning as-is")
		return request, nil
	}

	// Make a copy to avoid modifying the original
	data = deepCopyMap(data)

	// Apply default values first (only for missing fields)
	if len(cfg.DefaultValues) > 0 {
		data = rt.applyDefaultValues(data, cfg.DefaultValues)
	}

	// Remove fields
	if len(cfg.RemoveFields) > 0 {
		data = rt.removeFields(data, cfg.RemoveFields)
	}

	// Inject fields
	if len(cfg.InjectFields) > 0 {
		var err error
		data, err = rt.injectFields(ctx, data, cfg.InjectFields)
		if err != nil {
			return nil, fmt.Errorf("field injection failed: %w", err)
		}
	}

	rt.logger.Debug("request transformation completed")

	return data, nil
}

// applyDefaultValues applies default values to missing fields.
func (rt *requestTransformer) applyDefaultValues(
	data map[string]interface{},
	defaults map[string]interface{},
) map[string]interface{} {
	for key, defaultValue := range defaults {
		if _, exists := data[key]; !exists {
			data[key] = defaultValue
			rt.logger.Debug("applied default value",
				observability.String("field", key))
		}
	}
	return data
}

// removeFields removes specified fields from the data.
func (rt *requestTransformer) removeFields(data map[string]interface{}, fields []string) map[string]interface{} {
	for _, field := range fields {
		if err := deleteValueAtPath(data, field); err != nil {
			rt.logger.Debug("failed to remove field",
				observability.String("field", field),
				observability.Error(err))
		} else {
			rt.logger.Debug("removed field",
				observability.String("field", field))
		}
	}
	return data
}

// injectFields injects fields into the data.
func (rt *requestTransformer) injectFields(
	ctx context.Context,
	data map[string]interface{},
	injections []config.FieldInjection,
) (map[string]interface{}, error) {
	tc := TransformContextFromContext(ctx)

	for _, injection := range injections {
		var value interface{}

		if injection.Source != "" {
			// Get value from source
			value = rt.resolveSource(tc, injection.Source)
			if value == nil {
				rt.logger.Debug("source value not found",
					observability.String("source", injection.Source))
				continue
			}
		} else {
			value = injection.Value
		}

		if err := setValueAtPath(data, injection.Field, value); err != nil {
			return nil, fmt.Errorf("failed to inject field %s: %w", injection.Field, err)
		}

		rt.logger.Debug("injected field",
			observability.String("field", injection.Field))
	}

	return data, nil
}

// resolveSource resolves a value from the transform context.
// Supports paths like:
//   - "jwt.claim.sub" -> JWT claim "sub"
//   - "context.request_id" -> Request ID
//   - "metadata.key" -> Metadata value
//   - "headers.X-Custom" -> Header value
func (rt *requestTransformer) resolveSource(tc *TransformContext, source string) interface{} {
	parts := strings.SplitN(source, ".", 2)
	if len(parts) < 2 {
		return nil
	}

	category := parts[0]
	path := parts[1]

	switch category {
	case "jwt":
		return rt.resolveJWTSource(tc, path)
	case "context":
		return rt.resolveContextSource(tc, path)
	case "metadata":
		return tc.Metadata[path]
	case "headers":
		return tc.Headers[path]
	default:
		return nil
	}
}

// resolveJWTSource resolves a JWT claim value.
func (rt *requestTransformer) resolveJWTSource(tc *TransformContext, path string) interface{} {
	// Handle "claim.xxx" prefix
	if strings.HasPrefix(path, "claim.") {
		claimName := strings.TrimPrefix(path, "claim.")
		return tc.JWTClaims[claimName]
	}

	// Direct claim access
	return tc.JWTClaims[path]
}

// resolveContextSource resolves a context value.
func (rt *requestTransformer) resolveContextSource(tc *TransformContext, path string) interface{} {
	switch path {
	case "request_id":
		return tc.RequestID
	case "trace_id":
		return tc.TraceID
	default:
		return nil
	}
}

// TransformHeaders transforms request headers using the configuration.
func TransformHeaders(
	ctx context.Context,
	headers map[string]string,
	cfg *config.RequestTransformConfig,
	logger observability.Logger,
) (map[string]string, error) {
	if cfg == nil {
		return headers, nil
	}

	if logger == nil {
		logger = observability.NopLogger()
	}

	result := make(map[string]string)
	for k, v := range headers {
		result[k] = v
	}

	// Add static headers
	for name, value := range cfg.StaticHeaders {
		result[name] = value
		logger.Debug("added static header",
			observability.String("name", name))
	}

	// Add dynamic headers
	tc := TransformContextFromContext(ctx)
	rt := &requestTransformer{logger: logger}

	for _, dh := range cfg.DynamicHeaders {
		value := rt.resolveSource(tc, dh.Source)
		if value != nil {
			result[dh.Name] = fmt.Sprintf("%v", value)
			logger.Debug("added dynamic header",
				observability.String("name", dh.Name),
				observability.String("source", dh.Source))
		}
	}

	return result, nil
}
