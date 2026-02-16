// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"context"
	"fmt"
	"sort"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// responseTransformer implements the ResponseTransformer interface.
type responseTransformer struct {
	logger         observability.Logger
	fieldFilter    FieldFilter
	fieldMapper    FieldMapper
	templateEngine TemplateEngine
	merger         ResponseMerger
}

// ResponseTransformerOption is a functional option for configuring the response transformer.
type ResponseTransformerOption func(*responseTransformer)

// WithResponseLogger sets the logger for the response transformer.
func WithResponseLogger(logger observability.Logger) ResponseTransformerOption {
	return func(rt *responseTransformer) {
		rt.logger = logger
	}
}

// WithFieldFilter sets a custom field filter.
func WithFieldFilter(filter FieldFilter) ResponseTransformerOption {
	return func(rt *responseTransformer) {
		rt.fieldFilter = filter
	}
}

// WithFieldMapper sets a custom field mapper.
func WithFieldMapper(mapper FieldMapper) ResponseTransformerOption {
	return func(rt *responseTransformer) {
		rt.fieldMapper = mapper
	}
}

// WithTemplateEngine sets a custom template engine.
func WithTemplateEngine(engine TemplateEngine) ResponseTransformerOption {
	return func(rt *responseTransformer) {
		rt.templateEngine = engine
	}
}

// WithMerger sets a custom response merger.
func WithMerger(merger ResponseMerger) ResponseTransformerOption {
	return func(rt *responseTransformer) {
		rt.merger = merger
	}
}

// NewResponseTransformer creates a new ResponseTransformer instance.
func NewResponseTransformer(logger observability.Logger, opts ...ResponseTransformerOption) ResponseTransformer {
	if logger == nil {
		logger = observability.NopLogger()
	}

	rt := &responseTransformer{
		logger:         logger,
		fieldFilter:    NewFieldFilter(logger),
		fieldMapper:    NewFieldMapper(logger),
		templateEngine: NewTemplateEngine(logger),
		merger:         NewResponseMerger(logger),
	}

	for _, opt := range opts {
		opt(rt)
	}

	return rt
}

// Transform applies the default transformation to the data.
func (rt *responseTransformer) Transform(ctx context.Context, data interface{}) (interface{}, error) {
	// No-op for default transformation
	return data, nil
}

// TransformResponse transforms response data using the provided configuration.
func (rt *responseTransformer) TransformResponse(
	ctx context.Context,
	response interface{},
	cfg *config.ResponseTransformConfig,
) (interface{}, error) {
	if cfg == nil {
		return response, nil
	}

	if response == nil {
		return nil, nil
	}

	ctx, span := transformTracer.Start(ctx, "transform.response",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.Bool("transform.has_template", cfg.Template != ""),
			attribute.Int("transform.allow_fields_count", len(cfg.AllowFields)),
			attribute.Int("transform.deny_fields_count", len(cfg.DenyFields)),
			attribute.Int("transform.field_mappings_count", len(cfg.FieldMappings)),
		),
	)
	defer span.End()

	start := time.Now()
	metrics := GetTransformMetrics()

	rt.logger.Debug("starting response transformation",
		observability.Bool("hasAllowFields", len(cfg.AllowFields) > 0),
		observability.Bool("hasDenyFields", len(cfg.DenyFields) > 0),
		observability.Bool("hasFieldMappings", len(cfg.FieldMappings) > 0),
		observability.Bool("hasTemplate", cfg.Template != ""))

	// If template is specified, use it directly
	if cfg.Template != "" {
		return rt.templateEngine.Execute(cfg.Template, response)
	}

	// Convert to map if possible
	data, ok := response.(map[string]interface{})
	if !ok {
		// Try to handle arrays
		if arr, isArr := response.([]interface{}); isArr {
			return rt.transformArray(ctx, arr, cfg)
		}
		rt.logger.Debug("response is not a map or array, returning as-is")
		return response, nil
	}

	var err error

	// Apply field filtering (allow list)
	if len(cfg.AllowFields) > 0 {
		data = rt.fieldFilter.FilterAllow(data, cfg.AllowFields)
	}

	// Apply field filtering (deny list)
	if len(cfg.DenyFields) > 0 {
		data = rt.fieldFilter.FilterDeny(data, cfg.DenyFields)
	}

	// Apply field mappings
	if len(cfg.FieldMappings) > 0 {
		data, err = rt.fieldMapper.MapFields(data, cfg.FieldMappings)
		if err != nil {
			metrics.RecordOperation("response", "error")
			metrics.RecordError("response", "field_mapping")
			return nil, fmt.Errorf("field mapping failed: %w", err)
		}
	}

	// Apply field grouping
	if len(cfg.GroupFields) > 0 {
		data = GroupFields(data, cfg.GroupFields)
	}

	// Apply field flattening
	if len(cfg.FlattenFields) > 0 {
		data = FlattenFields(data, cfg.FlattenFields)
	}

	// Apply array operations
	if len(cfg.ArrayOperations) > 0 {
		data, err = rt.applyArrayOperations(data, cfg.ArrayOperations)
		if err != nil {
			return nil, fmt.Errorf("array operation failed: %w", err)
		}
	}

	metrics.operationDuration.WithLabelValues("response").Observe(time.Since(start).Seconds())
	metrics.RecordOperation("response", "success")
	rt.logger.Debug("response transformation completed")

	return data, nil
}

// transformArray transforms an array response.
func (rt *responseTransformer) transformArray(
	ctx context.Context,
	arr []interface{},
	cfg *config.ResponseTransformConfig,
) ([]interface{}, error) {
	result := make([]interface{}, 0, len(arr))

	for _, item := range arr {
		if itemMap, ok := item.(map[string]interface{}); ok {
			transformed, err := rt.TransformResponse(ctx, itemMap, cfg)
			if err != nil {
				return nil, err
			}
			result = append(result, transformed)
		} else {
			result = append(result, item)
		}
	}

	return result, nil
}

// applyArrayOperations applies array operations to the data.
func (rt *responseTransformer) applyArrayOperations(
	data map[string]interface{},
	operations []config.ArrayOperation,
) (map[string]interface{}, error) {
	result := deepCopyMap(data)

	for _, op := range operations {
		arr, err := getArrayAtPath(result, op.Field)
		if err != nil {
			rt.logger.Debug("array field not found",
				observability.String("field", op.Field),
				observability.Error(err))
			continue
		}

		var transformed []interface{}

		switch op.Operation {
		case config.ArrayOperationFilter:
			transformed = rt.filterArray(arr, op.Condition)
		case config.ArrayOperationSort:
			transformed = rt.sortArray(arr, op.Value)
		case config.ArrayOperationLimit:
			transformed = rt.limitArray(arr, op.Value)
		case config.ArrayOperationDeduplicate:
			transformed = rt.deduplicateArray(arr)
		case config.ArrayOperationAppend:
			transformed = rt.appendToArray(arr, op.Value)
		case config.ArrayOperationPrepend:
			transformed = rt.prependToArray(arr, op.Value)
		default:
			rt.logger.Warn("unknown array operation",
				observability.String("operation", op.Operation))
			continue
		}

		if err := setArrayAtPath(result, op.Field, transformed); err != nil {
			return nil, fmt.Errorf("failed to set array at path %s: %w", op.Field, err)
		}
	}

	return result, nil
}

// filterArray filters array elements based on a condition.
// Note: Full CEL expression support would require additional dependencies.
// This is a simplified implementation.
func (rt *responseTransformer) filterArray(arr []interface{}, condition string) []interface{} {
	if condition == "" {
		return arr
	}

	// Simplified filtering - just return all elements for now
	// Full CEL support would be added in a separate implementation
	rt.logger.Debug("array filter condition",
		observability.String("condition", condition),
		observability.Int("inputLength", len(arr)))

	return arr
}

// sortArray sorts array elements.
func (rt *responseTransformer) sortArray(arr []interface{}, sortKey interface{}) []interface{} {
	if len(arr) == 0 {
		return arr
	}

	result := make([]interface{}, len(arr))
	copy(result, arr)

	key, ok := sortKey.(string)
	if !ok || key == "" {
		return result
	}

	sort.SliceStable(result, func(i, j int) bool {
		iMap, iOk := result[i].(map[string]interface{})
		jMap, jOk := result[j].(map[string]interface{})

		if !iOk || !jOk {
			return false
		}

		iVal := fmt.Sprintf("%v", iMap[key])
		jVal := fmt.Sprintf("%v", jMap[key])

		return iVal < jVal
	})

	return result
}

// limitArray limits the number of array elements.
func (rt *responseTransformer) limitArray(arr []interface{}, limitVal interface{}) []interface{} {
	limit := 0

	switch v := limitVal.(type) {
	case int:
		limit = v
	case int64:
		limit = int(v)
	case float64:
		limit = int(v)
	default:
		return arr
	}

	if limit <= 0 || limit >= len(arr) {
		return arr
	}

	return arr[:limit]
}

// deduplicateArray removes duplicate elements from an array.
func (rt *responseTransformer) deduplicateArray(arr []interface{}) []interface{} {
	if len(arr) == 0 {
		return arr
	}

	seen := make(map[string]bool)
	result := make([]interface{}, 0, len(arr))

	for _, item := range arr {
		key := fmt.Sprintf("%v", item)
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}

	return result
}

// appendToArray appends a value to an array.
func (rt *responseTransformer) appendToArray(arr []interface{}, value interface{}) []interface{} {
	if value == nil {
		return arr
	}

	result := make([]interface{}, len(arr)+1)
	copy(result, arr)
	result[len(arr)] = value

	return result
}

// prependToArray prepends a value to an array.
func (rt *responseTransformer) prependToArray(arr []interface{}, value interface{}) []interface{} {
	if value == nil {
		return arr
	}

	result := make([]interface{}, len(arr)+1)
	result[0] = value
	copy(result[1:], arr)

	return result
}

// getArrayAtPath retrieves an array at the given path.
func getArrayAtPath(data map[string]interface{}, path string) ([]interface{}, error) {
	value, err := getValueAtPath(data, path)
	if err != nil {
		return nil, err
	}

	arr, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %s is not an array", ErrInvalidDataType, path)
	}

	return arr, nil
}

// setArrayAtPath sets an array at the given path.
func setArrayAtPath(data map[string]interface{}, path string, arr []interface{}) error {
	return setValueAtPath(data, path, arr)
}
