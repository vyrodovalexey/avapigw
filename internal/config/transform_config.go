// Package config provides configuration types and loading for the API Gateway.
package config

// TransformConfig represents the root transformation configuration for a route.
// It allows configuring both request and response transformations.
type TransformConfig struct {
	// Request contains request transformation configuration.
	Request *RequestTransformConfig `yaml:"request,omitempty" json:"request,omitempty"`

	// Response contains response transformation configuration.
	Response *ResponseTransformConfig `yaml:"response,omitempty" json:"response,omitempty"`
}

// ResponseTransformConfig contains configuration for response data transformation.
type ResponseTransformConfig struct {
	// AllowFields specifies fields to include in the response (whitelist).
	// Uses dot notation for nested fields (e.g., "user.name", "items[].id").
	AllowFields []string `yaml:"allowFields,omitempty" json:"allowFields,omitempty"`

	// DenyFields specifies fields to exclude from the response (blacklist).
	// Uses dot notation for nested fields (e.g., "user.password", "internal").
	DenyFields []string `yaml:"denyFields,omitempty" json:"denyFields,omitempty"`

	// FieldMappings defines field renaming/mapping rules.
	FieldMappings []FieldMapping `yaml:"fieldMappings,omitempty" json:"fieldMappings,omitempty"`

	// GroupFields defines how to group multiple fields into nested objects.
	GroupFields []FieldGroup `yaml:"groupFields,omitempty" json:"groupFields,omitempty"`

	// FlattenFields specifies nested objects to flatten into the parent.
	// Uses dot notation (e.g., "metadata" flattens metadata.* to root level).
	FlattenFields []string `yaml:"flattenFields,omitempty" json:"flattenFields,omitempty"`

	// ArrayOperations defines operations to perform on array fields.
	ArrayOperations []ArrayOperation `yaml:"arrayOperations,omitempty" json:"arrayOperations,omitempty"`

	// Template is a Go template string for custom response formatting.
	// When set, overrides other transformation rules.
	Template string `yaml:"template,omitempty" json:"template,omitempty"`

	// MergeStrategy defines how to merge responses from multiple backends.
	// Valid values: "deep", "shallow", "replace".
	MergeStrategy string `yaml:"mergeStrategy,omitempty" json:"mergeStrategy,omitempty"`
}

// RequestTransformConfig contains configuration for request data transformation.
type RequestTransformConfig struct {
	// PassthroughBody when true, passes the request body unchanged to the backend.
	PassthroughBody bool `yaml:"passthroughBody,omitempty" json:"passthroughBody,omitempty"`

	// BodyTemplate is a Go template string for custom request body formatting.
	BodyTemplate string `yaml:"bodyTemplate,omitempty" json:"bodyTemplate,omitempty"`

	// StaticHeaders defines headers to add with static values.
	StaticHeaders map[string]string `yaml:"staticHeaders,omitempty" json:"staticHeaders,omitempty"`

	// DynamicHeaders defines headers to add with values from context.
	DynamicHeaders []DynamicHeader `yaml:"dynamicHeaders,omitempty" json:"dynamicHeaders,omitempty"`

	// InjectFields defines fields to inject into the request body.
	InjectFields []FieldInjection `yaml:"injectFields,omitempty" json:"injectFields,omitempty"`

	// RemoveFields specifies fields to remove from the request body.
	// Uses dot notation for nested fields.
	RemoveFields []string `yaml:"removeFields,omitempty" json:"removeFields,omitempty"`

	// DefaultValues defines default values for fields if not present.
	DefaultValues map[string]interface{} `yaml:"defaultValues,omitempty" json:"defaultValues,omitempty"`

	// ValidateBeforeTransform when true, validates the request before transformation.
	ValidateBeforeTransform bool `yaml:"validateBeforeTransform,omitempty" json:"validateBeforeTransform,omitempty"`
}

// FieldMapping defines a mapping from source field to target field.
type FieldMapping struct {
	// Source is the source field path using dot notation.
	Source string `yaml:"source" json:"source"`

	// Target is the target field path using dot notation.
	Target string `yaml:"target" json:"target"`
}

// FieldGroup defines a grouping of fields into a nested object.
type FieldGroup struct {
	// Name is the name of the new nested object.
	Name string `yaml:"name" json:"name"`

	// Fields is the list of field paths to include in the group.
	Fields []string `yaml:"fields" json:"fields"`
}

// ArrayOperation defines an operation to perform on an array field.
type ArrayOperation struct {
	// Field is the path to the array field.
	Field string `yaml:"field" json:"field"`

	// Operation is the type of operation to perform.
	// Valid values: "append", "prepend", "filter", "sort", "limit", "deduplicate".
	Operation string `yaml:"operation" json:"operation"`

	// Value is the value to use for append/prepend operations.
	Value interface{} `yaml:"value,omitempty" json:"value,omitempty"`

	// Condition is a CEL expression for filter operations.
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty"`
}

// DynamicHeader defines a header with a value sourced from context.
type DynamicHeader struct {
	// Name is the header name.
	Name string `yaml:"name" json:"name"`

	// Source is the path to the value in context.
	// Examples: "jwt.claim.sub", "context.request_id", "metadata.key".
	Source string `yaml:"source" json:"source"`
}

// FieldInjection defines a field to inject into the request/response.
type FieldInjection struct {
	// Field is the path where to inject the value.
	Field string `yaml:"field" json:"field"`

	// Value is the static value to inject.
	Value interface{} `yaml:"value,omitempty" json:"value,omitempty"`

	// Source is the path to a dynamic value in context.
	// Examples: "jwt.claim.sub", "context.request_id".
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
}

// MergeStrategy constants for response merging.
const (
	// MergeStrategyDeep performs deep merge of nested objects.
	MergeStrategyDeep = "deep"

	// MergeStrategyShallow performs shallow merge (top-level only).
	MergeStrategyShallow = "shallow"

	// MergeStrategyReplace replaces the entire response.
	MergeStrategyReplace = "replace"
)

// ArrayOperationType constants for array operations.
const (
	// ArrayOperationAppend appends values to the array.
	ArrayOperationAppend = "append"

	// ArrayOperationPrepend prepends values to the array.
	ArrayOperationPrepend = "prepend"

	// ArrayOperationFilter filters array elements based on condition.
	ArrayOperationFilter = "filter"

	// ArrayOperationSort sorts array elements.
	ArrayOperationSort = "sort"

	// ArrayOperationLimit limits the number of array elements.
	ArrayOperationLimit = "limit"

	// ArrayOperationDeduplicate removes duplicate elements.
	ArrayOperationDeduplicate = "deduplicate"
)

// IsEmpty returns true if the TransformConfig has no configuration.
func (tc *TransformConfig) IsEmpty() bool {
	if tc == nil {
		return true
	}
	return tc.Request.IsEmpty() && tc.Response.IsEmpty()
}

// IsEmpty returns true if the RequestTransformConfig has no configuration.
func (rtc *RequestTransformConfig) IsEmpty() bool {
	if rtc == nil {
		return true
	}
	return !rtc.PassthroughBody &&
		rtc.BodyTemplate == "" &&
		len(rtc.StaticHeaders) == 0 &&
		len(rtc.DynamicHeaders) == 0 &&
		len(rtc.InjectFields) == 0 &&
		len(rtc.RemoveFields) == 0 &&
		len(rtc.DefaultValues) == 0 &&
		!rtc.ValidateBeforeTransform
}

// IsEmpty returns true if the ResponseTransformConfig has no configuration.
func (rtc *ResponseTransformConfig) IsEmpty() bool {
	if rtc == nil {
		return true
	}
	return len(rtc.AllowFields) == 0 &&
		len(rtc.DenyFields) == 0 &&
		len(rtc.FieldMappings) == 0 &&
		len(rtc.GroupFields) == 0 &&
		len(rtc.FlattenFields) == 0 &&
		len(rtc.ArrayOperations) == 0 &&
		rtc.Template == "" &&
		rtc.MergeStrategy == ""
}
