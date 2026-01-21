// Package config provides configuration types and loading for the API Gateway.
package config

// GRPCTransformConfig represents gRPC-specific transformation configuration.
type GRPCTransformConfig struct {
	// Request contains gRPC request transformation configuration.
	Request *GRPCRequestTransformConfig `yaml:"request,omitempty" json:"request,omitempty"`

	// Response contains gRPC response transformation configuration.
	Response *GRPCResponseTransformConfig `yaml:"response,omitempty" json:"response,omitempty"`
}

// GRPCResponseTransformConfig contains configuration for gRPC response transformation.
type GRPCResponseTransformConfig struct {
	// FieldMask specifies fields to include using protobuf FieldMask syntax.
	// Example: ["user.name", "user.email", "items"]
	FieldMask []string `yaml:"fieldMask,omitempty" json:"fieldMask,omitempty"`

	// FieldMappings defines protobuf field renaming rules.
	FieldMappings []FieldMapping `yaml:"fieldMappings,omitempty" json:"fieldMappings,omitempty"`

	// RepeatedFieldOps defines operations on repeated (array) fields.
	RepeatedFieldOps []RepeatedFieldOperation `yaml:"repeatedFieldOps,omitempty" json:"repeatedFieldOps,omitempty"`

	// MapFieldOps defines operations on map fields.
	MapFieldOps []MapFieldOperation `yaml:"mapFieldOps,omitempty" json:"mapFieldOps,omitempty"`

	// PreserveUnknownFields when true, preserves unknown protobuf fields.
	PreserveUnknownFields bool `yaml:"preserveUnknownFields,omitempty" json:"preserveUnknownFields,omitempty"`

	// StreamingConfig contains streaming-specific transformation options.
	StreamingConfig *StreamingTransformConfig `yaml:"streaming,omitempty" json:"streaming,omitempty"`

	// TrailerMetadata defines metadata to add to response trailers.
	TrailerMetadata map[string]string `yaml:"trailerMetadata,omitempty" json:"trailerMetadata,omitempty"`
}

// GRPCRequestTransformConfig contains configuration for gRPC request transformation.
type GRPCRequestTransformConfig struct {
	// InjectFieldMask specifies a FieldMask to inject into the request.
	InjectFieldMask []string `yaml:"injectFieldMask,omitempty" json:"injectFieldMask,omitempty"`

	// StaticMetadata defines metadata to add with static values.
	StaticMetadata map[string]string `yaml:"staticMetadata,omitempty" json:"staticMetadata,omitempty"`

	// DynamicMetadata defines metadata to add with values from context.
	DynamicMetadata []DynamicMetadata `yaml:"dynamicMetadata,omitempty" json:"dynamicMetadata,omitempty"`

	// InjectFields defines fields to inject into the request message.
	InjectFields []FieldInjection `yaml:"injectFields,omitempty" json:"injectFields,omitempty"`

	// RemoveFields specifies fields to remove from the request message.
	RemoveFields []string `yaml:"removeFields,omitempty" json:"removeFields,omitempty"`

	// DefaultValues defines default values for fields if not present.
	DefaultValues map[string]interface{} `yaml:"defaultValues,omitempty" json:"defaultValues,omitempty"`

	// ValidateBeforeTransform when true, validates the request before transformation.
	ValidateBeforeTransform bool `yaml:"validateBeforeTransform,omitempty" json:"validateBeforeTransform,omitempty"`

	// InjectDeadline specifies a deadline to inject into the request context.
	InjectDeadline Duration `yaml:"injectDeadline,omitempty" json:"injectDeadline,omitempty"`

	// AuthorityOverride overrides the :authority pseudo-header.
	AuthorityOverride string `yaml:"authorityOverride,omitempty" json:"authorityOverride,omitempty"`
}

// RepeatedFieldOperation defines an operation on a repeated (array) protobuf field.
type RepeatedFieldOperation struct {
	// Field is the path to the repeated field.
	Field string `yaml:"field" json:"field"`

	// Operation is the type of operation to perform.
	// Valid values: "filter", "sort", "limit", "deduplicate".
	Operation string `yaml:"operation" json:"operation"`

	// Condition is a CEL expression for filter operations.
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty"`

	// Limit is the maximum number of elements for limit operations.
	Limit int `yaml:"limit,omitempty" json:"limit,omitempty"`

	// SortField is the field to sort by for sort operations.
	SortField string `yaml:"sortField,omitempty" json:"sortField,omitempty"`

	// SortOrder is the sort direction: "asc" or "desc".
	SortOrder string `yaml:"sortOrder,omitempty" json:"sortOrder,omitempty"`
}

// MapFieldOperation defines an operation on a map protobuf field.
type MapFieldOperation struct {
	// Field is the path to the map field.
	Field string `yaml:"field" json:"field"`

	// Operation is the type of operation to perform.
	// Valid values: "filterKeys", "merge".
	Operation string `yaml:"operation" json:"operation"`

	// AllowKeys specifies keys to include (whitelist).
	AllowKeys []string `yaml:"allowKeys,omitempty" json:"allowKeys,omitempty"`

	// DenyKeys specifies keys to exclude (blacklist).
	DenyKeys []string `yaml:"denyKeys,omitempty" json:"denyKeys,omitempty"`

	// MergeWith specifies values to merge into the map.
	MergeWith map[string]interface{} `yaml:"mergeWith,omitempty" json:"mergeWith,omitempty"`
}

// DynamicMetadata defines gRPC metadata with a value sourced from context.
type DynamicMetadata struct {
	// Key is the metadata key name.
	Key string `yaml:"key" json:"key"`

	// Source is the path to the value in context.
	// Examples: "jwt.claim.sub", "peer.address", "request.header.x-request-id".
	Source string `yaml:"source" json:"source"`
}

// StreamingTransformConfig contains configuration for streaming transformations.
type StreamingTransformConfig struct {
	// PerMessageTransform when true, applies transformation to each message.
	PerMessageTransform bool `yaml:"perMessageTransform,omitempty" json:"perMessageTransform,omitempty"`

	// Aggregate when true, aggregates all messages before transformation.
	Aggregate bool `yaml:"aggregate,omitempty" json:"aggregate,omitempty"`

	// FilterCondition is a CEL expression to filter streaming messages.
	FilterCondition string `yaml:"filterCondition,omitempty" json:"filterCondition,omitempty"`

	// BufferSize is the number of messages to buffer.
	BufferSize int `yaml:"bufferSize,omitempty" json:"bufferSize,omitempty"`

	// RateLimit is the maximum messages per second.
	RateLimit int `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`

	// MessageTimeout is the timeout for receiving each message.
	MessageTimeout Duration `yaml:"messageTimeout,omitempty" json:"messageTimeout,omitempty"`

	// TotalTimeout is the total timeout for the streaming operation.
	TotalTimeout Duration `yaml:"totalTimeout,omitempty" json:"totalTimeout,omitempty"`
}

// RepeatedFieldOperationType constants for repeated field operations.
const (
	// RepeatedFieldOpFilter filters elements based on condition.
	RepeatedFieldOpFilter = "filter"

	// RepeatedFieldOpSort sorts elements.
	RepeatedFieldOpSort = "sort"

	// RepeatedFieldOpLimit limits the number of elements.
	RepeatedFieldOpLimit = "limit"

	// RepeatedFieldOpDeduplicate removes duplicate elements.
	RepeatedFieldOpDeduplicate = "deduplicate"
)

// MapFieldOperationType constants for map field operations.
const (
	// MapFieldOpFilterKeys filters map by keys.
	MapFieldOpFilterKeys = "filterKeys"

	// MapFieldOpMerge merges values into the map.
	MapFieldOpMerge = "merge"
)

// SortOrder constants for sort operations.
const (
	// SortOrderAsc sorts in ascending order.
	SortOrderAsc = "asc"

	// SortOrderDesc sorts in descending order.
	SortOrderDesc = "desc"
)

// IsEmpty returns true if the GRPCTransformConfig has no configuration.
func (gtc *GRPCTransformConfig) IsEmpty() bool {
	if gtc == nil {
		return true
	}
	return gtc.Request.IsEmpty() && gtc.Response.IsEmpty()
}

// IsEmpty returns true if the GRPCRequestTransformConfig has no configuration.
func (grtc *GRPCRequestTransformConfig) IsEmpty() bool {
	if grtc == nil {
		return true
	}
	return len(grtc.InjectFieldMask) == 0 &&
		len(grtc.StaticMetadata) == 0 &&
		len(grtc.DynamicMetadata) == 0 &&
		len(grtc.InjectFields) == 0 &&
		len(grtc.RemoveFields) == 0 &&
		len(grtc.DefaultValues) == 0 &&
		!grtc.ValidateBeforeTransform &&
		grtc.InjectDeadline == 0 &&
		grtc.AuthorityOverride == ""
}

// IsEmpty returns true if the GRPCResponseTransformConfig has no configuration.
func (grtc *GRPCResponseTransformConfig) IsEmpty() bool {
	if grtc == nil {
		return true
	}
	return len(grtc.FieldMask) == 0 &&
		len(grtc.FieldMappings) == 0 &&
		len(grtc.RepeatedFieldOps) == 0 &&
		len(grtc.MapFieldOps) == 0 &&
		!grtc.PreserveUnknownFields &&
		grtc.StreamingConfig.IsEmpty() &&
		len(grtc.TrailerMetadata) == 0
}

// IsEmpty returns true if the StreamingTransformConfig has no configuration.
func (stc *StreamingTransformConfig) IsEmpty() bool {
	if stc == nil {
		return true
	}
	return !stc.PerMessageTransform &&
		!stc.Aggregate &&
		stc.FilterCondition == "" &&
		stc.BufferSize == 0 &&
		stc.RateLimit == 0 &&
		stc.MessageTimeout == 0 &&
		stc.TotalTimeout == 0
}
