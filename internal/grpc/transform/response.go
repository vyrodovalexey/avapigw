// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GRPCResponseTransformer implements ResponseTransformer.
type GRPCResponseTransformer struct {
	logger          observability.Logger
	msgTransformer  *ProtobufTransformer
	fieldMaskFilter *FieldMaskFilter
}

// GRPCResponseTransformerOption is a functional option for configuring the response transformer.
type GRPCResponseTransformerOption func(*GRPCResponseTransformer)

// WithResponseMsgTransformer sets a custom message transformer.
func WithResponseMsgTransformer(t *ProtobufTransformer) GRPCResponseTransformerOption {
	return func(rt *GRPCResponseTransformer) {
		rt.msgTransformer = t
	}
}

// WithResponseFieldMaskFilter sets a custom field mask filter.
func WithResponseFieldMaskFilter(f *FieldMaskFilter) GRPCResponseTransformerOption {
	return func(rt *GRPCResponseTransformer) {
		rt.fieldMaskFilter = f
	}
}

// NewGRPCResponseTransformer creates a new gRPC response transformer.
func NewGRPCResponseTransformer(
	logger observability.Logger,
	opts ...GRPCResponseTransformerOption,
) *GRPCResponseTransformer {
	if logger == nil {
		logger = observability.NopLogger()
	}

	rt := &GRPCResponseTransformer{
		logger:          logger,
		msgTransformer:  NewProtobufTransformer(logger),
		fieldMaskFilter: NewFieldMaskFilter(logger),
	}

	for _, opt := range opts {
		opt(rt)
	}

	return rt
}

// TransformResponse transforms a gRPC response.
func (t *GRPCResponseTransformer) TransformResponse(
	ctx context.Context,
	msg proto.Message,
	cfg *config.GRPCResponseTransformConfig,
) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if cfg == nil {
		return msg, nil
	}

	t.logger.Debug("starting gRPC response transformation",
		observability.Bool("hasFieldMask", len(cfg.FieldMask) > 0),
		observability.Bool("hasFieldMappings", len(cfg.FieldMappings) > 0),
		observability.Bool("hasRepeatedFieldOps", len(cfg.RepeatedFieldOps) > 0),
		observability.Bool("hasMapFieldOps", len(cfg.MapFieldOps) > 0))

	// Create a transform config for the message transformer
	transformCfg := &config.GRPCTransformConfig{
		Response: cfg,
	}

	result, err := t.msgTransformer.TransformMessage(ctx, msg, transformCfg)
	if err != nil {
		return nil, fmt.Errorf("message transformation failed: %w", err)
	}

	t.logger.Debug("gRPC response transformation completed")

	return result, nil
}

// MergeResponses merges multiple responses from different backends.
// Supported strategies:
//   - "first": Return the first non-nil response
//   - "last": Return the last non-nil response
//   - "merge": Merge all responses (for messages with repeated fields)
func (t *GRPCResponseTransformer) MergeResponses(
	ctx context.Context,
	responses []proto.Message,
	strategy string,
) (proto.Message, error) {
	if len(responses) == 0 {
		return nil, ErrNilMessage
	}

	// Filter out nil responses
	validResponses := make([]proto.Message, 0, len(responses))
	for _, resp := range responses {
		if resp != nil {
			validResponses = append(validResponses, resp)
		}
	}

	if len(validResponses) == 0 {
		return nil, ErrNilMessage
	}

	if len(validResponses) == 1 {
		return validResponses[0], nil
	}

	switch strategy {
	case "first":
		return validResponses[0], nil
	case "last":
		return validResponses[len(validResponses)-1], nil
	case "merge", "":
		return t.mergeMessages(validResponses)
	default:
		return nil, NewTransformError("merge", "", fmt.Sprintf("unknown merge strategy: %s", strategy))
	}
}

// mergeMessages merges multiple protobuf messages.
// For repeated fields, elements are combined.
// For singular fields, later values override earlier ones.
func (t *GRPCResponseTransformer) mergeMessages(messages []proto.Message) (proto.Message, error) {
	if len(messages) == 0 {
		return nil, ErrNilMessage
	}

	// Start with a clone of the first message
	result := proto.Clone(messages[0])
	resultReflect := result.ProtoReflect()

	// Merge subsequent messages
	for i := 1; i < len(messages); i++ {
		srcReflect := messages[i].ProtoReflect()
		t.mergeMessageFields(resultReflect, srcReflect)
	}

	t.logger.Debug("merged responses",
		observability.Int("responseCount", len(messages)))

	return result, nil
}

// mergeMessageFields merges fields from source into destination.
func (t *GRPCResponseTransformer) mergeMessageFields(
	dst, src protoreflect.Message,
) {
	srcDesc := src.Descriptor()
	fields := srcDesc.Fields()

	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)

		if !src.Has(fd) {
			continue
		}

		srcValue := src.Get(fd)
		t.mergeField(dst, fd, srcValue)
	}
}

// mergeField merges a single field from source to destination.
func (t *GRPCResponseTransformer) mergeField(
	dst protoreflect.Message,
	fd protoreflect.FieldDescriptor,
	srcValue protoreflect.Value,
) {
	switch {
	case fd.IsList():
		// For repeated fields, append elements
		t.mergeRepeatedField(dst, fd, srcValue.List())
	case fd.IsMap():
		// For map fields, merge entries
		t.mergeMapField(dst, fd, srcValue.Map())
	case fd.Kind() == protoreflect.MessageKind:
		// For nested messages, recursively merge
		if dst.Has(fd) {
			t.mergeMessageFields(dst.Mutable(fd).Message(), srcValue.Message())
		} else {
			dst.Set(fd, srcValue)
		}
	default:
		// For scalar fields, override with source value
		dst.Set(fd, srcValue)
	}
}

// mergeRepeatedField appends elements from source list to destination.
func (t *GRPCResponseTransformer) mergeRepeatedField(
	dst protoreflect.Message,
	fd protoreflect.FieldDescriptor,
	srcList protoreflect.List,
) {
	dstList := dst.Mutable(fd).List()

	for i := 0; i < srcList.Len(); i++ {
		dstList.Append(srcList.Get(i))
	}
}

// mergeMapField merges entries from source map into destination.
func (t *GRPCResponseTransformer) mergeMapField(
	dst protoreflect.Message,
	fd protoreflect.FieldDescriptor,
	srcMap protoreflect.Map,
) {
	dstMap := dst.Mutable(fd).Map()

	srcMap.Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
		dstMap.Set(key, value)
		return true
	})
}

// TransformStreamingResponse transforms a streaming response message.
// This is a convenience method for streaming scenarios.
func (t *GRPCResponseTransformer) TransformStreamingResponse(
	ctx context.Context,
	msg proto.Message,
	cfg *config.GRPCResponseTransformConfig,
	sequence int,
) (proto.Message, error) {
	t.logger.Debug("transforming streaming response",
		observability.Int("sequence", sequence))

	return t.TransformResponse(ctx, msg, cfg)
}

// FilterResponseFields filters response fields based on a FieldMask.
// This is a convenience method that wraps the FieldMaskFilter.
func (t *GRPCResponseTransformer) FilterResponseFields(
	msg proto.Message,
	paths []string,
) (proto.Message, error) {
	return t.fieldMaskFilter.Filter(msg, paths)
}

// ApplyResponseTransformations applies a series of transformations to a response.
// This method applies transformations in the following order:
// 1. FieldMask filtering
// 2. Field mappings
// 3. Repeated field operations
// 4. Map field operations
func (t *GRPCResponseTransformer) ApplyResponseTransformations(
	ctx context.Context,
	msg proto.Message,
	cfg *config.GRPCResponseTransformConfig,
) (proto.Message, error) {
	return t.TransformResponse(ctx, msg, cfg)
}
