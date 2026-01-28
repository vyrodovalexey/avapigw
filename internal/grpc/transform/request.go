// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GRPCRequestTransformer implements RequestTransformer.
type GRPCRequestTransformer struct {
	logger          observability.Logger
	msgTransformer  *ProtobufTransformer
	metaTransformer *MetadataTransformerImpl
	fieldMaskFilter *FieldMaskFilter
}

// GRPCRequestTransformerOption is a functional option for configuring the request transformer.
type GRPCRequestTransformerOption func(*GRPCRequestTransformer)

// WithRequestMsgTransformer sets a custom message transformer.
func WithRequestMsgTransformer(t *ProtobufTransformer) GRPCRequestTransformerOption {
	return func(rt *GRPCRequestTransformer) {
		rt.msgTransformer = t
	}
}

// WithRequestMetaTransformer sets a custom metadata transformer.
func WithRequestMetaTransformer(t *MetadataTransformerImpl) GRPCRequestTransformerOption {
	return func(rt *GRPCRequestTransformer) {
		rt.metaTransformer = t
	}
}

// NewGRPCRequestTransformer creates a new gRPC request transformer.
func NewGRPCRequestTransformer(
	logger observability.Logger,
	opts ...GRPCRequestTransformerOption,
) *GRPCRequestTransformer {
	if logger == nil {
		logger = observability.NopLogger()
	}

	rt := &GRPCRequestTransformer{
		logger:          logger,
		msgTransformer:  NewProtobufTransformer(logger),
		metaTransformer: NewMetadataTransformer(logger),
		fieldMaskFilter: NewFieldMaskFilter(logger),
	}

	for _, opt := range opts {
		opt(rt)
	}

	return rt
}

// TransformRequest transforms a gRPC request.
func (t *GRPCRequestTransformer) TransformRequest(
	ctx context.Context,
	msg proto.Message,
	md metadata.MD,
	cfg *config.GRPCRequestTransformConfig,
) (proto.Message, metadata.MD, error) {
	if cfg == nil {
		return msg, md, nil
	}

	t.logTransformStart(cfg)

	// Validate request before transformation if configured
	if cfg.ValidateBeforeTransform {
		if err := t.ValidateRequest(ctx, msg); err != nil {
			return nil, nil, fmt.Errorf("request validation failed: %w", err)
		}
	}

	// Transform the message
	result, err := t.transformMessage(ctx, msg, cfg)
	if err != nil {
		return nil, nil, err
	}

	// Transform metadata
	resultMD, err := t.transformRequestMetadata(ctx, md, cfg)
	if err != nil {
		return nil, nil, err
	}

	t.logger.Debug("gRPC request transformation completed")

	return result, resultMD, nil
}

// logTransformStart logs the start of transformation with configuration details.
func (t *GRPCRequestTransformer) logTransformStart(cfg *config.GRPCRequestTransformConfig) {
	t.logger.Debug("starting gRPC request transformation",
		observability.Bool("hasInjectFieldMask", len(cfg.InjectFieldMask) > 0),
		observability.Bool("hasStaticMetadata", len(cfg.StaticMetadata) > 0),
		observability.Bool("hasDynamicMetadata", len(cfg.DynamicMetadata) > 0),
		observability.Bool("hasInjectFields", len(cfg.InjectFields) > 0),
		observability.Bool("hasRemoveFields", len(cfg.RemoveFields) > 0),
		observability.Bool("hasDefaultValues", len(cfg.DefaultValues) > 0))
}

// transformMessage applies message transformations.
func (t *GRPCRequestTransformer) transformMessage(
	ctx context.Context,
	msg proto.Message,
	cfg *config.GRPCRequestTransformConfig,
) (proto.Message, error) {
	if msg == nil {
		return nil, nil
	}

	result := msg

	// Set default values first
	result = t.applyDefaultValues(result, cfg.DefaultValues)

	// Remove fields
	result = t.applyRemoveFields(result, cfg.RemoveFields)

	// Inject fields
	if len(cfg.InjectFields) > 0 {
		var err error
		result, err = t.injectFieldsWithContext(ctx, result, cfg.InjectFields)
		if err != nil {
			return nil, fmt.Errorf("failed to inject fields: %w", err)
		}
	}

	// Inject FieldMask
	result = t.applyInjectFieldMask(result, cfg.InjectFieldMask)

	return result, nil
}

// applyDefaultValues sets default values for missing fields.
func (t *GRPCRequestTransformer) applyDefaultValues(
	msg proto.Message,
	defaults map[string]interface{},
) proto.Message {
	if len(defaults) == 0 {
		return msg
	}

	result, err := t.msgTransformer.SetDefaultValues(msg, defaults)
	if err != nil {
		t.logger.Warn("failed to set default values", observability.Error(err))
		return msg
	}
	return result
}

// applyRemoveFields removes specified fields from the message.
func (t *GRPCRequestTransformer) applyRemoveFields(msg proto.Message, fields []string) proto.Message {
	if len(fields) == 0 {
		return msg
	}

	result, err := t.msgTransformer.RemoveFields(msg, fields)
	if err != nil {
		t.logger.Warn("failed to remove fields", observability.Error(err))
		return msg
	}
	return result
}

// applyInjectFieldMask injects a FieldMask into the message.
func (t *GRPCRequestTransformer) applyInjectFieldMask(msg proto.Message, paths []string) proto.Message {
	if len(paths) == 0 {
		return msg
	}

	result, err := t.fieldMaskFilter.InjectFieldMask(msg, paths)
	if err != nil {
		t.logger.Warn("failed to inject field mask", observability.Error(err))
		return msg
	}
	return result
}

// transformRequestMetadata transforms the request metadata.
func (t *GRPCRequestTransformer) transformRequestMetadata(
	ctx context.Context,
	md metadata.MD,
	cfg *config.GRPCRequestTransformConfig,
) (metadata.MD, error) {
	resultMD := md

	// Transform metadata if needed
	if len(cfg.StaticMetadata) > 0 || len(cfg.DynamicMetadata) > 0 {
		var err error
		resultMD, err = t.metaTransformer.TransformMetadata(ctx, md, cfg)
		if err != nil {
			return nil, fmt.Errorf("metadata transformation failed: %w", err)
		}
	}

	// Override authority if configured
	if cfg.AuthorityOverride != "" {
		resultMD = t.OverrideAuthority(resultMD, cfg.AuthorityOverride)
	}

	return resultMD, nil
}

// injectFieldsWithContext injects fields with values resolved from context.
func (t *GRPCRequestTransformer) injectFieldsWithContext(
	ctx context.Context,
	msg proto.Message,
	injections []config.FieldInjection,
) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if len(injections) == 0 {
		return msg, nil
	}

	result := proto.Clone(msg)
	tctx := TransformContextFromContext(ctx)

	for _, injection := range injections {
		if injection.Field == "" {
			continue
		}

		var value interface{}

		if injection.Source != "" {
			// Resolve value from source
			resolved, err := t.metaTransformer.ExtractValue(ctx, injection.Source, tctx)
			if err != nil {
				t.logger.Debug("failed to extract value for injection",
					observability.String("field", injection.Field),
					observability.String("source", injection.Source),
					observability.Error(err))
				continue
			}
			value = resolved
		} else {
			value = injection.Value
		}

		if value == nil {
			continue
		}

		// Inject the field
		var err error
		result, err = t.msgTransformer.InjectFields(result, []config.FieldInjection{
			{Field: injection.Field, Value: value},
		})
		if err != nil {
			t.logger.Debug("failed to inject field",
				observability.String("field", injection.Field),
				observability.Error(err))
		}
	}

	return result, nil
}

// InjectDeadline injects a deadline into the context.
func (t *GRPCRequestTransformer) InjectDeadline(
	ctx context.Context,
	deadline time.Duration,
) (context.Context, context.CancelFunc) {
	if deadline <= 0 {
		return ctx, func() {}
	}

	newCtx, cancel := context.WithTimeout(ctx, deadline)

	t.logger.Debug("injected deadline into context",
		observability.Duration("deadline", deadline))

	return newCtx, cancel
}

// OverrideAuthority overrides the :authority pseudo-header.
func (t *GRPCRequestTransformer) OverrideAuthority(md metadata.MD, authority string) metadata.MD {
	if authority == "" {
		return md
	}

	if md == nil {
		md = metadata.MD{}
	}

	// Create a copy to avoid modifying the original
	result := md.Copy()
	result.Set(":authority", authority)

	t.logger.Debug("overrode authority",
		observability.String("authority", authority))

	return result
}

// ValidateRequest validates the request before transformation.
// This is a basic validation that checks for nil message.
// More sophisticated validation would use protobuf validation libraries.
func (t *GRPCRequestTransformer) ValidateRequest(ctx context.Context, msg proto.Message) error {
	if msg == nil {
		return ErrNilMessage
	}

	// Basic validation - check that the message is valid
	// More sophisticated validation could use protovalidate or similar
	msgReflect := msg.ProtoReflect()
	if !msgReflect.IsValid() {
		return NewTransformError("validation", "", "message is not valid")
	}

	t.logger.Debug("request validation passed")

	return nil
}

// TransformRequestWithDeadline transforms a request and injects a deadline.
// This is a convenience method that combines TransformRequest and InjectDeadline.
func (t *GRPCRequestTransformer) TransformRequestWithDeadline(
	ctx context.Context,
	msg proto.Message,
	md metadata.MD,
	cfg *config.GRPCRequestTransformConfig,
) (context.Context, proto.Message, metadata.MD, context.CancelFunc, error) {
	// Transform the request
	resultMsg, resultMD, err := t.TransformRequest(ctx, msg, md, cfg)
	if err != nil {
		return ctx, nil, nil, func() {}, err
	}

	// Inject deadline if configured
	var cancel context.CancelFunc
	resultCtx := ctx
	if cfg != nil && cfg.InjectDeadline > 0 {
		resultCtx, cancel = t.InjectDeadline(ctx, time.Duration(cfg.InjectDeadline))
	} else {
		cancel = func() {}
	}

	return resultCtx, resultMsg, resultMD, cancel, nil
}
