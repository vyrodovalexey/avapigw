// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// MetadataTransformerImpl implements MetadataTransformer.
type MetadataTransformerImpl struct {
	logger observability.Logger
}

// NewMetadataTransformer creates a new metadata transformer.
func NewMetadataTransformer(logger observability.Logger) *MetadataTransformerImpl {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &MetadataTransformerImpl{
		logger: logger,
	}
}

// TransformMetadata transforms incoming metadata.
func (t *MetadataTransformerImpl) TransformMetadata(
	ctx context.Context,
	md metadata.MD,
	cfg *config.GRPCRequestTransformConfig,
) (metadata.MD, error) {
	if cfg == nil {
		return md, nil
	}

	// Create a copy of the metadata
	result := md.Copy()

	// Inject static metadata
	if len(cfg.StaticMetadata) > 0 {
		result = t.InjectStaticMetadata(result, cfg.StaticMetadata)
	}

	// Inject dynamic metadata
	if len(cfg.DynamicMetadata) > 0 {
		tctx := TransformContextFromContext(ctx)
		var err error
		result, err = t.InjectDynamicMetadata(ctx, result, cfg.DynamicMetadata, tctx)
		if err != nil {
			return nil, err
		}
	}

	t.logger.Debug("transformed metadata",
		observability.Int("staticCount", len(cfg.StaticMetadata)),
		observability.Int("dynamicCount", len(cfg.DynamicMetadata)))

	return result, nil
}

// TransformTrailerMetadata transforms trailer metadata.
func (t *MetadataTransformerImpl) TransformTrailerMetadata(
	ctx context.Context,
	md metadata.MD,
	cfg *config.GRPCResponseTransformConfig,
) (metadata.MD, error) {
	if cfg == nil || len(cfg.TrailerMetadata) == 0 {
		return md, nil
	}

	// Create a copy of the metadata
	result := md.Copy()

	// Inject trailer metadata
	for key, value := range cfg.TrailerMetadata {
		result.Set(key, value)
		t.logger.Debug("added trailer metadata",
			observability.String("key", key))
	}

	t.logger.Debug("transformed trailer metadata",
		observability.Int("count", len(cfg.TrailerMetadata)))

	return result, nil
}

// InjectStaticMetadata injects static metadata values.
func (t *MetadataTransformerImpl) InjectStaticMetadata(
	md metadata.MD,
	static map[string]string,
) metadata.MD {
	if md == nil {
		md = metadata.MD{}
	}

	for key, value := range static {
		md.Set(key, value)
		t.logger.Debug("injected static metadata",
			observability.String("key", key))
	}

	return md
}

// InjectDynamicMetadata injects dynamic metadata values from context.
func (t *MetadataTransformerImpl) InjectDynamicMetadata(
	ctx context.Context,
	md metadata.MD,
	dynamic []config.DynamicMetadata,
	tctx *TransformContext,
) (metadata.MD, error) {
	if md == nil {
		md = metadata.MD{}
	}

	for _, dm := range dynamic {
		if dm.Key == "" || dm.Source == "" {
			continue
		}

		value, err := t.ExtractValue(ctx, dm.Source, tctx)
		if err != nil {
			t.logger.Debug("failed to extract dynamic metadata value",
				observability.String("key", dm.Key),
				observability.String("source", dm.Source),
				observability.Error(err))
			continue
		}

		if value != "" {
			md.Set(dm.Key, value)
			t.logger.Debug("injected dynamic metadata",
				observability.String("key", dm.Key),
				observability.String("source", dm.Source))
		}
	}

	return md, nil
}

// ExtractValue extracts a value from the source.
// Supported source formats:
//   - jwt.claim.<claim_name>: Extract JWT claim
//   - peer.address: Extract peer address
//   - request.header.<header_name>: Extract request header
//   - context.<key>: Extract context value
func (t *MetadataTransformerImpl) ExtractValue(
	ctx context.Context,
	source string,
	tctx *TransformContext,
) (string, error) {
	if tctx == nil {
		tctx = TransformContextFromContext(ctx)
	}

	parts := strings.SplitN(source, ".", 2)
	if len(parts) < 2 {
		return "", fmt.Errorf("%w: invalid source format: %s", ErrValueExtraction, source)
	}

	category := parts[0]
	path := parts[1]

	switch category {
	case "jwt":
		return t.extractJWTValue(tctx, path)
	case "peer":
		return t.extractPeerValue(tctx, path)
	case "request":
		return t.extractRequestValue(tctx, path)
	case "context":
		return t.extractContextValue(tctx, path)
	default:
		return "", fmt.Errorf("%w: unknown source category: %s", ErrValueExtraction, category)
	}
}

// extractJWTValue extracts a value from JWT claims.
func (t *MetadataTransformerImpl) extractJWTValue(tctx *TransformContext, path string) (string, error) {
	// Handle "claim.<claim_name>" format
	if strings.HasPrefix(path, "claim.") {
		claimName := strings.TrimPrefix(path, "claim.")
		if value, ok := tctx.Claims[claimName]; ok {
			return fmt.Sprintf("%v", value), nil
		}
		return "", nil
	}

	// Direct claim access
	if value, ok := tctx.Claims[path]; ok {
		return fmt.Sprintf("%v", value), nil
	}

	return "", nil
}

// extractPeerValue extracts a value from peer information.
func (t *MetadataTransformerImpl) extractPeerValue(tctx *TransformContext, path string) (string, error) {
	switch path {
	case "address":
		return tctx.PeerAddress, nil
	default:
		return "", fmt.Errorf("%w: unknown peer property: %s", ErrValueExtraction, path)
	}
}

// extractRequestValue extracts a value from request metadata.
func (t *MetadataTransformerImpl) extractRequestValue(tctx *TransformContext, path string) (string, error) {
	// Handle "header.<header_name>" format
	if strings.HasPrefix(path, "header.") {
		headerName := strings.TrimPrefix(path, "header.")
		if values := tctx.IncomingMetadata.Get(headerName); len(values) > 0 {
			return values[0], nil
		}
		return "", nil
	}

	return "", fmt.Errorf("%w: unknown request property: %s", ErrValueExtraction, path)
}

// extractContextValue extracts a value from the transform context.
func (t *MetadataTransformerImpl) extractContextValue(tctx *TransformContext, path string) (string, error) {
	switch path {
	case "request_id":
		return tctx.RequestID, nil
	case "trace_id":
		return tctx.TraceID, nil
	case "span_id":
		return tctx.SpanID, nil
	default:
		// Try custom data
		if value, ok := tctx.GetCustomData(path); ok {
			return fmt.Sprintf("%v", value), nil
		}
		return "", nil
	}
}

// CopyMetadata creates a deep copy of metadata.
func CopyMetadata(md metadata.MD) metadata.MD {
	if md == nil {
		return nil
	}
	return md.Copy()
}

// MergeMetadata merges multiple metadata into one.
// Later metadata values override earlier ones for the same key.
func MergeMetadata(mds ...metadata.MD) metadata.MD {
	result := metadata.MD{}

	for _, md := range mds {
		for key, values := range md {
			result[key] = append([]string{}, values...)
		}
	}

	return result
}

// FilterMetadata filters metadata to include only specified keys.
func FilterMetadata(md metadata.MD, allowKeys []string) metadata.MD {
	if md == nil || len(allowKeys) == 0 {
		return md
	}

	allowSet := make(map[string]bool)
	for _, key := range allowKeys {
		allowSet[strings.ToLower(key)] = true
	}

	result := metadata.MD{}
	for key, values := range md {
		if allowSet[strings.ToLower(key)] {
			result[key] = append([]string{}, values...)
		}
	}

	return result
}

// RemoveMetadataKeys removes specified keys from metadata.
func RemoveMetadataKeys(md metadata.MD, removeKeys []string) metadata.MD {
	if md == nil || len(removeKeys) == 0 {
		return md
	}

	result := md.Copy()
	for _, key := range removeKeys {
		delete(result, key)
		delete(result, strings.ToLower(key))
	}

	return result
}
