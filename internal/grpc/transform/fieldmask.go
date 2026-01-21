// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// FieldMaskFilter filters messages based on FieldMask.
type FieldMaskFilter struct {
	logger observability.Logger
}

// NewFieldMaskFilter creates a new FieldMask filter.
func NewFieldMaskFilter(logger observability.Logger) *FieldMaskFilter {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &FieldMaskFilter{
		logger: logger,
	}
}

// Filter filters a message based on the provided FieldMask paths.
// Only fields specified in the paths will be retained in the result.
func (f *FieldMaskFilter) Filter(msg proto.Message, paths []string) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if len(paths) == 0 {
		return msg, nil
	}

	// Validate the field mask
	mask, err := f.CreateFieldMask(paths)
	if err != nil {
		return nil, err
	}

	if err := f.ValidateFieldMask(msg, mask); err != nil {
		f.logger.Warn("field mask validation warning",
			observability.Error(err))
		// Continue with valid paths
	}

	// Create a new message of the same type
	result := msg.ProtoReflect().New().Interface()

	// Build a path tree for efficient lookup
	pathTree := buildFieldPathTree(paths)

	// Copy only the specified fields
	f.copyFields(msg.ProtoReflect(), result.ProtoReflect(), pathTree)

	f.logger.Debug("filtered message with field mask",
		observability.Int("pathCount", len(paths)))

	return result, nil
}

// CreateFieldMask creates a FieldMask from paths.
func (f *FieldMaskFilter) CreateFieldMask(paths []string) (*fieldmaskpb.FieldMask, error) {
	if len(paths) == 0 {
		return &fieldmaskpb.FieldMask{}, nil
	}

	// Normalize paths
	normalizedPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		normalized := normalizePath(path)
		if normalized != "" {
			normalizedPaths = append(normalizedPaths, normalized)
		}
	}

	return &fieldmaskpb.FieldMask{
		Paths: normalizedPaths,
	}, nil
}

// ValidateFieldMask validates that the FieldMask paths are valid for the message.
func (f *FieldMaskFilter) ValidateFieldMask(msg proto.Message, mask *fieldmaskpb.FieldMask) error {
	if msg == nil {
		return ErrNilMessage
	}

	if mask == nil || len(mask.Paths) == 0 {
		return nil
	}

	msgDesc := msg.ProtoReflect().Descriptor()
	var invalidPaths []string

	for _, path := range mask.Paths {
		if !f.isValidPath(msgDesc, path) {
			invalidPaths = append(invalidPaths, path)
		}
	}

	if len(invalidPaths) > 0 {
		return NewFieldMaskError("", fmt.Sprintf("invalid paths: %v", invalidPaths))
	}

	return nil
}

// MergeWithFieldMask merges source into destination using the FieldMask.
// Only fields specified in the mask will be copied from source to destination.
func (f *FieldMaskFilter) MergeWithFieldMask(dst, src proto.Message, mask *fieldmaskpb.FieldMask) error {
	if dst == nil || src == nil {
		return ErrNilMessage
	}

	if mask == nil || len(mask.Paths) == 0 {
		return nil
	}

	pathTree := buildFieldPathTree(mask.Paths)
	f.copyFields(src.ProtoReflect(), dst.ProtoReflect(), pathTree)

	f.logger.Debug("merged messages with field mask",
		observability.Int("pathCount", len(mask.Paths)))

	return nil
}

// InjectFieldMask injects a FieldMask into the message if it has a field_mask field.
// This is useful for requests that support partial updates.
func (f *FieldMaskFilter) InjectFieldMask(msg proto.Message, paths []string) (proto.Message, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}

	if len(paths) == 0 {
		return msg, nil
	}

	result := proto.Clone(msg)
	msgReflect := result.ProtoReflect()

	// Look for a field_mask field
	fd := f.findFieldMaskField(msgReflect.Descriptor())
	if fd == nil {
		f.logger.Debug("no field_mask field found in message")
		return result, nil
	}

	// Create the FieldMask
	mask, err := f.CreateFieldMask(paths)
	if err != nil {
		return nil, err
	}

	// Set the field mask
	msgReflect.Set(fd, protoreflect.ValueOfMessage(mask.ProtoReflect()))

	f.logger.Debug("injected field mask into message",
		observability.Int("pathCount", len(paths)))

	return result, nil
}

// isValidPath checks if a path is valid for the given message descriptor.
func (f *FieldMaskFilter) isValidPath(desc protoreflect.MessageDescriptor, path string) bool {
	parts := strings.Split(path, ".")
	current := desc

	for _, part := range parts {
		fd := current.Fields().ByName(protoreflect.Name(part))
		if fd == nil {
			// Try JSON name
			fd = current.Fields().ByJSONName(part)
		}

		if fd == nil {
			return false
		}

		// If not the last part, navigate to nested message
		if fd.Kind() == protoreflect.MessageKind && !fd.IsMap() && !fd.IsList() {
			current = fd.Message()
		}
	}

	return true
}

// copyFields copies fields from source to destination based on the path tree.
func (f *FieldMaskFilter) copyFields(
	src, dst protoreflect.Message,
	pathTree map[string]interface{},
) {
	srcDesc := src.Descriptor()

	for fieldName, subtree := range pathTree {
		fd := srcDesc.Fields().ByName(protoreflect.Name(fieldName))
		if fd == nil {
			fd = srcDesc.Fields().ByJSONName(fieldName)
		}

		if fd == nil || !src.Has(fd) {
			continue
		}

		subtreeMap, hasSubtree := subtree.(map[string]interface{})

		if !hasSubtree || len(subtreeMap) == 0 {
			// Copy the entire field
			dst.Set(fd, src.Get(fd))
			continue
		}

		// Handle nested message
		if fd.Kind() == protoreflect.MessageKind && !fd.IsMap() && !fd.IsList() {
			srcNested := src.Get(fd).Message()
			dstNested := dst.Mutable(fd).Message()
			f.copyFields(srcNested, dstNested, subtreeMap)
		} else {
			// For non-message fields with subtree, just copy the field
			dst.Set(fd, src.Get(fd))
		}
	}
}

// findFieldMaskField finds a FieldMask field in the message descriptor.
func (f *FieldMaskFilter) findFieldMaskField(desc protoreflect.MessageDescriptor) protoreflect.FieldDescriptor {
	fields := desc.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.Kind() == protoreflect.MessageKind {
			if fd.Message().FullName() == "google.protobuf.FieldMask" {
				return fd
			}
		}
	}
	return nil
}

// buildFieldPathTree builds a tree structure from field paths.
// Example: ["user.name", "user.email", "items"] becomes:
//
//	{
//	  "user": {"name": {}, "email": {}},
//	  "items": {}
//	}
func buildFieldPathTree(paths []string) map[string]interface{} {
	tree := make(map[string]interface{})

	for _, path := range paths {
		parts := strings.Split(path, ".")
		current := tree

		for i, part := range parts {
			if _, exists := current[part]; !exists {
				current[part] = make(map[string]interface{})
			}

			if i < len(parts)-1 {
				current = current[part].(map[string]interface{})
			}
		}
	}

	return tree
}

// normalizePath normalizes a field path.
func normalizePath(path string) string {
	// Remove leading/trailing whitespace and dots
	path = strings.TrimSpace(path)
	path = strings.Trim(path, ".")

	// Remove consecutive dots
	for strings.Contains(path, "..") {
		path = strings.ReplaceAll(path, "..", ".")
	}

	return path
}
