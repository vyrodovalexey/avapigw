// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewFieldMaskFilter(t *testing.T) {
	tests := []struct {
		name   string
		logger observability.Logger
	}{
		{
			name:   "with logger",
			logger: observability.NopLogger(),
		},
		{
			name:   "nil logger",
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFieldMaskFilter(tt.logger)
			assert.NotNil(t, filter)
		})
	}
}

func TestFieldMaskFilter_CreateFieldMask(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	tests := []struct {
		name      string
		paths     []string
		wantPaths []string
	}{
		{
			name:      "single path",
			paths:     []string{"name"},
			wantPaths: []string{"name"},
		},
		{
			name:      "multiple paths",
			paths:     []string{"name", "email", "age"},
			wantPaths: []string{"name", "email", "age"},
		},
		{
			name:      "nested paths",
			paths:     []string{"user.name", "user.email"},
			wantPaths: []string{"user.name", "user.email"},
		},
		{
			name:      "empty paths",
			paths:     []string{},
			wantPaths: []string{},
		},
		{
			name:      "nil paths",
			paths:     nil,
			wantPaths: []string{},
		},
		{
			name:      "paths with whitespace",
			paths:     []string{"  name  ", "  email  "},
			wantPaths: []string{"name", "email"},
		},
		{
			name:      "paths with leading/trailing dots",
			paths:     []string{".name.", ".email."},
			wantPaths: []string{"name", "email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mask, err := filter.CreateFieldMask(tt.paths)

			require.NoError(t, err)
			require.NotNil(t, mask)

			if len(tt.wantPaths) == 0 {
				assert.Empty(t, mask.Paths)
			} else {
				assert.Equal(t, tt.wantPaths, mask.Paths)
			}
		})
	}
}

func TestFieldMaskFilter_ValidateFieldMask_NilMessage(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	mask := &fieldmaskpb.FieldMask{Paths: []string{"name"}}
	err := filter.ValidateFieldMask(nil, mask)

	assert.ErrorIs(t, err, ErrNilMessage)
}

func TestFieldMaskFilter_ValidateFieldMask_NilMask(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	// Create a simple test message (using FieldMask itself as a test message)
	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}

	err := filter.ValidateFieldMask(msg, nil)
	assert.NoError(t, err)
}

func TestFieldMaskFilter_ValidateFieldMask_EmptyMask(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	mask := &fieldmaskpb.FieldMask{Paths: []string{}}

	err := filter.ValidateFieldMask(msg, mask)
	assert.NoError(t, err)
}

func TestFieldMaskFilter_Filter_NilMessage(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	result, err := filter.Filter(nil, []string{"name"})

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestFieldMaskFilter_Filter_EmptyPaths(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	result, err := filter.Filter(msg, []string{})

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestFieldMaskFilter_Filter_NilPaths(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	result, err := filter.Filter(msg, nil)

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestFieldMaskFilter_MergeWithFieldMask_NilMessages(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())
	mask := &fieldmaskpb.FieldMask{Paths: []string{"paths"}}

	// Nil destination
	err := filter.MergeWithFieldMask(nil, &fieldmaskpb.FieldMask{}, mask)
	assert.ErrorIs(t, err, ErrNilMessage)

	// Nil source
	err = filter.MergeWithFieldMask(&fieldmaskpb.FieldMask{}, nil, mask)
	assert.ErrorIs(t, err, ErrNilMessage)
}

func TestFieldMaskFilter_MergeWithFieldMask_NilMask(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	dst := &fieldmaskpb.FieldMask{Paths: []string{"dst"}}
	src := &fieldmaskpb.FieldMask{Paths: []string{"src"}}

	err := filter.MergeWithFieldMask(dst, src, nil)
	assert.NoError(t, err)

	// Destination should be unchanged
	assert.Equal(t, []string{"dst"}, dst.Paths)
}

func TestFieldMaskFilter_MergeWithFieldMask_EmptyMask(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	dst := &fieldmaskpb.FieldMask{Paths: []string{"dst"}}
	src := &fieldmaskpb.FieldMask{Paths: []string{"src"}}
	mask := &fieldmaskpb.FieldMask{Paths: []string{}}

	err := filter.MergeWithFieldMask(dst, src, mask)
	assert.NoError(t, err)
}

func TestFieldMaskFilter_InjectFieldMask_NilMessage(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	result, err := filter.InjectFieldMask(nil, []string{"name"})

	assert.ErrorIs(t, err, ErrNilMessage)
	assert.Nil(t, result)
}

func TestFieldMaskFilter_InjectFieldMask_EmptyPaths(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	msg := &fieldmaskpb.FieldMask{Paths: []string{"test"}}
	result, err := filter.InjectFieldMask(msg, []string{})

	require.NoError(t, err)
	assert.Equal(t, msg, result)
}

func TestBuildFieldPathTree(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		check func(t *testing.T, tree map[string]interface{})
	}{
		{
			name:  "single path",
			paths: []string{"name"},
			check: func(t *testing.T, tree map[string]interface{}) {
				assert.Contains(t, tree, "name")
			},
		},
		{
			name:  "nested path",
			paths: []string{"user.name"},
			check: func(t *testing.T, tree map[string]interface{}) {
				assert.Contains(t, tree, "user")
				userTree := tree["user"].(map[string]interface{})
				assert.Contains(t, userTree, "name")
			},
		},
		{
			name:  "multiple nested paths",
			paths: []string{"user.name", "user.email"},
			check: func(t *testing.T, tree map[string]interface{}) {
				assert.Contains(t, tree, "user")
				userTree := tree["user"].(map[string]interface{})
				assert.Contains(t, userTree, "name")
				assert.Contains(t, userTree, "email")
			},
		},
		{
			name:  "deeply nested path",
			paths: []string{"a.b.c.d"},
			check: func(t *testing.T, tree map[string]interface{}) {
				assert.Contains(t, tree, "a")
				aTree := tree["a"].(map[string]interface{})
				assert.Contains(t, aTree, "b")
				bTree := aTree["b"].(map[string]interface{})
				assert.Contains(t, bTree, "c")
				cTree := bTree["c"].(map[string]interface{})
				assert.Contains(t, cTree, "d")
			},
		},
		{
			name:  "empty paths",
			paths: []string{},
			check: func(t *testing.T, tree map[string]interface{}) {
				assert.Empty(t, tree)
			},
		},
		{
			name:  "mixed paths",
			paths: []string{"name", "user.email", "items"},
			check: func(t *testing.T, tree map[string]interface{}) {
				assert.Contains(t, tree, "name")
				assert.Contains(t, tree, "user")
				assert.Contains(t, tree, "items")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := buildFieldPathTree(tt.paths)
			tt.check(t, tree)
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "simple path",
			path: "name",
			want: "name",
		},
		{
			name: "path with whitespace",
			path: "  name  ",
			want: "name",
		},
		{
			name: "path with leading dot",
			path: ".name",
			want: "name",
		},
		{
			name: "path with trailing dot",
			path: "name.",
			want: "name",
		},
		{
			name: "path with leading and trailing dots",
			path: ".name.",
			want: "name",
		},
		{
			name: "path with consecutive dots",
			path: "user..name",
			want: "user.name",
		},
		{
			name: "path with multiple consecutive dots",
			path: "user...name",
			want: "user.name",
		},
		{
			name: "nested path",
			path: "user.name",
			want: "user.name",
		},
		{
			name: "empty path",
			path: "",
			want: "",
		},
		{
			name: "only dots",
			path: "...",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePath(tt.path)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestFieldMaskFilter_Filter_WithFieldMaskMessage(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	// Use FieldMask as a test message since it has a "paths" field
	msg := &fieldmaskpb.FieldMask{Paths: []string{"test1", "test2", "test3"}}

	// Filter to only include "paths" field
	result, err := filter.Filter(msg, []string{"paths"})

	require.NoError(t, err)
	require.NotNil(t, result)

	// Result should be a new message with only the paths field
	resultMask, ok := result.(*fieldmaskpb.FieldMask)
	require.True(t, ok)
	assert.Equal(t, []string{"test1", "test2", "test3"}, resultMask.Paths)
}

func TestFieldMaskFilter_MergeWithFieldMask_WithFieldMaskMessage(t *testing.T) {
	filter := NewFieldMaskFilter(observability.NopLogger())

	dst := &fieldmaskpb.FieldMask{Paths: []string{"original"}}
	src := &fieldmaskpb.FieldMask{Paths: []string{"new1", "new2"}}
	mask := &fieldmaskpb.FieldMask{Paths: []string{"paths"}}

	err := filter.MergeWithFieldMask(dst, src, mask)
	require.NoError(t, err)

	// Destination should have source's paths
	assert.Equal(t, []string{"new1", "new2"}, dst.Paths)
}
