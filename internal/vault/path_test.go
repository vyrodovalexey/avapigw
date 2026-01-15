package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPathBuilder(t *testing.T) {
	pb := NewPathBuilder("secret", "database", "uuid-123")

	assert.NotNil(t, pb)
	assert.Equal(t, "secret", pb.mountPoint)
	assert.Equal(t, "database", pb.instanceType)
	assert.Equal(t, "uuid-123", pb.instanceID)
}

func TestPathBuilder_Build(t *testing.T) {
	tests := []struct {
		name         string
		mountPoint   string
		instanceType string
		instanceID   string
		secretName   string
		expected     string
	}{
		{
			name:         "full path",
			mountPoint:   "secret",
			instanceType: "database",
			instanceID:   "uuid-123",
			secretName:   "credentials",
			expected:     "secret/database/uuid-123/credentials",
		},
		{
			name:         "without instance ID",
			mountPoint:   "secret",
			instanceType: "database",
			instanceID:   "",
			secretName:   "credentials",
			expected:     "secret/database/credentials",
		},
		{
			name:         "without instance type",
			mountPoint:   "secret",
			instanceType: "",
			instanceID:   "",
			secretName:   "credentials",
			expected:     "secret/credentials",
		},
		{
			name:         "mount point only",
			mountPoint:   "secret",
			instanceType: "",
			instanceID:   "",
			secretName:   "",
			expected:     "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := NewPathBuilder(tt.mountPoint, tt.instanceType, tt.instanceID)
			result := pb.Build(tt.secretName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPathBuilder_BuildKV2(t *testing.T) {
	tests := []struct {
		name         string
		mountPoint   string
		instanceType string
		instanceID   string
		secretName   string
		expected     string
	}{
		{
			name:         "full path",
			mountPoint:   "secret",
			instanceType: "database",
			instanceID:   "uuid-123",
			secretName:   "credentials",
			expected:     "secret/data/database/uuid-123/credentials",
		},
		{
			name:         "without instance ID",
			mountPoint:   "secret",
			instanceType: "database",
			instanceID:   "",
			secretName:   "credentials",
			expected:     "secret/data/database/credentials",
		},
		{
			name:         "without instance type",
			mountPoint:   "secret",
			instanceType: "",
			instanceID:   "",
			secretName:   "credentials",
			expected:     "secret/data/credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := NewPathBuilder(tt.mountPoint, tt.instanceType, tt.instanceID)
			result := pb.BuildKV2(tt.secretName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPathBuilder_BuildKV2Metadata(t *testing.T) {
	pb := NewPathBuilder("secret", "database", "uuid-123")
	result := pb.BuildKV2Metadata("credentials")
	assert.Equal(t, "secret/metadata/database/uuid-123/credentials", result)
}

func TestPathBuilder_BuildKV2Delete(t *testing.T) {
	pb := NewPathBuilder("secret", "database", "uuid-123")
	result := pb.BuildKV2Delete("credentials")
	assert.Equal(t, "secret/delete/database/uuid-123/credentials", result)
}

func TestPathBuilder_BuildKV2Destroy(t *testing.T) {
	pb := NewPathBuilder("secret", "database", "uuid-123")
	result := pb.BuildKV2Destroy("credentials")
	assert.Equal(t, "secret/destroy/database/uuid-123/credentials", result)
}

func TestPathBuilder_WithInstanceType(t *testing.T) {
	pb := NewPathBuilder("secret", "database", "uuid-123")
	newPb := pb.WithInstanceType("cache")

	assert.Equal(t, "cache", newPb.instanceType)
	assert.Equal(t, "database", pb.instanceType) // Original unchanged
}

func TestPathBuilder_WithInstanceID(t *testing.T) {
	pb := NewPathBuilder("secret", "database", "uuid-123")
	newPb := pb.WithInstanceID("uuid-456")

	assert.Equal(t, "uuid-456", newPb.instanceID)
	assert.Equal(t, "uuid-123", pb.instanceID) // Original unchanged
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		wantMountPoint   string
		wantInstanceType string
		wantInstanceID   string
		wantSecretName   string
		wantErr          bool
	}{
		{
			name:             "KV v2 full path",
			path:             "secret/data/database/uuid-123/credentials",
			wantMountPoint:   "secret",
			wantInstanceType: "database",
			wantInstanceID:   "uuid-123",
			wantSecretName:   "credentials",
			wantErr:          false,
		},
		{
			name:             "KV v2 metadata path",
			path:             "secret/metadata/database/uuid-123/credentials",
			wantMountPoint:   "secret",
			wantInstanceType: "database",
			wantInstanceID:   "uuid-123",
			wantSecretName:   "credentials",
			wantErr:          false,
		},
		{
			name:             "KV v1 path",
			path:             "secret/database/uuid-123/credentials",
			wantMountPoint:   "secret",
			wantInstanceType: "database",
			wantInstanceID:   "uuid-123",
			wantSecretName:   "credentials",
			wantErr:          false,
		},
		{
			name:             "simple path",
			path:             "secret/credentials",
			wantMountPoint:   "secret",
			wantInstanceType: "",
			wantInstanceID:   "",
			wantSecretName:   "credentials",
			wantErr:          false,
		},
		{
			name:             "mount point only",
			path:             "secret",
			wantMountPoint:   "secret",
			wantInstanceType: "",
			wantInstanceID:   "",
			wantSecretName:   "",
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mountPoint, instanceType, instanceID, secretName, err := ParsePath(tt.path)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantMountPoint, mountPoint)
			assert.Equal(t, tt.wantInstanceType, instanceType)
			assert.Equal(t, tt.wantInstanceID, instanceID)
			assert.Equal(t, tt.wantSecretName, secretName)
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"secret/path", "secret/path"},
		{"/secret/path", "secret/path"},
		{"secret/path/", "secret/path"},
		{"/secret/path/", "secret/path"},
		{"///secret/path///", "secret/path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizePath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct {
		name     string
		parts    []string
		expected string
	}{
		{
			name:     "simple join",
			parts:    []string{"secret", "data", "path"},
			expected: "secret/data/path",
		},
		{
			name:     "with empty parts",
			parts:    []string{"secret", "", "path"},
			expected: "secret/path",
		},
		{
			name:     "with slashes",
			parts:    []string{"/secret/", "/data/", "/path/"},
			expected: "secret/data/path",
		},
		{
			name:     "single part",
			parts:    []string{"secret"},
			expected: "secret",
		},
		{
			name:     "empty parts",
			parts:    []string{"", "", ""},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := JoinPath(tt.parts...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsKV2Path(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"secret/data/path", true},
		{"secret/metadata/path", true},
		{"secret/delete/path", true},
		{"secret/destroy/path", true},
		{"secret/path", false},
		{"secret", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := IsKV2Path(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertToKV2DataPath(t *testing.T) {
	tests := []struct {
		mountPoint string
		path       string
		expected   string
	}{
		{"secret", "mypath", "secret/data/mypath"},
		{"secret", "secret/mypath", "secret/data/mypath"},
		{"kv", "app/config", "kv/data/app/config"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := ConvertToKV2DataPath(tt.mountPoint, tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertToKV2MetadataPath(t *testing.T) {
	tests := []struct {
		mountPoint string
		path       string
		expected   string
	}{
		{"secret", "mypath", "secret/metadata/mypath"},
		{"secret", "data/mypath", "secret/metadata/mypath"},
		{"kv", "app/config", "kv/metadata/app/config"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := ConvertToKV2MetadataPath(tt.mountPoint, tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
