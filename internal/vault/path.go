package vault

import (
	"fmt"
	"strings"
)

// PathBuilder builds Vault secret paths following the convention:
// {mount_point}/{instance_type}/{uuid}/{secret_name}
type PathBuilder struct {
	mountPoint   string
	instanceType string
	instanceID   string
}

// NewPathBuilder creates a new PathBuilder.
func NewPathBuilder(mountPoint, instanceType, instanceID string) *PathBuilder {
	return &PathBuilder{
		mountPoint:   mountPoint,
		instanceType: instanceType,
		instanceID:   instanceID,
	}
}

// Build builds a path for a KV v1 secret.
func (b *PathBuilder) Build(secretName string) string {
	parts := []string{b.mountPoint}

	if b.instanceType != "" {
		parts = append(parts, b.instanceType)
	}

	if b.instanceID != "" {
		parts = append(parts, b.instanceID)
	}

	if secretName != "" {
		parts = append(parts, secretName)
	}

	return strings.Join(parts, "/")
}

// BuildKV2 builds a path for a KV v2 secret (includes "data" prefix).
func (b *PathBuilder) BuildKV2(secretName string) string {
	parts := []string{b.mountPoint, "data"}

	if b.instanceType != "" {
		parts = append(parts, b.instanceType)
	}

	if b.instanceID != "" {
		parts = append(parts, b.instanceID)
	}

	if secretName != "" {
		parts = append(parts, secretName)
	}

	return strings.Join(parts, "/")
}

// BuildKV2Metadata builds a metadata path for a KV v2 secret.
func (b *PathBuilder) BuildKV2Metadata(secretName string) string {
	parts := []string{b.mountPoint, "metadata"}

	if b.instanceType != "" {
		parts = append(parts, b.instanceType)
	}

	if b.instanceID != "" {
		parts = append(parts, b.instanceID)
	}

	if secretName != "" {
		parts = append(parts, secretName)
	}

	return strings.Join(parts, "/")
}

// BuildKV2Delete builds a delete path for a KV v2 secret.
func (b *PathBuilder) BuildKV2Delete(secretName string) string {
	parts := []string{b.mountPoint, "delete"}

	if b.instanceType != "" {
		parts = append(parts, b.instanceType)
	}

	if b.instanceID != "" {
		parts = append(parts, b.instanceID)
	}

	if secretName != "" {
		parts = append(parts, secretName)
	}

	return strings.Join(parts, "/")
}

// BuildKV2Destroy builds a destroy path for a KV v2 secret.
func (b *PathBuilder) BuildKV2Destroy(secretName string) string {
	parts := []string{b.mountPoint, "destroy"}

	if b.instanceType != "" {
		parts = append(parts, b.instanceType)
	}

	if b.instanceID != "" {
		parts = append(parts, b.instanceID)
	}

	if secretName != "" {
		parts = append(parts, secretName)
	}

	return strings.Join(parts, "/")
}

// WithInstanceType returns a new PathBuilder with the specified instance type.
func (b *PathBuilder) WithInstanceType(instanceType string) *PathBuilder {
	return &PathBuilder{
		mountPoint:   b.mountPoint,
		instanceType: instanceType,
		instanceID:   b.instanceID,
	}
}

// WithInstanceID returns a new PathBuilder with the specified instance ID.
func (b *PathBuilder) WithInstanceID(instanceID string) *PathBuilder {
	return &PathBuilder{
		mountPoint:   b.mountPoint,
		instanceType: b.instanceType,
		instanceID:   instanceID,
	}
}

// ParsePath parses a Vault path and extracts components.
func ParsePath(path string) (mountPoint, instanceType, instanceID, secretName string, err error) {
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		return "", "", "", "", fmt.Errorf("invalid path: %s", path)
	}

	// Handle KV v2 paths (skip "data", "metadata", etc.)
	startIdx := 0
	if len(parts) > 1 {
		switch parts[1] {
		case "data", "metadata", "delete", "destroy":
			mountPoint = parts[0]
			startIdx = 2
		default:
			mountPoint = parts[0]
			startIdx = 1
		}
	} else {
		mountPoint = parts[0]
		return mountPoint, "", "", "", nil
	}

	remaining := parts[startIdx:]
	switch len(remaining) {
	case 0:
		// Just mount point
	case 1:
		secretName = remaining[0]
	case 2:
		instanceType = remaining[0]
		secretName = remaining[1]
	default:
		instanceType = remaining[0]
		instanceID = remaining[1]
		secretName = strings.Join(remaining[2:], "/")
	}

	return mountPoint, instanceType, instanceID, secretName, nil
}

// NormalizePath normalizes a Vault path by removing leading/trailing slashes.
func NormalizePath(path string) string {
	return strings.Trim(path, "/")
}

// JoinPath joins path components.
func JoinPath(parts ...string) string {
	nonEmpty := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, strings.Trim(p, "/"))
		}
	}
	return strings.Join(nonEmpty, "/")
}

// IsKV2Path returns true if the path appears to be a KV v2 path.
func IsKV2Path(path string) bool {
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return false
	}
	switch parts[1] {
	case "data", "metadata", "delete", "destroy":
		return true
	}
	return false
}

// ConvertToKV2DataPath converts a path to a KV v2 data path.
func ConvertToKV2DataPath(mountPoint, path string) string {
	path = strings.TrimPrefix(path, mountPoint+"/")
	return JoinPath(mountPoint, "data", path)
}

// ConvertToKV2MetadataPath converts a path to a KV v2 metadata path.
func ConvertToKV2MetadataPath(mountPoint, path string) string {
	path = strings.TrimPrefix(path, mountPoint+"/")
	// Remove "data/" prefix if present
	path = strings.TrimPrefix(path, "data/")
	return JoinPath(mountPoint, "metadata", path)
}
