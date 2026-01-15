package vault

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// KV2Client provides a high-level interface for Vault KV v2 secrets engine.
type KV2Client struct {
	client     *Client
	mountPoint string
	logger     *zap.Logger
}

// NewKV2Client creates a new KV v2 client.
func NewKV2Client(client *Client, mountPoint string, logger *zap.Logger) *KV2Client {
	if mountPoint == "" {
		mountPoint = "secret"
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	return &KV2Client{
		client:     client,
		mountPoint: mountPoint,
		logger:     logger,
	}
}

// Get retrieves a secret from the KV v2 secrets engine.
func (c *KV2Client) Get(ctx context.Context, path string) (*Secret, error) {
	fullPath := c.dataPath(path)
	c.logger.Debug("Getting KV v2 secret", zap.String("path", fullPath))

	return c.client.ReadSecret(ctx, fullPath)
}

// GetVersion retrieves a specific version of a secret.
func (c *KV2Client) GetVersion(ctx context.Context, path string, version int) (*Secret, error) {
	fullPath := fmt.Sprintf("%s?version=%d", c.dataPath(path), version)
	c.logger.Debug("Getting KV v2 secret version",
		zap.String("path", path),
		zap.Int("version", version),
	)

	return c.client.ReadSecret(ctx, fullPath)
}

// Put writes a secret to the KV v2 secrets engine.
func (c *KV2Client) Put(ctx context.Context, path string, data map[string]interface{}) error {
	fullPath := c.dataPath(path)
	c.logger.Debug("Putting KV v2 secret", zap.String("path", fullPath))

	// KV v2 requires data to be wrapped in a "data" key
	wrappedData := map[string]interface{}{
		"data": data,
	}

	return c.client.WriteSecret(ctx, fullPath, wrappedData)
}

// PutWithOptions writes a secret with additional options.
func (c *KV2Client) PutWithOptions(
	ctx context.Context,
	path string,
	data map[string]interface{},
	options *KV2WriteOptions,
) error {
	fullPath := c.dataPath(path)
	c.logger.Debug("Putting KV v2 secret with options", zap.String("path", fullPath))

	wrappedData := map[string]interface{}{
		"data": data,
	}

	if options != nil {
		if options.CAS != nil {
			wrappedData["options"] = map[string]interface{}{
				"cas": *options.CAS,
			}
		}
	}

	return c.client.WriteSecret(ctx, fullPath, wrappedData)
}

// Delete soft-deletes the latest version of a secret.
func (c *KV2Client) Delete(ctx context.Context, path string) error {
	fullPath := c.dataPath(path)
	c.logger.Debug("Deleting KV v2 secret", zap.String("path", fullPath))

	return c.client.DeleteSecret(ctx, fullPath)
}

// DeleteVersions soft-deletes specific versions of a secret.
func (c *KV2Client) DeleteVersions(ctx context.Context, path string, versions []int) error {
	fullPath := c.deletePath(path)
	c.logger.Debug("Deleting KV v2 secret versions",
		zap.String("path", path),
		zap.Ints("versions", versions),
	)

	data := map[string]interface{}{
		"versions": versions,
	}

	return c.client.WriteSecret(ctx, fullPath, data)
}

// Undelete restores soft-deleted versions of a secret.
func (c *KV2Client) Undelete(ctx context.Context, path string, versions []int) error {
	fullPath := c.undeletePath(path)
	c.logger.Debug("Undeleting KV v2 secret versions",
		zap.String("path", path),
		zap.Ints("versions", versions),
	)

	data := map[string]interface{}{
		"versions": versions,
	}

	return c.client.WriteSecret(ctx, fullPath, data)
}

// Destroy permanently destroys specific versions of a secret.
func (c *KV2Client) Destroy(ctx context.Context, path string, versions []int) error {
	fullPath := c.destroyPath(path)
	c.logger.Debug("Destroying KV v2 secret versions",
		zap.String("path", path),
		zap.Ints("versions", versions),
	)

	data := map[string]interface{}{
		"versions": versions,
	}

	return c.client.WriteSecret(ctx, fullPath, data)
}

// GetMetadata retrieves the metadata for a secret.
func (c *KV2Client) GetMetadata(ctx context.Context, path string) (*KV2Metadata, error) {
	fullPath := c.metadataPath(path)
	c.logger.Debug("Getting KV v2 metadata", zap.String("path", fullPath))

	secret, err := c.client.ReadSecret(ctx, fullPath)
	if err != nil {
		return nil, err
	}

	return parseKV2Metadata(secret)
}

// DeleteMetadata permanently deletes all versions and metadata for a secret.
func (c *KV2Client) DeleteMetadata(ctx context.Context, path string) error {
	fullPath := c.metadataPath(path)
	c.logger.Debug("Deleting KV v2 metadata", zap.String("path", fullPath))

	return c.client.DeleteSecret(ctx, fullPath)
}

// List lists secrets at the specified path.
func (c *KV2Client) List(ctx context.Context, path string) ([]string, error) {
	fullPath := c.metadataPath(path)
	c.logger.Debug("Listing KV v2 secrets", zap.String("path", fullPath))

	return c.client.ListSecrets(ctx, fullPath)
}

// dataPath returns the data path for a secret.
func (c *KV2Client) dataPath(path string) string {
	return JoinPath(c.mountPoint, "data", path)
}

// metadataPath returns the metadata path for a secret.
func (c *KV2Client) metadataPath(path string) string {
	return JoinPath(c.mountPoint, "metadata", path)
}

// deletePath returns the delete path for a secret.
func (c *KV2Client) deletePath(path string) string {
	return JoinPath(c.mountPoint, "delete", path)
}

// undeletePath returns the undelete path for a secret.
func (c *KV2Client) undeletePath(path string) string {
	return JoinPath(c.mountPoint, "undelete", path)
}

// destroyPath returns the destroy path for a secret.
func (c *KV2Client) destroyPath(path string) string {
	return JoinPath(c.mountPoint, "destroy", path)
}

// KV2WriteOptions contains options for writing a KV v2 secret.
type KV2WriteOptions struct {
	// CAS is the Check-And-Set value. If set, the write will only succeed
	// if the current version matches this value.
	CAS *int
}

// KV2Metadata contains metadata for a KV v2 secret.
type KV2Metadata struct {
	// CreatedTime is when the secret was created.
	CreatedTime time.Time

	// CurrentVersion is the current version number.
	CurrentVersion int

	// MaxVersions is the maximum number of versions to keep.
	MaxVersions int

	// OldestVersion is the oldest version number.
	OldestVersion int

	// UpdatedTime is when the secret was last updated.
	UpdatedTime time.Time

	// Versions contains metadata for each version.
	Versions map[int]*KV2VersionMetadata

	// CustomMetadata contains custom metadata.
	CustomMetadata map[string]string

	// CASRequired indicates if CAS is required for writes.
	CASRequired bool

	// DeleteVersionAfter is the duration after which versions are deleted.
	DeleteVersionAfter time.Duration
}

// KV2VersionMetadata contains metadata for a specific version.
type KV2VersionMetadata struct {
	// CreatedTime is when this version was created.
	CreatedTime time.Time

	// DeletionTime is when this version was deleted (soft delete).
	DeletionTime *time.Time

	// Destroyed indicates if this version was permanently destroyed.
	Destroyed bool

	// Version is the version number.
	Version int
}

// parseKV2Metadata parses KV v2 metadata from a secret.
func parseKV2Metadata(secret *Secret) (*KV2Metadata, error) {
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no metadata found")
	}

	metadata := &KV2Metadata{
		Versions:       make(map[int]*KV2VersionMetadata),
		CustomMetadata: make(map[string]string),
	}

	// Parse created_time
	if createdTime, ok := secret.Data["created_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, createdTime); err == nil {
			metadata.CreatedTime = t
		}
	}

	// Parse current_version
	if currentVersion, ok := secret.Data["current_version"].(float64); ok {
		metadata.CurrentVersion = int(currentVersion)
	}

	// Parse max_versions
	if maxVersions, ok := secret.Data["max_versions"].(float64); ok {
		metadata.MaxVersions = int(maxVersions)
	}

	// Parse oldest_version
	if oldestVersion, ok := secret.Data["oldest_version"].(float64); ok {
		metadata.OldestVersion = int(oldestVersion)
	}

	// Parse updated_time
	if updatedTime, ok := secret.Data["updated_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, updatedTime); err == nil {
			metadata.UpdatedTime = t
		}
	}

	// Parse cas_required
	if casRequired, ok := secret.Data["cas_required"].(bool); ok {
		metadata.CASRequired = casRequired
	}

	// Parse delete_version_after
	if deleteAfter, ok := secret.Data["delete_version_after"].(string); ok {
		if d, err := time.ParseDuration(deleteAfter); err == nil {
			metadata.DeleteVersionAfter = d
		}
	}

	// Parse custom_metadata
	if customMeta, ok := secret.Data["custom_metadata"].(map[string]interface{}); ok {
		for k, v := range customMeta {
			if s, ok := v.(string); ok {
				metadata.CustomMetadata[k] = s
			}
		}
	}

	// Parse versions
	if versions, ok := secret.Data["versions"].(map[string]interface{}); ok {
		for versionStr, versionData := range versions {
			versionMeta := parseVersionMetadata(versionStr, versionData)
			if versionMeta != nil {
				metadata.Versions[versionMeta.Version] = versionMeta
			}
		}
	}

	return metadata, nil
}

// parseVersionMetadata parses a single version's metadata.
func parseVersionMetadata(versionStr string, versionData interface{}) *KV2VersionMetadata {
	var version int
	if _, err := fmt.Sscanf(versionStr, "%d", &version); err != nil {
		return nil
	}

	versionMeta := &KV2VersionMetadata{
		Version: version,
	}

	vData, ok := versionData.(map[string]interface{})
	if !ok {
		return versionMeta
	}

	if createdTime, ok := vData["created_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, createdTime); err == nil {
			versionMeta.CreatedTime = t
		}
	}

	if deletionTime, ok := vData["deletion_time"].(string); ok && deletionTime != "" {
		if t, err := time.Parse(time.RFC3339Nano, deletionTime); err == nil {
			versionMeta.DeletionTime = &t
		}
	}

	if destroyed, ok := vData["destroyed"].(bool); ok {
		versionMeta.Destroyed = destroyed
	}

	return versionMeta
}
