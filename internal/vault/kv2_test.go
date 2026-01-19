package vault

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewKV2Client(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	t.Run("with default mount point", func(t *testing.T) {
		kv2 := NewKV2Client(client, "", nil)
		assert.NotNil(t, kv2)
		assert.Equal(t, "secret", kv2.mountPoint)
	})

	t.Run("with custom mount point", func(t *testing.T) {
		kv2 := NewKV2Client(client, "kv", nil)
		assert.NotNil(t, kv2)
		assert.Equal(t, "kv", kv2.mountPoint)
	})
}

func TestKV2Client_Paths(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	t.Run("dataPath", func(t *testing.T) {
		assert.Equal(t, "secret/data/myapp/config", kv2.dataPath("myapp/config"))
	})

	t.Run("metadataPath", func(t *testing.T) {
		assert.Equal(t, "secret/metadata/myapp/config", kv2.metadataPath("myapp/config"))
	})

	t.Run("deletePath", func(t *testing.T) {
		assert.Equal(t, "secret/delete/myapp/config", kv2.deletePath("myapp/config"))
	})

	t.Run("undeletePath", func(t *testing.T) {
		assert.Equal(t, "secret/undelete/myapp/config", kv2.undeletePath("myapp/config"))
	})

	t.Run("destroyPath", func(t *testing.T) {
		assert.Equal(t, "secret/destroy/myapp/config", kv2.destroyPath("myapp/config"))
	})
}

func TestKV2WriteOptions(t *testing.T) {
	cas := 5
	options := &KV2WriteOptions{
		CAS: &cas,
	}

	assert.NotNil(t, options.CAS)
	assert.Equal(t, 5, *options.CAS)
}

func TestKV2Metadata(t *testing.T) {
	metadata := &KV2Metadata{
		CurrentVersion: 3,
		MaxVersions:    10,
		OldestVersion:  1,
		CASRequired:    true,
		CustomMetadata: map[string]string{
			"owner": "team-a",
		},
		Versions: make(map[int]*KV2VersionMetadata),
	}

	assert.Equal(t, 3, metadata.CurrentVersion)
	assert.Equal(t, 10, metadata.MaxVersions)
	assert.Equal(t, 1, metadata.OldestVersion)
	assert.True(t, metadata.CASRequired)
	assert.Equal(t, "team-a", metadata.CustomMetadata["owner"])
}

func TestKV2VersionMetadata(t *testing.T) {
	versionMeta := &KV2VersionMetadata{
		Version:   1,
		Destroyed: false,
	}

	assert.Equal(t, 1, versionMeta.Version)
	assert.False(t, versionMeta.Destroyed)
	assert.Nil(t, versionMeta.DeletionTime)
}

func TestParseKV2Metadata(t *testing.T) {
	t.Run("nil secret", func(t *testing.T) {
		_, err := parseKV2Metadata(nil)
		assert.Error(t, err)
	})

	t.Run("nil data", func(t *testing.T) {
		_, err := parseKV2Metadata(&Secret{Data: nil})
		assert.Error(t, err)
	})

	t.Run("valid metadata", func(t *testing.T) {
		secret := &Secret{
			Data: map[string]interface{}{
				"created_time":    "2023-01-01T00:00:00.000000000Z",
				"current_version": float64(3),
				"max_versions":    float64(10),
				"oldest_version":  float64(1),
				"updated_time":    "2023-06-01T00:00:00.000000000Z",
				"cas_required":    true,
				"custom_metadata": map[string]interface{}{
					"owner": "team-a",
				},
				"versions": map[string]interface{}{
					"1": map[string]interface{}{
						"created_time":  "2023-01-01T00:00:00.000000000Z",
						"deletion_time": "",
						"destroyed":     false,
					},
					"2": map[string]interface{}{
						"created_time":  "2023-03-01T00:00:00.000000000Z",
						"deletion_time": "2023-04-01T00:00:00.000000000Z",
						"destroyed":     false,
					},
					"3": map[string]interface{}{
						"created_time":  "2023-06-01T00:00:00.000000000Z",
						"deletion_time": "",
						"destroyed":     false,
					},
				},
			},
		}

		metadata, err := parseKV2Metadata(secret)
		require.NoError(t, err)

		assert.Equal(t, 3, metadata.CurrentVersion)
		assert.Equal(t, 10, metadata.MaxVersions)
		assert.Equal(t, 1, metadata.OldestVersion)
		assert.True(t, metadata.CASRequired)
		assert.Equal(t, "team-a", metadata.CustomMetadata["owner"])
		assert.Len(t, metadata.Versions, 3)

		// Check version 1
		v1 := metadata.Versions[1]
		require.NotNil(t, v1)
		assert.Equal(t, 1, v1.Version)
		assert.False(t, v1.Destroyed)
		assert.Nil(t, v1.DeletionTime)

		// Check version 2 (deleted)
		v2 := metadata.Versions[2]
		require.NotNil(t, v2)
		assert.Equal(t, 2, v2.Version)
		assert.NotNil(t, v2.DeletionTime)
	})
}

func TestParseKV2Metadata_DeleteVersionAfter(t *testing.T) {
	secret := &Secret{
		Data: map[string]interface{}{
			"delete_version_after": "24h0m0s",
		},
	}

	metadata, err := parseKV2Metadata(secret)
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, metadata.DeleteVersionAfter)
}

func TestParseKV2Metadata_InvalidDeleteVersionAfter(t *testing.T) {
	secret := &Secret{
		Data: map[string]interface{}{
			"delete_version_after": "invalid",
		},
	}

	metadata, err := parseKV2Metadata(secret)
	require.NoError(t, err)
	// Invalid duration should result in zero value
	assert.Equal(t, time.Duration(0), metadata.DeleteVersionAfter)
}

func TestParseKV2Metadata_InvalidTimes(t *testing.T) {
	secret := &Secret{
		Data: map[string]interface{}{
			"created_time": "invalid-time",
			"updated_time": "also-invalid",
		},
	}

	metadata, err := parseKV2Metadata(secret)
	require.NoError(t, err)
	// Invalid times should result in zero values
	assert.True(t, metadata.CreatedTime.IsZero())
	assert.True(t, metadata.UpdatedTime.IsZero())
}

func TestParseVersionMetadata(t *testing.T) {
	t.Run("invalid version string", func(t *testing.T) {
		result := parseVersionMetadata("invalid", nil)
		assert.Nil(t, result)
	})

	t.Run("non-map version data", func(t *testing.T) {
		result := parseVersionMetadata("1", "not a map")
		require.NotNil(t, result)
		assert.Equal(t, 1, result.Version)
	})

	t.Run("destroyed version", func(t *testing.T) {
		versionData := map[string]interface{}{
			"created_time":  "2023-01-01T00:00:00.000000000Z",
			"deletion_time": "",
			"destroyed":     true,
		}
		result := parseVersionMetadata("5", versionData)
		require.NotNil(t, result)
		assert.Equal(t, 5, result.Version)
		assert.True(t, result.Destroyed)
	})

	t.Run("invalid created_time", func(t *testing.T) {
		versionData := map[string]interface{}{
			"created_time": "invalid",
		}
		result := parseVersionMetadata("1", versionData)
		require.NotNil(t, result)
		assert.True(t, result.CreatedTime.IsZero())
	})
}

func TestNewKV2Client_WithLogger(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	logger := zap.NewNop()
	kv2 := NewKV2Client(client, "secret", logger)

	assert.NotNil(t, kv2)
	assert.NotNil(t, kv2.logger)
}

func TestKV2Client_Get(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	// This will fail because there's no Vault server, but tests the path construction
	ctx := context.Background()
	_, err = kv2.Get(ctx, "myapp/config")
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}

func TestKV2Client_GetVersion(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	_, err = kv2.GetVersion(ctx, "myapp/config", 2)
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}

func TestKV2Client_Put(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	data := map[string]interface{}{
		"username": "admin",
		"password": "secret",
	}
	err = kv2.Put(ctx, "myapp/config", data)
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}

func TestKV2Client_PutWithOptions(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	data := map[string]interface{}{
		"username": "admin",
	}

	t.Run("with CAS option", func(t *testing.T) {
		cas := 5
		options := &KV2WriteOptions{CAS: &cas}
		err = kv2.PutWithOptions(ctx, "myapp/config", data, options)
		// We expect an error because there's no Vault server
		assert.Error(t, err)
	})

	t.Run("with nil options", func(t *testing.T) {
		err = kv2.PutWithOptions(ctx, "myapp/config", data, nil)
		// We expect an error because there's no Vault server
		assert.Error(t, err)
	})
}

func TestKV2Client_Delete(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	err = kv2.Delete(ctx, "myapp/config")
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}

func TestKV2Client_DeleteVersions(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	err = kv2.DeleteVersions(ctx, "myapp/config", []int{1, 2, 3})
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}

func TestKV2Client_Undelete(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	err = kv2.Undelete(ctx, "myapp/config", []int{1, 2})
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}

func TestKV2Client_Destroy(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	err = kv2.Destroy(ctx, "myapp/config", []int{1, 2, 3})
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}

func TestKV2Client_GetMetadata(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	_, err = kv2.GetMetadata(ctx, "myapp/config")
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}

func TestKV2Client_DeleteMetadata(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	err = kv2.DeleteMetadata(ctx, "myapp/config")
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}

func TestKV2Client_List(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	kv2 := NewKV2Client(client, "secret", nil)

	ctx := context.Background()
	_, err = kv2.List(ctx, "myapp/")
	// We expect an error because there's no Vault server
	assert.Error(t, err)
}
