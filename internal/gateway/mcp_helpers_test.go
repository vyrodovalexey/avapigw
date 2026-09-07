package gateway

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

func TestDecodeParams(t *testing.T) {
	t.Parallel()

	t.Run("empty yields non-nil map", func(t *testing.T) {
		t.Parallel()
		p, err := decodeParams(nil)
		require.NoError(t, err)
		assert.NotNil(t, p)
		assert.Empty(t, p)
	})

	t.Run("object", func(t *testing.T) {
		t.Parallel()
		p, err := decodeParams(json.RawMessage(`{"name":"x"}`))
		require.NoError(t, err)
		assert.Equal(t, "x", p["name"])
	})

	t.Run("non-object errors", func(t *testing.T) {
		t.Parallel()
		_, err := decodeParams(json.RawMessage(`[1,2,3]`))
		assert.Error(t, err)
	})
}

func TestExtractMeta(t *testing.T) {
	t.Parallel()

	t.Run("absent yields empty map", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, extractMeta(map[string]any{}))
	})

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		meta := extractMeta(map[string]any{"_meta": map[string]any{"a": "b"}})
		assert.Equal(t, "b", meta["a"])
	})
}

func TestRawMeta(t *testing.T) {
	t.Parallel()

	t.Run("absent yields nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, rawMeta(map[string]any{}))
	})

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		raw := rawMeta(map[string]any{"_meta": map[string]any{"a": "b"}})
		assert.JSONEq(t, `{"a":"b"}`, string(raw))
	})
}

func TestMetaProtocolVersion(t *testing.T) {
	t.Parallel()

	assert.Empty(t, metaProtocolVersion(map[string]any{}))
	params := map[string]any{
		"_meta": map[string]any{protocol.MetaProtocolVersion: "2026-07-28"},
	}
	assert.Equal(t, "2026-07-28", metaProtocolVersion(params))
}

func TestPrimitiveName(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "weather", primitiveName(map[string]any{"name": "weather"}))
	assert.Equal(t, "file://x", primitiveName(map[string]any{"uri": "file://x"}))
	assert.Empty(t, primitiveName(map[string]any{}))
	assert.Equal(t, "weather", name0(map[string]any{"name": "weather"}))
}

func TestDenamespaceParams(t *testing.T) {
	t.Parallel()

	mapper, err := namespace.NewDefaultMapper(".")
	require.NoError(t, err)
	require.NoError(t, mapper.Register("up1", "svc"))

	// namespaced name "svc.weather" -> original "weather"
	out := denamespaceParams(mapper, map[string]any{"name": "svc.weather", "other": 1})
	assert.Equal(t, "weather", out["name"])
	assert.Equal(t, 1, out["other"])

	// unknown name preserved unchanged
	out2 := denamespaceParams(mapper, map[string]any{"name": "unknown"})
	assert.Equal(t, "unknown", out2["name"])

	// uri rewritten
	require.NoError(t, mapper.Register("up2", "res"))
	_, err = mapper.Namespace("up2", "file://x")
	require.NoError(t, err)
	out3 := denamespaceParams(mapper, map[string]any{"uri": "res.file://x"})
	assert.Equal(t, "file://x", out3["uri"])
}

func TestNegotiatedVersion(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "pinned",
		negotiatedVersion(config.MCPBackend{PinnedVersion: "pinned"}, "downstream"))
	assert.Equal(t, "downstream",
		negotiatedVersion(config.MCPBackend{}, "downstream"))
}

func TestBrokerableCaps(t *testing.T) {
	t.Parallel()

	caps := brokerableCaps()
	assert.True(t, caps["tools"])
	assert.True(t, caps["resources"])
	assert.True(t, caps["prompts"])
	assert.False(t, caps["logging"])
}
