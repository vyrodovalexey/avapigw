package meta

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

func TestDecode(t *testing.T) {
	t.Parallel()

	t.Run("empty yields non-nil empty map", func(t *testing.T) {
		t.Parallel()
		m, err := Decode(nil)
		require.NoError(t, err)
		require.NotNil(t, m)
		assert.Empty(t, m)
	})

	t.Run("zero-length raw", func(t *testing.T) {
		t.Parallel()
		m, err := Decode(json.RawMessage{})
		require.NoError(t, err)
		assert.Empty(t, m)
	})

	t.Run("valid object", func(t *testing.T) {
		t.Parallel()
		m, err := Decode(json.RawMessage(`{"a":"b","n":1}`))
		require.NoError(t, err)
		assert.Len(t, m, 2)
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()
		m, err := Decode(json.RawMessage(`{bad}`))
		require.Error(t, err)
		assert.Nil(t, m)
		assert.Contains(t, err.Error(), "decode _meta")
	})
}

func TestEncode(t *testing.T) {
	t.Parallel()

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		m := Meta{"k": json.RawMessage(`"v"`)}
		raw, err := m.Encode()
		require.NoError(t, err)
		assert.JSONEq(t, `{"k":"v"}`, string(raw))
	})

	t.Run("invalid raw value fails to marshal", func(t *testing.T) {
		t.Parallel()
		// A RawMessage that is not valid JSON causes json.Marshal to error.
		m := Meta{"k": json.RawMessage(`{bad`)}
		_, err := m.Encode()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encode _meta")
	})
}

func TestNarrowCapabilities(t *testing.T) {
	t.Parallel()
	client := map[string]json.RawMessage{
		"tools":       json.RawMessage(`{}`),
		"elicitation": json.RawMessage(`{"x":1}`),
		"sampling":    json.RawMessage(`{}`),
	}
	brokerable := map[string]bool{
		"tools":    true,
		"sampling": true,
		// "roots" is brokerable but NOT declared by client => must never appear.
		"roots": true,
	}
	narrowed := NarrowCapabilities(client, brokerable)

	// Intersection only.
	assert.Contains(t, narrowed, "tools")
	assert.Contains(t, narrowed, "sampling")
	// Client had elicitation but hub can't broker it.
	assert.NotContains(t, narrowed, "elicitation")
	// Brokerable but undeclared: never widened.
	assert.NotContains(t, narrowed, "roots")
	// Value preserved verbatim.
	assert.JSONEq(t, `{}`, string(narrowed["tools"]))

	t.Run("empty client", func(t *testing.T) {
		t.Parallel()
		out := NarrowCapabilities(map[string]json.RawMessage{}, brokerable)
		assert.Empty(t, out)
	})
}

func TestBuildUpstreamMeta(t *testing.T) {
	t.Parallel()

	downstream := Meta{
		protocol.MetaProtocolVersion:    json.RawMessage(`"2025-11-25"`),
		protocol.MetaClientCapabilities: json.RawMessage(`{"tools":{},"elicitation":{}}`),
		protocol.MetaClientInfo:         json.RawMessage(`{"name":"downstream-client"}`),
		protocol.MetaServerInfo:         json.RawMessage(`{"name":"downstream-server"}`),
		protocol.MetaLogLevel:           json.RawMessage(`"debug"`),
		protocol.MetaTraceparent:        json.RawMessage(`"00-trace-span-01"`),
		protocol.MetaTracestate:         json.RawMessage(`"vendor=abc"`),
		protocol.MetaBaggage:            json.RawMessage(`"userId=42,unknownKey=keepme"`),
	}
	opts := BuildUpstreamOptions{
		NegotiatedUpstreamVersion: "2026-07-28",
		HubClientInfo:             Info{Name: "avapigw-hub", Version: "1.0"},
		BrokerableCaps:            map[string]bool{"tools": true},
	}

	up, err := BuildUpstreamMeta(downstream, opts)
	require.NoError(t, err)

	// Per-upstream protocol version overwritten.
	assert.Equal(t, "2026-07-28", up.ProtocolVersion())

	// clientInfo replaced with hub identity.
	var ci Info
	require.NoError(t, json.Unmarshal(up[protocol.MetaClientInfo], &ci))
	assert.Equal(t, "avapigw-hub", ci.Name)
	assert.Equal(t, "1.0", ci.Version)

	// Capabilities narrowed: elicitation must be gone, tools kept.
	var caps map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(up[protocol.MetaClientCapabilities], &caps))
	assert.Contains(t, caps, "tools")
	assert.NotContains(t, caps, "elicitation")

	// serverInfo never carried over from downstream (upstream-owned).
	assert.NotContains(t, up, protocol.MetaServerInfo)

	// logLevel propagated verbatim.
	assert.Equal(t, "debug", up.LogLevel())

	// tracing propagated verbatim, unknown baggage entry kept.
	assert.Equal(t, json.RawMessage(`"00-trace-span-01"`), up[protocol.MetaTraceparent])
	assert.Equal(t, json.RawMessage(`"vendor=abc"`), up[protocol.MetaTracestate])
	assert.Equal(t, json.RawMessage(`"userId=42,unknownKey=keepme"`), up[protocol.MetaBaggage])
}

func TestBuildUpstreamMetaNoCapabilities(t *testing.T) {
	t.Parallel()
	// Downstream without clientCapabilities key => setNarrowedCapabilities no-op.
	down := Meta{}
	up, err := BuildUpstreamMeta(down, BuildUpstreamOptions{
		NegotiatedUpstreamVersion: "2026-07-28",
		HubClientInfo:             Info{Name: "hub"},
		BrokerableCaps:            map[string]bool{"tools": true},
	})
	require.NoError(t, err)
	assert.NotContains(t, up, protocol.MetaClientCapabilities)
	assert.Equal(t, "2026-07-28", up.ProtocolVersion())
	// No trace keys present.
	assert.NotContains(t, up, protocol.MetaTraceparent)
}

func TestBuildUpstreamMetaInvalidCapabilities(t *testing.T) {
	t.Parallel()
	down := Meta{
		protocol.MetaClientCapabilities: json.RawMessage(`"not-an-object"`),
	}
	up, err := BuildUpstreamMeta(down, BuildUpstreamOptions{
		NegotiatedUpstreamVersion: "2026-07-28",
		HubClientInfo:             Info{Name: "hub"},
	})
	require.Error(t, err)
	assert.Nil(t, up)
	assert.Contains(t, err.Error(), "decode clientCapabilities")
}

func TestInjectServerInfo(t *testing.T) {
	t.Parallel()
	hub := Info{Name: "avapigw-hub", Version: "1.2.3", Title: "Hub"}

	t.Run("empty result creates meta", func(t *testing.T) {
		t.Parallel()
		out, err := InjectServerInfo(nil, hub)
		require.NoError(t, err)
		var obj map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out, &obj))
		m, err := Decode(obj["_meta"])
		require.NoError(t, err)
		var si Info
		require.NoError(t, json.Unmarshal(m[protocol.MetaServerInfo], &si))
		assert.Equal(t, "avapigw-hub", si.Name)
	})

	t.Run("overwrites upstream serverInfo and preserves other fields", func(t *testing.T) {
		t.Parallel()
		result := json.RawMessage(`{"tools":[{"name":"x"}],"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"upstream"},"keep":"yes"}}`)
		out, err := InjectServerInfo(result, hub)
		require.NoError(t, err)

		var obj map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out, &obj))
		// Non-meta field preserved.
		assert.JSONEq(t, `[{"name":"x"}]`, string(obj["tools"]))

		m, err := Decode(obj["_meta"])
		require.NoError(t, err)
		var si Info
		require.NoError(t, json.Unmarshal(m[protocol.MetaServerInfo], &si))
		assert.Equal(t, "avapigw-hub", si.Name) // hub identity, not upstream
		// Unknown meta key preserved.
		assert.Equal(t, json.RawMessage(`"yes"`), m["keep"])
	})

	t.Run("invalid result json", func(t *testing.T) {
		t.Parallel()
		_, err := InjectServerInfo(json.RawMessage(`{bad`), hub)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode result")
	})

	t.Run("invalid _meta json", func(t *testing.T) {
		t.Parallel()
		_, err := InjectServerInfo(json.RawMessage(`{"_meta":123}`), hub)
		require.Error(t, err)
	})
}

func TestMetaGetString(t *testing.T) {
	t.Parallel()

	m := Meta{
		protocol.MetaProtocolVersion: json.RawMessage(`"2026-07-28"`),
		protocol.MetaLogLevel:        json.RawMessage(`42`), // not a string
	}
	assert.Equal(t, "2026-07-28", m.ProtocolVersion())
	// Non-string value yields "".
	assert.Equal(t, "", m.LogLevel())
	// Absent key yields "".
	empty := Meta{}
	assert.Equal(t, "", empty.ProtocolVersion())
}
