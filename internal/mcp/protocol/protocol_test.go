package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
)

func TestMetaKeyConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "io.modelcontextprotocol/protocolVersion", MetaProtocolVersion)
	assert.Equal(t, "io.modelcontextprotocol/clientCapabilities", MetaClientCapabilities)
	assert.Equal(t, "io.modelcontextprotocol/clientInfo", MetaClientInfo)
	assert.Equal(t, "io.modelcontextprotocol/serverInfo", MetaServerInfo)
	assert.Equal(t, "io.modelcontextprotocol/logLevel", MetaLogLevel)
	assert.Equal(t, "io.modelcontextprotocol/subscriptionId", MetaSubscriptionID)
	assert.Equal(t, "traceparent", MetaTraceparent)
	assert.Equal(t, "tracestate", MetaTracestate)
	assert.Equal(t, "baggage", MetaBaggage)
}

func TestResultTypeConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "complete", ResultComplete)
	assert.Equal(t, "input_required", ResultInputRequired)
}

func TestMethodNameConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "tools/call", MethodToolsCall)
	assert.Equal(t, "tools/list", MethodToolsList)
	assert.Equal(t, "resources/read", MethodResourcesRead)
	assert.Equal(t, "resources/list", MethodResourcesList)
	assert.Equal(t, "resources/templates/list", MethodResourceTemplatesList)
	assert.Equal(t, "prompts/get", MethodPromptsGet)
	assert.Equal(t, "prompts/list", MethodPromptsList)
	assert.Equal(t, "server/discover", MethodServerDiscover)
	assert.Equal(t, "subscriptions/listen", MethodSubscriptionsListen)
}

func TestMCPErrorCodeConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -32020, HeaderMismatch)
	assert.Equal(t, -32021, MissingRequiredClientCapability)
	assert.Equal(t, -32022, UnsupportedProtocolVersion)
	// Re-exported standard codes must equal the jsonrpc package values.
	assert.Equal(t, jsonrpc.CodeInvalidParams, InvalidParams)
	assert.Equal(t, jsonrpc.CodeInvalidRequest, InvalidRequest)
	assert.Equal(t, jsonrpc.CodeMethodNotFound, MethodNotFound)
	assert.Equal(t, jsonrpc.CodeInternalError, InternalError)
	assert.Equal(t, jsonrpc.CodeParseError, ParseError)
}

func TestReservedRangeBounds(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -32768, ReservedLow)
	assert.Equal(t, -32000, ReservedHigh)
	assert.Equal(t, -32099, MCPReservedLow)
	assert.Equal(t, -32020, MCPReservedHigh)
}

func TestHubSupportedVersions(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "2026-07-28", LatestVersion)
	assert.Contains(t, HubSupportedVersions, LatestVersion)
	// Interop versions are bridging targets, not advertised downstream.
	assert.NotContains(t, HubSupportedVersions, "2025-11-25")
	assert.Contains(t, InteropVersions, "2025-11-25")
	assert.Contains(t, InteropVersions, "2025-06-18")
	assert.Contains(t, InteropVersions, "2025-03-26")
}

func TestIsSupportedVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		version string
		want    bool
	}{
		{LatestVersion, true},
		{"2026-07-28", true},
		{"2025-11-25", false}, // interop only, not supported downstream
		{"2025-06-18", false},
		{"", false},
		{"9999-99-99", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, IsSupportedVersion(tc.version))
		})
	}
}

// UT-ERR-01: only spec error codes are permitted inside the reserved range;
// hub-specific codes must live outside it.
func TestValidHubErrorCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		code int
		want bool
	}{
		// Retired codes are never permitted.
		{"retired -32002", -32002, false},
		{"retired -32042", -32042, false},
		// Defined MCP sub-range codes permitted.
		{"defined header mismatch", HeaderMismatch, true},
		{"defined missing capability", MissingRequiredClientCapability, true},
		{"defined unsupported version", UnsupportedProtocolVersion, true},
		// Undefined codes inside the MCP sub-range are rejected.
		{"undefined mcp sub-range -32023", -32023, false},
		{"undefined mcp sub-range low bound -32099", -32099, false},
		{"undefined mcp sub-range -32050", -32050, false},
		// Standard JSON-RPC codes permitted.
		{"standard parse error", ParseError, true},
		{"standard invalid request", InvalidRequest, true},
		{"standard method not found", MethodNotFound, true},
		{"standard invalid params", InvalidParams, true},
		{"standard internal error", InternalError, true},
		// Non-standard code inside reserved range but outside MCP sub-range.
		{"reserved non-standard -32000", -32000, false},
		{"reserved non-standard -32100", -32100, false},
		{"reserved non-standard low bound -32768", -32768, false},
		// Hub-specific codes outside the reserved range are permitted.
		{"hub code -31999", -31999, true},
		{"hub code -32769", -32769, true},
		{"positive code", 100, true},
		{"zero", 0, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, ValidHubErrorCode(tc.code))
		})
	}
}
