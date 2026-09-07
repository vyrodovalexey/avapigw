// Package protocol defines MCP (Model Context Protocol) wire constants and
// helpers shared across the hub: `_meta` key names, result-type values,
// supported protocol versions, method names and the error-code registry
// enforcing the hub's error-code discipline (HUB-409).
package protocol

import "github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"

// MCP `_meta` key constants (vendor-prefixed per the MCP specification).
const (
	// MetaProtocolVersion carries the negotiated protocol version.
	MetaProtocolVersion = "io.modelcontextprotocol/protocolVersion"
	// MetaClientCapabilities carries the client's declared capabilities.
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	// MetaClientInfo carries the client's self-reported identity.
	MetaClientInfo = "io.modelcontextprotocol/clientInfo"
	// MetaServerInfo carries the server's self-reported identity.
	MetaServerInfo = "io.modelcontextprotocol/serverInfo"
	// MetaLogLevel carries the requested log level.
	MetaLogLevel = "io.modelcontextprotocol/logLevel"
	// MetaSubscriptionID carries the subscription identifier.
	MetaSubscriptionID = "io.modelcontextprotocol/subscriptionId"
)

// Distributed-tracing `_meta` keys propagated verbatim from downstream to
// upstream (HUB-127).
const (
	// MetaTraceparent carries the W3C traceparent header value.
	MetaTraceparent = "traceparent"
	// MetaTracestate carries the W3C tracestate header value.
	MetaTracestate = "tracestate"
	// MetaBaggage carries the W3C baggage header value.
	MetaBaggage = "baggage"
)

// Result-type constants (HUB-181, HUB-201).
const (
	// ResultComplete marks a terminal, complete result.
	ResultComplete = "complete"
	// ResultInputRequired marks an MRTR input-required result.
	ResultInputRequired = "input_required"
)

// Protocol versions.
const (
	// LatestVersion is the hub's target protocol revision.
	LatestVersion = "2026-07-28"
)

// HubSupportedVersions is the set of protocol versions the hub itself
// implements toward downstream clients (HUB-123). It is independent of
// upstream eras — the hub translates.
var HubSupportedVersions = []string{LatestVersion}

// InteropVersions is the set of legacy protocol versions the hub can bridge
// to upstreams (interop targets). It is not advertised downstream.
var InteropVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// MCP method-name constants.
const (
	// MethodToolsCall invokes a tool.
	MethodToolsCall = "tools/call"
	// MethodToolsList lists tools.
	MethodToolsList = "tools/list"
	// MethodResourcesRead reads a resource.
	MethodResourcesRead = "resources/read"
	// MethodResourcesList lists resources.
	MethodResourcesList = "resources/list"
	// MethodResourceTemplatesList lists resource templates.
	MethodResourceTemplatesList = "resources/templates/list"
	// MethodPromptsGet fetches a prompt.
	MethodPromptsGet = "prompts/get"
	// MethodPromptsList lists prompts.
	MethodPromptsList = "prompts/list"
	// MethodServerDiscover performs hub/upstream discovery.
	MethodServerDiscover = "server/discover"
	// MethodSubscriptionsListen opens a subscription stream.
	MethodSubscriptionsListen = "subscriptions/listen"
)

// MCP-specific error codes defined by the specification. These live inside
// the JSON-RPC server-error reserved range (-32099..-32000) and MUST match
// the specification exactly (HUB-409).
const (
	// HeaderMismatch indicates a mirrored header disagrees with the body or
	// a required header is missing (HUB-122, HUB-141).
	HeaderMismatch = -32020
	// MissingRequiredClientCapability indicates the client did not declare a
	// capability required to satisfy an input request (HUB-206).
	MissingRequiredClientCapability = -32021
	// UnsupportedProtocolVersion indicates the hub does not implement the
	// requested protocol version (HUB-123).
	UnsupportedProtocolVersion = -32022
)

// Re-exported standard JSON-RPC codes for convenience within the MCP layer.
const (
	// InvalidParams mirrors jsonrpc.CodeInvalidParams (HUB-121).
	InvalidParams = jsonrpc.CodeInvalidParams
	// InvalidRequest mirrors jsonrpc.CodeInvalidRequest.
	InvalidRequest = jsonrpc.CodeInvalidRequest
	// MethodNotFound mirrors jsonrpc.CodeMethodNotFound.
	MethodNotFound = jsonrpc.CodeMethodNotFound
	// InternalError mirrors jsonrpc.CodeInternalError.
	InternalError = jsonrpc.CodeInternalError
	// ParseError mirrors jsonrpc.CodeParseError.
	ParseError = jsonrpc.CodeParseError
)

// JSON-RPC reserved-range bounds. Codes in [ReservedLow, ReservedHigh] are
// reserved by the JSON-RPC 2.0 specification; hub-specific (non-spec) codes
// MUST be allocated outside this range (HUB-409).
const (
	// ReservedLow is the inclusive lower bound of the reserved range.
	ReservedLow = -32768
	// ReservedHigh is the inclusive upper bound of the reserved range.
	ReservedHigh = -32000
)

// MCP-specific reserved sub-range bounds. The specification reserves
// [MCPReservedLow, MCPReservedHigh] for MCP-defined codes; the hub MUST NOT
// emit codes in this sub-range other than the ones it defines (HUB-409).
const (
	// MCPReservedLow is the inclusive lower bound of the MCP sub-range.
	MCPReservedLow = -32099
	// MCPReservedHigh is the inclusive upper bound of the MCP sub-range.
	MCPReservedHigh = -32020
)

// definedMCPCodes is the set of specification-defined MCP codes in the
// -32020..-32099 sub-range that the hub is permitted to emit.
var definedMCPCodes = map[int]bool{
	HeaderMismatch:                  true,
	MissingRequiredClientCapability: true,
	UnsupportedProtocolVersion:      true,
}

// standardJSONRPCCodes is the set of standard JSON-RPC codes the hub may emit
// from within the reserved range.
var standardJSONRPCCodes = map[int]bool{
	ParseError:     true,
	InvalidRequest: true,
	MethodNotFound: true,
	InvalidParams:  true,
	InternalError:  true,
}

// retiredCodes lists codes retired by the specification that the hub MUST NOT
// reuse (HUB-409).
var retiredCodes = map[int]bool{
	-32002: true,
	-32042: true,
}

// ValidHubErrorCode reports whether the hub is permitted to emit the given
// error code, enforcing the code discipline of HUB-409:
//
//   - retired codes (-32002, -32042) are never permitted;
//   - codes in the MCP sub-range (-32020..-32099) are permitted only when
//     defined by the specification;
//   - other codes inside the JSON-RPC reserved range (-32768..-32000) are
//     permitted only if they are standard JSON-RPC codes;
//   - hub-specific codes MUST live outside the reserved range.
func ValidHubErrorCode(code int) bool {
	if retiredCodes[code] {
		return false
	}
	if code >= MCPReservedLow && code <= MCPReservedHigh {
		return definedMCPCodes[code]
	}
	if code >= ReservedLow && code <= ReservedHigh {
		return standardJSONRPCCodes[code]
	}
	// Outside the reserved range: allocatable for hub-specific codes.
	return true
}

// IsSupportedVersion reports whether the hub implements the given protocol
// version toward downstream clients.
func IsSupportedVersion(version string) bool {
	for _, v := range HubSupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}
