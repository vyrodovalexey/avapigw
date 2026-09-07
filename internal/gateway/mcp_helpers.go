package gateway

import (
	"encoding/json"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// decodeParams decodes the JSON-RPC params object into a generic map. A nil or
// empty params yields an empty, non-nil map so callers can safely read keys. A
// non-object params (e.g. an array) yields an error.
func decodeParams(raw json.RawMessage) (map[string]any, error) {
	params := make(map[string]any)
	if len(raw) == 0 {
		return params, nil
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	return params, nil
}

// extractMeta returns the decoded params._meta object as a generic map, or an
// empty map when absent.
func extractMeta(params map[string]any) map[string]any {
	metaObj, ok := params["_meta"].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return metaObj
}

// rawMeta returns the raw JSON of params._meta, or nil when absent. It is used
// to re-decode the downstream _meta into the mcp/meta.Meta type.
func rawMeta(params map[string]any) json.RawMessage {
	metaObj, ok := params["_meta"]
	if !ok {
		return nil
	}
	raw, err := json.Marshal(metaObj)
	if err != nil {
		return nil
	}
	return raw
}

// metaProtocolVersion returns the protocolVersion recorded in params._meta, or
// "" when absent.
func metaProtocolVersion(params map[string]any) string {
	v, _ := extractMeta(params)[protocol.MetaProtocolVersion].(string)
	return v
}

// primitiveName returns the primitive name for the request: params.name for
// tools/prompts, params.uri for resources. It returns "" when neither is set.
func primitiveName(params map[string]any) string {
	if name, ok := params["name"].(string); ok && name != "" {
		return name
	}
	if uri, ok := params["uri"].(string); ok && uri != "" {
		return uri
	}
	return ""
}

// name0 returns the primitive name for metric labeling, bounded to "" when
// absent to keep metric cardinality predictable.
func name0(params map[string]any) string {
	return primitiveName(params)
}

// denamespaceParams returns a shallow copy of params with the namespaced
// primitive name (params.name / params.uri) rewritten to its upstream-original
// form. Keys other than name/uri are preserved unchanged.
func denamespaceParams(mapper namespace.Mapper, params map[string]any) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
	}
	if name, ok := out["name"].(string); ok && name != "" {
		if _, original, found := mapper.Denamespace(name); found {
			out["name"] = original
		}
	}
	if uri, ok := out["uri"].(string); ok && uri != "" {
		if _, original, found := mapper.Denamespace(uri); found {
			out["uri"] = original
		}
	}
	return out
}

// negotiatedVersion returns the protocol version to send upstream: the
// upstream's pinned version when set, otherwise the downstream-negotiated
// version (HUB-724). Version translation for legacy eras is a later milestone.
func negotiatedVersion(upstream config.MCPBackend, downstreamVersion string) string {
	if upstream.PinnedVersion != "" {
		return upstream.PinnedVersion
	}
	return downstreamVersion
}

// brokerableCaps returns the set of capability names the hub can broker. In
// this milestone the hub narrows to the core primitive capabilities; the set
// widens as later milestones add subscription/logging brokering.
func brokerableCaps() map[string]bool {
	return map[string]bool{
		"tools":     true,
		"resources": true,
		"prompts":   true,
	}
}

// BrokerableCapabilities exposes the hub's brokerable capability set so callers
// wiring the discovery aggregator advertise exactly the same set the tools/call
// broker path narrows to, keeping the forwarded _meta consistent (HUB-124).
func BrokerableCapabilities() map[string]bool {
	return brokerableCaps()
}
