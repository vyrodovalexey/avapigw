// Package meta builds the fresh `_meta` object the hub sends upstream for
// every forwarded request, and injects the hub's identity into results
// returned downstream. It implements the metadata discipline of HUB-124..128:
// per-upstream protocol version, capability narrowing (never widening), hub
// clientInfo/serverInfo, and verbatim propagation of tracing context.
package meta

import (
	"encoding/json"
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// Info describes an MCP participant (client or server) identity.
type Info struct {
	// Name is the participant name.
	Name string `json:"name"`
	// Version is the participant version.
	Version string `json:"version,omitempty"`
	// Title is an optional human-readable title.
	Title string `json:"title,omitempty"`
}

// Meta is a decoded `_meta` object. Unknown keys are preserved so the hub
// never drops metadata it does not understand (HUB-127).
type Meta map[string]json.RawMessage

// Decode parses a raw `_meta` object. A nil or empty input yields an empty,
// non-nil Meta so callers can safely add keys.
func Decode(raw json.RawMessage) (Meta, error) {
	m := make(Meta)
	if len(raw) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("meta: decode _meta: %w", err)
	}
	return m, nil
}

// Encode marshals the Meta back to a raw JSON object.
func (m Meta) Encode() (json.RawMessage, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("meta: encode _meta: %w", err)
	}
	return raw, nil
}

// getString returns the string value stored at key, or "" if absent or not a
// JSON string.
func (m Meta) getString(key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// NarrowCapabilities returns the intersection of the client's declared
// capabilities with the set the hub is able to broker. It never widens the
// set: a capability absent from client is never present in the result, even
// if brokerable lists it (HUB-124/125).
//
// Both maps are treated as capability namespaces keyed by capability name;
// the client's value is preserved for keys retained.
func NarrowCapabilities(client map[string]json.RawMessage, brokerable map[string]bool) map[string]json.RawMessage {
	narrowed := make(map[string]json.RawMessage, len(client))
	for name, val := range client {
		if brokerable[name] {
			narrowed[name] = val
		}
	}
	return narrowed
}

// BuildUpstreamOptions carries the inputs for BuildUpstreamMeta.
type BuildUpstreamOptions struct {
	// NegotiatedUpstreamVersion is the protocol version negotiated with the
	// target upstream (HUB-124).
	NegotiatedUpstreamVersion string
	// HubClientInfo is the hub's own identity, sent upstream as clientInfo
	// (HUB-124).
	HubClientInfo Info
	// BrokerableCaps is the set of capability names the hub can broker; the
	// downstream capabilities are narrowed to this set (HUB-125).
	BrokerableCaps map[string]bool
}

// BuildUpstreamMeta constructs the fresh `_meta` for an upstream request from
// the downstream `_meta`. It:
//
//   - sets protocolVersion to the version negotiated with that upstream;
//   - narrows clientCapabilities to the brokerable intersection (never wider);
//   - replaces clientInfo with the hub's identity;
//   - propagates traceparent/tracestate/baggage verbatim (HUB-127);
//   - propagates logLevel verbatim when present (HUB-124).
//
// It does not carry over serverInfo (that is upstream-owned) or any other
// downstream key, guaranteeing a fresh object.
func BuildUpstreamMeta(downstream Meta, opts BuildUpstreamOptions) (Meta, error) {
	up := make(Meta)

	if err := up.setString(protocol.MetaProtocolVersion, opts.NegotiatedUpstreamVersion); err != nil {
		return nil, err
	}

	if err := up.setNarrowedCapabilities(downstream, opts.BrokerableCaps); err != nil {
		return nil, err
	}

	if err := up.setJSON(protocol.MetaClientInfo, opts.HubClientInfo); err != nil {
		return nil, err
	}

	up.propagateVerbatim(downstream, protocol.MetaLogLevel)
	up.propagateVerbatim(downstream, protocol.MetaTraceparent)
	up.propagateVerbatim(downstream, protocol.MetaTracestate)
	up.propagateVerbatim(downstream, protocol.MetaBaggage)

	return up, nil
}

// setNarrowedCapabilities narrows the downstream clientCapabilities to the
// brokerable set and stores them under the capabilities key.
func (m Meta) setNarrowedCapabilities(downstream Meta, brokerable map[string]bool) error {
	raw, ok := downstream[protocol.MetaClientCapabilities]
	if !ok {
		return nil
	}
	var caps map[string]json.RawMessage
	if err := json.Unmarshal(raw, &caps); err != nil {
		return fmt.Errorf("meta: decode clientCapabilities: %w", err)
	}
	narrowed := NarrowCapabilities(caps, brokerable)
	return m.setJSON(protocol.MetaClientCapabilities, narrowed)
}

// propagateVerbatim copies the raw value at key from src to m when present,
// keeping unknown structure (e.g. baggage entries) intact (HUB-127).
func (m Meta) propagateVerbatim(src Meta, key string) {
	if raw, ok := src[key]; ok {
		m[key] = raw
	}
}

// setString stores a JSON string value at key.
func (m Meta) setString(key, value string) error {
	return m.setJSON(key, value)
}

// setJSON encodes value and stores it at key.
func (m Meta) setJSON(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("meta: encode %q: %w", key, err)
	}
	m[key] = raw
	return nil
}

// InjectServerInfo adds the hub's serverInfo into a result's `_meta`,
// identifying the hub (not the upstream), as mandated by HUB-126. The result
// is expected to be a JSON object; its `_meta` object is created when absent
// and any existing upstream serverInfo is overwritten with the hub's.
func InjectServerInfo(result json.RawMessage, hubServerInfo Info) (json.RawMessage, error) {
	obj := make(map[string]json.RawMessage)
	if len(result) > 0 {
		if err := json.Unmarshal(result, &obj); err != nil {
			return nil, fmt.Errorf("meta: decode result: %w", err)
		}
	}

	m, err := Decode(obj["_meta"])
	if err != nil {
		return nil, err
	}
	if err := m.setJSON(protocol.MetaServerInfo, hubServerInfo); err != nil {
		return nil, err
	}

	rawMeta, err := m.Encode()
	if err != nil {
		return nil, err
	}
	obj["_meta"] = rawMeta

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("meta: encode result: %w", err)
	}
	return out, nil
}

// ProtocolVersion returns the protocolVersion recorded in the `_meta`, or ""
// when absent.
func (m Meta) ProtocolVersion() string {
	return m.getString(protocol.MetaProtocolVersion)
}

// LogLevel returns the logLevel recorded in the `_meta`, or "" when absent.
func (m Meta) LogLevel() string {
	return m.getString(protocol.MetaLogLevel)
}
