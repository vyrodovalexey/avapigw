package security

import (
	"encoding/json"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// untrustedFields are the free-text primitive fields treated as untrusted
// content from an untrusted upstream (HUB-401). They can carry prompt-injection
// or misleading text, so the hub either strips them or flags them.
var untrustedFields = []string{"description", "title", "annotations", "instructions"}

// untrustedFlagPrefix is prepended to a flagged free-text field so a downstream
// consumer can see the content originated from an untrusted upstream (HUB-401).
const untrustedFlagPrefix = "[untrusted] "

// ApplyTrustPolicy rewrites an untrusted upstream's primitive definition
// according to policy (HUB-401): "strip" removes the untrusted free-text
// fields, "flag" prefixes string fields with a marker. A trusted upstream (or a
// nil/empty trust level) returns the definition unchanged. The input is not
// mutated; a rewritten copy is returned on change.
func ApplyTrustPolicy(cfg config.MCPBackend, policy string, item json.RawMessage) json.RawMessage {
	if cfg.TrustLevel != config.MCPTrustUntrusted {
		return item
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(item, &obj); err != nil {
		return item
	}
	changed := false
	for _, field := range untrustedFields {
		if _, ok := obj[field]; !ok {
			continue
		}
		if applyFieldPolicy(obj, field, policy) {
			changed = true
		}
	}
	if !changed {
		return item
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return item
	}
	return out
}

// applyFieldPolicy applies the trust policy to a single field, returning true
// when the field was modified.
func applyFieldPolicy(obj map[string]json.RawMessage, field, policy string) bool {
	if policy == config.MCPTrustPolicyFlag {
		return flagField(obj, field)
	}
	// Default: strip the field entirely.
	delete(obj, field)
	return true
}

// flagField prefixes a string field with the untrusted marker. Non-string
// fields (e.g. annotations objects) are removed since they cannot be prefixed.
func flagField(obj map[string]json.RawMessage, field string) bool {
	var s string
	if err := json.Unmarshal(obj[field], &s); err != nil {
		delete(obj, field)
		return true
	}
	flagged, err := json.Marshal(untrustedFlagPrefix + s)
	if err != nil {
		delete(obj, field)
		return true
	}
	obj[field] = flagged
	return true
}
