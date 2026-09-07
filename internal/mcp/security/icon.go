package security

import (
	"encoding/json"
	"net/url"
	"strings"
)

// allowedIconSchemes are the URI schemes permitted for icon references in
// results (HUB-406). Only https and data URIs are accepted; the hub never
// fetches an icon, so http/file/ftp and any other scheme are rejected.
var allowedIconSchemes = map[string]bool{
	"https": true,
	"data":  true,
}

// IsAllowedIconURI reports whether an icon URI is safe to forward downstream
// (HUB-406): its scheme must be https or data. The hub does not fetch icons,
// so this is a scheme allowlist only; credentials are never sent.
func IsAllowedIconURI(uri string) bool {
	if uri == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(uri), "data:") {
		return true
	}
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	return allowedIconSchemes[strings.ToLower(u.Scheme)]
}

// SanitizeIcons walks a result object and drops any "icons" entries whose URI
// scheme is not in the allowlist (HUB-406). It returns the possibly-rewritten
// result and the number of icons dropped. A best-effort decode failure returns
// the input unchanged.
func SanitizeIcons(result json.RawMessage) (out json.RawMessage, dropped int) {
	if len(result) == 0 {
		return result, 0
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(result, &obj); err != nil {
		return result, 0
	}
	rawIcons, ok := obj["icons"]
	if !ok {
		return result, 0
	}
	kept, n := filterIcons(rawIcons)
	if n == 0 {
		return result, 0
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return result, 0
	}
	obj["icons"] = encoded
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return result, 0
	}
	return rewritten, n
}

// filterIcons returns the icons whose "src"/"uri" scheme is allowed and the
// count of dropped icons.
func filterIcons(rawIcons json.RawMessage) (kept []json.RawMessage, dropped int) {
	var icons []json.RawMessage
	if err := json.Unmarshal(rawIcons, &icons); err != nil {
		return nil, 0
	}
	kept = make([]json.RawMessage, 0, len(icons))
	for _, icon := range icons {
		if iconAllowed(icon) {
			kept = append(kept, icon)
		} else {
			dropped++
		}
	}
	return kept, dropped
}

// iconAllowed reports whether a single icon object carries an allowed URI. The
// URI is read from "src" (MCP) or "uri" (fallback).
func iconAllowed(icon json.RawMessage) bool {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(icon, &obj); err != nil {
		return false
	}
	for _, field := range []string{"src", "uri"} {
		if raw, ok := obj[field]; ok {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && s != "" {
				return IsAllowedIconURI(s)
			}
		}
	}
	// An icon without a URI carries no fetchable reference; keep it.
	return true
}
