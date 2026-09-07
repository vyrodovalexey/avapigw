package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// RedactedValue is the placeholder written in place of a redacted value.
const RedactedValue = "[REDACTED]"

// sensitiveKeySubstrings are lower-cased substrings that mark a param/arg key
// as sensitive so its value is redacted from logs/audit (HUB-407).
var sensitiveKeySubstrings = []string{
	"token", "secret", "password", "passwd", "apikey", "api_key",
	"authorization", "cookie", "credential", "private", "requeststate",
}

// IsSensitiveKey reports whether a key name marks a sensitive value that must
// be redacted from logs and audit records (HUB-407).
func IsSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range sensitiveKeySubstrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// RedactArgs returns a copy of a JSON-RPC arguments object with sensitive
// values replaced by RedactedValue (HUB-407). Nested objects are redacted
// recursively. The original map is not mutated.
func RedactArgs(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		if IsSensitiveKey(k) {
			out[k] = RedactedValue
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

// redactValue recursively redacts a value: nested maps are walked, other
// values are returned unchanged (only keys drive redaction).
func redactValue(v any) any {
	if m, ok := v.(map[string]any); ok {
		return RedactArgs(m)
	}
	return v
}

// ArgumentDigest returns a stable, non-reversible digest of the request
// arguments suitable for an audit record (HUB-408). Sensitive values are
// redacted before hashing so the digest never depends on secret material.
func ArgumentDigest(args map[string]any) string {
	redacted := RedactArgs(args)
	raw, err := json.Marshal(redacted)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// RedactToken returns a bounded, non-sensitive fingerprint of a bearer token
// or opaque state string for correlation in logs without leaking the value
// (HUB-407). An empty input yields "".
func RedactToken(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:8])
}
