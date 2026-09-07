package discovery

import (
	"encoding/json"
	"strings"
)

// xMcpHeaderKey is the schema annotation carrying the mirrored-header name for
// a tool parameter (HUB-144/145).
const xMcpHeaderKey = "x-mcp-header"

// tokenSpecials is the set of RFC 7230 "tchar" special characters permitted in
// an HTTP token in addition to the alphanumerics.
//
//nolint:gosec // G101: this is the RFC 7230 tchar special-character set, not a credential
const tokenSpecials = "!#$%&'*+-.^_`|~"

// validateXMcpHeader inspects a tool object for x-mcp-header annotations and
// reports the first constraint violation (HUB-145):
//
//   - the header name MUST be non-empty and valid HTTP token syntax;
//   - it MUST contain no CR/LF;
//   - names MUST be case-insensitively unique across the tool;
//   - the annotated property MUST be a primitive type (number is not permitted);
//   - the property MUST be statically reachable via inputSchema.properties.
//
// It returns an empty string when the tool is valid (or carries no
// annotations), or a human-readable reason on the first violation so the
// caller can log the tool name plus the reason and continue serving the rest.
func validateXMcpHeader(tool map[string]json.RawMessage) string {
	schema := decodeResultObject(tool["inputSchema"])
	if schema == nil {
		return ""
	}
	props := decodeResultObject(schema["properties"])
	if props == nil {
		return ""
	}

	seen := make(map[string]struct{})
	for propName := range props {
		if reason := validateProperty(props[propName], propName, seen); reason != "" {
			return reason
		}
	}
	return ""
}

// validateProperty validates a single property's x-mcp-header annotation and
// its type constraint. It updates seen with the lowercased header name for the
// case-insensitive uniqueness check.
func validateProperty(raw json.RawMessage, propName string, seen map[string]struct{}) string {
	prop := decodeResultObject(raw)
	if prop == nil {
		return ""
	}
	hdr, ok := prop[xMcpHeaderKey]
	if !ok {
		return ""
	}
	var headerName string
	if err := json.Unmarshal(hdr, &headerName); err != nil {
		return "property " + propName + ": x-mcp-header must be a string"
	}
	if reason := validateHeaderName(propName, headerName, seen); reason != "" {
		return reason
	}
	return validatePrimitiveType(propName, prop)
}

// validateHeaderName enforces the non-empty, no-CR/LF, HTTP-token and
// case-insensitive-uniqueness constraints on a header name.
func validateHeaderName(propName, headerName string, seen map[string]struct{}) string {
	if headerName == "" {
		return "property " + propName + ": x-mcp-header is empty"
	}
	if strings.ContainsAny(headerName, "\r\n") {
		return "property " + propName + ": x-mcp-header contains CR/LF"
	}
	if !isHTTPToken(headerName) {
		return "property " + propName + ": x-mcp-header is not a valid HTTP token"
	}
	lower := strings.ToLower(headerName)
	if _, dup := seen[lower]; dup {
		return "property " + propName + ": x-mcp-header duplicates another header"
	}
	seen[lower] = struct{}{}
	return ""
}

// validatePrimitiveType enforces the primitive-type constraint: the property
// type MUST be one of string/integer/boolean; number and composite types are
// rejected (HUB-145).
func validatePrimitiveType(propName string, prop map[string]json.RawMessage) string {
	var typ string
	if err := json.Unmarshal(prop["type"], &typ); err != nil {
		return "property " + propName + ": x-mcp-header property has no scalar type"
	}
	switch typ {
	case "string", "integer", "boolean":
		return ""
	default:
		return "property " + propName + ": x-mcp-header type " + typ + " is not a permitted primitive"
	}
}

// isHTTPToken reports whether s is a valid RFC 7230 token (tchar sequence).
func isHTTPToken(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if strings.ContainsRune(tokenSpecials, r) {
			continue
		}
		return false
	}
	return true
}
