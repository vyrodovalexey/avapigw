// Package headers implements the MCP header-mirroring and validation rules
// (HUB-141..148): requiring Mcp-Method / Mcp-Name, decoding the Base64
// sentinel form, comparing mirrored headers against the request body with
// numeric comparison for integer parameters, re-deriving headers after a body
// rewrite, and gating enforcement on the protocol revision.
package headers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// MCP mirrored-header names.
const (
	// HeaderMcpMethod mirrors the JSON-RPC method (HUB-141).
	HeaderMcpMethod = "Mcp-Method"
	// HeaderMcpName mirrors params.name / params.uri (HUB-141).
	HeaderMcpName = "Mcp-Name"
	// HeaderMcpProtocolVersion carries the protocol revision (HUB-122).
	HeaderMcpProtocolVersion = "MCP-Protocol-Version"
	// ParamHeaderPrefix is the prefix for mirrored parameter headers
	// (HUB-144).
	ParamHeaderPrefix = "Mcp-Param-"
)

// sentinel markers for the Base64 sentinel encoding `=?base64?<b64>?=`
// (HUB-142).
const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// HeaderError describes a header validation failure. It carries the MCP error
// code (HeaderMismatch) so callers can surface HUB-122/141 errors directly.
type HeaderError struct {
	// Code is the MCP/JSON-RPC error code to emit.
	Code int
	// Message describes the failure.
	Message string
}

// Error implements the error interface.
func (e *HeaderError) Error() string {
	return fmt.Sprintf("mcp header error %d: %s", e.Code, e.Message)
}

// newMismatch builds a HeaderMismatch (-32020) HeaderError.
func newMismatch(format string, args ...any) *HeaderError {
	return &HeaderError{Code: protocol.HeaderMismatch, Message: fmt.Sprintf(format, args...)}
}

// methodsRequiringName lists the methods that MUST carry Mcp-Name (HUB-141).
var methodsRequiringName = map[string]bool{
	protocol.MethodToolsCall:     true,
	protocol.MethodResourcesRead: true,
	protocol.MethodPromptsGet:    true,
}

// DecodeSentinel decodes the Base64 sentinel form `=?base64?<b64>?=`
// (HUB-142). It returns the decoded string and true when the value is a
// sentinel; otherwise it returns the input unchanged and false. A malformed
// sentinel body yields an error.
func DecodeSentinel(v string) (decoded string, isSentinel bool, err error) {
	if !strings.HasPrefix(v, sentinelPrefix) || !strings.HasSuffix(v, sentinelSuffix) {
		return v, false, nil
	}
	body := v[len(sentinelPrefix) : len(v)-len(sentinelSuffix)]
	raw, decErr := base64.StdEncoding.DecodeString(body)
	if decErr != nil {
		return "", true, fmt.Errorf("headers: decode base64 sentinel: %w", decErr)
	}
	return string(raw), true, nil
}

// decodeHeaderValue returns the effective header value, decoding a Base64
// sentinel when present.
func decodeHeaderValue(v string) (string, error) {
	decoded, _, err := DecodeSentinel(v)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

// VersionGate reports whether the request's MCP-Protocol-Version names a
// revision that mandates header/body validation (HUB-147). When it returns
// false the caller MUST reject the request rather than trusting unvalidated
// mirrored headers.
func VersionGate(r *http.Request) bool {
	version := r.Header.Get(HeaderMcpProtocolVersion)
	if version == "" {
		return false
	}
	return protocol.IsSupportedVersion(version)
}

// ValidateHeaders enforces the mirrored-header rules for a downstream request
// (HUB-141/142): Mcp-Method MUST be present and MUST equal the body method;
// Mcp-Name MUST be present for tools/call, resources/read and prompts/get and
// MUST equal the body name (after Base64-sentinel decoding); every Mcp-Param-*
// header that maps to a known parameter MUST match the body value, using
// numeric comparison for integer parameters. On any mismatch it returns a
// *HeaderError carrying protocol.HeaderMismatch (-32020).
func ValidateHeaders(r *http.Request, method, name string, params map[string]any) error {
	if err := validateMethodHeader(r, method); err != nil {
		return err
	}
	if err := validateNameHeader(r, method, name); err != nil {
		return err
	}
	return validateParamHeaders(r, params)
}

// validateMethodHeader enforces the Mcp-Method requirement and consistency.
func validateMethodHeader(r *http.Request, method string) error {
	hdr := r.Header.Get(HeaderMcpMethod)
	if hdr == "" {
		return newMismatch("%s header is required", HeaderMcpMethod)
	}
	if hdr != method {
		return newMismatch("%s %q does not match body method %q", HeaderMcpMethod, hdr, method)
	}
	return nil
}

// validateNameHeader enforces the Mcp-Name requirement and consistency for the
// methods that mandate it.
func validateNameHeader(r *http.Request, method, name string) error {
	hdr := r.Header.Get(HeaderMcpName)
	if !methodsRequiringName[method] {
		return nil
	}
	if hdr == "" {
		return newMismatch("%s header is required for method %q", HeaderMcpName, method)
	}
	decoded, err := decodeHeaderValue(hdr)
	if err != nil {
		return newMismatch("%s decode failed: %v", HeaderMcpName, err)
	}
	if decoded != name {
		return newMismatch("%s %q does not match body name %q", HeaderMcpName, decoded, name)
	}
	return nil
}

// validateParamHeaders compares each Mcp-Param-* header that maps to a known
// body parameter, applying numeric comparison for integer parameters.
// Parameter names are matched CASE-INSENSITIVELY (HUB-142): Go canonicalizes an
// incoming Mcp-Param-userId to Mcp-Param-Userid, so a literal comparison would
// never match the camelCase body key userId and would silently skip the
// mirrored parameter from validation — the header/body-mismatch hole the spec
// treats as a security requirement. Unrecognized Mcp-Param-* headers are left
// for verbatim forwarding (HUB-146) and are not validated here.
func validateParamHeaders(r *http.Request, params map[string]any) error {
	index := lowercaseParamIndex(params)
	for canonical, values := range r.Header {
		if !strings.HasPrefix(canonical, ParamHeaderPrefix) || len(values) == 0 {
			continue
		}
		paramName := strings.TrimPrefix(canonical, ParamHeaderPrefix)
		bodyVal, ok := index[strings.ToLower(paramName)]
		if !ok {
			continue // unrecognized: forwarded verbatim elsewhere
		}
		decoded, err := decodeHeaderValue(values[0])
		if err != nil {
			return newMismatch("%s%s decode failed: %v", ParamHeaderPrefix, paramName, err)
		}
		if !valuesMatch(decoded, bodyVal) {
			return newMismatch("%s%s %q does not match body parameter", ParamHeaderPrefix, paramName, decoded)
		}
	}
	return nil
}

// lowercaseParamIndex builds a lower-cased index of the top-level body
// parameters so mirrored Mcp-Param-* headers can be matched case-insensitively
// (HUB-142). When two body keys collide case-insensitively the last wins; such
// collisions are pathological and not expected in MCP tool arguments.
func lowercaseParamIndex(params map[string]any) map[string]any {
	index := make(map[string]any, len(params))
	for k, v := range params {
		index[strings.ToLower(k)] = v
	}
	return index
}

// valuesMatch compares a mirrored header string against a body parameter
// value. Integer/float body values are compared numerically (HUB-142);
// everything else is compared as a string via fmt.
func valuesMatch(headerVal string, bodyVal any) bool {
	switch v := bodyVal.(type) {
	case string:
		return headerVal == v
	case bool:
		return headerVal == fmt.Sprintf("%t", v)
	case float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return numericEqual(headerVal, fmt.Sprintf("%v", v))
	case json.Number:
		return numericEqual(headerVal, v.String())
	default:
		return headerVal == fmt.Sprintf("%v", v)
	}
}

// numericEqual compares two numeric string representations by value rather
// than lexically, so "1" and "1.0" or "01" compare equal (HUB-142).
func numericEqual(a, b string) bool {
	af, aok := new(big.Float).SetString(strings.TrimSpace(a))
	bf, bok := new(big.Float).SetString(strings.TrimSpace(b))
	if !aok || !bok {
		return a == b
	}
	return af.Cmp(bf) == 0
}

// DeriveUpstreamHeaders re-derives the mirrored headers for the upstream
// request after any body rewrite such as tool de-namespacing (HUB-143/144).
// It sets Mcp-Method and, for name-bearing methods, Mcp-Name from the rewritten
// values, mirrors x-mcp-header-annotated parameters into Mcp-Param-{Name}
// (omitting absent values, HUB-144), and preserves unrecognized Mcp-Param-*
// headers from the original request via CopyUnrecognizedParams (HUB-146).
func DeriveUpstreamHeaders(method, name string, params map[string]any, xMcpHeaderParams map[string]string) http.Header {
	out := make(http.Header)
	out.Set(HeaderMcpMethod, method)
	if methodsRequiringName[method] && name != "" {
		out.Set(HeaderMcpName, name)
	}

	for paramName, headerName := range xMcpHeaderParams {
		val, ok := params[paramName]
		if !ok || val == nil {
			continue // omit when absent (HUB-144)
		}
		out.Set(ParamHeaderPrefix+headerName, fmt.Sprintf("%v", val))
	}
	return out
}

// CopyUnrecognizedParams copies every Mcp-Param-* header from src into dst
// whose parameter name is not present in recognized, forwarding unrecognized
// mirrored parameters unchanged (HUB-146). Headers already set in dst are not
// overwritten.
func CopyUnrecognizedParams(dst, src http.Header, recognized map[string]struct{}) {
	for canonical, values := range src {
		if !strings.HasPrefix(canonical, ParamHeaderPrefix) {
			continue
		}
		paramName := strings.TrimPrefix(canonical, ParamHeaderPrefix)
		if _, ok := recognized[paramName]; ok {
			continue
		}
		if len(dst[canonical]) > 0 {
			continue
		}
		for _, v := range values {
			dst.Add(canonical, v)
		}
	}
}

// ErrMissingMethodHeader is returned by RequireMethod when Mcp-Method is
// absent.
var ErrMissingMethodHeader = errors.New("headers: Mcp-Method header is required")

// RequireMethod returns the Mcp-Method header value or ErrMissingMethodHeader
// when absent. It is a convenience for the header-only fast path (HUB-148).
func RequireMethod(r *http.Request) (string, error) {
	m := r.Header.Get(HeaderMcpMethod)
	if m == "" {
		return "", ErrMissingMethodHeader
	}
	return m, nil
}
