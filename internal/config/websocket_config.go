package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// WSOriginWildcard is the allowedOrigins entry that explicitly allows
// WebSocket upgrade requests from every origin.
const WSOriginWildcard = "*"

// Normalized origin scheme values produced by ParseWSOrigin.
const (
	wsSchemeHTTP  = "http"
	wsSchemeHTTPS = "https"
)

// WebSocketConfig contains WebSocket-specific gateway configuration.
type WebSocketConfig struct {
	// AllowedOrigins is the list of origins permitted to open cross-origin
	// WebSocket connections through the gateway (CSWSH protection).
	//
	// Entry forms:
	//   - "*"                        — explicitly allow every origin
	//   - "https://app.example.com"  — scheme + host[:port] match
	//   - "app.example.com"          — host[:port] match for any scheme
	//
	// Behavior:
	//   - Empty (default): every origin is accepted for backward
	//     compatibility and a warning is logged once at startup.
	//   - Non-empty: only listed origins and same-origin requests are
	//     accepted; other origins are rejected during the handshake
	//     with HTTP 403.
	AllowedOrigins []string `yaml:"allowedOrigins,omitempty" json:"allowedOrigins,omitempty"`
}

// Sentinel errors for WebSocket origin parsing. They are wrapped with the
// offending value by ParseWSOrigin, so use errors.Is for classification.
var (
	// ErrWSOriginEmpty indicates an empty or blank origin value.
	ErrWSOriginEmpty = errors.New("origin must not be empty")

	// ErrWSOriginHost indicates an origin without a usable host.
	ErrWSOriginHost = errors.New("origin must include a host")

	// ErrWSOriginPath indicates an origin carrying a path, query,
	// fragment, or credentials, which origins must not have.
	ErrWSOriginPath = errors.New(
		"origin must not contain a path, query, fragment, or credentials")

	// ErrWSOriginScheme indicates an unsupported origin scheme.
	ErrWSOriginScheme = errors.New(
		"origin scheme must be http, https, ws, or wss")

	// ErrWSOriginWildcardHost indicates a host containing a wildcard.
	// Wildcard patterns are not supported; only the standalone "*" entry
	// (handled before parsing) allows all origins.
	ErrWSOriginWildcardHost = errors.New(
		`origin host must not contain a wildcard; use a standalone "*" entry to allow all origins`)
)

// ParseWSOrigin parses and normalizes a WebSocket origin value. It accepts
// either a full origin ("scheme://host[:port]") or a bare "host[:port]".
//
// The returned scheme is lowercased with ws/wss mapped to their HTTP
// equivalents, and is empty for bare-host values (meaning "any scheme").
// The returned host is lowercased. The wildcard entry ("*") is not an
// origin and must be handled by the caller before parsing.
func ParseWSOrigin(value string) (scheme, host string, err error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", "", ErrWSOriginEmpty
	}

	raw := trimmed
	if !strings.Contains(trimmed, "://") {
		// Bare host[:port] — parse as a scheme-relative URL.
		raw = "//" + trimmed
	}

	u, parseErr := url.Parse(raw)
	if parseErr != nil {
		return "", "", fmt.Errorf("invalid websocket origin %q: %w", value, parseErr)
	}
	if checkErr := checkWSOriginURL(u); checkErr != nil {
		return "", "", fmt.Errorf("invalid websocket origin %q: %w", value, checkErr)
	}

	scheme, schemeErr := normalizeWSOriginScheme(u.Scheme)
	if schemeErr != nil {
		return "", "", fmt.Errorf("invalid websocket origin %q: %w", value, schemeErr)
	}

	return scheme, strings.ToLower(u.Host), nil
}

// checkWSOriginURL verifies that a parsed origin URL carries only the
// components an origin is allowed to have (scheme and host).
func checkWSOriginURL(u *url.URL) error {
	switch {
	case u.Host == "":
		return ErrWSOriginHost
	case strings.Contains(u.Host, WSOriginWildcard):
		return ErrWSOriginWildcardHost
	case u.User != nil, u.RawQuery != "", u.Fragment != "":
		return ErrWSOriginPath
	case u.Path != "" && u.Path != "/":
		return ErrWSOriginPath
	default:
		return nil
	}
}

// normalizeWSOriginScheme lowercases an origin scheme and maps the
// WebSocket schemes to their HTTP equivalents, because browsers send the
// page origin (http/https) in the Origin header during the WS handshake.
func normalizeWSOriginScheme(scheme string) (string, error) {
	switch strings.ToLower(scheme) {
	case "":
		return "", nil // bare host entry: matches any scheme
	case "ws", wsSchemeHTTP:
		return wsSchemeHTTP, nil
	case "wss", wsSchemeHTTPS:
		return wsSchemeHTTPS, nil
	default:
		return "", ErrWSOriginScheme
	}
}
