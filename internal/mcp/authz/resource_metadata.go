// Package authz implements the MCP hub's OAuth 2.1 resource-server surface and
// authorization enforcement (HUB-301/302/305/306/307/310):
//
//   - the RFC 9728 /.well-known/oauth-protected-resource endpoint;
//   - bearer extraction from the Authorization header only, with the RFC 6750
//     WWW-Authenticate challenge on missing/invalid tokens;
//   - token audience validation against the hub's canonical URI (RFC 8707);
//   - scope mapping and hierarchy-aware sufficiency enforcement;
//   - a deny-by-default policy engine keyed on (principal, upstream, primitive,
//     method).
//
// The package never forwards the downstream client's token upstream; upstream
// credentials are sourced independently by the proxy via ServiceBackend.
package authz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// WellKnownPath is the RFC 9728 protected-resource metadata path (HUB-301).
const WellKnownPath = "/.well-known/oauth-protected-resource"

// bearerScheme is the only accepted authorization scheme (HUB-301: bearer only
// in the Authorization header).
const bearerScheme = "Bearer"

// bearerMethodHeader is the single supported bearer method advertised in the
// RFC 9728 metadata: the Authorization header.
const bearerMethodHeader = "header"

// ResourceMetadata is the RFC 9728 protected-resource metadata document served
// at WellKnownPath.
type ResourceMetadata struct {
	// Resource is the hub's canonical resource identifier.
	Resource string `json:"resource"`
	// AuthorizationServers lists the trusted authorization-server issuers.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	// ScopesSupported lists the scopes the hub advertises.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// BearerMethodsSupported lists the accepted bearer-token methods.
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// ResourceMetadataHandler serves the RFC 9728 protected-resource metadata
// document (HUB-301). It is a plain http.Handler so it can be registered on the
// gateway mux or wrapped by the MCP dispatcher.
type ResourceMetadataHandler struct {
	metadata     ResourceMetadata
	metadataJSON []byte
}

// NewResourceMetadataHandler constructs the well-known handler from the hub's
// canonical resource URI, trusted authorization servers and advertised scopes.
func NewResourceMetadataHandler(
	resource string, authServers, scopes []string,
) (*ResourceMetadataHandler, error) {
	md := ResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   authServers,
		ScopesSupported:        scopes,
		BearerMethodsSupported: []string{bearerMethodHeader},
	}
	raw, err := json.Marshal(md)
	if err != nil {
		return nil, fmt.Errorf("authz: encode resource metadata: %w", err)
	}
	return &ResourceMetadataHandler{metadata: md, metadataJSON: raw}, nil
}

// Metadata returns the resource metadata document.
func (h *ResourceMetadataHandler) Metadata() ResourceMetadata { return h.metadata }

// ServeHTTP serves the metadata document as application/json (HUB-301). Only
// GET (and HEAD) are permitted.
func (h *ResourceMetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(h.metadataJSON)
}

// ExtractBearer returns the bearer token from the Authorization header, or ""
// when absent or not a bearer credential. Per HUB-301 the hub accepts bearer
// tokens ONLY in the Authorization header (never query/body).
func ExtractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	const prefix = bearerScheme + " "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

// challengeParams builds an ordered WWW-Authenticate parameter string. The
// resulting header always starts with the Bearer scheme.
func challengeParams(pairs [][2]string) string {
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if p[1] == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%q", p[0], p[1]))
	}
	if len(parts) == 0 {
		return bearerScheme
	}
	return bearerScheme + " " + strings.Join(parts, ", ")
}

// WriteUnauthorized writes a 401 with a RFC 6750 WWW-Authenticate challenge
// carrying the resource_metadata URL and requested scope (HUB-301).
func WriteUnauthorized(w http.ResponseWriter, resourceMetadataURL, scope, description string) {
	challenge := challengeParams([][2]string{
		{"resource_metadata", resourceMetadataURL},
		{"scope", scope},
		{"error", "invalid_token"},
		{"error_description", description},
	})
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// WriteInsufficientScope writes a 403 with a RFC 6750 WWW-Authenticate
// challenge naming ALL scopes required for the operation in a single challenge
// (HUB-305).
func WriteInsufficientScope(w http.ResponseWriter, resourceMetadataURL string, requiredScopes []string) {
	challenge := challengeParams([][2]string{
		{"error", "insufficient_scope"},
		{"scope", strings.Join(requiredScopes, " ")},
		{"resource_metadata", resourceMetadataURL},
	})
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, "insufficient scope", http.StatusForbidden)
}
