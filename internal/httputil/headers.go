// Package httputil provides shared HTTP utility functions for proxy packages.
package httputil

// HopByHopHeaders are headers that should not be forwarded by proxies.
// Per RFC 2616 Section 13.5.1 and RFC 7230 Section 6.1.
var HopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// IsHopByHop returns true if the header should not be forwarded by proxies.
func IsHopByHop(header string) bool {
	_, ok := HopByHopHeaders[header]
	return ok
}
