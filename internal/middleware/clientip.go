package middleware

import (
	"net"
	"net/http"
	"strings"
)

// ClientIPExtractor extracts the real client IP from requests,
// handling X-Forwarded-For with trusted proxy validation.
// When no trusted proxies are configured, only RemoteAddr is used
// (secure default to prevent IP spoofing).
type ClientIPExtractor struct {
	trustedCIDRs []*net.IPNet
}

// NewClientIPExtractor creates a new ClientIPExtractor with the given
// trusted proxy CIDRs. Invalid CIDRs are silently skipped.
// If trustedProxies is empty, the extractor always returns RemoteAddr.
func NewClientIPExtractor(trustedProxies []string) *ClientIPExtractor {
	cidrs := make([]*net.IPNet, 0, len(trustedProxies))
	for _, proxy := range trustedProxies {
		_, cidr, err := net.ParseCIDR(proxy)
		if err != nil {
			// Try parsing as a single IP address
			ip := net.ParseIP(proxy)
			if ip == nil {
				continue
			}
			cidr = singleIPToCIDR(ip)
		}
		cidrs = append(cidrs, cidr)
	}
	return &ClientIPExtractor{trustedCIDRs: cidrs}
}

// singleIPToCIDR converts a single IP address to a /32 or /128 CIDR.
func singleIPToCIDR(ip net.IP) *net.IPNet {
	bits := 32
	if ip.To4() == nil {
		bits = 128 //nolint:mnd // IPv6 prefix length
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(bits, bits),
	}
}

// Extract returns the real client IP from the request.
// If no trusted proxies are configured, it returns RemoteAddr (port stripped).
// If trusted proxies are configured and RemoteAddr is from a trusted proxy,
// it walks X-Forwarded-For right-to-left and returns the first non-trusted IP.
func (e *ClientIPExtractor) Extract(r *http.Request) string {
	remoteIP := stripPort(r.RemoteAddr)

	// Secure default: no trusted proxies means only use RemoteAddr
	if len(e.trustedCIDRs) == 0 {
		return remoteIP
	}

	// Check if the direct connection is from a trusted proxy
	if !e.isTrusted(remoteIP) {
		return remoteIP
	}

	// Parse X-Forwarded-For and walk right-to-left
	return e.extractFromXFF(r, remoteIP)
}

// extractFromXFF parses X-Forwarded-For header and returns the first
// non-trusted IP walking right-to-left. Falls back to the provided
// fallback IP if all IPs in the chain are trusted.
func (e *ClientIPExtractor) extractFromXFF(
	r *http.Request,
	fallback string,
) string {
	xff := r.Header.Get(HeaderXForwardedFor)
	if xff == "" {
		return fallback
	}

	ips := strings.Split(xff, ",")
	// Walk right-to-left to find the first non-trusted IP
	for i := len(ips) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(ips[i])
		if ip == "" {
			continue
		}
		if !e.isTrusted(ip) {
			return ip
		}
	}

	// All IPs in the chain are trusted, return fallback
	return fallback
}

// isTrusted checks if the given IP string is within any trusted CIDR.
func (e *ClientIPExtractor) isTrusted(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range e.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// stripPort removes the port from an address string.
// Handles both IPv4 ("192.168.1.1:8080") and IPv6 ("[::1]:8080") formats.
func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port present or invalid format, return as-is
		return addr
	}
	return host
}

// globalExtractor is used by middleware functions to extract client IPs.
// It defaults to the secure extractor (only RemoteAddr, no header trust).
//
//nolint:gochecknoglobals // Package-level extractor set once at startup
var globalExtractor = NewClientIPExtractor(nil)

// SetGlobalIPExtractor sets the package-level ClientIPExtractor used by
// all middleware functions. This should be called once during application
// startup before any requests are served.
func SetGlobalIPExtractor(e *ClientIPExtractor) {
	if e != nil {
		globalExtractor = e
	}
}
