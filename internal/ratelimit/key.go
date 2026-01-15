package ratelimit

import (
	"net/http"
	"strings"
)

// KeyFunc is a function that extracts a rate limit key from an HTTP request.
type KeyFunc func(r *http.Request) string

// IPKeyFunc returns a KeyFunc that uses the client IP as the rate limit key.
func IPKeyFunc(r *http.Request) string {
	return GetClientIP(r)
}

// HeaderKeyFunc returns a KeyFunc that uses a specific header value as the rate limit key.
func HeaderKeyFunc(header string) KeyFunc {
	return func(r *http.Request) string {
		value := r.Header.Get(header)
		if value == "" {
			return GetClientIP(r)
		}
		return value
	}
}

// JWTClaimKeyFunc returns a KeyFunc that extracts a claim from a JWT token.
// The claim is expected to be in the request context under the specified key.
func JWTClaimKeyFunc(claim string) KeyFunc {
	return func(r *http.Request) string {
		// Try to get claim from context (set by auth middleware)
		if claims, ok := r.Context().Value("jwt_claims").(map[string]interface{}); ok {
			if value, exists := claims[claim]; exists {
				if str, ok := value.(string); ok {
					return str
				}
			}
		}

		// Fall back to IP
		return GetClientIP(r)
	}
}

// CompositeKeyFunc returns a KeyFunc that combines multiple key functions.
func CompositeKeyFunc(funcs ...KeyFunc) KeyFunc {
	return func(r *http.Request) string {
		parts := make([]string, 0, len(funcs))
		for _, fn := range funcs {
			if key := fn(r); key != "" {
				parts = append(parts, key)
			}
		}
		if len(parts) == 0 {
			return GetClientIP(r)
		}
		return strings.Join(parts, ":")
	}
}

// PathKeyFunc returns a KeyFunc that uses the request path as part of the key.
func PathKeyFunc(r *http.Request) string {
	return r.URL.Path
}

// MethodKeyFunc returns a KeyFunc that uses the request method as part of the key.
func MethodKeyFunc(r *http.Request) string {
	return r.Method
}

// MethodPathKeyFunc returns a KeyFunc that combines method and path.
func MethodPathKeyFunc(r *http.Request) string {
	return r.Method + ":" + r.URL.Path
}

// UserAgentKeyFunc returns a KeyFunc that uses the User-Agent header.
func UserAgentKeyFunc(r *http.Request) string {
	return r.UserAgent()
}

// APIKeyFunc returns a KeyFunc that uses an API key from a header or query parameter.
func APIKeyFunc(headerName, queryParam string) KeyFunc {
	return func(r *http.Request) string {
		// Try header first
		if key := r.Header.Get(headerName); key != "" {
			return key
		}

		// Try query parameter
		if key := r.URL.Query().Get(queryParam); key != "" {
			return key
		}

		// Fall back to IP
		return GetClientIP(r)
	}
}

// GetClientIP extracts the client IP from the request.
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Check CF-Connecting-IP header (Cloudflare)
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return cfip
	}

	// Check True-Client-IP header (Akamai, Cloudflare Enterprise)
	if tcip := r.Header.Get("True-Client-IP"); tcip != "" {
		return tcip
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Remove brackets from IPv6 addresses
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")

	return ip
}

// PerRouteKeyFunc returns a KeyFunc that includes the route name in the key.
func PerRouteKeyFunc(routeName string, baseKeyFunc KeyFunc) KeyFunc {
	return func(r *http.Request) string {
		baseKey := baseKeyFunc(r)
		return routeName + ":" + baseKey
	}
}

// PerEndpointKeyFunc returns a KeyFunc that includes the endpoint (method + path) in the key.
func PerEndpointKeyFunc(baseKeyFunc KeyFunc) KeyFunc {
	return func(r *http.Request) string {
		baseKey := baseKeyFunc(r)
		return r.Method + ":" + r.URL.Path + ":" + baseKey
	}
}
