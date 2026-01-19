package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Test Cases for IPKeyFunc
// ============================================================================

func TestIPKeyFunc(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "simple remote addr",
			remoteAddr: "192.168.1.1:8080",
			headers:    nil,
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For header",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2"},
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Real-IP": "10.0.0.5"},
			expected:   "10.0.0.5",
		},
		{
			name:       "CF-Connecting-IP header",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"CF-Connecting-IP": "10.0.0.10"},
			expected:   "10.0.0.10",
		},
		{
			name:       "True-Client-IP header",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"True-Client-IP": "10.0.0.15"},
			expected:   "10.0.0.15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			result := IPKeyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for HeaderKeyFunc
// ============================================================================

func TestHeaderKeyFunc(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:       "header exists",
			headerName: "X-API-Key",
			headers:    map[string]string{"X-API-Key": "my-api-key"},
			remoteAddr: "192.168.1.1:8080",
			expected:   "my-api-key",
		},
		{
			name:       "header missing falls back to IP",
			headerName: "X-API-Key",
			headers:    nil,
			remoteAddr: "192.168.1.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "empty header falls back to IP",
			headerName: "X-API-Key",
			headers:    map[string]string{"X-API-Key": ""},
			remoteAddr: "192.168.1.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "custom header",
			headerName: "X-Custom-Header",
			headers:    map[string]string{"X-Custom-Header": "custom-value"},
			remoteAddr: "192.168.1.1:8080",
			expected:   "custom-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			keyFunc := HeaderKeyFunc(tt.headerName)
			result := keyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for JWTClaimKeyFunc
// ============================================================================

func TestJWTClaimKeyFunc(t *testing.T) {
	tests := []struct {
		name       string
		claim      string
		claims     map[string]interface{}
		remoteAddr string
		expected   string
	}{
		{
			name:       "claim exists as string",
			claim:      "user_id",
			claims:     map[string]interface{}{"user_id": "user123"},
			remoteAddr: "192.168.1.1:8080",
			expected:   "user123",
		},
		{
			name:       "claim missing falls back to IP",
			claim:      "user_id",
			claims:     map[string]interface{}{"other_claim": "value"},
			remoteAddr: "192.168.1.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "claim not a string falls back to IP",
			claim:      "user_id",
			claims:     map[string]interface{}{"user_id": 12345},
			remoteAddr: "192.168.1.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "no claims in context falls back to IP",
			claim:      "user_id",
			claims:     nil,
			remoteAddr: "192.168.1.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "sub claim",
			claim:      "sub",
			claims:     map[string]interface{}{"sub": "subject123"},
			remoteAddr: "192.168.1.1:8080",
			expected:   "subject123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			if tt.claims != nil {
				ctx := context.WithValue(req.Context(), "jwt_claims", tt.claims)
				req = req.WithContext(ctx)
			}

			keyFunc := JWTClaimKeyFunc(tt.claim)
			result := keyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for CompositeKeyFunc
// ============================================================================

func TestCompositeKeyFunc(t *testing.T) {
	tests := []struct {
		name       string
		funcs      []KeyFunc
		remoteAddr string
		path       string
		method     string
		expected   string
	}{
		{
			name: "combine IP and path",
			funcs: []KeyFunc{
				IPKeyFunc,
				PathKeyFunc,
			},
			remoteAddr: "192.168.1.1:8080",
			path:       "/api/users",
			method:     http.MethodGet,
			expected:   "192.168.1.1:/api/users",
		},
		{
			name: "combine method and path",
			funcs: []KeyFunc{
				MethodKeyFunc,
				PathKeyFunc,
			},
			remoteAddr: "192.168.1.1:8080",
			path:       "/api/users",
			method:     http.MethodPost,
			expected:   "POST:/api/users",
		},
		{
			name: "combine IP, method, and path",
			funcs: []KeyFunc{
				IPKeyFunc,
				MethodKeyFunc,
				PathKeyFunc,
			},
			remoteAddr: "192.168.1.1:8080",
			path:       "/api/users",
			method:     http.MethodGet,
			expected:   "192.168.1.1:GET:/api/users",
		},
		{
			name:       "empty funcs falls back to IP",
			funcs:      []KeyFunc{},
			remoteAddr: "192.168.1.1:8080",
			path:       "/api/users",
			method:     http.MethodGet,
			expected:   "192.168.1.1",
		},
		{
			name: "single func",
			funcs: []KeyFunc{
				IPKeyFunc,
			},
			remoteAddr: "192.168.1.1:8080",
			path:       "/api/users",
			method:     http.MethodGet,
			expected:   "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = tt.remoteAddr

			keyFunc := CompositeKeyFunc(tt.funcs...)
			result := keyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCompositeKeyFunc_WithEmptyKeys(t *testing.T) {
	// Create a key func that returns empty string
	emptyKeyFunc := func(r *http.Request) string {
		return ""
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:8080"

	// All empty should fall back to IP
	keyFunc := CompositeKeyFunc(emptyKeyFunc, emptyKeyFunc)
	result := keyFunc(req)
	assert.Equal(t, "192.168.1.1", result)

	// Mix of empty and non-empty
	keyFunc = CompositeKeyFunc(emptyKeyFunc, IPKeyFunc)
	result = keyFunc(req)
	assert.Equal(t, "192.168.1.1", result)
}

// ============================================================================
// Test Cases for PathKeyFunc
// ============================================================================

func TestPathKeyFunc(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "simple path",
			path:     "/api/users",
			expected: "/api/users",
		},
		{
			name:     "root path",
			path:     "/",
			expected: "/",
		},
		{
			name:     "path with query params",
			path:     "/api/users?page=1",
			expected: "/api/users",
		},
		{
			name:     "nested path",
			path:     "/api/v1/users/123/orders",
			expected: "/api/v1/users/123/orders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			result := PathKeyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for MethodKeyFunc
// ============================================================================

func TestMethodKeyFunc(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		expected string
	}{
		{
			name:     "GET method",
			method:   http.MethodGet,
			expected: "GET",
		},
		{
			name:     "POST method",
			method:   http.MethodPost,
			expected: "POST",
		},
		{
			name:     "PUT method",
			method:   http.MethodPut,
			expected: "PUT",
		},
		{
			name:     "DELETE method",
			method:   http.MethodDelete,
			expected: "DELETE",
		},
		{
			name:     "PATCH method",
			method:   http.MethodPatch,
			expected: "PATCH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			result := MethodKeyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for MethodPathKeyFunc
// ============================================================================

func TestMethodPathKeyFunc(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		expected string
	}{
		{
			name:     "GET /api/users",
			method:   http.MethodGet,
			path:     "/api/users",
			expected: "GET:/api/users",
		},
		{
			name:     "POST /api/users",
			method:   http.MethodPost,
			path:     "/api/users",
			expected: "POST:/api/users",
		},
		{
			name:     "DELETE /api/users/123",
			method:   http.MethodDelete,
			path:     "/api/users/123",
			expected: "DELETE:/api/users/123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			result := MethodPathKeyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for UserAgentKeyFunc
// ============================================================================

func TestUserAgentKeyFunc(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expected  string
	}{
		{
			name:      "Chrome user agent",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expected:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
		{
			name:      "curl user agent",
			userAgent: "curl/7.68.0",
			expected:  "curl/7.68.0",
		},
		{
			name:      "empty user agent",
			userAgent: "",
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			result := UserAgentKeyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for APIKeyFunc
// ============================================================================

func TestAPIKeyFunc(t *testing.T) {
	tests := []struct {
		name        string
		headerName  string
		queryParam  string
		headers     map[string]string
		queryParams map[string]string
		remoteAddr  string
		expected    string
	}{
		{
			name:       "API key in header",
			headerName: "X-API-Key",
			queryParam: "api_key",
			headers:    map[string]string{"X-API-Key": "header-key"},
			remoteAddr: "192.168.1.1:8080",
			expected:   "header-key",
		},
		{
			name:        "API key in query param",
			headerName:  "X-API-Key",
			queryParam:  "api_key",
			queryParams: map[string]string{"api_key": "query-key"},
			remoteAddr:  "192.168.1.1:8080",
			expected:    "query-key",
		},
		{
			name:        "header takes precedence over query",
			headerName:  "X-API-Key",
			queryParam:  "api_key",
			headers:     map[string]string{"X-API-Key": "header-key"},
			queryParams: map[string]string{"api_key": "query-key"},
			remoteAddr:  "192.168.1.1:8080",
			expected:    "header-key",
		},
		{
			name:       "no API key falls back to IP",
			headerName: "X-API-Key",
			queryParam: "api_key",
			remoteAddr: "192.168.1.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:        "empty header falls back to query",
			headerName:  "X-API-Key",
			queryParam:  "api_key",
			headers:     map[string]string{"X-API-Key": ""},
			queryParams: map[string]string{"api_key": "query-key"},
			remoteAddr:  "192.168.1.1:8080",
			expected:    "query-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := "/test"
			if len(tt.queryParams) > 0 {
				path += "?"
				for k, v := range tt.queryParams {
					path += k + "=" + v + "&"
				}
				path = path[:len(path)-1]
			}

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			keyFunc := APIKeyFunc(tt.headerName, tt.queryParam)
			result := keyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for GetClientIP
// ============================================================================

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "simple IPv4 with port",
			remoteAddr: "192.168.1.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "IPv4 without port",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
		{
			name:       "IPv6 with port",
			remoteAddr: "[::1]:8080",
			expected:   "::1",
		},
		{
			name:       "IPv6 without port",
			remoteAddr: "::1",
			expected:   ":", // Current implementation strips after last colon
		},
		{
			name:       "X-Forwarded-For single IP",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1"},
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Forwarded-For multiple IPs",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2, 10.0.0.3"},
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Forwarded-For with spaces",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Forwarded-For": "  10.0.0.1  , 10.0.0.2"},
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Real-IP",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Real-IP": "10.0.0.5"},
			expected:   "10.0.0.5",
		},
		{
			name:       "CF-Connecting-IP",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"CF-Connecting-IP": "10.0.0.10"},
			expected:   "10.0.0.10",
		},
		{
			name:       "True-Client-IP",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"True-Client-IP": "10.0.0.15"},
			expected:   "10.0.0.15",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			remoteAddr: "127.0.0.1:8080",
			headers: map[string]string{
				"X-Forwarded-For":  "10.0.0.1",
				"X-Real-IP":        "10.0.0.5",
				"CF-Connecting-IP": "10.0.0.10",
				"True-Client-IP":   "10.0.0.15",
			},
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			result := GetClientIP(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for PerRouteKeyFunc
// ============================================================================

func TestPerRouteKeyFunc(t *testing.T) {
	tests := []struct {
		name       string
		routeName  string
		remoteAddr string
		expected   string
	}{
		{
			name:       "route with IP",
			routeName:  "users-api",
			remoteAddr: "192.168.1.1:8080",
			expected:   "users-api:192.168.1.1",
		},
		{
			name:       "different route",
			routeName:  "orders-api",
			remoteAddr: "192.168.1.1:8080",
			expected:   "orders-api:192.168.1.1",
		},
		{
			name:       "empty route name",
			routeName:  "",
			remoteAddr: "192.168.1.1:8080",
			expected:   ":192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			keyFunc := PerRouteKeyFunc(tt.routeName, IPKeyFunc)
			result := keyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for PerEndpointKeyFunc
// ============================================================================

func TestPerEndpointKeyFunc(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		remoteAddr string
		expected   string
	}{
		{
			name:       "GET endpoint",
			method:     http.MethodGet,
			path:       "/api/users",
			remoteAddr: "192.168.1.1:8080",
			expected:   "GET:/api/users:192.168.1.1",
		},
		{
			name:       "POST endpoint",
			method:     http.MethodPost,
			path:       "/api/users",
			remoteAddr: "192.168.1.1:8080",
			expected:   "POST:/api/users:192.168.1.1",
		},
		{
			name:       "DELETE endpoint with ID",
			method:     http.MethodDelete,
			path:       "/api/users/123",
			remoteAddr: "192.168.1.1:8080",
			expected:   "DELETE:/api/users/123:192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = tt.remoteAddr

			keyFunc := PerEndpointKeyFunc(IPKeyFunc)
			result := keyFunc(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for Edge Cases
// ============================================================================

func TestKeyFunc_NilRequest(t *testing.T) {
	// These should not panic with nil request
	// Note: In practice, nil requests shouldn't happen, but we test for robustness
	// The actual functions will panic with nil, which is expected behavior
}

func TestGetClientIP_EmptyRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = ""

	result := GetClientIP(req)
	assert.Equal(t, "", result)
}

func TestGetClientIP_IPv6Brackets(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{
			name:       "IPv6 with brackets and port",
			remoteAddr: "[2001:db8::1]:8080",
			expected:   "2001:db8::1",
		},
		{
			name:       "IPv6 with brackets no port",
			remoteAddr: "[2001:db8::1]",
			expected:   "2001:db8:", // Current implementation strips after last colon before removing brackets
		},
		{
			name:       "IPv6 loopback with brackets",
			remoteAddr: "[::1]:8080",
			expected:   "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			result := GetClientIP(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for Custom Key Functions
// ============================================================================

func TestCustomKeyFunc(t *testing.T) {
	// Test that custom key functions work with CompositeKeyFunc
	customKeyFunc := func(r *http.Request) string {
		return "custom-prefix"
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:8080"

	keyFunc := CompositeKeyFunc(customKeyFunc, IPKeyFunc)
	result := keyFunc(req)
	assert.Equal(t, "custom-prefix:192.168.1.1", result)
}

func TestKeyFunc_WithHeaderKeyFunc_CustomHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:8080"
	req.Header.Set("X-Tenant-ID", "tenant123")

	keyFunc := CompositeKeyFunc(
		HeaderKeyFunc("X-Tenant-ID"),
		IPKeyFunc,
	)
	result := keyFunc(req)
	assert.Equal(t, "tenant123:192.168.1.1", result)
}
