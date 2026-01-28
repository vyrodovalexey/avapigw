package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientIPExtractor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		trustedProxies []string
		expectedCIDRs  int
	}{
		{
			name:           "nil proxies",
			trustedProxies: nil,
			expectedCIDRs:  0,
		},
		{
			name:           "empty proxies",
			trustedProxies: []string{},
			expectedCIDRs:  0,
		},
		{
			name:           "single CIDR",
			trustedProxies: []string{"10.0.0.0/8"},
			expectedCIDRs:  1,
		},
		{
			name:           "multiple CIDRs",
			trustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
			expectedCIDRs:  2,
		},
		{
			name:           "single IP without CIDR notation",
			trustedProxies: []string{"192.168.1.1"},
			expectedCIDRs:  1,
		},
		{
			name:           "invalid CIDR is skipped",
			trustedProxies: []string{"invalid", "10.0.0.0/8"},
			expectedCIDRs:  1,
		},
		{
			name:           "IPv6 CIDR",
			trustedProxies: []string{"fd00::/8"},
			expectedCIDRs:  1,
		},
		{
			name:           "IPv6 single address",
			trustedProxies: []string{"::1"},
			expectedCIDRs:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := NewClientIPExtractor(tt.trustedProxies)
			require.NotNil(t, e)
			assert.Len(t, e.trustedCIDRs, tt.expectedCIDRs)
		})
	}
}

func TestClientIPExtractor_Extract_NoTrustedProxies(t *testing.T) {
	t.Parallel()

	e := NewClientIPExtractor(nil)

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		expectedIP string
	}{
		{
			name:       "returns RemoteAddr with port stripped",
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "ignores X-Forwarded-For",
			remoteAddr: "192.168.1.1:12345",
			xff:        "10.0.0.1",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "ignores X-Real-IP",
			remoteAddr: "192.168.1.1:12345",
			xRealIP:    "10.0.0.2",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "ignores both headers",
			remoteAddr: "192.168.1.1:12345",
			xff:        "10.0.0.1, 10.0.0.2",
			xRealIP:    "10.0.0.3",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "handles RemoteAddr without port",
			remoteAddr: "192.168.1.1",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "handles IPv6 RemoteAddr with port",
			remoteAddr: "[::1]:12345",
			expectedIP: "::1",
		},
		{
			name:       "handles IPv6 RemoteAddr without port",
			remoteAddr: "::1",
			expectedIP: "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := e.Extract(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestClientIPExtractor_Extract_WithTrustedProxies(t *testing.T) {
	t.Parallel()

	e := NewClientIPExtractor([]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	})

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		expectedIP string
	}{
		{
			name:       "untrusted RemoteAddr returns RemoteAddr",
			remoteAddr: "203.0.113.1:12345",
			xff:        "10.0.0.1",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "trusted proxy with single XFF entry",
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.50",
			expectedIP: "203.0.113.50",
		},
		{
			name:       "trusted proxy with multiple XFF entries",
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.50, 172.16.0.1",
			expectedIP: "203.0.113.50",
		},
		{
			name:       "trusted proxy chain - returns first non-trusted",
			remoteAddr: "10.0.0.1:12345",
			xff:        "8.8.8.8, 172.16.0.1, 192.168.1.1",
			expectedIP: "8.8.8.8",
		},
		{
			name:       "all XFF IPs trusted returns RemoteAddr",
			remoteAddr: "10.0.0.1:12345",
			xff:        "172.16.0.1, 192.168.1.1",
			expectedIP: "10.0.0.1",
		},
		{
			name:       "trusted proxy with empty XFF returns RemoteAddr",
			remoteAddr: "10.0.0.1:12345",
			xff:        "",
			expectedIP: "10.0.0.1",
		},
		{
			name:       "trusted proxy with no XFF header returns RemoteAddr",
			remoteAddr: "10.0.0.1:12345",
			expectedIP: "10.0.0.1",
		},
		{
			name:       "XFF with whitespace is trimmed",
			remoteAddr: "10.0.0.1:12345",
			xff:        " 203.0.113.50 , 172.16.0.1 ",
			expectedIP: "203.0.113.50",
		},
		{
			name:       "XFF with empty entries are skipped",
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.50,,",
			expectedIP: "203.0.113.50",
		},
		{
			name:       "single IP trusted proxy",
			remoteAddr: "192.168.1.100:8080",
			xff:        "1.2.3.4",
			expectedIP: "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			ip := e.Extract(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestClientIPExtractor_Extract_IPv6(t *testing.T) {
	t.Parallel()

	e := NewClientIPExtractor([]string{"fd00::/8"})

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		expectedIP string
	}{
		{
			name:       "IPv6 trusted proxy with IPv4 client",
			remoteAddr: "[fd00::1]:12345",
			xff:        "203.0.113.50",
			expectedIP: "203.0.113.50",
		},
		{
			name:       "IPv6 trusted proxy with IPv6 client",
			remoteAddr: "[fd00::1]:12345",
			xff:        "2001:db8::1",
			expectedIP: "2001:db8::1",
		},
		{
			name:       "IPv6 untrusted RemoteAddr",
			remoteAddr: "[2001:db8::1]:12345",
			xff:        "10.0.0.1",
			expectedIP: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			ip := e.Extract(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestClientIPExtractor_Extract_SingleIPProxy(t *testing.T) {
	t.Parallel()

	e := NewClientIPExtractor([]string{"10.0.0.1"})

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		expectedIP string
	}{
		{
			name:       "exact IP match trusts XFF",
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.50",
			expectedIP: "203.0.113.50",
		},
		{
			name:       "different IP does not trust XFF",
			remoteAddr: "10.0.0.2:12345",
			xff:        "203.0.113.50",
			expectedIP: "10.0.0.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			ip := e.Extract(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestStripPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{
			name:     "IPv4 with port",
			addr:     "192.168.1.1:12345",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv4 without port",
			addr:     "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv6 with port",
			addr:     "[::1]:12345",
			expected: "::1",
		},
		{
			name:     "IPv6 without port",
			addr:     "::1",
			expected: "::1",
		},
		{
			name:     "empty string",
			addr:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := stripPort(tt.addr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSetGlobalIPExtractor(t *testing.T) {
	// Save and restore the global extractor
	original := globalExtractor
	defer func() { globalExtractor = original }()

	// Setting nil should not change the extractor
	SetGlobalIPExtractor(nil)
	assert.Equal(t, original, globalExtractor)

	// Setting a new extractor should update it
	newExtractor := NewClientIPExtractor([]string{"10.0.0.0/8"})
	SetGlobalIPExtractor(newExtractor)
	assert.Equal(t, newExtractor, globalExtractor)
}

func TestClientIPExtractor_SpoofingPrevention(t *testing.T) {
	t.Parallel()

	t.Run("attacker cannot spoof IP without trusted proxies", func(t *testing.T) {
		t.Parallel()

		e := NewClientIPExtractor(nil)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "203.0.113.1:12345"
		req.Header.Set("X-Forwarded-For", "10.0.0.1")

		ip := e.Extract(req)
		assert.Equal(t, "203.0.113.1", ip,
			"should use RemoteAddr, not spoofed XFF")
	})

	t.Run("attacker cannot spoof IP from untrusted source", func(t *testing.T) {
		t.Parallel()

		e := NewClientIPExtractor([]string{"10.0.0.0/8"})
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "203.0.113.1:12345"
		req.Header.Set("X-Forwarded-For", "10.0.0.1")

		ip := e.Extract(req)
		assert.Equal(t, "203.0.113.1", ip,
			"should use RemoteAddr when source is not trusted")
	})

	t.Run("attacker prepends fake IP to XFF via trusted proxy", func(t *testing.T) {
		t.Parallel()

		e := NewClientIPExtractor([]string{"10.0.0.0/8"})
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		// Attacker sent "1.1.1.1" as XFF, proxy appended real client IP
		req.Header.Set("X-Forwarded-For", "1.1.1.1, 203.0.113.50")

		ip := e.Extract(req)
		assert.Equal(t, "203.0.113.50", ip,
			"should return rightmost non-trusted IP, not attacker-injected")
	})
}

func TestGetClientIP_WithGlobalExtractor(t *testing.T) {
	// Save and restore the global extractor
	original := globalExtractor
	defer func() { globalExtractor = original }()

	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		xff            string
		expectedIP     string
	}{
		{
			name:           "no trusted proxies - uses RemoteAddr",
			trustedProxies: nil,
			remoteAddr:     "203.0.113.1:12345",
			xff:            "10.0.0.1",
			expectedIP:     "203.0.113.1",
		},
		{
			name:           "no trusted proxies - ignores XFF",
			trustedProxies: nil,
			remoteAddr:     "192.168.1.1:8080",
			xff:            "1.2.3.4",
			expectedIP:     "192.168.1.1",
		},
		{
			name:           "trusted proxies configured - extracts from XFF",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.1:12345",
			xff:            "203.0.113.50",
			expectedIP:     "203.0.113.50",
		},
		{
			name:           "trusted proxies configured - no XFF falls back to RemoteAddr",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.1:12345",
			xff:            "",
			expectedIP:     "10.0.0.1",
		},
		{
			name:           "trusted proxies configured - untrusted RemoteAddr ignores XFF",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "203.0.113.1:12345",
			xff:            "1.2.3.4",
			expectedIP:     "203.0.113.1",
		},
		{
			name:           "RemoteAddr without port",
			trustedProxies: nil,
			remoteAddr:     "192.168.1.1",
			expectedIP:     "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global extractor for this test case
			extractor := NewClientIPExtractor(tt.trustedProxies)
			SetGlobalIPExtractor(extractor)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			ip := GetClientIP(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestSingleIPToCIDR(t *testing.T) {
	t.Parallel()

	t.Run("IPv4 creates /32 mask", func(t *testing.T) {
		t.Parallel()

		e := NewClientIPExtractor([]string{"192.168.1.1"})
		require.Len(t, e.trustedCIDRs, 1)
		ones, bits := e.trustedCIDRs[0].Mask.Size()
		assert.Equal(t, 32, ones)
		assert.Equal(t, 32, bits)
	})

	t.Run("IPv6 creates /128 mask", func(t *testing.T) {
		t.Parallel()

		e := NewClientIPExtractor([]string{"::1"})
		require.Len(t, e.trustedCIDRs, 1)
		ones, bits := e.trustedCIDRs[0].Mask.Size()
		assert.Equal(t, 128, ones)
		assert.Equal(t, 128, bits)
	})
}
