// Package httputil provides shared HTTP utility functions for proxy packages.
package httputil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsHopByHop(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		// Positive cases: all 9 hop-by-hop headers
		{name: "Connection", header: "Connection", expected: true},
		{name: "Proxy-Connection", header: "Proxy-Connection", expected: true},
		{name: "Keep-Alive", header: "Keep-Alive", expected: true},
		{name: "Proxy-Authenticate", header: "Proxy-Authenticate", expected: true},
		{name: "Proxy-Authorization", header: "Proxy-Authorization", expected: true},
		{name: "Te", header: "Te", expected: true},
		{name: "Trailer", header: "Trailer", expected: true},
		{name: "Transfer-Encoding", header: "Transfer-Encoding", expected: true},
		{name: "Upgrade", header: "Upgrade", expected: true},

		// Negative cases: common non-hop-by-hop headers
		{name: "Content-Type is not hop-by-hop", header: "Content-Type", expected: false},
		{name: "Authorization is not hop-by-hop", header: "Authorization", expected: false},
		{name: "Accept is not hop-by-hop", header: "Accept", expected: false},
		{name: "Content-Length is not hop-by-hop", header: "Content-Length", expected: false},
		{name: "Host is not hop-by-hop", header: "Host", expected: false},
		{name: "X-Forwarded-For is not hop-by-hop", header: "X-Forwarded-For", expected: false},
		{name: "X-Custom-Header is not hop-by-hop", header: "X-Custom-Header", expected: false},
		{name: "Cookie is not hop-by-hop", header: "Cookie", expected: false},
		{name: "Set-Cookie is not hop-by-hop", header: "Set-Cookie", expected: false},

		// Edge case: empty string
		{name: "empty string", header: "", expected: false},

		// Case sensitivity: Go's map is case-sensitive
		{name: "lowercase connection is not matched", header: "connection", expected: false},
		{name: "uppercase CONNECTION is not matched", header: "CONNECTION", expected: false},
		{name: "mixed case keep-alive is not matched", header: "keep-alive", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsHopByHop(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHopByHopHeaders_Count(t *testing.T) {
	t.Parallel()

	// Verify the map has exactly 9 entries per RFC 2616/7230
	assert.Len(t, HopByHopHeaders, 9, "HopByHopHeaders should contain exactly 9 entries")
}

func TestHopByHopHeaders_AllEntriesPresent(t *testing.T) {
	t.Parallel()

	expectedHeaders := []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, header := range expectedHeaders {
		_, ok := HopByHopHeaders[header]
		assert.True(t, ok, "HopByHopHeaders should contain %q", header)
	}
}
