package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid http URL",
			url:     "http://example.com",
			wantErr: false,
		},
		{
			name:    "valid https URL",
			url:     "https://example.com",
			wantErr: false,
		},
		{
			name:    "valid URL with port",
			url:     "http://example.com:8080",
			wantErr: false,
		},
		{
			name:    "valid URL with path",
			url:     "https://example.com/api/v1",
			wantErr: false,
		},
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
		},
		{
			name:    "missing scheme",
			url:     "example.com",
			wantErr: true,
		},
		{
			name:    "invalid scheme",
			url:     "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "missing host",
			url:     "http://",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHeaderName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{
			name:    "valid header",
			header:  "Content-Type",
			wantErr: false,
		},
		{
			name:    "valid header with numbers",
			header:  "X-Custom-Header-123",
			wantErr: false,
		},
		{
			name:    "valid header lowercase",
			header:  "x-request-id",
			wantErr: false,
		},
		{
			name:    "empty header",
			header:  "",
			wantErr: true,
		},
		{
			name:    "header with space",
			header:  "Content Type",
			wantErr: true,
		},
		{
			name:    "header with colon",
			header:  "Content:Type",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateHeaderName(tt.header)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{
			name:    "valid port 80",
			port:    80,
			wantErr: false,
		},
		{
			name:    "valid port 443",
			port:    443,
			wantErr: false,
		},
		{
			name:    "valid port 8080",
			port:    8080,
			wantErr: false,
		},
		{
			name:    "valid port 1",
			port:    1,
			wantErr: false,
		},
		{
			name:    "valid port 65535",
			port:    65535,
			wantErr: false,
		},
		{
			name:    "invalid port 0",
			port:    0,
			wantErr: true,
		},
		{
			name:    "invalid port negative",
			port:    -1,
			wantErr: true,
		},
		{
			name:    "invalid port too high",
			port:    65536,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePort(tt.port)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateNonNegativePort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{
			name:    "valid port 0",
			port:    0,
			wantErr: false,
		},
		{
			name:    "valid port 8080",
			port:    8080,
			wantErr: false,
		},
		{
			name:    "valid port 65535",
			port:    65535,
			wantErr: false,
		},
		{
			name:    "invalid port negative",
			port:    -1,
			wantErr: true,
		},
		{
			name:    "invalid port too high",
			port:    65536,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateNonNegativePort(tt.port)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "standard format seconds",
			input:    "30s",
			expected: 30 * time.Second,
			wantErr:  false,
		},
		{
			name:     "standard format minutes",
			input:    "5m",
			expected: 5 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "standard format hours",
			input:    "1h",
			expected: time.Hour,
			wantErr:  false,
		},
		{
			name:     "standard format milliseconds",
			input:    "100ms",
			expected: 100 * time.Millisecond,
			wantErr:  false,
		},
		{
			name:     "numeric only (seconds)",
			input:    "30",
			expected: 30 * time.Second,
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "invalid format",
			input:    "invalid",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := ParseDuration(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestValidateDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		duration time.Duration
		wantErr  bool
	}{
		{
			name:     "positive duration",
			duration: time.Second,
			wantErr:  false,
		},
		{
			name:     "zero duration",
			duration: 0,
			wantErr:  false,
		},
		{
			name:     "negative duration",
			duration: -time.Second,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDuration(tt.duration)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePositiveDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		duration time.Duration
		wantErr  bool
	}{
		{
			name:     "positive duration",
			duration: time.Second,
			wantErr:  false,
		},
		{
			name:     "zero duration",
			duration: 0,
			wantErr:  true,
		},
		{
			name:     "negative duration",
			duration: -time.Second,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePositiveDuration(tt.duration)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{
			name:    "valid simple pattern",
			pattern: "^/api/.*",
			wantErr: false,
		},
		{
			name:    "valid complex pattern",
			pattern: `^/users/(?P<id>\d+)$`,
			wantErr: false,
		},
		{
			name:    "empty pattern",
			pattern: "",
			wantErr: false,
		},
		{
			name:    "invalid pattern",
			pattern: "[invalid",
			wantErr: true,
		},
		{
			name:    "invalid pattern unclosed group",
			pattern: "(unclosed",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateRegex(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHTTPMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		wantErr bool
	}{
		{
			name:    "GET",
			method:  "GET",
			wantErr: false,
		},
		{
			name:    "POST",
			method:  "POST",
			wantErr: false,
		},
		{
			name:    "PUT",
			method:  "PUT",
			wantErr: false,
		},
		{
			name:    "DELETE",
			method:  "DELETE",
			wantErr: false,
		},
		{
			name:    "PATCH",
			method:  "PATCH",
			wantErr: false,
		},
		{
			name:    "HEAD",
			method:  "HEAD",
			wantErr: false,
		},
		{
			name:    "OPTIONS",
			method:  "OPTIONS",
			wantErr: false,
		},
		{
			name:    "TRACE",
			method:  "TRACE",
			wantErr: false,
		},
		{
			name:    "CONNECT",
			method:  "CONNECT",
			wantErr: false,
		},
		{
			name:    "wildcard",
			method:  "*",
			wantErr: false,
		},
		{
			name:    "lowercase get",
			method:  "get",
			wantErr: false,
		},
		{
			name:    "invalid method",
			method:  "INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateHTTPMethod(tt.method)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHTTPStatusCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		code    int
		wantErr bool
	}{
		{
			name:    "200 OK",
			code:    200,
			wantErr: false,
		},
		{
			name:    "201 Created",
			code:    201,
			wantErr: false,
		},
		{
			name:    "301 Redirect",
			code:    301,
			wantErr: false,
		},
		{
			name:    "400 Bad Request",
			code:    400,
			wantErr: false,
		},
		{
			name:    "404 Not Found",
			code:    404,
			wantErr: false,
		},
		{
			name:    "500 Internal Server Error",
			code:    500,
			wantErr: false,
		},
		{
			name:    "100 Continue",
			code:    100,
			wantErr: false,
		},
		{
			name:    "599 max valid",
			code:    599,
			wantErr: false,
		},
		{
			name:    "99 too low",
			code:    99,
			wantErr: true,
		},
		{
			name:    "600 too high",
			code:    600,
			wantErr: true,
		},
		{
			name:    "negative",
			code:    -1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateHTTPStatusCode(tt.code)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePercentage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   float64
		wantErr bool
	}{
		{
			name:    "0 percent",
			value:   0,
			wantErr: false,
		},
		{
			name:    "50 percent",
			value:   50,
			wantErr: false,
		},
		{
			name:    "100 percent",
			value:   100,
			wantErr: false,
		},
		{
			name:    "decimal percent",
			value:   33.33,
			wantErr: false,
		},
		{
			name:    "negative percent",
			value:   -1,
			wantErr: true,
		},
		{
			name:    "over 100 percent",
			value:   101,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePercentage(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateWeight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		weight  int
		wantErr bool
	}{
		{
			name:    "0 weight",
			weight:  0,
			wantErr: false,
		},
		{
			name:    "50 weight",
			weight:  50,
			wantErr: false,
		},
		{
			name:    "100 weight",
			weight:  100,
			wantErr: false,
		},
		{
			name:    "negative weight",
			weight:  -1,
			wantErr: true,
		},
		{
			name:    "over 100 weight",
			weight:  101,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateWeight(tt.weight)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateNonEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		field   string
		wantErr bool
	}{
		{
			name:    "non-empty value",
			value:   "test",
			field:   "name",
			wantErr: false,
		},
		{
			name:    "empty value",
			value:   "",
			field:   "name",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			value:   "   ",
			field:   "name",
			wantErr: true,
		},
		{
			name:    "value with whitespace",
			value:   "  test  ",
			field:   "name",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateNonEmpty(tt.value, tt.field)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.field)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{
			name:     "simple hostname",
			hostname: "example",
			wantErr:  false,
		},
		{
			name:     "domain name",
			hostname: "example.com",
			wantErr:  false,
		},
		{
			name:     "subdomain",
			hostname: "api.example.com",
			wantErr:  false,
		},
		{
			name:     "wildcard",
			hostname: "*",
			wantErr:  false,
		},
		{
			name:     "wildcard subdomain",
			hostname: "*.example.com",
			wantErr:  false,
		},
		{
			name:     "hostname with numbers",
			hostname: "api1.example.com",
			wantErr:  false,
		},
		{
			name:     "hostname with hyphen",
			hostname: "my-api.example.com",
			wantErr:  false,
		},
		{
			name:     "empty hostname",
			hostname: "",
			wantErr:  true,
		},
		{
			name:     "hostname too long",
			hostname: string(make([]byte, 254)),
			wantErr:  true,
		},
		{
			name:     "label too long",
			hostname: string(make([]byte, 64)) + ".com",
			wantErr:  true,
		},
		{
			name:     "empty label",
			hostname: "example..com",
			wantErr:  true,
		},
		{
			name:     "starts with hyphen",
			hostname: "-example.com",
			wantErr:  true,
		},
		{
			name:     "ends with hyphen",
			hostname: "example-.com",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateHostname(tt.hostname)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{
			name:    "valid IPv4",
			ip:      "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "valid IPv4 all zeros",
			ip:      "0.0.0.0",
			wantErr: false,
		},
		{
			name:    "valid IPv6 all zeros",
			ip:      "::",
			wantErr: false,
		},
		{
			name:    "valid IPv6",
			ip:      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			wantErr: false,
		},
		{
			name:    "valid IPv6 short",
			ip:      "::1",
			wantErr: false,
		},
		{
			name:    "empty IP",
			ip:      "",
			wantErr: true,
		},
		{
			name:    "invalid characters",
			ip:      "192.168.1.x",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateIPAddress(tt.ip)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsNumeric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "numeric string",
			input:    "12345",
			expected: true,
		},
		{
			name:     "single digit",
			input:    "0",
			expected: true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "contains letters",
			input:    "123abc",
			expected: false,
		},
		{
			name:     "contains decimal",
			input:    "12.34",
			expected: false,
		},
		{
			name:     "negative number",
			input:    "-123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isNumeric(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidHostnameChar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		char     rune
		isFirst  bool
		isLast   bool
		expected bool
	}{
		{
			name:     "lowercase letter",
			char:     'a',
			isFirst:  false,
			isLast:   false,
			expected: true,
		},
		{
			name:     "uppercase letter",
			char:     'Z',
			isFirst:  false,
			isLast:   false,
			expected: true,
		},
		{
			name:     "digit",
			char:     '5',
			isFirst:  false,
			isLast:   false,
			expected: true,
		},
		{
			name:     "hyphen in middle",
			char:     '-',
			isFirst:  false,
			isLast:   false,
			expected: true,
		},
		{
			name:     "hyphen at start",
			char:     '-',
			isFirst:  true,
			isLast:   false,
			expected: false,
		},
		{
			name:     "hyphen at end",
			char:     '-',
			isFirst:  false,
			isLast:   true,
			expected: false,
		},
		{
			name:     "invalid character",
			char:     '@',
			isFirst:  false,
			isLast:   false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isValidHostnameChar(tt.char, tt.isFirst, tt.isLast)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidIPChar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		char     rune
		expected bool
	}{
		{
			name:     "digit",
			char:     '5',
			expected: true,
		},
		{
			name:     "lowercase hex",
			char:     'a',
			expected: true,
		},
		{
			name:     "uppercase hex",
			char:     'F',
			expected: true,
		},
		{
			name:     "dot",
			char:     '.',
			expected: true,
		},
		{
			name:     "colon",
			char:     ':',
			expected: true,
		},
		{
			name:     "invalid letter",
			char:     'g',
			expected: false,
		},
		{
			name:     "invalid character",
			char:     '@',
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isValidIPChar(tt.char)
			assert.Equal(t, tt.expected, result)
		})
	}
}
