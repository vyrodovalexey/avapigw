package config

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// ParseWSOrigin
// ============================================================================

func TestParseWSOrigin_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		value      string
		wantScheme string
		wantHost   string
	}{
		{
			name:       "https origin",
			value:      "https://app.example.com",
			wantScheme: "https",
			wantHost:   "app.example.com",
		},
		{
			name:       "http origin with port",
			value:      "http://app.example.com:8080",
			wantScheme: "http",
			wantHost:   "app.example.com:8080",
		},
		{
			name:       "uppercase normalized to lowercase",
			value:      "HTTPS://APP.Example.COM",
			wantScheme: "https",
			wantHost:   "app.example.com",
		},
		{
			name:       "wss mapped to https",
			value:      "wss://push.example.com",
			wantScheme: "https",
			wantHost:   "push.example.com",
		},
		{
			name:       "ws mapped to http",
			value:      "ws://push.example.com",
			wantScheme: "http",
			wantHost:   "push.example.com",
		},
		{
			name:       "bare host matches any scheme",
			value:      "app.example.com",
			wantScheme: "",
			wantHost:   "app.example.com",
		},
		{
			name:       "bare host with port",
			value:      "app.example.com:8443",
			wantScheme: "",
			wantHost:   "app.example.com:8443",
		},
		{
			name:       "trailing slash accepted",
			value:      "https://app.example.com/",
			wantScheme: "https",
			wantHost:   "app.example.com",
		},
		{
			name:       "surrounding whitespace trimmed",
			value:      "  https://app.example.com  ",
			wantScheme: "https",
			wantHost:   "app.example.com",
		},
		{
			name:       "localhost with port",
			value:      "http://localhost:3000",
			wantScheme: "http",
			wantHost:   "localhost:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scheme, host, err := ParseWSOrigin(tt.value)
			require.NoError(t, err)
			assert.Equal(t, tt.wantScheme, scheme)
			assert.Equal(t, tt.wantHost, host)
		})
	}
}

func TestParseWSOrigin_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{
			name:    "empty value",
			value:   "",
			wantErr: ErrWSOriginEmpty,
		},
		{
			name:    "blank value",
			value:   "   ",
			wantErr: ErrWSOriginEmpty,
		},
		{
			name:    "scheme without host",
			value:   "https://",
			wantErr: ErrWSOriginHost,
		},
		{
			name:    "path not allowed",
			value:   "https://app.example.com/path",
			wantErr: ErrWSOriginPath,
		},
		{
			name:    "query not allowed",
			value:   "https://app.example.com?x=1",
			wantErr: ErrWSOriginPath,
		},
		{
			name:    "fragment not allowed",
			value:   "https://app.example.com#frag",
			wantErr: ErrWSOriginPath,
		},
		{
			name:    "credentials not allowed",
			value:   "https://user:pass@app.example.com",
			wantErr: ErrWSOriginPath,
		},
		{
			name:    "unsupported scheme",
			value:   "ftp://app.example.com",
			wantErr: ErrWSOriginScheme,
		},
		{
			name:    "wildcard pattern host",
			value:   "*.example.com",
			wantErr: ErrWSOriginWildcardHost,
		},
		{
			name:    "wildcard pattern with scheme",
			value:   "https://*.example.com",
			wantErr: ErrWSOriginWildcardHost,
		},
		{
			name:    "standalone wildcard is not an origin",
			value:   "*",
			wantErr: ErrWSOriginWildcardHost,
		},
		{
			name:  "unparseable url",
			value: "http://[::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := ParseWSOrigin(tt.value)
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// Validator — spec.websocket
// ============================================================================

// validWebSocketGatewayConfig returns a minimal valid gateway config with
// the given WebSocket configuration attached.
func validWebSocketGatewayConfig(ws *WebSocketConfig) *GatewayConfig {
	cfg := DefaultConfig()
	cfg.Spec.WebSocket = ws
	return cfg
}

func TestValidator_WebSocket(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ws        *WebSocketConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "nil websocket config is valid",
			ws:      nil,
			wantErr: false,
		},
		{
			name:    "empty allowlist is valid (permissive default)",
			ws:      &WebSocketConfig{},
			wantErr: false,
		},
		{
			name: "valid entries",
			ws: &WebSocketConfig{
				AllowedOrigins: []string{
					"https://app.example.com",
					"app.example.com:8443",
					"ws://push.example.com",
				},
			},
			wantErr: false,
		},
		{
			name: "wildcard entry is valid",
			ws: &WebSocketConfig{
				AllowedOrigins: []string{WSOriginWildcard},
			},
			wantErr: false,
		},
		{
			name: "wildcard with surrounding whitespace is valid",
			ws: &WebSocketConfig{
				AllowedOrigins: []string{"  *  "},
			},
			wantErr: false,
		},
		{
			name: "invalid entry with path",
			ws: &WebSocketConfig{
				AllowedOrigins: []string{"https://app.example.com/path"},
			},
			wantErr:   true,
			errSubstr: "spec.websocket.allowedOrigins[0]",
		},
		{
			name: "invalid empty entry",
			ws: &WebSocketConfig{
				AllowedOrigins: []string{""},
			},
			wantErr:   true,
			errSubstr: "spec.websocket.allowedOrigins[0]",
		},
		{
			name: "wildcard pattern entry rejected",
			ws: &WebSocketConfig{
				AllowedOrigins: []string{"https://ok.example.com", "*.example.com"},
			},
			wantErr:   true,
			errSubstr: "spec.websocket.allowedOrigins[1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateConfig(validWebSocketGatewayConfig(tt.ws))
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}

// ============================================================================
// WebSocketConfig serialization round-trips
// ============================================================================

func TestWebSocketConfig_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := GatewaySpec{
		Listeners: []Listener{
			{Name: "http", Port: 8080, Protocol: "HTTP"},
		},
		WebSocket: &WebSocketConfig{
			AllowedOrigins: []string{"https://app.example.com", "*"},
		},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), "allowedOrigins")

	var restored GatewaySpec
	require.NoError(t, yaml.Unmarshal(data, &restored))
	require.NotNil(t, restored.WebSocket)
	assert.Equal(t, original.WebSocket.AllowedOrigins, restored.WebSocket.AllowedOrigins)
}

func TestWebSocketConfig_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := GatewaySpec{
		Listeners: []Listener{
			{Name: "http", Port: 8080, Protocol: "HTTP"},
		},
		WebSocket: &WebSocketConfig{
			AllowedOrigins: []string{"https://app.example.com"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"websocket"`)
	assert.Contains(t, string(data), `"allowedOrigins"`)

	var restored GatewaySpec
	require.NoError(t, json.Unmarshal(data, &restored))
	require.NotNil(t, restored.WebSocket)
	assert.Equal(t, original.WebSocket.AllowedOrigins, restored.WebSocket.AllowedOrigins)
}

func TestWebSocketConfig_OmittedWhenNil(t *testing.T) {
	t.Parallel()

	spec := GatewaySpec{
		Listeners: []Listener{
			{Name: "http", Port: 8080, Protocol: "HTTP"},
		},
	}

	data, err := json.Marshal(spec)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"websocket"`)
}

// TestParseWSOrigin_ErrorsWrapValue verifies wrapped errors keep the
// offending value for diagnostics while remaining errors.Is-classifiable.
func TestParseWSOrigin_ErrorsWrapValue(t *testing.T) {
	t.Parallel()

	_, _, err := ParseWSOrigin("https://app.example.com/api")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWSOriginPath))
	assert.Contains(t, err.Error(), "https://app.example.com/api")
}
