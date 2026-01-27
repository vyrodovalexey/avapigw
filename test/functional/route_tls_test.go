//go:build functional
// +build functional

package functional

import (
	cryptotls "crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestFunctional_RouteTLS_ConfigParsing tests route TLS configuration parsing.
func TestFunctional_RouteTLS_ConfigParsing(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		config *config.RouteTLSConfig
		valid  bool
	}{
		{
			name: "valid file-based config",
			config: &config.RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"api.example.com"},
			},
			valid: true,
		},
		{
			name: "valid config with multiple SNI hosts",
			config: &config.RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"api.example.com", "www.example.com", "admin.example.com"},
			},
			valid: true,
		},
		{
			name: "valid config with wildcard SNI",
			config: &config.RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"*.example.com"},
			},
			valid: true,
		},
		{
			name: "valid config with TLS versions",
			config: &config.RouteTLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				SNIHosts:   []string{"api.example.com"},
				MinVersion: "TLS12",
				MaxVersion: "TLS13",
			},
			valid: true,
		},
		{
			name: "valid config with client validation",
			config: &config.RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"api.example.com"},
				ClientValidation: &config.RouteClientValidationConfig{
					Enabled:           true,
					CAFile:            "/path/to/ca.pem",
					RequireClientCert: true,
				},
			},
			valid: true,
		},
		{
			name: "valid config with cipher suites",
			config: &config.RouteTLSConfig{
				CertFile:     "/path/to/cert.pem",
				KeyFile:      "/path/to/key.pem",
				SNIHosts:     []string{"api.example.com"},
				CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			},
			valid: true,
		},
		{
			name:   "empty config",
			config: &config.RouteTLSConfig{},
			valid:  true, // Empty config is valid (no TLS override)
		},
		{
			name: "missing key file",
			config: &config.RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				SNIHosts: []string{"api.example.com"},
			},
			valid: false,
		},
		{
			name: "missing cert file",
			config: &config.RouteTLSConfig{
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"api.example.com"},
			},
			valid: false,
		},
		{
			name: "SNI hosts without certificate source",
			config: &config.RouteTLSConfig{
				SNIHosts: []string{"api.example.com"},
			},
			valid: false,
		},
		{
			name: "invalid SNI host",
			config: &config.RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"invalid..hostname"},
			},
			valid: false,
		},
		{
			name: "invalid min version",
			config: &config.RouteTLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				SNIHosts:   []string{"api.example.com"},
				MinVersion: "INVALID",
			},
			valid: false,
		},
		{
			name: "invalid max version",
			config: &config.RouteTLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				SNIHosts:   []string{"api.example.com"},
				MaxVersion: "INVALID",
			},
			valid: false,
		},
		{
			name: "min version greater than max version",
			config: &config.RouteTLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				SNIHosts:   []string{"api.example.com"},
				MinVersion: "TLS13",
				MaxVersion: "TLS12",
			},
			valid: false,
		},
		{
			name: "client validation without CA file",
			config: &config.RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"api.example.com"},
				ClientValidation: &config.RouteClientValidationConfig{
					Enabled: true,
				},
			},
			valid: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create a gateway config with the route TLS config
			gwConfig := &config.GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata: config.Metadata{
					Name: "test-gateway",
				},
				Spec: config.GatewaySpec{
					Listeners: []config.Listener{
						{
							Name:     "https",
							Port:     8443,
							Protocol: "HTTPS",
							Hosts:    []string{"*"},
							TLS: &config.ListenerTLSConfig{
								Mode:       "SIMPLE",
								MinVersion: "TLS12",
								CertFile:   "/path/to/listener-cert.pem",
								KeyFile:    "/path/to/listener-key.pem",
							},
						},
					},
					Routes: []config.Route{
						{
							Name: "test-route",
							Match: []config.RouteMatch{
								{
									URI: &config.URIMatch{
										Prefix: "/api",
									},
								},
							},
							Route: []config.RouteDestination{
								{
									Destination: config.Destination{
										Host: "127.0.0.1",
										Port: 8080,
									},
								},
							},
							TLS: tc.config,
						},
					},
				},
			}

			validator := config.NewValidator()
			err := validator.Validate(gwConfig)

			if tc.valid {
				// Filter out errors not related to route TLS
				routeTLSErrors := filterRouteTLSErrorsFromError(err)
				assert.Empty(t, routeTLSErrors, "Expected no route TLS validation errors")
			} else {
				assert.NotNil(t, err, "Expected validation errors")
			}
		})
	}
}

// TestFunctional_RouteTLS_SNIHostMatching tests SNI host matching logic.
func TestFunctional_RouteTLS_SNIHostMatching(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		pattern     string
		serverName  string
		shouldMatch bool
	}{
		// Exact matches
		{
			name:        "exact match",
			pattern:     "api.example.com",
			serverName:  "api.example.com",
			shouldMatch: true,
		},
		{
			name:        "exact match case insensitive",
			pattern:     "api.example.com",
			serverName:  "API.EXAMPLE.COM",
			shouldMatch: true,
		},
		{
			name:        "exact match different domain",
			pattern:     "api.example.com",
			serverName:  "api.other.com",
			shouldMatch: false,
		},

		// Wildcard matches
		{
			name:        "wildcard match single level",
			pattern:     "*.example.com",
			serverName:  "api.example.com",
			shouldMatch: true,
		},
		{
			name:        "wildcard match www",
			pattern:     "*.example.com",
			serverName:  "www.example.com",
			shouldMatch: true,
		},
		{
			name:        "wildcard no match multi-level",
			pattern:     "*.example.com",
			serverName:  "api.v1.example.com",
			shouldMatch: false,
		},
		{
			name:        "wildcard no match root domain",
			pattern:     "*.example.com",
			serverName:  "example.com",
			shouldMatch: false,
		},
		{
			name:        "wildcard no match different domain",
			pattern:     "*.example.com",
			serverName:  "api.other.com",
			shouldMatch: false,
		},
		{
			name:        "wildcard case insensitive",
			pattern:     "*.example.com",
			serverName:  "API.EXAMPLE.COM",
			shouldMatch: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := matchSNIHost(tc.pattern, tc.serverName)
			assert.Equal(t, tc.shouldMatch, result)
		})
	}
}

// TestFunctional_RouteTLS_CertificateSelection tests certificate selection logic.
func TestFunctional_RouteTLS_CertificateSelection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		routes      []routeConfig
		serverName  string
		shouldMatch bool
	}{
		{
			name: "exact SNI match",
			routes: []routeConfig{
				{name: "api-route", sniHosts: []string{"api.example.com"}},
				{name: "www-route", sniHosts: []string{"www.example.com"}},
			},
			serverName:  "api.example.com",
			shouldMatch: true,
		},
		{
			name: "wildcard SNI match",
			routes: []routeConfig{
				{name: "wildcard-route", sniHosts: []string{"*.example.com"}},
			},
			serverName:  "api.example.com",
			shouldMatch: true,
		},
		{
			name: "exact match with wildcard also present",
			routes: []routeConfig{
				{name: "exact-route", sniHosts: []string{"api.example.com"}},
				{name: "wildcard-route", sniHosts: []string{"*.example.com"}},
			},
			serverName:  "api.example.com",
			shouldMatch: true,
		},
		{
			name: "no match without base manager",
			routes: []routeConfig{
				{name: "api-route", sniHosts: []string{"api.example.com"}},
			},
			serverName:  "other.example.com",
			shouldMatch: false,
		},
		{
			name: "multiple SNI hosts on single route",
			routes: []routeConfig{
				{name: "multi-route", sniHosts: []string{"api.example.com", "www.example.com", "admin.example.com"}},
			},
			serverName:  "admin.example.com",
			shouldMatch: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Generate test certificates for each subtest
			certs, err := helpers.GenerateTestCertificates()
			require.NoError(t, err)
			require.NoError(t, certs.WriteToFiles())
			defer certs.Cleanup()

			manager := tls.NewRouteTLSManager()
			defer manager.Close()

			// Add routes
			for _, route := range tc.routes {
				cfg := &tls.RouteTLSConfig{
					CertFile: certs.ServerCertPath(),
					KeyFile:  certs.ServerKeyPath(),
					SNIHosts: route.sniHosts,
				}
				err := manager.AddRoute(route.name, cfg)
				require.NoError(t, err)
			}

			// Test certificate selection using GetCertificate
			hello := &cryptotls.ClientHelloInfo{
				ServerName: tc.serverName,
			}
			cert, err := manager.GetCertificate(hello)

			if tc.shouldMatch {
				require.NoError(t, err, "Expected certificate to be found for SNI: %s", tc.serverName)
				require.NotNil(t, cert, "Expected certificate to be returned")
			} else {
				assert.Error(t, err, "Expected no certificate for SNI: %s", tc.serverName)
			}
		})
	}
}

// TestFunctional_RouteTLS_Validation tests route TLS validation.
func TestFunctional_RouteTLS_Validation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		config      *tls.RouteTLSConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &tls.RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"api.example.com"},
			},
			expectError: false,
		},
		{
			name: "missing cert file",
			config: &tls.RouteTLSConfig{
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"api.example.com"},
			},
			expectError: true,
			errorMsg:    "certFile is required",
		},
		{
			name: "missing key file",
			config: &tls.RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				SNIHosts: []string{"api.example.com"},
			},
			expectError: true,
			errorMsg:    "keyFile is required",
		},
		{
			name: "no certificate source",
			config: &tls.RouteTLSConfig{
				SNIHosts: []string{"api.example.com"},
			},
			expectError: true,
			errorMsg:    "either certFile/keyFile or vault configuration is required",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			manager := tls.NewRouteTLSManager()
			defer manager.Close()

			err := manager.AddRoute("test-route", tc.config)

			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				// Note: This will fail if the cert files don't exist
				// In a real test, we'd use actual certificate files
				// We expect an error due to missing files, but NOT a validation error
				if err != nil {
					// Should fail due to missing files, not validation
					assert.Contains(t, err.Error(), "no such file or directory",
						"Expected file not found error, not validation error")
				}
			}
		})
	}
}

// TestFunctional_RouteTLS_RouteHasTLSOverride tests the HasTLSOverride method.
func TestFunctional_RouteTLS_RouteHasTLSOverride(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		route    config.Route
		expected bool
	}{
		{
			name: "no TLS config",
			route: config.Route{
				Name: "test-route",
			},
			expected: false,
		},
		{
			name: "empty TLS config",
			route: config.Route{
				Name: "test-route",
				TLS:  &config.RouteTLSConfig{},
			},
			expected: false,
		},
		{
			name: "TLS with cert files",
			route: config.Route{
				Name: "test-route",
				TLS: &config.RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with only cert file",
			route: config.Route{
				Name: "test-route",
				TLS: &config.RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with only key file",
			route: config.Route{
				Name: "test-route",
				TLS: &config.RouteTLSConfig{
					KeyFile: "/path/to/key.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with Vault enabled",
			route: config.Route{
				Name: "test-route",
				TLS: &config.RouteTLSConfig{
					Vault: &config.VaultTLSConfig{
						Enabled: true,
					},
				},
			},
			expected: true,
		},
		{
			name: "TLS with Vault disabled",
			route: config.Route{
				Name: "test-route",
				TLS: &config.RouteTLSConfig{
					Vault: &config.VaultTLSConfig{
						Enabled: false,
					},
				},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.route.HasTLSOverride())
		})
	}
}

// TestFunctional_RouteTLS_GetEffectiveSNIHosts tests the GetEffectiveSNIHosts method.
func TestFunctional_RouteTLS_GetEffectiveSNIHosts(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		route    config.Route
		expected []string
	}{
		{
			name: "no TLS config",
			route: config.Route{
				Name: "test-route",
			},
			expected: nil,
		},
		{
			name: "empty TLS config",
			route: config.Route{
				Name: "test-route",
				TLS:  &config.RouteTLSConfig{},
			},
			expected: nil,
		},
		{
			name: "TLS with empty SNI hosts",
			route: config.Route{
				Name: "test-route",
				TLS: &config.RouteTLSConfig{
					SNIHosts: []string{},
				},
			},
			expected: nil,
		},
		{
			name: "TLS with single SNI host",
			route: config.Route{
				Name: "test-route",
				TLS: &config.RouteTLSConfig{
					SNIHosts: []string{"api.example.com"},
				},
			},
			expected: []string{"api.example.com"},
		},
		{
			name: "TLS with multiple SNI hosts",
			route: config.Route{
				Name: "test-route",
				TLS: &config.RouteTLSConfig{
					SNIHosts: []string{"api.example.com", "www.example.com", "*.example.com"},
				},
			},
			expected: []string{"api.example.com", "www.example.com", "*.example.com"},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.route.GetEffectiveSNIHosts())
		})
	}
}

// TestFunctional_RouteTLS_WildcardMatching tests wildcard SNI matching edge cases.
func TestFunctional_RouteTLS_WildcardMatching(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		pattern     string
		serverName  string
		shouldMatch bool
	}{
		// Standard wildcard cases
		{"single label match", "*.example.com", "api.example.com", true},
		{"www match", "*.example.com", "www.example.com", true},
		{"test match", "*.example.com", "test.example.com", true},

		// Multi-level subdomain (should NOT match)
		{"multi-level no match", "*.example.com", "api.v1.example.com", false},
		{"deep subdomain no match", "*.example.com", "a.b.c.example.com", false},

		// Root domain (should NOT match)
		{"root domain no match", "*.example.com", "example.com", false},

		// Different domains
		{"different domain no match", "*.example.com", "api.other.com", false},
		{"similar domain no match", "*.example.com", "api.example.org", false},

		// Case sensitivity
		{"uppercase match", "*.example.com", "API.EXAMPLE.COM", true},
		{"mixed case match", "*.example.com", "Api.Example.Com", true},

		// Edge cases
		{"empty server name", "*.example.com", "", false},
		{"single char subdomain", "*.example.com", "a.example.com", true},
		{"numeric subdomain", "*.example.com", "123.example.com", true},
		{"hyphenated subdomain", "*.example.com", "api-v1.example.com", true},

		// Non-wildcard patterns (should not match as wildcard)
		{"non-wildcard exact", "api.example.com", "api.example.com", false}, // matchWildcard only handles wildcards
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := matchWildcard(tc.pattern, tc.serverName)
			assert.Equal(t, tc.shouldMatch, result)
		})
	}
}

// Helper types and functions

type routeConfig struct {
	name     string
	sniHosts []string
}

// matchSNIHost matches a server name against a pattern (exact or wildcard).
func matchSNIHost(pattern, serverName string) bool {
	// Normalize to lowercase
	pattern = toLower(pattern)
	serverName = toLower(serverName)

	// Check for wildcard pattern
	if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
		return matchWildcard(pattern, serverName)
	}

	// Exact match
	return pattern == serverName
}

// matchWildcard checks if a server name matches a wildcard pattern.
func matchWildcard(pattern, serverName string) bool {
	if len(pattern) < 3 || pattern[0] != '*' || pattern[1] != '.' {
		return false
	}

	domain := toLower(pattern[2:])
	serverName = toLower(serverName)

	if !hasSuffix(serverName, domain) {
		return false
	}

	prefix := serverName[:len(serverName)-len(domain)]
	if prefix == "" {
		return false
	}

	prefix = trimSuffix(prefix, ".")
	return !contains(prefix, ".")
}

// filterRouteTLSErrorsFromError filters validation errors to only include route TLS related errors.
func filterRouteTLSErrorsFromError(err error) []config.ValidationError {
	if err == nil {
		return nil
	}

	// Try to cast to ValidationErrors
	if validationErrors, ok := err.(config.ValidationErrors); ok {
		var filtered []config.ValidationError
		for _, verr := range validationErrors {
			if contains(verr.Path, "routes") && contains(verr.Path, "tls") {
				filtered = append(filtered, verr)
			}
		}
		return filtered
	}

	return nil
}

// String helper functions
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func trimSuffix(s, suffix string) string {
	if hasSuffix(s, suffix) {
		return s[:len(s)-len(suffix)]
	}
	return s
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
