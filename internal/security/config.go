package security

import (
	"errors"
	"fmt"
	"strings"
)

// Config represents the main security configuration.
type Config struct {
	// Enabled enables security features.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Headers configures security headers.
	Headers *HeadersConfig `yaml:"headers,omitempty" json:"headers,omitempty"`

	// HSTS configures HTTP Strict Transport Security.
	HSTS *HSTSConfig `yaml:"hsts,omitempty" json:"hsts,omitempty"`

	// CSP configures Content Security Policy.
	CSP *CSPConfig `yaml:"csp,omitempty" json:"csp,omitempty"`

	// PermissionsPolicy configures Permissions Policy.
	PermissionsPolicy *PermissionsPolicyConfig `yaml:"permissionsPolicy,omitempty" json:"permissionsPolicy,omitempty"`

	// ReferrerPolicy configures the Referrer-Policy header.
	ReferrerPolicy string `yaml:"referrerPolicy,omitempty" json:"referrerPolicy,omitempty"`

	// CrossOriginOpenerPolicy configures the Cross-Origin-Opener-Policy header.
	CrossOriginOpenerPolicy string `yaml:"coopPolicy,omitempty" json:"coopPolicy,omitempty"`

	// CrossOriginEmbedderPolicy configures the Cross-Origin-Embedder-Policy header.
	CrossOriginEmbedderPolicy string `yaml:"coepPolicy,omitempty" json:"coepPolicy,omitempty"`

	// CrossOriginResourcePolicy configures the Cross-Origin-Resource-Policy header.
	CrossOriginResourcePolicy string `yaml:"corpPolicy,omitempty" json:"corpPolicy,omitempty"`
}

// HeadersConfig configures security headers.
type HeadersConfig struct {
	// Enabled enables security headers.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// XFrameOptions sets the X-Frame-Options header.
	// Valid values: DENY, SAMEORIGIN, ALLOW-FROM uri
	XFrameOptions string `yaml:"xFrameOptions,omitempty" json:"xFrameOptions,omitempty"`

	// XContentTypeOptions sets the X-Content-Type-Options header.
	// Valid value: nosniff
	XContentTypeOptions string `yaml:"xContentTypeOptions,omitempty" json:"xContentTypeOptions,omitempty"`

	// XXSSProtection sets the X-XSS-Protection header.
	// Valid values: 0, 1, 1; mode=block
	XXSSProtection string `yaml:"xXSSProtection,omitempty" json:"xXSSProtection,omitempty"`

	// CacheControl sets the Cache-Control header for sensitive responses.
	CacheControl string `yaml:"cacheControl,omitempty" json:"cacheControl,omitempty"`

	// Pragma sets the Pragma header for sensitive responses.
	Pragma string `yaml:"pragma,omitempty" json:"pragma,omitempty"`

	// CustomHeaders allows setting custom headers.
	CustomHeaders map[string]string `yaml:"customHeaders,omitempty" json:"customHeaders,omitempty"`

	// RemoveHeaders specifies headers to remove from responses.
	RemoveHeaders []string `yaml:"removeHeaders,omitempty" json:"removeHeaders,omitempty"`
}

// HSTSConfig configures HTTP Strict Transport Security.
type HSTSConfig struct {
	// Enabled enables HSTS.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MaxAge is the max-age directive value in seconds.
	MaxAge int `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`

	// IncludeSubDomains includes the includeSubDomains directive.
	IncludeSubDomains bool `yaml:"includeSubDomains,omitempty" json:"includeSubDomains,omitempty"`

	// Preload includes the preload directive.
	Preload bool `yaml:"preload,omitempty" json:"preload,omitempty"`
}

// CSPConfig configures Content Security Policy.
type CSPConfig struct {
	// Enabled enables CSP.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Policy is the full CSP policy string.
	Policy string `yaml:"policy,omitempty" json:"policy,omitempty"`

	// ReportOnly sets the header to Content-Security-Policy-Report-Only.
	ReportOnly bool `yaml:"reportOnly,omitempty" json:"reportOnly,omitempty"`

	// ReportURI is the URI to report CSP violations.
	ReportURI string `yaml:"reportUri,omitempty" json:"reportUri,omitempty"`

	// Directives allows setting individual CSP directives.
	Directives *CSPDirectives `yaml:"directives,omitempty" json:"directives,omitempty"`
}

// CSPDirectives contains individual CSP directives.
type CSPDirectives struct {
	DefaultSrc              []string `yaml:"defaultSrc,omitempty" json:"defaultSrc,omitempty"`
	ScriptSrc               []string `yaml:"scriptSrc,omitempty" json:"scriptSrc,omitempty"`
	StyleSrc                []string `yaml:"styleSrc,omitempty" json:"styleSrc,omitempty"`
	ImgSrc                  []string `yaml:"imgSrc,omitempty" json:"imgSrc,omitempty"`
	FontSrc                 []string `yaml:"fontSrc,omitempty" json:"fontSrc,omitempty"`
	ConnectSrc              []string `yaml:"connectSrc,omitempty" json:"connectSrc,omitempty"`
	MediaSrc                []string `yaml:"mediaSrc,omitempty" json:"mediaSrc,omitempty"`
	ObjectSrc               []string `yaml:"objectSrc,omitempty" json:"objectSrc,omitempty"`
	FrameSrc                []string `yaml:"frameSrc,omitempty" json:"frameSrc,omitempty"`
	FrameAncestors          []string `yaml:"frameAncestors,omitempty" json:"frameAncestors,omitempty"`
	FormAction              []string `yaml:"formAction,omitempty" json:"formAction,omitempty"`
	BaseURI                 []string `yaml:"baseUri,omitempty" json:"baseUri,omitempty"`
	UpgradeInsecureRequests bool     `yaml:"upgradeInsecureRequests,omitempty" json:"upgradeInsecureRequests,omitempty"`
	BlockAllMixedContent    bool     `yaml:"blockAllMixedContent,omitempty" json:"blockAllMixedContent,omitempty"`
}

// PermissionsPolicyConfig configures Permissions Policy.
type PermissionsPolicyConfig struct {
	// Enabled enables Permissions Policy.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Policy is the full Permissions Policy string.
	Policy string `yaml:"policy,omitempty" json:"policy,omitempty"`

	// Features allows setting individual features.
	Features map[string][]string `yaml:"features,omitempty" json:"features,omitempty"`
}

// Validate validates the security configuration.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}

	if !c.Enabled {
		return nil
	}

	if c.Headers != nil && c.Headers.Enabled {
		if err := c.Headers.Validate(); err != nil {
			return fmt.Errorf("headers config: %w", err)
		}
	}

	if c.HSTS != nil && c.HSTS.Enabled {
		if err := c.HSTS.Validate(); err != nil {
			return fmt.Errorf("hsts config: %w", err)
		}
	}

	if c.CSP != nil && c.CSP.Enabled {
		if err := c.CSP.Validate(); err != nil {
			return fmt.Errorf("csp config: %w", err)
		}
	}

	if err := c.validateReferrerPolicy(); err != nil {
		return err
	}

	return nil
}

// validateReferrerPolicy validates the Referrer-Policy value.
func (c *Config) validateReferrerPolicy() error {
	if c.ReferrerPolicy == "" {
		return nil
	}

	validPolicies := map[string]bool{
		"no-referrer":                     true,
		"no-referrer-when-downgrade":      true,
		"origin":                          true,
		"origin-when-cross-origin":        true,
		"same-origin":                     true,
		"strict-origin":                   true,
		"strict-origin-when-cross-origin": true,
		"unsafe-url":                      true,
	}

	if !validPolicies[c.ReferrerPolicy] {
		return fmt.Errorf("invalid referrer policy: %s", c.ReferrerPolicy)
	}

	return nil
}

// Validate validates the headers configuration.
func (c *HeadersConfig) Validate() error {
	if c == nil {
		return nil
	}

	// Validate X-Frame-Options
	if c.XFrameOptions != "" {
		upper := strings.ToUpper(c.XFrameOptions)
		if upper != "DENY" && upper != "SAMEORIGIN" && !strings.HasPrefix(upper, "ALLOW-FROM ") {
			return fmt.Errorf("invalid X-Frame-Options: %s", c.XFrameOptions)
		}
	}

	// Validate X-Content-Type-Options
	if c.XContentTypeOptions != "" && c.XContentTypeOptions != "nosniff" {
		return fmt.Errorf("invalid X-Content-Type-Options: %s (must be 'nosniff')", c.XContentTypeOptions)
	}

	return nil
}

// Validate validates the HSTS configuration.
func (c *HSTSConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.MaxAge < 0 {
		return errors.New("maxAge must be non-negative")
	}

	// Preload requires includeSubDomains and maxAge >= 1 year
	if c.Preload {
		if !c.IncludeSubDomains {
			return errors.New("preload requires includeSubDomains")
		}
		if c.MaxAge < 31536000 {
			return errors.New("preload requires maxAge >= 31536000 (1 year)")
		}
	}

	return nil
}

// Validate validates the CSP configuration.
func (c *CSPConfig) Validate() error {
	if c == nil {
		return nil
	}

	// Either policy or directives must be set
	if c.Policy == "" && c.Directives == nil {
		return errors.New("either policy or directives must be set")
	}

	return nil
}

// DefaultConfig returns a default security configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled: true,
		Headers: &HeadersConfig{
			Enabled:             true,
			XFrameOptions:       "DENY",
			XContentTypeOptions: "nosniff",
			XXSSProtection:      "1; mode=block",
			CacheControl:        "no-store, no-cache, must-revalidate",
			Pragma:              "no-cache",
		},
		HSTS: &HSTSConfig{
			Enabled:           true,
			MaxAge:            31536000,
			IncludeSubDomains: true,
			Preload:           false,
		},
		ReferrerPolicy: "strict-origin-when-cross-origin",
	}
}

// IsHeadersEnabled returns true if security headers are enabled.
func (c *Config) IsHeadersEnabled() bool {
	return c != nil && c.Enabled && c.Headers != nil && c.Headers.Enabled
}

// IsHSTSEnabled returns true if HSTS is enabled.
func (c *Config) IsHSTSEnabled() bool {
	return c != nil && c.Enabled && c.HSTS != nil && c.HSTS.Enabled
}

// IsCSPEnabled returns true if CSP is enabled.
func (c *Config) IsCSPEnabled() bool {
	return c != nil && c.Enabled && c.CSP != nil && c.CSP.Enabled
}

// IsPermissionsPolicyEnabled returns true if Permissions Policy is enabled.
func (c *Config) IsPermissionsPolicyEnabled() bool {
	return c != nil && c.Enabled && c.PermissionsPolicy != nil && c.PermissionsPolicy.Enabled
}
