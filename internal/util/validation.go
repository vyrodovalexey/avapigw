package util

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// headerNameRegex validates HTTP header names according to RFC 7230.
var headerNameRegex = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

// ValidateURL validates a URL string.
func ValidateURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme == "" {
		return fmt.Errorf("URL must have a scheme (http or https)")
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https, got: %s", parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("URL must have a host")
	}

	return nil
}

// ValidateHeaderName validates an HTTP header name.
func ValidateHeaderName(name string) error {
	if name == "" {
		return fmt.Errorf("header name cannot be empty")
	}

	if !headerNameRegex.MatchString(name) {
		return fmt.Errorf("invalid header name: %s", name)
	}

	return nil
}

// ValidatePort validates a port number.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got: %d", port)
	}
	return nil
}

// ValidateNonNegativePort validates a port number (0 is allowed for auto-assign).
func ValidateNonNegativePort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("port must be between 0 and 65535, got: %d", port)
	}
	return nil
}

// ParseDuration parses a duration string with support for common formats.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}

	// Try standard Go duration format first
	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}

	// Try parsing as seconds if it's just a number
	s = strings.TrimSpace(s)
	if isNumeric(s) {
		return time.ParseDuration(s + "s")
	}

	return 0, fmt.Errorf("invalid duration format: %s", s)
}

// isNumeric checks if a string contains only digits.
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// ValidateDuration validates a duration is positive.
func ValidateDuration(d time.Duration) error {
	if d < 0 {
		return fmt.Errorf("duration cannot be negative: %v", d)
	}
	return nil
}

// ValidatePositiveDuration validates a duration is strictly positive.
func ValidatePositiveDuration(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("duration must be positive: %v", d)
	}
	return nil
}

// ValidateRegex validates a regex pattern.
func ValidateRegex(pattern string) error {
	if pattern == "" {
		return nil
	}

	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	return nil
}

// ValidateHTTPMethod validates an HTTP method.
func ValidateHTTPMethod(method string) error {
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
		"TRACE":   true,
		"CONNECT": true,
		"*":       true, // Wildcard
	}

	method = strings.ToUpper(method)
	if !validMethods[method] {
		return fmt.Errorf("invalid HTTP method: %s", method)
	}

	return nil
}

// ValidateHTTPStatusCode validates an HTTP status code.
func ValidateHTTPStatusCode(code int) error {
	if code < 100 || code > 599 {
		return fmt.Errorf("HTTP status code must be between 100 and 599, got: %d", code)
	}
	return nil
}

// ValidatePercentage validates a percentage value (0-100).
func ValidatePercentage(value float64) error {
	if value < 0 || value > 100 {
		return fmt.Errorf("percentage must be between 0 and 100, got: %f", value)
	}
	return nil
}

// ValidateWeight validates a weight value (0-100).
func ValidateWeight(weight int) error {
	if weight < 0 || weight > 100 {
		return fmt.Errorf("weight must be between 0 and 100, got: %d", weight)
	}
	return nil
}

// ValidateNonEmpty validates that a string is not empty.
func ValidateNonEmpty(value, name string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s cannot be empty", name)
	}
	return nil
}

// ValidateHostname validates a hostname.
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	// Allow wildcard
	if hostname == "*" {
		return nil
	}

	// Basic hostname validation
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long: %d characters (max 253)", len(hostname))
	}

	// Check each label
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("hostname has empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("hostname label too long: %d characters (max 63)", len(label))
		}
		// Allow wildcard prefix
		if label == "*" {
			continue
		}
		// Check valid characters
		for i, c := range label {
			if !isValidHostnameChar(c, i == 0, i == len(label)-1) {
				return fmt.Errorf("invalid character in hostname: %c", c)
			}
		}
	}

	return nil
}

// isValidHostnameChar checks if a character is valid in a hostname label.
func isValidHostnameChar(c rune, isFirst, isLast bool) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	if c == '-' && !isFirst && !isLast {
		return true
	}
	return false
}

// ValidateIPAddress validates an IP address (v4 or v6).
func ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}

	// Allow 0.0.0.0 for binding to all interfaces
	if ip == "0.0.0.0" || ip == "::" {
		return nil
	}

	// Basic validation - check for valid characters
	for _, c := range ip {
		if !isValidIPChar(c) {
			return fmt.Errorf("invalid character in IP address: %c", c)
		}
	}

	return nil
}

// isValidIPChar checks if a character is valid in an IP address.
func isValidIPChar(c rune) bool {
	if c >= '0' && c <= '9' {
		return true
	}
	if c >= 'a' && c <= 'f' {
		return true
	}
	if c >= 'A' && c <= 'F' {
		return true
	}
	if c == '.' || c == ':' {
		return true
	}
	return false
}
