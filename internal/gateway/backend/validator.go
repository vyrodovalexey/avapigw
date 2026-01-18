// Package backend provides backend management and proxying functionality.
package backend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// Validation errors for URL validation.
var (
	ErrInvalidURL           = errors.New("invalid URL")
	ErrInvalidScheme        = errors.New("invalid URL scheme: only http and https are allowed")
	ErrEmptyHost            = errors.New("empty host in URL")
	ErrPrivateIPBlocked     = errors.New("private IP addresses are blocked")
	ErrLoopbackBlocked      = errors.New("loopback addresses are blocked")
	ErrLinkLocalBlocked     = errors.New("link-local addresses are blocked")
	ErrBlockedCIDR          = errors.New("IP address is in blocked CIDR range")
	ErrHostResolutionFailed = errors.New("failed to resolve hostname")
	ErrResolvedIPBlocked    = errors.New("resolved IP address is blocked")
)

// Prometheus metrics for URL validation.
var (
	urlValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "backend",
			Name:      "url_validation_total",
			Help:      "Total number of URL validations",
		},
		[]string{"result", "reason"},
	)

	urlValidationBlockedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "avapigw",
			Subsystem: "backend",
			Name:      "url_validation_blocked_total",
			Help:      "Total number of blocked URL validation requests",
		},
		[]string{"reason"},
	)

	urlValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "avapigw",
			Subsystem: "backend",
			Name:      "url_validation_duration_seconds",
			Help:      "Duration of URL validation in seconds",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		},
	)
)

// Default private IP CIDR ranges that should be blocked.
var defaultPrivateCIDRs = []string{
	"10.0.0.0/8",     // RFC 1918 Class A private network
	"172.16.0.0/12",  // RFC 1918 Class B private network
	"192.168.0.0/16", // RFC 1918 Class C private network
	"127.0.0.0/8",    // Loopback
	"169.254.0.0/16", // Link-local
	"::1/128",        // IPv6 loopback
	"fc00::/7",       // IPv6 unique local addresses
	"fe80::/10",      // IPv6 link-local
}

// URLValidatorConfig holds configuration for the URL validator.
type URLValidatorConfig struct {
	// BlockPrivateIPs blocks private IP ranges (10.x, 172.16-31.x, 192.168.x)
	BlockPrivateIPs bool

	// BlockLoopback blocks loopback addresses (127.x, ::1)
	BlockLoopback bool

	// BlockLinkLocal blocks link-local addresses (169.254.x, fe80::)
	BlockLinkLocal bool

	// AllowedSchemes specifies allowed URL schemes (default: http, https)
	AllowedSchemes []string

	// AllowedCIDRs specifies CIDR ranges that are explicitly allowed (overrides blocks)
	AllowedCIDRs []string

	// BlockedCIDRs specifies additional CIDR ranges to block
	BlockedCIDRs []string

	// AllowedHosts specifies hostnames that are explicitly allowed (overrides IP checks)
	AllowedHosts []string

	// BlockedHosts specifies hostnames that are explicitly blocked
	BlockedHosts []string

	// EnableDNSRebindingProtection resolves hostnames and validates the resolved IP
	EnableDNSRebindingProtection bool

	// DNSResolutionTimeout is the timeout for DNS resolution
	DNSResolutionTimeout time.Duration
}

// DefaultURLValidatorConfig returns a URLValidatorConfig with secure defaults.
func DefaultURLValidatorConfig() *URLValidatorConfig {
	return &URLValidatorConfig{
		BlockPrivateIPs:              true,
		BlockLoopback:                true,
		BlockLinkLocal:               true,
		AllowedSchemes:               []string{"http", "https"},
		AllowedCIDRs:                 nil,
		BlockedCIDRs:                 nil,
		AllowedHosts:                 nil,
		BlockedHosts:                 nil,
		EnableDNSRebindingProtection: true,
		DNSResolutionTimeout:         2 * time.Second,
	}
}

// URLValidator validates backend URLs to prevent SSRF attacks.
type URLValidator struct {
	config         *URLValidatorConfig
	logger         *zap.Logger
	allowedNets    []*net.IPNet
	blockedNets    []*net.IPNet
	privateNets    []*net.IPNet
	allowedHosts   map[string]bool
	blockedHosts   map[string]bool
	allowedSchemes map[string]bool
	mu             sync.RWMutex
}

// NewURLValidator creates a new URL validator with the given configuration.
func NewURLValidator(config *URLValidatorConfig, logger *zap.Logger) (*URLValidator, error) {
	if config == nil {
		config = DefaultURLValidatorConfig()
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	v := &URLValidator{
		config:         config,
		logger:         logger,
		allowedHosts:   make(map[string]bool),
		blockedHosts:   make(map[string]bool),
		allowedSchemes: make(map[string]bool),
	}

	v.initAllowedSchemes(config.AllowedSchemes)

	if err := v.initPrivateNetworks(config); err != nil {
		return nil, err
	}

	if err := v.initCIDRNetworks(config); err != nil {
		return nil, err
	}

	v.initHostMaps(config)

	return v, nil
}

// initAllowedSchemes initializes the allowed URL schemes map.
func (v *URLValidator) initAllowedSchemes(schemes []string) {
	if len(schemes) == 0 {
		v.allowedSchemes["http"] = true
		v.allowedSchemes["https"] = true
		return
	}
	for _, scheme := range schemes {
		v.allowedSchemes[strings.ToLower(scheme)] = true
	}
}

// initPrivateNetworks parses and initializes private CIDR ranges if blocking is enabled.
func (v *URLValidator) initPrivateNetworks(config *URLValidatorConfig) error {
	if !config.BlockPrivateIPs && !config.BlockLoopback && !config.BlockLinkLocal {
		return nil
	}

	for _, cidr := range defaultPrivateCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse default private CIDR %s: %w", cidr, err)
		}
		v.privateNets = append(v.privateNets, ipNet)
	}
	return nil
}

// initCIDRNetworks parses and initializes allowed and blocked CIDR ranges.
func (v *URLValidator) initCIDRNetworks(config *URLValidatorConfig) error {
	for _, cidr := range config.AllowedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse allowed CIDR %s: %w", cidr, err)
		}
		v.allowedNets = append(v.allowedNets, ipNet)
	}

	for _, cidr := range config.BlockedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse blocked CIDR %s: %w", cidr, err)
		}
		v.blockedNets = append(v.blockedNets, ipNet)
	}
	return nil
}

// initHostMaps initializes the allowed and blocked hosts maps.
func (v *URLValidator) initHostMaps(config *URLValidatorConfig) {
	for _, host := range config.AllowedHosts {
		v.allowedHosts[strings.ToLower(host)] = true
	}
	for _, host := range config.BlockedHosts {
		v.blockedHosts[strings.ToLower(host)] = true
	}
}

// ValidateURL validates a URL string and returns an error if it's not allowed.
func (v *URLValidator) ValidateURL(rawURL string) error {
	return v.ValidateURLWithContext(context.Background(), rawURL)
}

// ValidateURLWithContext validates a URL string with context support for DNS resolution.
func (v *URLValidator) ValidateURLWithContext(ctx context.Context, rawURL string) error {
	start := time.Now()
	defer func() {
		urlValidationDuration.Observe(time.Since(start).Seconds())
	}()

	parsedURL, err := v.parseAndValidateURL(rawURL)
	if err != nil {
		return err
	}

	host := parsedURL.Hostname()
	if err := v.validateHost(ctx, rawURL, host); err != nil {
		return err
	}

	v.recordAllowed()
	v.logger.Debug("URL validation passed", zap.String("url", rawURL))
	return nil
}

// parseAndValidateURL parses the URL and validates its scheme.
func (v *URLValidator) parseAndValidateURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		v.recordBlocked("invalid_url")
		v.logger.Warn("URL validation failed: invalid URL",
			zap.String("url", rawURL),
			zap.Error(err),
		)
		return nil, fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}

	if err := v.validateScheme(parsedURL.Scheme); err != nil {
		v.recordBlocked("invalid_scheme")
		v.logger.Warn("URL validation failed: invalid scheme",
			zap.String("url", rawURL),
			zap.String("scheme", parsedURL.Scheme),
		)
		return nil, err
	}

	return parsedURL, nil
}

// validateHost validates the host portion of the URL.
func (v *URLValidator) validateHost(ctx context.Context, rawURL, host string) error {
	if host == "" {
		v.recordBlocked("empty_host")
		v.logger.Warn("URL validation failed: empty host", zap.String("url", rawURL))
		return ErrEmptyHost
	}

	if v.isBlockedHost(host) {
		v.recordBlocked("blocked_host")
		v.logger.Warn("URL validation failed: blocked host",
			zap.String("url", rawURL),
			zap.String("host", host),
		)
		return fmt.Errorf("host %s is blocked", host)
	}

	if v.isAllowedHost(host) {
		v.logger.Debug("URL validation passed: allowed host",
			zap.String("url", rawURL),
			zap.String("host", host),
		)
		return nil
	}

	return v.validateHostOrIP(ctx, rawURL, host)
}

// validateHostOrIP validates the host as either an IP address or hostname.
func (v *URLValidator) validateHostOrIP(ctx context.Context, rawURL, host string) error {
	ip := net.ParseIP(host)
	if ip != nil {
		return v.validateIPHost(rawURL, ip)
	}

	return v.validateHostnameWithDNS(ctx, rawURL, host)
}

// validateIPHost validates a host that is an IP address.
func (v *URLValidator) validateIPHost(rawURL string, ip net.IP) error {
	if err := v.validateIP(ip); err != nil {
		v.recordBlocked("blocked_ip")
		v.logger.Warn("URL validation failed: blocked IP",
			zap.String("url", rawURL),
			zap.String("ip", ip.String()),
			zap.Error(err),
		)
		return err
	}
	return nil
}

// validateHostnameWithDNS validates a hostname with optional DNS rebinding protection.
func (v *URLValidator) validateHostnameWithDNS(ctx context.Context, rawURL, host string) error {
	if !v.config.EnableDNSRebindingProtection {
		return nil
	}

	if err := v.validateHostname(ctx, host); err != nil {
		v.recordBlocked("dns_rebinding_protection")
		v.logger.Warn("URL validation failed: DNS rebinding protection",
			zap.String("url", rawURL),
			zap.String("host", host),
			zap.Error(err),
		)
		return err
	}
	return nil
}

// ValidateEndpoint validates an endpoint address and port.
func (v *URLValidator) ValidateEndpoint(address string, port int) error {
	return v.ValidateEndpointWithContext(context.Background(), address, port)
}

// ValidateEndpointWithContext validates an endpoint with context support.
func (v *URLValidator) ValidateEndpointWithContext(ctx context.Context, address string, port int) error {
	// Construct URL from endpoint
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	rawURL := fmt.Sprintf("%s://%s:%d", scheme, address, port)
	return v.ValidateURLWithContext(ctx, rawURL)
}

// validateScheme validates the URL scheme.
func (v *URLValidator) validateScheme(scheme string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.allowedSchemes[strings.ToLower(scheme)] {
		return fmt.Errorf("%w: %s", ErrInvalidScheme, scheme)
	}
	return nil
}

// validateIP validates an IP address against configured rules.
func (v *URLValidator) validateIP(ip net.IP) error {
	// Check if IP is in allowed CIDRs (explicit allow overrides blocks)
	if v.isIPInAllowedCIDRs(ip) {
		return nil
	}

	// Check if IP is in blocked CIDRs
	if v.isIPInBlockedCIDRs(ip) {
		return ErrBlockedCIDR
	}

	// Check loopback
	if v.config.BlockLoopback && ip.IsLoopback() {
		return ErrLoopbackBlocked
	}

	// Check link-local
	if v.config.BlockLinkLocal && ip.IsLinkLocalUnicast() {
		return ErrLinkLocalBlocked
	}

	// Check private IPs
	if v.config.BlockPrivateIPs && v.isPrivateIP(ip) {
		return ErrPrivateIPBlocked
	}

	return nil
}

// validateHostname resolves a hostname and validates the resolved IPs.
func (v *URLValidator) validateHostname(ctx context.Context, hostname string) error {
	// Create context with timeout for DNS resolution
	resolveCtx := ctx
	if v.config.DNSResolutionTimeout > 0 {
		var cancel context.CancelFunc
		resolveCtx, cancel = context.WithTimeout(ctx, v.config.DNSResolutionTimeout)
		defer cancel()
	}

	// Resolve hostname
	resolver := net.DefaultResolver
	ips, err := resolver.LookupIPAddr(resolveCtx, hostname)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHostResolutionFailed, err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("%w: no IP addresses found", ErrHostResolutionFailed)
	}

	// Validate all resolved IPs
	for _, ipAddr := range ips {
		if err := v.validateIP(ipAddr.IP); err != nil {
			return fmt.Errorf(
				"%w: %s resolves to blocked IP %s: %v", ErrResolvedIPBlocked, hostname, ipAddr.IP.String(), err)
		}
	}

	return nil
}

// isPrivateIP checks if an IP is in a private range.
func (v *URLValidator) isPrivateIP(ip net.IP) bool {
	// Check against default private networks
	for _, ipNet := range v.privateNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	// Also use Go's built-in private check
	return ip.IsPrivate()
}

// isIPInAllowedCIDRs checks if an IP is in any allowed CIDR range.
func (v *URLValidator) isIPInAllowedCIDRs(ip net.IP) bool {
	for _, ipNet := range v.allowedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// isIPInBlockedCIDRs checks if an IP is in any blocked CIDR range.
func (v *URLValidator) isIPInBlockedCIDRs(ip net.IP) bool {
	for _, ipNet := range v.blockedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// isAllowedHost checks if a host is explicitly allowed.
func (v *URLValidator) isAllowedHost(host string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.allowedHosts[strings.ToLower(host)]
}

// isBlockedHost checks if a host is explicitly blocked.
func (v *URLValidator) isBlockedHost(host string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.blockedHosts[strings.ToLower(host)]
}

// AddAllowedHost adds a host to the allowed list.
func (v *URLValidator) AddAllowedHost(host string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowedHosts[strings.ToLower(host)] = true
}

// RemoveAllowedHost removes a host from the allowed list.
func (v *URLValidator) RemoveAllowedHost(host string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.allowedHosts, strings.ToLower(host))
}

// AddBlockedHost adds a host to the blocked list.
func (v *URLValidator) AddBlockedHost(host string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.blockedHosts[strings.ToLower(host)] = true
}

// RemoveBlockedHost removes a host from the blocked list.
func (v *URLValidator) RemoveBlockedHost(host string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.blockedHosts, strings.ToLower(host))
}

// AddAllowedCIDR adds a CIDR range to the allowed list.
func (v *URLValidator) AddAllowedCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR %s: %w", cidr, err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowedNets = append(v.allowedNets, ipNet)
	return nil
}

// AddBlockedCIDR adds a CIDR range to the blocked list.
func (v *URLValidator) AddBlockedCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR %s: %w", cidr, err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.blockedNets = append(v.blockedNets, ipNet)
	return nil
}

// recordAllowed records a successful validation.
func (v *URLValidator) recordAllowed() {
	urlValidationTotal.WithLabelValues("allowed", "").Inc()
}

// recordBlocked records a blocked validation with reason.
func (v *URLValidator) recordBlocked(reason string) {
	urlValidationTotal.WithLabelValues("blocked", reason).Inc()
	urlValidationBlockedTotal.WithLabelValues(reason).Inc()
}

// GetConfig returns the current validator configuration.
func (v *URLValidator) GetConfig() *URLValidatorConfig {
	return v.config
}
