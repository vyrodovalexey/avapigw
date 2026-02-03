// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

// Package operator provides the client for connecting to the avapigw operator.
package operator

import (
	"fmt"
	"os"
	"time"
)

// Default configuration values.
const (
	// DefaultHeartbeatInterval is the default interval for sending heartbeats.
	DefaultHeartbeatInterval = 30 * time.Second

	// DefaultInitialBackoff is the default initial backoff for reconnection.
	DefaultInitialBackoff = 1 * time.Second

	// DefaultMaxBackoff is the default maximum backoff for reconnection.
	DefaultMaxBackoff = 30 * time.Second

	// DefaultBackoffMultiplier is the default multiplier for exponential backoff.
	DefaultBackoffMultiplier = 2.0

	// DefaultMaxRetries is the default maximum number of reconnection attempts.
	// A value of 0 means unlimited retries.
	DefaultMaxRetries = 0

	// DefaultConnectionTimeout is the default timeout for establishing connection.
	DefaultConnectionTimeout = 10 * time.Second

	// DefaultStreamTimeout is the default timeout for stream operations.
	DefaultStreamTimeout = 0 // No timeout for streaming
)

// Config contains configuration for the operator client.
type Config struct {
	// Enabled enables operator mode.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Address is the operator gRPC server address (host:port).
	Address string `yaml:"address" json:"address"`

	// TLS configuration for the connection.
	TLS *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// GatewayName is the name of this gateway instance.
	GatewayName string `yaml:"gatewayName" json:"gatewayName"`

	// GatewayNamespace is the namespace of this gateway.
	GatewayNamespace string `yaml:"gatewayNamespace" json:"gatewayNamespace"`

	// GatewayVersion is the version of this gateway.
	GatewayVersion string `yaml:"gatewayVersion,omitempty" json:"gatewayVersion,omitempty"`

	// Namespaces to watch (empty = all namespaces).
	Namespaces []string `yaml:"namespaces,omitempty" json:"namespaces,omitempty"`

	// ReconnectBackoff configuration for reconnection attempts.
	ReconnectBackoff BackoffConfig `yaml:"reconnectBackoff,omitempty" json:"reconnectBackoff,omitempty"`

	// HeartbeatInterval for keep-alive messages.
	HeartbeatInterval time.Duration `yaml:"heartbeatInterval,omitempty" json:"heartbeatInterval,omitempty"`

	// ConnectionTimeout is the timeout for establishing connection.
	ConnectionTimeout time.Duration `yaml:"connectionTimeout,omitempty" json:"connectionTimeout,omitempty"`

	// Labels are additional labels for this gateway.
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`

	// Annotations are additional annotations for this gateway.
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

// TLSConfig contains TLS configuration for the operator connection.
type TLSConfig struct {
	// Enabled enables TLS for the connection.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CertFile is the path to the client certificate file.
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the client private key file.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// CAFile is the path to the CA certificate file for server verification.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// InsecureSkipVerify skips server certificate verification (dev only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`

	// ServerName overrides the server name for TLS verification.
	ServerName string `yaml:"serverName,omitempty" json:"serverName,omitempty"`
}

// BackoffConfig contains configuration for exponential backoff.
type BackoffConfig struct {
	// InitialInterval is the initial backoff interval.
	InitialInterval time.Duration `yaml:"initialInterval,omitempty" json:"initialInterval,omitempty"`

	// MaxInterval is the maximum backoff interval.
	MaxInterval time.Duration `yaml:"maxInterval,omitempty" json:"maxInterval,omitempty"`

	// Multiplier is the multiplier for exponential backoff.
	Multiplier float64 `yaml:"multiplier,omitempty" json:"multiplier,omitempty"`

	// MaxRetries is the maximum number of retry attempts (0 = unlimited).
	MaxRetries int `yaml:"maxRetries,omitempty" json:"maxRetries,omitempty"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Enabled:           false,
		HeartbeatInterval: DefaultHeartbeatInterval,
		ConnectionTimeout: DefaultConnectionTimeout,
		ReconnectBackoff: BackoffConfig{
			InitialInterval: DefaultInitialBackoff,
			MaxInterval:     DefaultMaxBackoff,
			Multiplier:      DefaultBackoffMultiplier,
			MaxRetries:      DefaultMaxRetries,
		},
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Address == "" {
		return fmt.Errorf("operator address is required when operator mode is enabled")
	}

	if c.GatewayName == "" {
		return fmt.Errorf("gateway name is required when operator mode is enabled")
	}

	if c.GatewayNamespace == "" {
		return fmt.Errorf("gateway namespace is required when operator mode is enabled")
	}

	if c.TLS != nil {
		if err := c.TLS.Validate(); err != nil {
			return fmt.Errorf("TLS config: %w", err)
		}
	}

	return nil
}

// Validate validates the TLS configuration.
func (c *TLSConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	// If cert is provided, key must also be provided
	if c.CertFile != "" && c.KeyFile == "" {
		return fmt.Errorf("keyFile is required when certFile is provided")
	}
	if c.KeyFile != "" && c.CertFile == "" {
		return fmt.Errorf("certFile is required when keyFile is provided")
	}

	// Validate file paths exist if provided
	if c.CertFile != "" {
		if _, err := os.Stat(c.CertFile); err != nil {
			return fmt.Errorf("certFile not found: %s", c.CertFile)
		}
	}
	if c.KeyFile != "" {
		if _, err := os.Stat(c.KeyFile); err != nil {
			return fmt.Errorf("keyFile not found: %s", c.KeyFile)
		}
	}
	if c.CAFile != "" {
		if _, err := os.Stat(c.CAFile); err != nil {
			return fmt.Errorf("caFile not found: %s", c.CAFile)
		}
	}

	return nil
}

// GetInitialInterval returns the effective initial backoff interval.
func (c *BackoffConfig) GetInitialInterval() time.Duration {
	if c.InitialInterval <= 0 {
		return DefaultInitialBackoff
	}
	return c.InitialInterval
}

// GetMaxInterval returns the effective maximum backoff interval.
func (c *BackoffConfig) GetMaxInterval() time.Duration {
	if c.MaxInterval <= 0 {
		return DefaultMaxBackoff
	}
	return c.MaxInterval
}

// GetMultiplier returns the effective backoff multiplier.
func (c *BackoffConfig) GetMultiplier() float64 {
	if c.Multiplier <= 0 {
		return DefaultBackoffMultiplier
	}
	return c.Multiplier
}

// GetMaxRetries returns the effective maximum retries.
func (c *BackoffConfig) GetMaxRetries() int {
	// 0 means unlimited, so we don't apply a default
	return c.MaxRetries
}

// GetHeartbeatInterval returns the effective heartbeat interval.
func (c *Config) GetHeartbeatInterval() time.Duration {
	if c.HeartbeatInterval <= 0 {
		return DefaultHeartbeatInterval
	}
	return c.HeartbeatInterval
}

// GetConnectionTimeout returns the effective connection timeout.
func (c *Config) GetConnectionTimeout() time.Duration {
	if c.ConnectionTimeout <= 0 {
		return DefaultConnectionTimeout
	}
	return c.ConnectionTimeout
}

// IsTLSEnabled returns true if TLS is enabled.
func (c *Config) IsTLSEnabled() bool {
	return c.TLS != nil && c.TLS.Enabled
}

// GetPodName returns the pod name from environment or empty string.
func (c *Config) GetPodName() string {
	return os.Getenv("POD_NAME")
}

// GetNodeName returns the node name from environment or empty string.
func (c *Config) GetNodeName() string {
	return os.Getenv("NODE_NAME")
}
