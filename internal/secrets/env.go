package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DefaultEnvPrefix is the default prefix for environment variable secrets
const DefaultEnvPrefix = "AVAPIGW_SECRET_"

// EnvProviderConfig holds configuration for the environment variable secrets provider
type EnvProviderConfig struct {
	// Prefix is the prefix for environment variables
	// Default: "AVAPIGW_SECRET_"
	Prefix string
	// Logger is the logger instance
	Logger *zap.Logger
}

// EnvProvider implements the Provider interface using environment variables
// Secrets are read from environment variables with a configurable prefix.
// Path format: "SECRET_NAME" maps to env var "{PREFIX}SECRET_NAME"
// For complex secrets with multiple keys, the env var value should be JSON-encoded.
type EnvProvider struct {
	prefix string
	logger *zap.Logger
}

// NewEnvProvider creates a new environment variable secrets provider
func NewEnvProvider(cfg *EnvProviderConfig) (*EnvProvider, error) {
	if cfg == nil {
		cfg = &EnvProviderConfig{}
	}

	prefix := cfg.Prefix
	if prefix == "" {
		prefix = DefaultEnvPrefix
	}

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &EnvProvider{
		prefix: prefix,
		logger: logger,
	}, nil
}

// Type returns the provider type
func (p *EnvProvider) Type() ProviderType {
	return ProviderTypeEnv
}

// normalizeEnvName converts a secret path to an environment variable name
// - Converts to uppercase
// - Replaces dashes and dots with underscores
// - Adds the configured prefix
func (p *EnvProvider) normalizeEnvName(path string) string {
	// Convert to uppercase and replace common separators
	name := strings.ToUpper(path)
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, "/", "_")

	return p.prefix + name
}

// GetSecret retrieves a secret from environment variables
// The path is converted to an environment variable name using the configured prefix.
// If the value is valid JSON, it's parsed as a map of key-value pairs.
// Otherwise, the entire value is stored under the key "value".
func (p *EnvProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "get", time.Since(start), nil)
	}()

	if path == "" {
		RecordOperation(p.Type(), "get", time.Since(start), ErrInvalidPath)
		return nil, ErrInvalidPath
	}

	envName := p.normalizeEnvName(path)

	p.logger.Debug("Getting secret from environment variable",
		zap.String("path", path),
		zap.String("envVar", envName),
	)

	value, exists := os.LookupEnv(envName)
	if !exists {
		p.logger.Debug("Environment variable not found",
			zap.String("envVar", envName),
		)
		RecordOperation(p.Type(), "get", time.Since(start), ErrSecretNotFound)
		return nil, fmt.Errorf("%w: environment variable %s not set", ErrSecretNotFound, envName)
	}

	data := make(map[string][]byte)

	// Try to parse as JSON for complex secrets
	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(value), &jsonData); err == nil {
		// Successfully parsed as JSON
		for k, v := range jsonData {
			switch val := v.(type) {
			case string:
				data[k] = []byte(val)
			default:
				// Convert other types to JSON
				jsonBytes, err := json.Marshal(val)
				if err != nil {
					p.logger.Warn("Failed to marshal value to JSON",
						zap.String("key", k),
						zap.Error(err),
					)
					continue
				}
				data[k] = jsonBytes
			}
		}
	} else {
		// Not JSON, store as single value
		data["value"] = []byte(value)
	}

	p.logger.Debug("Successfully retrieved secret from environment",
		zap.String("path", path),
		zap.String("envVar", envName),
		zap.Int("keys", len(data)),
	)

	return &Secret{
		Name: path,
		Data: data,
		Metadata: map[string]string{
			"source":  "environment",
			"env_var": envName,
		},
	}, nil
}

// ListSecrets lists all secrets available from environment variables
// Returns all environment variables that match the configured prefix
func (p *EnvProvider) ListSecrets(ctx context.Context, path string) ([]string, error) {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "list", time.Since(start), nil)
	}()

	p.logger.Debug("Listing secrets from environment variables",
		zap.String("prefix", p.prefix),
	)

	var secrets []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := parts[0]
		if strings.HasPrefix(name, p.prefix) {
			// Remove prefix and convert back to path format
			secretName := strings.TrimPrefix(name, p.prefix)
			secretName = strings.ToLower(secretName)
			secretName = strings.ReplaceAll(secretName, "_", "-")
			secrets = append(secrets, secretName)
		}
	}

	p.logger.Debug("Successfully listed secrets from environment",
		zap.Int("count", len(secrets)),
	)

	return secrets, nil
}

// WriteSecret is not supported for environment variables
func (p *EnvProvider) WriteSecret(ctx context.Context, path string, data map[string][]byte) error {
	return ErrReadOnly
}

// DeleteSecret is not supported for environment variables
func (p *EnvProvider) DeleteSecret(ctx context.Context, path string) error {
	return ErrReadOnly
}

// IsReadOnly returns true as environment variables are read-only
func (p *EnvProvider) IsReadOnly() bool {
	return true
}

// HealthCheck always returns nil as environment variables are always available
func (p *EnvProvider) HealthCheck(ctx context.Context) error {
	start := time.Now()

	// Check if at least one secret with our prefix exists
	hasSecrets := false
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, p.prefix) {
			hasSecrets = true
			break
		}
	}

	if !hasSecrets {
		p.logger.Debug("No secrets found with configured prefix",
			zap.String("prefix", p.prefix),
		)
	}

	RecordHealthStatus(p.Type(), true)
	RecordOperation(p.Type(), "health_check", time.Since(start), nil)
	return nil
}

// Close cleans up provider resources
func (p *EnvProvider) Close() error {
	p.logger.Debug("Closing environment secrets provider")
	return nil
}
