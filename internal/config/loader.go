package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// envVarPattern matches ${VAR} and ${VAR:-default} patterns.
var envVarPattern = regexp.MustCompile(`\$\{([^}:]+)(?::-([^}]*))?\}`)

// Loader handles configuration loading from files and readers.
type Loader struct {
	basePath     string
	loadedFiles  map[string]bool
	maxIncludes  int
	includeCount int
}

// NewLoader creates a new configuration loader.
func NewLoader() *Loader {
	return &Loader{
		loadedFiles: make(map[string]bool),
		maxIncludes: 10,
	}
}

// LoadConfig loads configuration from a file path.
func LoadConfig(path string) (*GatewayConfig, error) {
	loader := NewLoader()
	return loader.Load(path)
}

// LoadConfigFromReader loads configuration from an io.Reader.
func LoadConfigFromReader(r io.Reader) (*GatewayConfig, error) {
	loader := NewLoader()
	return loader.LoadFromReader(r)
}

// Load loads configuration from a file path.
func (l *Loader) Load(path string) (*GatewayConfig, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path %s: %w", path, err)
	}

	l.basePath = filepath.Dir(absPath)

	data, err := os.ReadFile(absPath) //nolint:gosec // path is validated via filepath.Abs
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	l.loadedFiles[absPath] = true

	return l.parseConfig(data)
}

// LoadFromReader loads configuration from an io.Reader.
func (l *Loader) LoadFromReader(r io.Reader) (*GatewayConfig, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	return l.parseConfig(data)
}

// parseConfig parses YAML data into a GatewayConfig.
func (l *Loader) parseConfig(data []byte) (*GatewayConfig, error) {
	// Substitute environment variables
	content := l.substituteEnvVars(string(data))

	// Parse YAML
	var config GatewayConfig
	if err := yaml.Unmarshal([]byte(content), &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &config, nil
}

// substituteEnvVars replaces ${VAR} and ${VAR:-default} patterns with environment variable values.
func (l *Loader) substituteEnvVars(content string) string {
	// Handle escaped dollar signs first
	content = strings.ReplaceAll(content, "$$", "\x00ESCAPED_DOLLAR\x00")

	result := envVarPattern.ReplaceAllStringFunc(content, func(match string) string {
		submatches := envVarPattern.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		varName := submatches[1]
		defaultValue := ""
		if len(submatches) >= 3 {
			defaultValue = submatches[2]
		}

		if value, exists := os.LookupEnv(varName); exists {
			return value
		}
		return defaultValue
	})

	// Restore escaped dollar signs
	result = strings.ReplaceAll(result, "\x00ESCAPED_DOLLAR\x00", "$")

	return result
}

// LoadWithIncludes loads configuration with support for include directives.
func (l *Loader) LoadWithIncludes(path string) (*GatewayConfig, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path %s: %w", path, err)
	}

	l.basePath = filepath.Dir(absPath)

	return l.loadWithIncludes(absPath)
}

// loadWithIncludes recursively loads configuration files with include support.
func (l *Loader) loadWithIncludes(path string) (*GatewayConfig, error) {
	// Check for circular includes
	if l.loadedFiles[path] {
		return nil, fmt.Errorf("circular include detected: %s", path)
	}

	// Check max includes
	if l.includeCount >= l.maxIncludes {
		return nil, fmt.Errorf("maximum include depth (%d) exceeded", l.maxIncludes)
	}

	l.loadedFiles[path] = true
	l.includeCount++

	data, err := os.ReadFile(path) //nolint:gosec // path validated via circular include check
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// First, check for includes in raw YAML
	var rawConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &rawConfig); err != nil {
		return nil, fmt.Errorf("failed to parse YAML for includes: %w", err)
	}

	// Process includes if present
	if includes, ok := rawConfig["includes"].([]interface{}); ok {
		for _, inc := range includes {
			if includePath, ok := inc.(string); ok {
				// Resolve relative paths
				if !filepath.IsAbs(includePath) {
					includePath = filepath.Join(filepath.Dir(path), includePath)
				}

				includedConfig, err := l.loadWithIncludes(includePath)
				if err != nil {
					return nil, fmt.Errorf("failed to load include %s: %w", includePath, err)
				}

				// Merge included config (included config is base, current overrides)
				_ = includedConfig // TODO: implement merging
			}
		}
	}

	return l.parseConfig(data)
}

// MergeConfigs merges multiple configurations, with later configs taking precedence.
func MergeConfigs(configs ...*GatewayConfig) *GatewayConfig {
	if len(configs) == 0 {
		return DefaultConfig()
	}

	result := configs[0]
	for i := 1; i < len(configs); i++ {
		result = mergeTwo(result, configs[i])
	}

	return result
}

// mergeTwo merges two configurations, with the second taking precedence.
func mergeTwo(base, override *GatewayConfig) *GatewayConfig {
	if override == nil {
		return base
	}
	if base == nil {
		return override
	}

	result := *base

	// Override basic fields
	if override.APIVersion != "" {
		result.APIVersion = override.APIVersion
	}
	if override.Kind != "" {
		result.Kind = override.Kind
	}
	if override.Metadata.Name != "" {
		result.Metadata.Name = override.Metadata.Name
	}

	// Merge labels
	if result.Metadata.Labels == nil {
		result.Metadata.Labels = make(map[string]string)
	}
	for k, v := range override.Metadata.Labels {
		result.Metadata.Labels[k] = v
	}

	// Merge annotations
	if result.Metadata.Annotations == nil {
		result.Metadata.Annotations = make(map[string]string)
	}
	for k, v := range override.Metadata.Annotations {
		result.Metadata.Annotations[k] = v
	}

	// Override listeners (replace entirely if provided)
	if len(override.Spec.Listeners) > 0 {
		result.Spec.Listeners = override.Spec.Listeners
	}

	// Merge routes (append)
	result.Spec.Routes = append(result.Spec.Routes, override.Spec.Routes...)

	// Merge backends (append)
	result.Spec.Backends = append(result.Spec.Backends, override.Spec.Backends...)

	// Override rate limit if provided
	if override.Spec.RateLimit != nil {
		result.Spec.RateLimit = override.Spec.RateLimit
	}

	// Override circuit breaker if provided
	if override.Spec.CircuitBreaker != nil {
		result.Spec.CircuitBreaker = override.Spec.CircuitBreaker
	}

	// Override CORS if provided
	if override.Spec.CORS != nil {
		result.Spec.CORS = override.Spec.CORS
	}

	// Override observability if provided
	if override.Spec.Observability != nil {
		result.Spec.Observability = override.Spec.Observability
	}

	return &result
}

// ResolveConfigPath resolves a configuration file path, checking common locations.
func ResolveConfigPath(path string) (string, error) {
	// If path is absolute and exists, use it
	if filepath.IsAbs(path) {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("config file not found: %s", path)
	}

	// Check relative to current directory
	if _, err := os.Stat(path); err == nil {
		return filepath.Abs(path)
	}

	// Check common locations
	etcPath := filepath.Join(string(filepath.Separator), "etc", "avapigw")
	commonPaths := []string{
		filepath.Join("configs", path),
		filepath.Join(etcPath, path),
		filepath.Join(os.Getenv("HOME"), ".avapigw", path),
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return filepath.Abs(p)
		}
	}

	return "", fmt.Errorf("config file not found: %s", path)
}
