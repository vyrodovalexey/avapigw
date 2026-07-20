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

	// Start with nil base config - will be built from includes
	var baseConfig *GatewayConfig

	// Process includes if present
	baseConfig, err = l.processIncludes(rawConfig, path, baseConfig)
	if err != nil {
		return nil, err
	}

	// Parse the current config
	currentConfig, err := l.parseConfig(data)
	if err != nil {
		return nil, err
	}

	// Merge current config on top of base (current config overrides includes)
	if baseConfig != nil {
		return mergeTwo(baseConfig, currentConfig), nil
	}

	return currentConfig, nil
}

// processIncludes processes include directives from raw config and merges them into baseConfig.
func (l *Loader) processIncludes(
	rawConfig map[string]interface{},
	path string,
	baseConfig *GatewayConfig,
) (*GatewayConfig, error) {
	includes, ok := rawConfig["includes"].([]interface{})
	if !ok {
		return baseConfig, nil
	}

	for _, inc := range includes {
		includePath, ok := inc.(string)
		if !ok {
			continue
		}

		// Resolve relative paths
		if !filepath.IsAbs(includePath) {
			includePath = filepath.Join(filepath.Dir(path), includePath)
		}

		includedConfig, err := l.loadWithIncludes(includePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load include %s: %w", includePath, err)
		}

		// Merge included config into base (included configs are merged in order)
		if baseConfig == nil {
			baseConfig = includedConfig
		} else {
			baseConfig = mergeTwo(baseConfig, includedConfig)
		}
	}

	return baseConfig, nil
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
//
// EVERY config.GatewaySpec field MUST be handled here (resource lists are
// appended, scalar lists replace when set, pointer sections override when
// non-nil). The reflection guard test in loader_merge_guard_test.go fails
// the build when a newly added GatewaySpec field is not carried through this
// merge, preventing silent section drops for include-based configurations.
func mergeTwo(base, override *GatewayConfig) *GatewayConfig {
	if override == nil {
		return base
	}
	if base == nil {
		return override
	}

	result := *base

	mergeRootFields(&result, override)
	mergeMetadata(&result, override)
	mergeSpecResources(&result.Spec, &override.Spec)
	mergeSpecSections(&result.Spec, &override.Spec)

	return &result
}

// mergeRootFields overrides apiVersion/kind when set on the override config.
func mergeRootFields(result, override *GatewayConfig) {
	if override.APIVersion != "" {
		result.APIVersion = override.APIVersion
	}
	if override.Kind != "" {
		result.Kind = override.Kind
	}
}

// mergeMetadata merges metadata name, labels, and annotations.
func mergeMetadata(result, override *GatewayConfig) {
	if override.Metadata.Name != "" {
		result.Metadata.Name = override.Metadata.Name
	}

	if result.Metadata.Labels == nil {
		result.Metadata.Labels = make(map[string]string)
	}
	for k, v := range override.Metadata.Labels {
		result.Metadata.Labels[k] = v
	}

	if result.Metadata.Annotations == nil {
		result.Metadata.Annotations = make(map[string]string)
	}
	for k, v := range override.Metadata.Annotations {
		result.Metadata.Annotations[k] = v
	}
}

// mergeSpecResources merges the resource collections: listeners and
// trustedProxies replace entirely when provided (positional semantics),
// route/backend lists append so includes can contribute resources.
func mergeSpecResources(result, override *GatewaySpec) {
	if len(override.Listeners) > 0 {
		result.Listeners = override.Listeners
	}
	if len(override.TrustedProxies) > 0 {
		result.TrustedProxies = override.TrustedProxies
	}

	result.Routes = append(result.Routes, override.Routes...)
	result.Backends = append(result.Backends, override.Backends...)
	result.GRPCRoutes = append(result.GRPCRoutes, override.GRPCRoutes...)
	result.GRPCBackends = append(result.GRPCBackends, override.GRPCBackends...)
	result.GraphQLRoutes = append(result.GraphQLRoutes, override.GraphQLRoutes...)
	result.GraphQLBackends = append(result.GraphQLBackends, override.GraphQLBackends...)
}

// mergeSpecSections overrides every pointer-typed spec section when the
// override provides it. Sections are carried as whole blocks (no per-field
// deep merge), matching the documented include semantics: the later file
// wins for a section it defines.
func mergeSpecSections(result, override *GatewaySpec) {
	if override.RateLimit != nil {
		result.RateLimit = override.RateLimit
	}
	if override.CircuitBreaker != nil {
		result.CircuitBreaker = override.CircuitBreaker
	}
	if override.CORS != nil {
		result.CORS = override.CORS
	}
	if override.Observability != nil {
		result.Observability = override.Observability
	}
	if override.Authentication != nil {
		result.Authentication = override.Authentication
	}
	if override.Authorization != nil {
		result.Authorization = override.Authorization
	}
	if override.Security != nil {
		result.Security = override.Security
	}
	if override.Audit != nil {
		result.Audit = override.Audit
	}
	if override.RequestLimits != nil {
		result.RequestLimits = override.RequestLimits
	}
	if override.MaxSessions != nil {
		result.MaxSessions = override.MaxSessions
	}
	if override.GraphQL != nil {
		result.GraphQL = override.GraphQL
	}
	if override.OpenAPIValidation != nil {
		result.OpenAPIValidation = override.OpenAPIValidation
	}
	if override.WebSocket != nil {
		result.WebSocket = override.WebSocket
	}
	if override.Vault != nil {
		result.Vault = override.Vault
	}
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
		// Clean the path to prevent path traversal attacks (G703)
		cleanPath := filepath.Clean(p)
		if _, err := os.Stat(cleanPath); err == nil {
			return filepath.Abs(cleanPath)
		}
	}

	return "", fmt.Errorf("config file not found: %s", path)
}
