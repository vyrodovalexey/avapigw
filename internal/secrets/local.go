package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// LocalProviderConfig holds configuration for the local file secrets provider
type LocalProviderConfig struct {
	// BasePath is the base directory for secrets
	BasePath string
	// Logger is the logger instance
	Logger *zap.Logger
}

// LocalProvider implements the Provider interface using local files
// Secrets are stored in a directory structure:
// - base-path/secret-name/key (each key is a separate file)
// - base-path/secret-name.yaml (single file with all keys)
// - base-path/secret-name.json (single file with all keys)
type LocalProvider struct {
	basePath string
	logger   *zap.Logger
}

// NewLocalProvider creates a new local file secrets provider
func NewLocalProvider(cfg *LocalProviderConfig) (*LocalProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is required", ErrProviderNotConfigured)
	}
	if cfg.BasePath == "" {
		return nil, fmt.Errorf("%w: base path is required", ErrProviderNotConfigured)
	}

	// Verify base path exists
	info, err := os.Stat(cfg.BasePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: base path does not exist: %s", ErrProviderNotConfigured, cfg.BasePath)
		}
		return nil, fmt.Errorf("%w: failed to access base path: %v", ErrProviderNotConfigured, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: base path is not a directory: %s", ErrProviderNotConfigured, cfg.BasePath)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &LocalProvider{
		basePath: cfg.BasePath,
		logger:   logger,
	}, nil
}

// Type returns the provider type
func (p *LocalProvider) Type() ProviderType {
	return ProviderTypeLocal
}

// GetSecret retrieves a secret by path
// Tries multiple formats:
// 1. Directory with individual key files: base-path/secret-name/key
// 2. YAML file: base-path/secret-name.yaml
// 3. JSON file: base-path/secret-name.json
func (p *LocalProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "get", time.Since(start), nil)
	}()

	if path == "" {
		RecordOperation(p.Type(), "get", time.Since(start), ErrInvalidPath)
		return nil, ErrInvalidPath
	}

	// Clean the path to prevent directory traversal
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		RecordOperation(p.Type(), "get", time.Since(start), ErrInvalidPath)
		return nil, fmt.Errorf("%w: path contains invalid characters", ErrInvalidPath)
	}

	p.logger.Debug("Getting local secret",
		zap.String("path", path),
		zap.String("basePath", p.basePath),
	)

	// Try directory format first
	dirPath := filepath.Join(p.basePath, cleanPath)
	if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
		secret, err := p.readSecretFromDirectory(dirPath, cleanPath)
		if err == nil {
			return secret, nil
		}
		p.logger.Debug("Failed to read secret from directory, trying file formats",
			zap.String("path", dirPath),
			zap.Error(err),
		)
	}

	// Try YAML file
	yamlPath := filepath.Join(p.basePath, cleanPath+".yaml")
	if _, err := os.Stat(yamlPath); err == nil {
		secret, err := p.readSecretFromYAML(yamlPath, cleanPath)
		if err == nil {
			return secret, nil
		}
		p.logger.Debug("Failed to read secret from YAML",
			zap.String("path", yamlPath),
			zap.Error(err),
		)
	}

	// Try YML file
	ymlPath := filepath.Join(p.basePath, cleanPath+".yml")
	if _, err := os.Stat(ymlPath); err == nil {
		secret, err := p.readSecretFromYAML(ymlPath, cleanPath)
		if err == nil {
			return secret, nil
		}
		p.logger.Debug("Failed to read secret from YML",
			zap.String("path", ymlPath),
			zap.Error(err),
		)
	}

	// Try JSON file
	jsonPath := filepath.Join(p.basePath, cleanPath+".json")
	if _, err := os.Stat(jsonPath); err == nil {
		secret, err := p.readSecretFromJSON(jsonPath, cleanPath)
		if err == nil {
			return secret, nil
		}
		p.logger.Debug("Failed to read secret from JSON",
			zap.String("path", jsonPath),
			zap.Error(err),
		)
	}

	p.logger.Debug("Secret not found in any format",
		zap.String("path", path),
	)
	RecordOperation(p.Type(), "get", time.Since(start), ErrSecretNotFound)
	return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, path)
}

// readSecretFromDirectory reads a secret from a directory where each file is a key
func (p *LocalProvider) readSecretFromDirectory(dirPath, name string) (*Secret, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("directory is empty")
	}

	data := make(map[string][]byte)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		keyName := entry.Name()
		filePath := filepath.Join(dirPath, keyName)

		content, err := os.ReadFile(filePath)
		if err != nil {
			p.logger.Warn("Failed to read key file",
				zap.String("file", filePath),
				zap.Error(err),
			)
			continue
		}

		// Trim trailing newline (common in secret files)
		content = []byte(strings.TrimSuffix(string(content), "\n"))
		data[keyName] = content
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no valid key files found")
	}

	// Get directory info for timestamps
	info, _ := os.Stat(dirPath)
	modTime := info.ModTime()

	return &Secret{
		Name:      name,
		Data:      data,
		Metadata:  map[string]string{"source": "directory"},
		UpdatedAt: &modTime,
	}, nil
}

// readSecretFromYAML reads a secret from a YAML file
func (p *LocalProvider) readSecretFromYAML(filePath, name string) (*Secret, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file: %w", err)
	}

	var rawData map[string]interface{}
	if err := yaml.Unmarshal(content, &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	data := make(map[string][]byte)
	for k, v := range rawData {
		switch val := v.(type) {
		case string:
			data[k] = []byte(val)
		case []byte:
			data[k] = val
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

	// Get file info for timestamps
	info, _ := os.Stat(filePath)
	modTime := info.ModTime()

	return &Secret{
		Name:      name,
		Data:      data,
		Metadata:  map[string]string{"source": "yaml", "file": filePath},
		UpdatedAt: &modTime,
	}, nil
}

// readSecretFromJSON reads a secret from a JSON file
func (p *LocalProvider) readSecretFromJSON(filePath, name string) (*Secret, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON file: %w", err)
	}

	var rawData map[string]interface{}
	if err := json.Unmarshal(content, &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	data := make(map[string][]byte)
	for k, v := range rawData {
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

	// Get file info for timestamps
	info, _ := os.Stat(filePath)
	modTime := info.ModTime()

	return &Secret{
		Name:      name,
		Data:      data,
		Metadata:  map[string]string{"source": "json", "file": filePath},
		UpdatedAt: &modTime,
	}, nil
}

// ListSecrets lists secrets in the base path
func (p *LocalProvider) ListSecrets(ctx context.Context, path string) ([]string, error) {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "list", time.Since(start), nil)
	}()

	searchPath := p.basePath
	if path != "" {
		cleanPath := filepath.Clean(path)
		if strings.Contains(cleanPath, "..") {
			RecordOperation(p.Type(), "list", time.Since(start), ErrInvalidPath)
			return nil, fmt.Errorf("%w: path contains invalid characters", ErrInvalidPath)
		}
		searchPath = filepath.Join(p.basePath, cleanPath)
	}

	p.logger.Debug("Listing local secrets",
		zap.String("path", searchPath),
	)

	entries, err := os.ReadDir(searchPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		p.logger.Error("Failed to list secrets",
			zap.String("path", searchPath),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "list", time.Since(start), err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	secrets := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()

		if entry.IsDir() {
			// Directory is a secret
			secrets[name] = true
		} else {
			// Check for supported file extensions
			for _, ext := range []string{".yaml", ".yml", ".json"} {
				if strings.HasSuffix(name, ext) {
					secretName := strings.TrimSuffix(name, ext)
					secrets[secretName] = true
					break
				}
			}
		}
	}

	result := make([]string, 0, len(secrets))
	for name := range secrets {
		result = append(result, name)
	}

	p.logger.Debug("Successfully listed secrets",
		zap.String("path", searchPath),
		zap.Int("count", len(result)),
	)

	return result, nil
}

// WriteSecret writes a secret to a YAML file
func (p *LocalProvider) WriteSecret(ctx context.Context, path string, data map[string][]byte) error {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "write", time.Since(start), nil)
	}()

	if path == "" {
		RecordOperation(p.Type(), "write", time.Since(start), ErrInvalidPath)
		return ErrInvalidPath
	}

	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		RecordOperation(p.Type(), "write", time.Since(start), ErrInvalidPath)
		return fmt.Errorf("%w: path contains invalid characters", ErrInvalidPath)
	}

	p.logger.Debug("Writing local secret",
		zap.String("path", path),
	)

	// Convert data to string map for YAML
	stringData := make(map[string]string)
	for k, v := range data {
		stringData[k] = string(v)
	}

	yamlContent, err := yaml.Marshal(stringData)
	if err != nil {
		p.logger.Error("Failed to marshal secret to YAML",
			zap.String("path", path),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "write", time.Since(start), err)
		return fmt.Errorf("failed to marshal secret: %w", err)
	}

	filePath := filepath.Join(p.basePath, cleanPath+".yaml")

	// Ensure parent directory exists
	parentDir := filepath.Dir(filePath)
	if err := os.MkdirAll(parentDir, 0750); err != nil {
		p.logger.Error("Failed to create parent directory",
			zap.String("path", parentDir),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "write", time.Since(start), err)
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file with restricted permissions
	if err := os.WriteFile(filePath, yamlContent, 0600); err != nil {
		p.logger.Error("Failed to write secret file",
			zap.String("path", filePath),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "write", time.Since(start), err)
		return fmt.Errorf("failed to write secret: %w", err)
	}

	p.logger.Info("Wrote secret",
		zap.String("path", filePath),
	)

	return nil
}

// DeleteSecret deletes a secret
func (p *LocalProvider) DeleteSecret(ctx context.Context, path string) error {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "delete", time.Since(start), nil)
	}()

	if path == "" {
		RecordOperation(p.Type(), "delete", time.Since(start), ErrInvalidPath)
		return ErrInvalidPath
	}

	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		RecordOperation(p.Type(), "delete", time.Since(start), ErrInvalidPath)
		return fmt.Errorf("%w: path contains invalid characters", ErrInvalidPath)
	}

	p.logger.Debug("Deleting local secret",
		zap.String("path", path),
	)

	deleted := false

	// Try to delete directory
	dirPath := filepath.Join(p.basePath, cleanPath)
	if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
		if err := os.RemoveAll(dirPath); err != nil {
			p.logger.Error("Failed to delete secret directory",
				zap.String("path", dirPath),
				zap.Error(err),
			)
			RecordOperation(p.Type(), "delete", time.Since(start), err)
			return fmt.Errorf("failed to delete secret directory: %w", err)
		}
		deleted = true
	}

	// Try to delete files
	for _, ext := range []string{".yaml", ".yml", ".json"} {
		filePath := filepath.Join(p.basePath, cleanPath+ext)
		if _, err := os.Stat(filePath); err == nil {
			if err := os.Remove(filePath); err != nil {
				p.logger.Error("Failed to delete secret file",
					zap.String("path", filePath),
					zap.Error(err),
				)
				RecordOperation(p.Type(), "delete", time.Since(start), err)
				return fmt.Errorf("failed to delete secret file: %w", err)
			}
			deleted = true
		}
	}

	if !deleted {
		p.logger.Debug("Secret not found for deletion",
			zap.String("path", path),
		)
	} else {
		p.logger.Info("Deleted secret",
			zap.String("path", path),
		)
	}

	return nil
}

// IsReadOnly returns false as local provider supports writes
func (p *LocalProvider) IsReadOnly() bool {
	return false
}

// HealthCheck checks if the base path is accessible
func (p *LocalProvider) HealthCheck(ctx context.Context) error {
	start := time.Now()

	info, err := os.Stat(p.basePath)
	if err != nil {
		p.logger.Error("Local provider health check failed", zap.Error(err))
		RecordHealthStatus(p.Type(), false)
		RecordOperation(p.Type(), "health_check", time.Since(start), err)
		return fmt.Errorf("base path not accessible: %w", err)
	}

	if !info.IsDir() {
		err := fmt.Errorf("base path is not a directory")
		p.logger.Error("Local provider health check failed", zap.Error(err))
		RecordHealthStatus(p.Type(), false)
		RecordOperation(p.Type(), "health_check", time.Since(start), err)
		return err
	}

	RecordHealthStatus(p.Type(), true)
	RecordOperation(p.Type(), "health_check", time.Since(start), nil)
	return nil
}

// Close cleans up provider resources
func (p *LocalProvider) Close() error {
	p.logger.Debug("Closing local secrets provider")
	return nil
}
