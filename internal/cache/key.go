// Package cache provides caching capabilities for the API Gateway.
package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"text/template"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// KeyGenerator generates cache keys from requests.
type KeyGenerator interface {
	// GenerateKey generates a cache key for the given request.
	GenerateKey(r *http.Request) (string, error)
}

// keyGenerator implements the KeyGenerator interface.
type keyGenerator struct {
	logger   observability.Logger
	cfg      *config.CacheKeyConfig
	template *template.Template
}

// NewKeyGenerator creates a new KeyGenerator.
func NewKeyGenerator(cfg *config.CacheKeyConfig, logger observability.Logger) (KeyGenerator, error) {
	if cfg == nil {
		cfg = &config.CacheKeyConfig{
			IncludeMethod: true,
			IncludePath:   true,
		}
	}

	if logger == nil {
		logger = observability.NopLogger()
	}

	kg := &keyGenerator{
		logger: logger,
		cfg:    cfg,
	}

	// Parse custom template if provided
	if cfg.KeyTemplate != "" {
		tmpl, err := template.New("cacheKey").Parse(cfg.KeyTemplate)
		if err != nil {
			return nil, err
		}
		kg.template = tmpl
	}

	return kg, nil
}

// GenerateKey generates a cache key for the given request.
func (kg *keyGenerator) GenerateKey(r *http.Request) (string, error) {
	// Use custom template if provided
	if kg.template != nil {
		return kg.generateFromTemplate(r)
	}

	return kg.generateDefault(r), nil
}

// generateFromTemplate generates a key using the custom template.
func (kg *keyGenerator) generateFromTemplate(r *http.Request) (string, error) {
	data := kg.buildTemplateData(r)

	var buf bytes.Buffer
	if err := kg.template.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// generateDefault generates a key using the default configuration.
func (kg *keyGenerator) generateDefault(r *http.Request) string {
	var parts []string

	// Include method
	if kg.cfg.IncludeMethod {
		parts = append(parts, r.Method)
	}

	// Include path
	if kg.cfg.IncludePath {
		parts = append(parts, r.URL.Path)
	}

	// Include query parameters
	if len(kg.cfg.IncludeQueryParams) > 0 {
		queryPart := kg.buildQueryPart(r.URL.Query())
		if queryPart != "" {
			parts = append(parts, queryPart)
		}
	}

	// Include headers
	if len(kg.cfg.IncludeHeaders) > 0 {
		headerPart := kg.buildHeaderPart(r.Header)
		if headerPart != "" {
			parts = append(parts, headerPart)
		}
	}

	// Include body hash
	if kg.cfg.IncludeBodyHash && r.Body != nil {
		bodyHash := kg.hashBody(r)
		if bodyHash != "" {
			parts = append(parts, bodyHash)
		}
	}

	key := strings.Join(parts, ":")

	kg.logger.Debug("generated cache key",
		observability.String("key", key),
		observability.String("method", r.Method),
		observability.String("path", r.URL.Path))

	return key
}

// buildQueryPart builds the query parameter part of the key.
func (kg *keyGenerator) buildQueryPart(query url.Values) string {
	if len(kg.cfg.IncludeQueryParams) == 0 {
		return ""
	}

	var parts []string

	// Sort for consistent ordering
	params := make([]string, 0, len(kg.cfg.IncludeQueryParams))
	params = append(params, kg.cfg.IncludeQueryParams...)
	sort.Strings(params)

	for _, param := range params {
		if values, ok := query[param]; ok {
			for _, v := range values {
				parts = append(parts, param+"="+v)
			}
		}
	}

	if len(parts) == 0 {
		return ""
	}

	return "q:" + strings.Join(parts, "&")
}

// buildHeaderPart builds the header part of the key.
func (kg *keyGenerator) buildHeaderPart(headers http.Header) string {
	if len(kg.cfg.IncludeHeaders) == 0 {
		return ""
	}

	var parts []string

	// Sort for consistent ordering
	headerNames := make([]string, 0, len(kg.cfg.IncludeHeaders))
	headerNames = append(headerNames, kg.cfg.IncludeHeaders...)
	sort.Strings(headerNames)

	for _, name := range headerNames {
		if values := headers.Values(name); len(values) > 0 {
			for _, v := range values {
				parts = append(parts, name+"="+v)
			}
		}
	}

	if len(parts) == 0 {
		return ""
	}

	return "h:" + strings.Join(parts, "&")
}

// hashBody computes a hash of the request body.
func (kg *keyGenerator) hashBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}

	// Read the body
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r.Body); err != nil {
		kg.logger.Debug("failed to read body for hashing",
			observability.Error(err))
		return ""
	}

	// Restore the body for later use
	r.Body = &readCloser{Reader: bytes.NewReader(buf.Bytes())}

	if buf.Len() == 0 {
		return ""
	}

	// Compute SHA256 hash
	hash := sha256.Sum256(buf.Bytes())
	return "b:" + hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter key
}

// buildTemplateData builds the data for template execution.
func (kg *keyGenerator) buildTemplateData(r *http.Request) map[string]interface{} {
	// Build query map
	queryMap := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			queryMap[key] = values[0]
		}
	}

	// Build header map
	headerMap := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headerMap[key] = values[0]
		}
	}

	return map[string]interface{}{
		"Method": r.Method,
		"Path":   r.URL.Path,
		"Host":   r.Host,
		"Query":  queryMap,
		"Header": headerMap,
	}
}

// readCloser wraps a Reader to implement ReadCloser.
type readCloser struct {
	*bytes.Reader
}

func (rc *readCloser) Close() error {
	return nil
}

// GenerateSimpleKey generates a simple cache key from method and path.
func GenerateSimpleKey(method, path string) string {
	return method + ":" + path
}

// HashKey hashes a key to a fixed length.
func HashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// SanitizeKey removes or replaces characters that might cause issues in cache keys.
func SanitizeKey(key string) string {
	// Replace problematic characters
	replacer := strings.NewReplacer(
		" ", "_",
		"\n", "",
		"\r", "",
		"\t", "",
	)
	return replacer.Replace(key)
}
