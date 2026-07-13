package openapi

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
)

// Loader defines the interface for loading OpenAPI specifications.
type Loader interface {
	// LoadFromFile loads an OpenAPI spec from a file path.
	LoadFromFile(ctx context.Context, path string) (*openapi3.T, error)

	// LoadFromURL loads an OpenAPI spec from a URL.
	LoadFromURL(ctx context.Context, specURL string) (*openapi3.T, error)

	// LoadFromData loads an OpenAPI spec from raw in-memory bytes.
	// This is used when the spec content is delivered inline (for example,
	// resolved from a Kubernetes ConfigMap by the operator) rather than
	// referenced by file path or URL.
	LoadFromData(ctx context.Context, data []byte) (*openapi3.T, error)

	// Invalidate removes a cached spec, forcing reload on next access.
	Invalidate(key string)
}

// SpecLoader loads and caches OpenAPI 3.x specifications.
// It is safe for concurrent use.
type SpecLoader struct {
	mu    sync.RWMutex
	cache map[string]*openapi3.T
}

// NewSpecLoader creates a new SpecLoader instance.
func NewSpecLoader() *SpecLoader {
	return &SpecLoader{
		cache: make(map[string]*openapi3.T),
	}
}

// LoadFromFile loads an OpenAPI spec from a file path.
// Parsed specs are cached by file path for reuse.
func (l *SpecLoader) LoadFromFile(ctx context.Context, path string) (*openapi3.T, error) {
	l.mu.RLock()
	if doc, ok := l.cache[path]; ok {
		l.mu.RUnlock()
		return doc, nil
	}
	l.mu.RUnlock()

	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check after acquiring write lock.
	if doc, ok := l.cache[path]; ok {
		return doc, nil
	}

	loader := openapi3.NewLoader()
	loader.Context = ctx

	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI spec from file %s: %w", path, err)
	}

	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI spec in file %s: %w", path, err)
	}

	l.cache[path] = doc
	return doc, nil
}

// LoadFromURL loads an OpenAPI spec from a URL.
// Parsed specs are cached by URL for reuse.
func (l *SpecLoader) LoadFromURL(ctx context.Context, specURL string) (*openapi3.T, error) {
	l.mu.RLock()
	if doc, ok := l.cache[specURL]; ok {
		l.mu.RUnlock()
		return doc, nil
	}
	l.mu.RUnlock()

	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check after acquiring write lock.
	if doc, ok := l.cache[specURL]; ok {
		return doc, nil
	}

	parsedURL, err := url.Parse(specURL)
	if err != nil {
		return nil, fmt.Errorf("invalid spec URL %s: %w", specURL, err)
	}

	loader := openapi3.NewLoader()
	loader.Context = ctx

	doc, err := loader.LoadFromURI(parsedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI spec from URL %s: %w", specURL, err)
	}

	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI spec from URL %s: %w", specURL, err)
	}

	l.cache[specURL] = doc
	return doc, nil
}

// LoadFromData loads an OpenAPI spec from raw in-memory bytes.
// Parsed specs are cached by a content-derived key so that identical inline
// specs are only parsed once.
func (l *SpecLoader) LoadFromData(ctx context.Context, data []byte) (*openapi3.T, error) {
	cacheKey := dataCacheKey(data)

	l.mu.RLock()
	if doc, ok := l.cache[cacheKey]; ok {
		l.mu.RUnlock()
		return doc, nil
	}
	l.mu.RUnlock()

	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check after acquiring write lock.
	if doc, ok := l.cache[cacheKey]; ok {
		return doc, nil
	}

	loader := openapi3.NewLoader()
	loader.Context = ctx

	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI spec from inline data: %w", err)
	}

	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI spec in inline data: %w", err)
	}

	l.cache[cacheKey] = doc
	return doc, nil
}

// dataCacheKey derives a stable cache key from inline spec content.
func dataCacheKey(data []byte) string {
	sum := sha256.Sum256(data)
	return "inline:" + fmt.Sprintf("%x", sum)
}

// Invalidate removes a cached spec, forcing reload on next access.
// This supports hot-reload when spec files change.
func (l *SpecLoader) Invalidate(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.cache, key)
}
