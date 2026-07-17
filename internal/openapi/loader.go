package openapi

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

// defaultSpecFetchTimeout bounds every remote OpenAPI spec fetch and, on the
// validator side, each whole spec load. kin-openapi's default URI reader uses
// http.DefaultClient, which has no timeout and would let an unresponsive spec
// URL hang gateway startup or reload indefinitely.
const defaultSpecFetchTimeout = 30 * time.Second

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

	// httpClient fetches remote specs. Its Timeout caps every single fetch
	// at defaultSpecFetchTimeout so a hung spec URL fails fast instead of
	// blocking forever; tests may substitute a client with a shorter timeout.
	httpClient *http.Client
}

// NewSpecLoader creates a new SpecLoader instance.
func NewSpecLoader() *SpecLoader {
	return &SpecLoader{
		cache:      make(map[string]*openapi3.T),
		httpClient: &http.Client{Timeout: defaultSpecFetchTimeout},
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
	loader.ReadFromURIFunc = l.newURIReadFunc(ctx, parsedURL)

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

// newURIReadFunc builds the cache-wrapped URI reader used for a single URL
// document load. Remote reads are bound to the caller context and to the
// timeout-bounded HTTP client instead of kin-openapi's default
// http.DefaultClient (which has no timeout).
//
// SECURITY: installing a custom ReadFromURIFunc disables kin-openapi's
// built-in IsExternalRefsAllowed enforcement, so the reader re-applies the
// deny-by-default policy itself: only the root document may be read unless
// the loader explicitly allows external references. This preserves protection
// against SSRF and local-file reads via $ref in untrusted documents.
//
// The byte cache is scoped to one load so that Invalidate/Reload genuinely
// refetches the spec while duplicate $ref reads within a load are deduped.
func (l *SpecLoader) newURIReadFunc(ctx context.Context, root *url.URL) openapi3.ReadFromURIFunc {
	read := openapi3.ReadFromURIs(readFromHTTPWithContext(ctx, l.httpClient), openapi3.ReadFromFile)
	rootURI := root.String()

	guarded := func(loader *openapi3.Loader, location *url.URL) ([]byte, error) {
		if location.String() != rootURI && !loader.IsExternalRefsAllowed {
			return nil, fmt.Errorf("encountered disallowed external reference: %q", location.String())
		}
		return read(loader, location)
	}

	return openapi3.URIMapCache(guarded)
}

// readFromHTTPWithContext mirrors openapi3.ReadFromHTTP but binds each request
// to the caller context (cancellation/deadline) and to the given client's
// timeout, so a hung spec source fails fast instead of hanging indefinitely.
func readFromHTTPWithContext(ctx context.Context, client *http.Client) openapi3.ReadFromURIFunc {
	return func(_ *openapi3.Loader, location *url.URL) ([]byte, error) {
		if location.Scheme == "" || location.Host == "" {
			return nil, openapi3.ErrURINotSupported
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build spec fetch request for %q: %w", location.String(), err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch spec from %q: %w", location.String(), err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode > 399 {
			return nil, fmt.Errorf("request to %q returned status code %d", location.String(), resp.StatusCode)
		}

		return io.ReadAll(resp.Body)
	}
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
