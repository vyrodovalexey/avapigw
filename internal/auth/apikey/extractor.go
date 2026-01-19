package apikey

import (
	"errors"
	"net/http"
	"strings"
)

// Common errors for API key extraction.
var (
	ErrNoAPIKeyFound       = errors.New("no API key found")
	ErrMissingAPIKeyHeader = errors.New("missing API key header")
	ErrMissingAPIKeyQuery  = errors.New("missing API key query parameter")
)

// Extractor defines the interface for extracting API keys from HTTP requests.
type Extractor interface {
	// Extract extracts an API key from the request.
	Extract(r *http.Request) (string, error)
}

// HeaderExtractor extracts API keys from HTTP headers.
type HeaderExtractor struct {
	header string
	prefix string
}

// NewHeaderExtractor creates a new header extractor.
// If header is empty, it defaults to "X-API-Key".
func NewHeaderExtractor(header, prefix string) *HeaderExtractor {
	if header == "" {
		header = "X-API-Key"
	}
	return &HeaderExtractor{
		header: header,
		prefix: prefix,
	}
}

// Extract extracts the API key from the header.
func (e *HeaderExtractor) Extract(r *http.Request) (string, error) {
	value := r.Header.Get(e.header)
	if value == "" {
		return "", ErrMissingAPIKeyHeader
	}

	// Remove prefix if specified
	if e.prefix != "" {
		if !strings.HasPrefix(value, e.prefix) {
			return "", ErrMissingAPIKeyHeader
		}
		value = strings.TrimPrefix(value, e.prefix)
	}

	return strings.TrimSpace(value), nil
}

// QueryExtractor extracts API keys from query parameters.
type QueryExtractor struct {
	param string
}

// NewQueryExtractor creates a new query parameter extractor.
// If param is empty, it defaults to "api_key".
func NewQueryExtractor(param string) *QueryExtractor {
	if param == "" {
		param = "api_key"
	}
	return &QueryExtractor{
		param: param,
	}
}

// Extract extracts the API key from the query parameter.
func (e *QueryExtractor) Extract(r *http.Request) (string, error) {
	key := r.URL.Query().Get(e.param)
	if key == "" {
		return "", ErrMissingAPIKeyQuery
	}
	return key, nil
}

// CompositeExtractor tries multiple extractors in order.
type CompositeExtractor struct {
	extractors []Extractor
}

// NewCompositeExtractor creates a new composite extractor.
func NewCompositeExtractor(extractors ...Extractor) *CompositeExtractor {
	return &CompositeExtractor{
		extractors: extractors,
	}
}

// Extract tries each extractor in order and returns the first successful result.
func (e *CompositeExtractor) Extract(r *http.Request) (string, error) {
	var lastErr error

	for _, extractor := range e.extractors {
		key, err := extractor.Extract(r)
		if err == nil && key != "" {
			return key, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", ErrNoAPIKeyFound
}

// Add adds an extractor to the composite.
func (e *CompositeExtractor) Add(extractor Extractor) {
	e.extractors = append(e.extractors, extractor)
}

// DefaultExtractor returns a default API key extractor that checks:
// 1. X-API-Key header
// 2. api_key query parameter
func DefaultExtractor() Extractor {
	return NewCompositeExtractor(
		NewHeaderExtractor("X-API-Key", ""),
		NewQueryExtractor("api_key"),
	)
}

// ExtractorFunc is a function type that implements Extractor.
type ExtractorFunc func(r *http.Request) (string, error)

// Extract implements Extractor.
func (f ExtractorFunc) Extract(r *http.Request) (string, error) {
	return f(r)
}

// AuthorizationHeaderExtractor extracts API keys from the Authorization header.
type AuthorizationHeaderExtractor struct {
	scheme string
}

// NewAuthorizationHeaderExtractor creates a new Authorization header extractor.
// If scheme is empty, it defaults to "ApiKey".
func NewAuthorizationHeaderExtractor(scheme string) *AuthorizationHeaderExtractor {
	if scheme == "" {
		scheme = "ApiKey"
	}
	return &AuthorizationHeaderExtractor{
		scheme: scheme,
	}
}

// Extract extracts the API key from the Authorization header.
func (e *AuthorizationHeaderExtractor) Extract(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", ErrMissingAPIKeyHeader
	}

	// Check scheme (case-insensitive)
	prefix := e.scheme + " "
	if len(auth) < len(prefix) {
		return "", ErrMissingAPIKeyHeader
	}

	if !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", ErrMissingAPIKeyHeader
	}

	return strings.TrimSpace(auth[len(prefix):]), nil
}

// CookieExtractor extracts API keys from cookies.
type CookieExtractor struct {
	cookie string
}

// NewCookieExtractor creates a new cookie extractor.
func NewCookieExtractor(cookie string) *CookieExtractor {
	return &CookieExtractor{
		cookie: cookie,
	}
}

// Extract extracts the API key from the cookie.
func (e *CookieExtractor) Extract(r *http.Request) (string, error) {
	cookie, err := r.Cookie(e.cookie)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", ErrNoAPIKeyFound
		}
		return "", err
	}

	if cookie.Value == "" {
		return "", ErrNoAPIKeyFound
	}

	return cookie.Value, nil
}
