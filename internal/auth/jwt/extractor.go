package jwt

import (
	"errors"
	"net/http"
	"strings"
)

// Common errors for token extraction.
var (
	ErrNoTokenFound      = errors.New("no token found")
	ErrInvalidToken      = errors.New("invalid token format")
	ErrMissingHeader     = errors.New("missing authorization header")
	ErrInvalidPrefix     = errors.New("invalid authorization prefix")
	ErrMissingCookie     = errors.New("missing cookie")
	ErrMissingQueryParam = errors.New("missing query parameter")
)

// TokenExtractor defines the interface for extracting tokens from HTTP requests.
type TokenExtractor interface {
	// Extract extracts a token from the request.
	Extract(r *http.Request) (string, error)
}

// HeaderExtractor extracts tokens from HTTP headers.
type HeaderExtractor struct {
	header string
	prefix string
}

// NewHeaderExtractor creates a new header extractor.
// If header is empty, it defaults to "Authorization".
// If prefix is empty, it defaults to "Bearer ".
func NewHeaderExtractor(header, prefix string) *HeaderExtractor {
	if header == "" {
		header = "Authorization"
	}
	if prefix == "" {
		prefix = "Bearer "
	}
	return &HeaderExtractor{
		header: header,
		prefix: prefix,
	}
}

// Extract extracts the token from the header.
func (e *HeaderExtractor) Extract(r *http.Request) (string, error) {
	authHeader := r.Header.Get(e.header)
	if authHeader == "" {
		return "", ErrMissingHeader
	}

	// Check prefix (case-insensitive)
	if e.prefix != "" {
		if len(authHeader) < len(e.prefix) {
			return "", ErrInvalidPrefix
		}
		if !strings.EqualFold(authHeader[:len(e.prefix)], e.prefix) {
			return "", ErrInvalidPrefix
		}
		return strings.TrimSpace(authHeader[len(e.prefix):]), nil
	}

	return strings.TrimSpace(authHeader), nil
}

// CookieExtractor extracts tokens from cookies.
type CookieExtractor struct {
	cookie string
}

// NewCookieExtractor creates a new cookie extractor.
func NewCookieExtractor(cookie string) *CookieExtractor {
	return &CookieExtractor{
		cookie: cookie,
	}
}

// Extract extracts the token from the cookie.
func (e *CookieExtractor) Extract(r *http.Request) (string, error) {
	cookie, err := r.Cookie(e.cookie)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", ErrMissingCookie
		}
		return "", err
	}

	if cookie.Value == "" {
		return "", ErrMissingCookie
	}

	return cookie.Value, nil
}

// QueryExtractor extracts tokens from query parameters.
type QueryExtractor struct {
	param string
}

// NewQueryExtractor creates a new query parameter extractor.
func NewQueryExtractor(param string) *QueryExtractor {
	return &QueryExtractor{
		param: param,
	}
}

// Extract extracts the token from the query parameter.
func (e *QueryExtractor) Extract(r *http.Request) (string, error) {
	token := r.URL.Query().Get(e.param)
	if token == "" {
		return "", ErrMissingQueryParam
	}
	return token, nil
}

// CompositeExtractor tries multiple extractors in order.
type CompositeExtractor struct {
	extractors []TokenExtractor
}

// NewCompositeExtractor creates a new composite extractor.
func NewCompositeExtractor(extractors ...TokenExtractor) *CompositeExtractor {
	return &CompositeExtractor{
		extractors: extractors,
	}
}

// Extract tries each extractor in order and returns the first successful result.
func (e *CompositeExtractor) Extract(r *http.Request) (string, error) {
	var lastErr error

	for _, extractor := range e.extractors {
		token, err := extractor.Extract(r)
		if err == nil && token != "" {
			return token, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", ErrNoTokenFound
}

// Add adds an extractor to the composite.
func (e *CompositeExtractor) Add(extractor TokenExtractor) {
	e.extractors = append(e.extractors, extractor)
}

// DefaultExtractor returns a default token extractor that checks:
// 1. Authorization header with Bearer prefix
// 2. access_token query parameter
func DefaultExtractor() TokenExtractor {
	return NewCompositeExtractor(
		NewHeaderExtractor("Authorization", "Bearer "),
		NewQueryExtractor("access_token"),
	)
}

// ExtractorFunc is a function type that implements TokenExtractor.
type ExtractorFunc func(r *http.Request) (string, error)

// Extract implements TokenExtractor.
func (f ExtractorFunc) Extract(r *http.Request) (string, error) {
	return f(r)
}

// MetadataExtractor extracts tokens from gRPC metadata.
// This is useful for gRPC-Gateway or similar scenarios.
type MetadataExtractor struct {
	key    string
	prefix string
}

// NewMetadataExtractor creates a new metadata extractor.
func NewMetadataExtractor(key, prefix string) *MetadataExtractor {
	if key == "" {
		key = "authorization"
	}
	return &MetadataExtractor{
		key:    key,
		prefix: prefix,
	}
}

// Extract extracts the token from the request metadata (stored in headers).
func (e *MetadataExtractor) Extract(r *http.Request) (string, error) {
	// gRPC metadata is typically passed as headers
	value := r.Header.Get(e.key)
	if value == "" {
		// Try lowercase
		value = r.Header.Get(strings.ToLower(e.key))
	}

	if value == "" {
		return "", ErrMissingHeader
	}

	if e.prefix != "" {
		if !strings.HasPrefix(strings.ToLower(value), strings.ToLower(e.prefix)) {
			return "", ErrInvalidPrefix
		}
		return strings.TrimSpace(value[len(e.prefix):]), nil
	}

	return strings.TrimSpace(value), nil
}

// FormExtractor extracts tokens from form data.
type FormExtractor struct {
	field string
}

// NewFormExtractor creates a new form extractor.
func NewFormExtractor(field string) *FormExtractor {
	return &FormExtractor{
		field: field,
	}
}

// Extract extracts the token from form data.
func (e *FormExtractor) Extract(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", err
	}

	token := r.FormValue(e.field)
	if token == "" {
		return "", ErrNoTokenFound
	}

	return token, nil
}
