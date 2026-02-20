// Package router provides HTTP routing functionality for the API Gateway.
package router

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// PathMatcher is the interface for path matching.
type PathMatcher interface {
	Match(path string) (bool, map[string]string)
	Type() string
	Pattern() string
}

// ExactMatcher matches exact paths.
type ExactMatcher struct {
	path string
}

// NewExactMatcher creates a new exact path matcher.
func NewExactMatcher(path string) *ExactMatcher {
	return &ExactMatcher{path: path}
}

// Match checks if the path matches exactly.
func (m *ExactMatcher) Match(path string) (matched bool, params map[string]string) {
	return path == m.path, nil
}

// Type returns the matcher type.
func (m *ExactMatcher) Type() string {
	return "exact"
}

// Pattern returns the pattern.
func (m *ExactMatcher) Pattern() string {
	return m.path
}

// PrefixMatcher matches path prefixes.
type PrefixMatcher struct {
	prefix string
}

// NewPrefixMatcher creates a new prefix path matcher.
func NewPrefixMatcher(prefix string) *PrefixMatcher {
	return &PrefixMatcher{prefix: prefix}
}

// Match checks if the path starts with the prefix.
func (m *PrefixMatcher) Match(path string) (matched bool, params map[string]string) {
	if strings.HasPrefix(path, m.prefix) {
		// Ensure we match at path boundaries
		if len(path) == len(m.prefix) {
			return true, nil
		}
		// Check if the next character is a slash or the prefix ends with a slash
		if strings.HasSuffix(m.prefix, "/") || path[len(m.prefix)] == '/' {
			return true, nil
		}
	}
	return false, nil
}

// Type returns the matcher type.
func (m *PrefixMatcher) Type() string {
	return "prefix"
}

// Pattern returns the pattern.
func (m *PrefixMatcher) Pattern() string {
	return m.prefix
}

// RegexMatcher matches paths using regular expressions.
type RegexMatcher struct {
	pattern string
	regex   *regexp.Regexp
}

// regexCacheMaxSize is the maximum number of entries in the regex cache.
const regexCacheMaxSize = 1000

// regexCacheEntry holds a compiled regex and its access order for LRU eviction.
type regexCacheEntry struct {
	regex       *regexp.Regexp
	accessOrder int64
}

// regexCache is a bounded LRU cache for compiled regular expressions.
var (
	regexCache         = make(map[string]*regexCacheEntry)
	regexCacheMu       sync.RWMutex
	regexAccessCounter int64
)

// NewRegexMatcher creates a new regex path matcher.
func NewRegexMatcher(pattern string) (*RegexMatcher, error) {
	metrics := getRegexCacheMetrics()

	regexCacheMu.Lock()
	entry, ok := regexCache[pattern]
	if ok {
		// Cache hit: update access order for LRU tracking
		regexAccessCounter++
		entry.accessOrder = regexAccessCounter
		regexCacheMu.Unlock()

		metrics.cacheHits.Inc()

		return &RegexMatcher{
			pattern: pattern,
			regex:   entry.regex,
		}, nil
	}
	regexCacheMu.Unlock()

	metrics.cacheMisses.Inc()

	// Compile the regex outside the lock (expensive operation)
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCacheMu.Lock()
	// Double-check after acquiring lock (another goroutine may have added it)
	if existingEntry, exists := regexCache[pattern]; exists {
		regexAccessCounter++
		existingEntry.accessOrder = regexAccessCounter
		regexCacheMu.Unlock()
		return &RegexMatcher{
			pattern: pattern,
			regex:   existingEntry.regex,
		}, nil
	}

	// Evict LRU entry if cache is at capacity
	if len(regexCache) >= regexCacheMaxSize {
		evictLRURegexEntry()
		metrics.cacheEvictions.Inc()
	}

	regexAccessCounter++
	regexCache[pattern] = &regexCacheEntry{
		regex:       regex,
		accessOrder: regexAccessCounter,
	}
	metrics.cacheSize.Set(float64(len(regexCache)))
	regexCacheMu.Unlock()

	return &RegexMatcher{
		pattern: pattern,
		regex:   regex,
	}, nil
}

// evictLRURegexEntry removes the least recently used entry from the cache.
// Must be called with regexCacheMu held.
func evictLRURegexEntry() {
	var lruKey string
	var lruOrder int64 = -1

	for key, entry := range regexCache {
		if lruOrder == -1 || entry.accessOrder < lruOrder {
			lruOrder = entry.accessOrder
			lruKey = key
		}
	}

	if lruKey != "" {
		delete(regexCache, lruKey)
	}
}

// Match checks if the path matches the regex.
func (m *RegexMatcher) Match(path string) (matched bool, params map[string]string) {
	matches := m.regex.FindStringSubmatch(path)
	if matches == nil {
		return false, nil
	}

	// Extract named groups
	params = make(map[string]string)
	for i, name := range m.regex.SubexpNames() {
		if i > 0 && name != "" && i < len(matches) {
			params[name] = matches[i]
		}
	}

	return true, params
}

// Type returns the matcher type.
func (m *RegexMatcher) Type() string {
	return "regex"
}

// Pattern returns the pattern.
func (m *RegexMatcher) Pattern() string {
	return m.pattern
}

// ParameterMatcher matches paths with parameters like /users/{id}.
type ParameterMatcher struct {
	pattern  string
	segments []segment
	regex    *regexp.Regexp
}

type segment struct {
	value     string
	isParam   bool
	paramName string
}

// NewParameterMatcher creates a new parameter path matcher.
func NewParameterMatcher(pattern string) (*ParameterMatcher, error) {
	segments := parsePathPattern(pattern)

	// Build regex from pattern
	var regexPattern strings.Builder
	regexPattern.WriteString("^")

	for _, seg := range segments {
		if seg.isParam {
			regexPattern.WriteString("/(?P<")
			regexPattern.WriteString(seg.paramName)
			regexPattern.WriteString(">[^/]+)")
		} else {
			regexPattern.WriteString("/")
			regexPattern.WriteString(regexp.QuoteMeta(seg.value))
		}
	}
	regexPattern.WriteString("$")

	regex, err := regexp.Compile(regexPattern.String())
	if err != nil {
		return nil, err
	}

	return &ParameterMatcher{
		pattern:  pattern,
		segments: segments,
		regex:    regex,
	}, nil
}

// parsePathPattern parses a path pattern into segments.
func parsePathPattern(pattern string) []segment {
	parts := strings.Split(strings.Trim(pattern, "/"), "/")
	segments := make([]segment, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			continue
		}

		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			paramName := part[1 : len(part)-1]
			segments = append(segments, segment{
				value:     part,
				isParam:   true,
				paramName: paramName,
			})
		} else {
			segments = append(segments, segment{
				value:   part,
				isParam: false,
			})
		}
	}

	return segments
}

// Match checks if the path matches the pattern and extracts parameters.
func (m *ParameterMatcher) Match(path string) (matched bool, params map[string]string) {
	matches := m.regex.FindStringSubmatch(path)
	if matches == nil {
		return false, nil
	}

	params = make(map[string]string)
	for i, name := range m.regex.SubexpNames() {
		if i > 0 && name != "" && i < len(matches) {
			params[name] = matches[i]
		}
	}

	return true, params
}

// Type returns the matcher type.
func (m *ParameterMatcher) Type() string {
	return "parameter"
}

// Pattern returns the pattern.
func (m *ParameterMatcher) Pattern() string {
	return m.pattern
}

// WildcardMatcher matches paths with wildcards (* and **).
type WildcardMatcher struct {
	pattern string
	regex   *regexp.Regexp
}

// NewWildcardMatcher creates a new wildcard path matcher.
func NewWildcardMatcher(pattern string) (*WildcardMatcher, error) {
	// Convert wildcard pattern to regex
	regexPattern := wildcardToRegex(pattern)

	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, err
	}

	return &WildcardMatcher{
		pattern: pattern,
		regex:   regex,
	}, nil
}

// wildcardToRegex converts a wildcard pattern to a regex pattern.
func wildcardToRegex(pattern string) string {
	var result strings.Builder
	result.WriteString("^")

	i := 0
	for i < len(pattern) {
		switch {
		case i+1 < len(pattern) && pattern[i:i+2] == "**":
			result.WriteString(".*")
			i += 2
		case pattern[i] == '*':
			result.WriteString("[^/]*")
			i++
		case pattern[i] == '?':
			result.WriteString("[^/]")
			i++
		default:
			result.WriteString(regexp.QuoteMeta(string(pattern[i])))
			i++
		}
	}

	result.WriteString("$")
	return result.String()
}

// Match checks if the path matches the wildcard pattern.
func (m *WildcardMatcher) Match(path string) (matched bool, params map[string]string) {
	return m.regex.MatchString(path), nil
}

// Type returns the matcher type.
func (m *WildcardMatcher) Type() string {
	return "wildcard"
}

// Pattern returns the pattern.
func (m *WildcardMatcher) Pattern() string {
	return m.pattern
}

// MethodMatcher matches HTTP methods.
type MethodMatcher struct {
	methods map[string]bool
}

// NewMethodMatcher creates a new method matcher.
func NewMethodMatcher(methods []string) *MethodMatcher {
	m := &MethodMatcher{
		methods: make(map[string]bool),
	}

	for _, method := range methods {
		m.methods[strings.ToUpper(method)] = true
	}

	return m
}

// Match checks if the method matches.
func (m *MethodMatcher) Match(method string) bool {
	method = strings.ToUpper(method)

	// Wildcard matches all methods
	if m.methods["*"] {
		return true
	}

	// HEAD automatically matches GET
	if method == "HEAD" && m.methods["GET"] {
		return true
	}

	return m.methods[method]
}

// HeaderMatcher matches HTTP headers.
type HeaderMatcher struct {
	config config.HeaderMatch
	regex  *regexp.Regexp
}

// NewHeaderMatcher creates a new header matcher.
func NewHeaderMatcher(cfg config.HeaderMatch) (*HeaderMatcher, error) {
	m := &HeaderMatcher{config: cfg}

	if cfg.Regex != "" {
		regex, err := regexp.Compile(cfg.Regex)
		if err != nil {
			return nil, err
		}
		m.regex = regex
	}

	return m, nil
}

// Match checks if the headers match.
func (m *HeaderMatcher) Match(headers http.Header) bool {
	// Header names are case-insensitive
	value := headers.Get(m.config.Name)
	hasHeader := value != ""

	// Check presence/absence
	if m.config.Present != nil {
		if *m.config.Present && !hasHeader {
			return false
		}
		if !*m.config.Present && hasHeader {
			return false
		}
		return true
	}

	if m.config.Absent != nil {
		if *m.config.Absent && hasHeader {
			return false
		}
		if !*m.config.Absent && !hasHeader {
			return false
		}
		return true
	}

	// If header is required but not present
	if !hasHeader {
		return false
	}

	// Check exact match
	if m.config.Exact != "" {
		return value == m.config.Exact
	}

	// Check prefix match
	if m.config.Prefix != "" {
		return strings.HasPrefix(value, m.config.Prefix)
	}

	// Check regex match
	if m.regex != nil {
		return m.regex.MatchString(value)
	}

	return true
}

// QueryParamMatcher matches query parameters.
type QueryParamMatcher struct {
	config config.QueryParamMatch
	regex  *regexp.Regexp
}

// NewQueryParamMatcher creates a new query parameter matcher.
func NewQueryParamMatcher(cfg config.QueryParamMatch) (*QueryParamMatcher, error) {
	m := &QueryParamMatcher{config: cfg}

	if cfg.Regex != "" {
		regex, err := regexp.Compile(cfg.Regex)
		if err != nil {
			return nil, err
		}
		m.regex = regex
	}

	return m, nil
}

// Match checks if the query parameters match.
func (m *QueryParamMatcher) Match(query url.Values) bool {
	value := query.Get(m.config.Name)
	hasParam := query.Has(m.config.Name)

	// Check presence
	if m.config.Present != nil {
		if *m.config.Present && !hasParam {
			return false
		}
		if !*m.config.Present && hasParam {
			return false
		}
		return true
	}

	// If param is required but not present
	if !hasParam {
		return false
	}

	// Check exact match
	if m.config.Exact != "" {
		return value == m.config.Exact
	}

	// Check regex match
	if m.regex != nil {
		return m.regex.MatchString(value)
	}

	return true
}

// CreatePathMatcher creates a path matcher from URI match configuration.
func CreatePathMatcher(uri *config.URIMatch) (PathMatcher, error) {
	if uri == nil {
		return nil, nil
	}

	if uri.Exact != "" {
		return NewExactMatcher(uri.Exact), nil
	}

	if uri.Prefix != "" {
		return NewPrefixMatcher(uri.Prefix), nil
	}

	if uri.Regex != "" {
		return NewRegexMatcher(uri.Regex)
	}

	return nil, nil
}

// HasPathParameters checks if a path contains parameters.
func HasPathParameters(path string) bool {
	return strings.Contains(path, "{") && strings.Contains(path, "}")
}

// HasWildcards checks if a path contains wildcards.
func HasWildcards(path string) bool {
	return strings.Contains(path, "*")
}
