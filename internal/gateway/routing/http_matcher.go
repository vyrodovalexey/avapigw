package routing

import (
	"regexp"
	"strings"
)

// PathMatcher defines the interface for path matching.
type PathMatcher interface {
	Match(path string) (bool, map[string]string)
	Type() string
}

// MethodMatcher defines the interface for method matching.
type MethodMatcher interface {
	Match(method string) bool
}

// HeaderMatcher defines the interface for header matching.
type HeaderMatcher interface {
	Name() string
	Match(value string) bool
}

// QueryMatcher defines the interface for query parameter matching.
type QueryMatcher interface {
	Name() string
	Match(value string) bool
}

// ExactPathMatcher matches paths exactly.
type ExactPathMatcher struct {
	path string
}

// NewExactPathMatcher creates a new exact path matcher.
func NewExactPathMatcher(path string) *ExactPathMatcher {
	return &ExactPathMatcher{path: path}
}

// Match checks if the path matches exactly.
// Returns whether the path matches and any captured parameters (always nil for exact matching).
func (m *ExactPathMatcher) Match(path string) (matched bool, params map[string]string) {
	return path == m.path, nil
}

// Type returns the matcher type.
func (m *ExactPathMatcher) Type() string {
	return "Exact"
}

// PrefixPathMatcher matches paths by prefix.
type PrefixPathMatcher struct {
	prefix string
}

// NewPrefixPathMatcher creates a new prefix path matcher.
func NewPrefixPathMatcher(prefix string) *PrefixPathMatcher {
	return &PrefixPathMatcher{prefix: prefix}
}

// Match checks if the path starts with the prefix.
// Returns whether the path matches and any captured parameters (always nil for prefix matching).
func (m *PrefixPathMatcher) Match(path string) (matched bool, params map[string]string) {
	if !strings.HasPrefix(path, m.prefix) {
		return false, nil
	}

	// Ensure prefix match is at a path boundary
	if len(path) > len(m.prefix) {
		nextChar := path[len(m.prefix)]
		if nextChar != '/' && m.prefix[len(m.prefix)-1] != '/' {
			return false, nil
		}
	}

	return true, nil
}

// Type returns the matcher type.
func (m *PrefixPathMatcher) Type() string {
	return "PathPrefix"
}

// RegexPathMatcher matches paths using regular expressions.
type RegexPathMatcher struct {
	regex        *regexp.Regexp
	pattern      string
	captureNames []string
}

// NewRegexPathMatcher creates a new regex path matcher.
func NewRegexPathMatcher(pattern string) (*RegexPathMatcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return &RegexPathMatcher{
		regex:        regex,
		pattern:      pattern,
		captureNames: regex.SubexpNames(),
	}, nil
}

// Match checks if the path matches the regex.
// Returns whether the path matches and any captured named groups from the regex.
func (m *RegexPathMatcher) Match(path string) (matched bool, params map[string]string) {
	matches := m.regex.FindStringSubmatch(path)
	if matches == nil {
		return false, nil
	}

	captures := make(map[string]string)
	for i, name := range m.captureNames {
		if name != "" && i < len(matches) {
			captures[name] = matches[i]
		}
	}

	return true, captures
}

// Type returns the matcher type.
func (m *RegexPathMatcher) Type() string {
	return "RegularExpression"
}

// SimpleMethodMatcher matches a single HTTP method.
type SimpleMethodMatcher struct {
	method string
}

// NewSimpleMethodMatcher creates a new simple method matcher.
func NewSimpleMethodMatcher(method string) *SimpleMethodMatcher {
	return &SimpleMethodMatcher{method: strings.ToUpper(method)}
}

// Match checks if the method matches.
func (m *SimpleMethodMatcher) Match(method string) bool {
	return strings.EqualFold(method, m.method)
}

// MultiMethodMatcher matches multiple HTTP methods.
type MultiMethodMatcher struct {
	methods map[string]bool
}

// NewMultiMethodMatcher creates a new multi-method matcher.
func NewMultiMethodMatcher(methods []string) *MultiMethodMatcher {
	m := &MultiMethodMatcher{
		methods: make(map[string]bool),
	}
	for _, method := range methods {
		m.methods[strings.ToUpper(method)] = true
	}
	return m
}

// Match checks if the method is in the allowed list.
func (m *MultiMethodMatcher) Match(method string) bool {
	return m.methods[strings.ToUpper(method)]
}

// ExactHeaderMatcher matches headers exactly.
type ExactHeaderMatcher struct {
	name  string
	value string
}

// NewExactHeaderMatcher creates a new exact header matcher.
func NewExactHeaderMatcher(name, value string) *ExactHeaderMatcher {
	return &ExactHeaderMatcher{
		name:  strings.ToLower(name),
		value: value,
	}
}

// Name returns the header name.
func (m *ExactHeaderMatcher) Name() string {
	return m.name
}

// Match checks if the header value matches exactly.
func (m *ExactHeaderMatcher) Match(value string) bool {
	return value == m.value
}

// RegexHeaderMatcher matches headers using regular expressions.
type RegexHeaderMatcher struct {
	name  string
	regex *regexp.Regexp
}

// NewRegexHeaderMatcher creates a new regex header matcher.
func NewRegexHeaderMatcher(name, pattern string) (*RegexHeaderMatcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return &RegexHeaderMatcher{
		name:  strings.ToLower(name),
		regex: regex,
	}, nil
}

// Name returns the header name.
func (m *RegexHeaderMatcher) Name() string {
	return m.name
}

// Match checks if the header value matches the regex.
func (m *RegexHeaderMatcher) Match(value string) bool {
	return m.regex.MatchString(value)
}

// PresentHeaderMatcher checks if a header is present.
type PresentHeaderMatcher struct {
	name string
}

// NewPresentHeaderMatcher creates a new present header matcher.
func NewPresentHeaderMatcher(name string) *PresentHeaderMatcher {
	return &PresentHeaderMatcher{name: strings.ToLower(name)}
}

// Name returns the header name.
func (m *PresentHeaderMatcher) Name() string {
	return m.name
}

// Match always returns true (header presence is checked before calling Match).
func (m *PresentHeaderMatcher) Match(value string) bool {
	return true
}

// ExactQueryMatcher matches query parameters exactly.
type ExactQueryMatcher struct {
	name  string
	value string
}

// NewExactQueryMatcher creates a new exact query matcher.
func NewExactQueryMatcher(name, value string) *ExactQueryMatcher {
	return &ExactQueryMatcher{
		name:  name,
		value: value,
	}
}

// Name returns the query parameter name.
func (m *ExactQueryMatcher) Name() string {
	return m.name
}

// Match checks if the query parameter value matches exactly.
func (m *ExactQueryMatcher) Match(value string) bool {
	return value == m.value
}

// RegexQueryMatcher matches query parameters using regular expressions.
type RegexQueryMatcher struct {
	name  string
	regex *regexp.Regexp
}

// NewRegexQueryMatcher creates a new regex query matcher.
func NewRegexQueryMatcher(name, pattern string) (*RegexQueryMatcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return &RegexQueryMatcher{
		name:  name,
		regex: regex,
	}, nil
}

// Name returns the query parameter name.
func (m *RegexQueryMatcher) Name() string {
	return m.name
}

// Match checks if the query parameter value matches the regex.
func (m *RegexQueryMatcher) Match(value string) bool {
	return m.regex.MatchString(value)
}

// PresentQueryMatcher checks if a query parameter is present.
type PresentQueryMatcher struct {
	name string
}

// NewPresentQueryMatcher creates a new present query matcher.
func NewPresentQueryMatcher(name string) *PresentQueryMatcher {
	return &PresentQueryMatcher{name: name}
}

// Name returns the query parameter name.
func (m *PresentQueryMatcher) Name() string {
	return m.name
}

// Match always returns true (parameter presence is checked before calling Match).
func (m *PresentQueryMatcher) Match(value string) bool {
	return true
}

// HostnameMatcher matches hostnames with wildcard support.
type HostnameMatcher struct {
	pattern string
	regex   *regexp.Regexp
}

// NewHostnameMatcher creates a new hostname matcher.
func NewHostnameMatcher(pattern string) *HostnameMatcher {
	m := &HostnameMatcher{pattern: pattern}

	if pattern != "" && pattern != "*" {
		// Convert wildcard pattern to regex
		escaped := regexp.QuoteMeta(pattern)
		escaped = strings.ReplaceAll(escaped, `\*`, `[^.]+`)
		regexPattern := "^" + escaped + "$"
		if regex, err := regexp.Compile(regexPattern); err == nil {
			m.regex = regex
		}
	}

	return m
}

// Match checks if the hostname matches the pattern.
func (m *HostnameMatcher) Match(hostname string) bool {
	if m.pattern == "" || m.pattern == "*" {
		return true
	}

	if m.regex != nil {
		return m.regex.MatchString(hostname)
	}

	return hostname == m.pattern
}
