package router

import (
	"regexp"
	"strings"
	"sync"

	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// StringMatcher is the interface for string matching.
type StringMatcher interface {
	Match(value string) bool
	Type() string
	Pattern() string
}

// ExactStringMatcher matches strings exactly.
type ExactStringMatcher struct {
	pattern string
}

// NewExactStringMatcher creates a new exact string matcher.
func NewExactStringMatcher(pattern string) *ExactStringMatcher {
	return &ExactStringMatcher{pattern: pattern}
}

// Match checks if the value matches exactly.
func (m *ExactStringMatcher) Match(value string) bool {
	return value == m.pattern
}

// Type returns the matcher type.
func (m *ExactStringMatcher) Type() string {
	return "exact"
}

// Pattern returns the pattern.
func (m *ExactStringMatcher) Pattern() string {
	return m.pattern
}

// PrefixStringMatcher matches strings by prefix.
type PrefixStringMatcher struct {
	prefix string
}

// NewPrefixStringMatcher creates a new prefix string matcher.
func NewPrefixStringMatcher(prefix string) *PrefixStringMatcher {
	return &PrefixStringMatcher{prefix: prefix}
}

// Match checks if the value starts with the prefix.
func (m *PrefixStringMatcher) Match(value string) bool {
	return strings.HasPrefix(value, m.prefix)
}

// Type returns the matcher type.
func (m *PrefixStringMatcher) Type() string {
	return "prefix"
}

// Pattern returns the pattern.
func (m *PrefixStringMatcher) Pattern() string {
	return m.prefix
}

// RegexStringMatcher matches strings using regular expressions.
type RegexStringMatcher struct {
	pattern string
	regex   *regexp.Regexp
}

// regexCache caches compiled regular expressions.
var (
	regexCache   = make(map[string]*regexp.Regexp)
	regexCacheMu sync.RWMutex
)

// NewRegexStringMatcher creates a new regex string matcher.
func NewRegexStringMatcher(pattern string) (*RegexStringMatcher, error) {
	regexCacheMu.RLock()
	regex, ok := regexCache[pattern]
	regexCacheMu.RUnlock()

	if !ok {
		var err error
		regex, err = regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}

		regexCacheMu.Lock()
		regexCache[pattern] = regex
		regexCacheMu.Unlock()
	}

	return &RegexStringMatcher{
		pattern: pattern,
		regex:   regex,
	}, nil
}

// Match checks if the value matches the regex.
func (m *RegexStringMatcher) Match(value string) bool {
	return m.regex.MatchString(value)
}

// Type returns the matcher type.
func (m *RegexStringMatcher) Type() string {
	return "regex"
}

// Pattern returns the pattern.
func (m *RegexStringMatcher) Pattern() string {
	return m.pattern
}

// WildcardStringMatcher matches all strings.
type WildcardStringMatcher struct{}

// NewWildcardStringMatcher creates a new wildcard string matcher.
func NewWildcardStringMatcher() *WildcardStringMatcher {
	return &WildcardStringMatcher{}
}

// Match always returns true.
func (m *WildcardStringMatcher) Match(_ string) bool {
	return true
}

// Type returns the matcher type.
func (m *WildcardStringMatcher) Type() string {
	return "wildcard"
}

// Pattern returns the pattern.
func (m *WildcardStringMatcher) Pattern() string {
	return "*"
}

// NewStringMatcher creates a StringMatcher from a StringMatch configuration.
func NewStringMatcher(match *config.StringMatch) (StringMatcher, error) {
	if match == nil {
		return NewWildcardStringMatcher(), nil
	}

	// Check for wildcard
	if match.Exact == "*" || match.Prefix == "*" {
		return NewWildcardStringMatcher(), nil
	}

	if match.Exact != "" {
		return NewExactStringMatcher(match.Exact), nil
	}

	if match.Prefix != "" {
		return NewPrefixStringMatcher(match.Prefix), nil
	}

	if match.Regex != "" {
		return NewRegexStringMatcher(match.Regex)
	}

	// Empty match means wildcard
	return NewWildcardStringMatcher(), nil
}

// MetadataMatcher is the interface for metadata matching.
type MetadataMatcher interface {
	Match(md metadata.MD) bool
	Name() string
}

// ExactMetadataMatcher matches metadata values exactly.
type ExactMetadataMatcher struct {
	name  string
	value string
}

// NewExactMetadataMatcher creates a new exact metadata matcher.
func NewExactMetadataMatcher(name, value string) *ExactMetadataMatcher {
	return &ExactMetadataMatcher{
		name:  strings.ToLower(name), // gRPC metadata keys are lowercase
		value: value,
	}
}

// Match checks if the metadata value matches exactly.
func (m *ExactMetadataMatcher) Match(md metadata.MD) bool {
	values := md.Get(m.name)
	for _, v := range values {
		if v == m.value {
			return true
		}
	}
	return false
}

// Name returns the metadata key name.
func (m *ExactMetadataMatcher) Name() string {
	return m.name
}

// PrefixMetadataMatcher matches metadata values by prefix.
type PrefixMetadataMatcher struct {
	name   string
	prefix string
}

// NewPrefixMetadataMatcher creates a new prefix metadata matcher.
func NewPrefixMetadataMatcher(name, prefix string) *PrefixMetadataMatcher {
	return &PrefixMetadataMatcher{
		name:   strings.ToLower(name),
		prefix: prefix,
	}
}

// Match checks if any metadata value starts with the prefix.
func (m *PrefixMetadataMatcher) Match(md metadata.MD) bool {
	values := md.Get(m.name)
	for _, v := range values {
		if strings.HasPrefix(v, m.prefix) {
			return true
		}
	}
	return false
}

// Name returns the metadata key name.
func (m *PrefixMetadataMatcher) Name() string {
	return m.name
}

// RegexMetadataMatcher matches metadata values using regular expressions.
type RegexMetadataMatcher struct {
	name  string
	regex *regexp.Regexp
}

// NewRegexMetadataMatcher creates a new regex metadata matcher.
func NewRegexMetadataMatcher(name, pattern string) (*RegexMetadataMatcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return &RegexMetadataMatcher{
		name:  strings.ToLower(name),
		regex: regex,
	}, nil
}

// Match checks if any metadata value matches the regex.
func (m *RegexMetadataMatcher) Match(md metadata.MD) bool {
	values := md.Get(m.name)
	for _, v := range values {
		if m.regex.MatchString(v) {
			return true
		}
	}
	return false
}

// Name returns the metadata key name.
func (m *RegexMetadataMatcher) Name() string {
	return m.name
}

// PresentMetadataMatcher matches if metadata key is present.
type PresentMetadataMatcher struct {
	name string
}

// NewPresentMetadataMatcher creates a new present metadata matcher.
func NewPresentMetadataMatcher(name string) *PresentMetadataMatcher {
	return &PresentMetadataMatcher{
		name: strings.ToLower(name),
	}
}

// Match checks if the metadata key is present.
func (m *PresentMetadataMatcher) Match(md metadata.MD) bool {
	values := md.Get(m.name)
	return len(values) > 0
}

// Name returns the metadata key name.
func (m *PresentMetadataMatcher) Name() string {
	return m.name
}

// AbsentMetadataMatcher matches if metadata key is absent.
type AbsentMetadataMatcher struct {
	name string
}

// NewAbsentMetadataMatcher creates a new absent metadata matcher.
func NewAbsentMetadataMatcher(name string) *AbsentMetadataMatcher {
	return &AbsentMetadataMatcher{
		name: strings.ToLower(name),
	}
}

// Match checks if the metadata key is absent.
func (m *AbsentMetadataMatcher) Match(md metadata.MD) bool {
	values := md.Get(m.name)
	return len(values) == 0
}

// Name returns the metadata key name.
func (m *AbsentMetadataMatcher) Name() string {
	return m.name
}

// NewMetadataMatcher creates a MetadataMatcher from a MetadataMatch configuration.
func NewMetadataMatcher(match config.MetadataMatch) (MetadataMatcher, error) {
	// Check for present/absent first
	if match.Present != nil && *match.Present {
		return NewPresentMetadataMatcher(match.Name), nil
	}

	if match.Absent != nil && *match.Absent {
		return NewAbsentMetadataMatcher(match.Name), nil
	}

	// Check for value matchers
	if match.Exact != "" {
		return NewExactMetadataMatcher(match.Name, match.Exact), nil
	}

	if match.Prefix != "" {
		return NewPrefixMetadataMatcher(match.Name, match.Prefix), nil
	}

	if match.Regex != "" {
		return NewRegexMetadataMatcher(match.Name, match.Regex)
	}

	// Default to present matcher if only name is specified
	return NewPresentMetadataMatcher(match.Name), nil
}

// ParseFullMethod parses a gRPC full method name into service and method.
// Full method format: /package.Service/Method
func ParseFullMethod(fullMethod string) (service, method string) {
	// Remove leading slash
	fullMethod = strings.TrimPrefix(fullMethod, "/")

	// Split by last slash
	idx := strings.LastIndex(fullMethod, "/")
	if idx < 0 {
		return fullMethod, ""
	}

	return fullMethod[:idx], fullMethod[idx+1:]
}
