// Package transform provides request and response transformation for the API Gateway.
package transform

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// RequestTransformer transforms HTTP requests.
type RequestTransformer struct {
	urlRewriter    *URLRewriter
	headerModifier *HeaderModifier
	queryModifier  *QueryModifier
}

// URLRewriter handles URL rewriting.
type URLRewriter struct {
	rules []*URLRewriteRule
}

// URLRewriteRule defines a URL rewrite rule.
type URLRewriteRule struct {
	Type               URLRewriteType
	Pattern            *regexp.Regexp
	Replacement        string
	ReplaceFullPath    string
	ReplacePrefixMatch string
	PrefixToMatch      string
}

// URLRewriteType defines the type of URL rewrite.
type URLRewriteType string

const (
	URLRewriteReplaceFullPath    URLRewriteType = "ReplaceFullPath"
	URLRewriteReplacePrefixMatch URLRewriteType = "ReplacePrefixMatch"
	URLRewriteRegex              URLRewriteType = "Regex"
)

// HeaderModifier modifies HTTP headers.
type HeaderModifier struct {
	set    map[string]string
	add    map[string]string
	remove []string
}

// QueryModifier modifies query parameters.
type QueryModifier struct {
	set    map[string]string
	add    map[string]string
	remove []string
}

// NewRequestTransformer creates a new request transformer.
func NewRequestTransformer() *RequestTransformer {
	return &RequestTransformer{
		urlRewriter:    &URLRewriter{rules: make([]*URLRewriteRule, 0)},
		headerModifier: &HeaderModifier{set: make(map[string]string), add: make(map[string]string)},
		queryModifier:  &QueryModifier{set: make(map[string]string), add: make(map[string]string)},
	}
}

// Transform applies all transformations to the request.
func (t *RequestTransformer) Transform(r *http.Request) error {
	// Apply URL rewriting
	if err := t.urlRewriter.Rewrite(r); err != nil {
		return err
	}

	// Apply header modifications
	t.headerModifier.Modify(r.Header)

	// Apply query modifications
	t.queryModifier.Modify(r.URL)

	return nil
}

// SetURLRewriteRules sets the URL rewrite rules.
func (t *RequestTransformer) SetURLRewriteRules(rules []*URLRewriteRule) {
	t.urlRewriter.rules = rules
}

// SetHeaderModifications sets header modifications.
func (t *RequestTransformer) SetHeaderModifications(set, add map[string]string, remove []string) {
	t.headerModifier.set = set
	t.headerModifier.add = add
	t.headerModifier.remove = remove
}

// SetQueryModifications sets query parameter modifications.
func (t *RequestTransformer) SetQueryModifications(set, add map[string]string, remove []string) {
	t.queryModifier.set = set
	t.queryModifier.add = add
	t.queryModifier.remove = remove
}

// Rewrite applies URL rewrite rules to the request.
func (u *URLRewriter) Rewrite(r *http.Request) error {
	for _, rule := range u.rules {
		switch rule.Type {
		case URLRewriteReplaceFullPath:
			r.URL.Path = rule.ReplaceFullPath
		case URLRewriteReplacePrefixMatch:
			if strings.HasPrefix(r.URL.Path, rule.PrefixToMatch) {
				r.URL.Path = rule.ReplacePrefixMatch + strings.TrimPrefix(r.URL.Path, rule.PrefixToMatch)
			}
		case URLRewriteRegex:
			if rule.Pattern != nil {
				r.URL.Path = rule.Pattern.ReplaceAllString(r.URL.Path, rule.Replacement)
			}
		}
	}
	return nil
}

// AddRule adds a URL rewrite rule.
func (u *URLRewriter) AddRule(rule *URLRewriteRule) {
	u.rules = append(u.rules, rule)
}

// ClearRules clears all URL rewrite rules.
func (u *URLRewriter) ClearRules() {
	u.rules = make([]*URLRewriteRule, 0)
}

// Modify applies header modifications.
func (h *HeaderModifier) Modify(header http.Header) {
	// Remove headers first
	for _, name := range h.remove {
		header.Del(name)
	}

	// Set headers (overwrites existing)
	for name, value := range h.set {
		header.Set(name, value)
	}

	// Add headers
	for name, value := range h.add {
		header.Add(name, value)
	}
}

// SetHeader sets a header to be set.
func (h *HeaderModifier) SetHeader(name, value string) {
	h.set[name] = value
}

// AddHeader adds a header to be added.
func (h *HeaderModifier) AddHeader(name, value string) {
	h.add[name] = value
}

// RemoveHeader adds a header to be removed.
func (h *HeaderModifier) RemoveHeader(name string) {
	h.remove = append(h.remove, name)
}

// Clear clears all header modifications.
func (h *HeaderModifier) Clear() {
	h.set = make(map[string]string)
	h.add = make(map[string]string)
	h.remove = nil
}

// Modify applies query parameter modifications.
func (q *QueryModifier) Modify(u *url.URL) {
	query := u.Query()

	// Remove parameters first
	for _, name := range q.remove {
		query.Del(name)
	}

	// Set parameters (overwrites existing)
	for name, value := range q.set {
		query.Set(name, value)
	}

	// Add parameters
	for name, value := range q.add {
		query.Add(name, value)
	}

	u.RawQuery = query.Encode()
}

// SetParam sets a query parameter to be set.
func (q *QueryModifier) SetParam(name, value string) {
	q.set[name] = value
}

// AddParam adds a query parameter to be added.
func (q *QueryModifier) AddParam(name, value string) {
	q.add[name] = value
}

// RemoveParam adds a query parameter to be removed.
func (q *QueryModifier) RemoveParam(name string) {
	q.remove = append(q.remove, name)
}

// Clear clears all query modifications.
func (q *QueryModifier) Clear() {
	q.set = make(map[string]string)
	q.add = make(map[string]string)
	q.remove = nil
}

// RewritePath rewrites the path using the specified type and values.
func RewritePath(path string, rewriteType URLRewriteType, fullPath, prefixMatch, prefixToMatch string) string {
	switch rewriteType {
	case URLRewriteReplaceFullPath:
		return fullPath
	case URLRewriteReplacePrefixMatch:
		if strings.HasPrefix(path, prefixToMatch) {
			return prefixMatch + strings.TrimPrefix(path, prefixToMatch)
		}
	}
	return path
}

// StripPrefix removes a prefix from the path.
func StripPrefix(path, prefix string) string {
	if strings.HasPrefix(path, prefix) {
		newPath := strings.TrimPrefix(path, prefix)
		if newPath == "" {
			return "/"
		}
		if !strings.HasPrefix(newPath, "/") {
			return "/" + newPath
		}
		return newPath
	}
	return path
}

// AddPrefix adds a prefix to the path.
func AddPrefix(path, prefix string) string {
	if prefix == "" {
		return path
	}
	if strings.HasSuffix(prefix, "/") && strings.HasPrefix(path, "/") {
		return prefix + path[1:]
	}
	if !strings.HasSuffix(prefix, "/") && !strings.HasPrefix(path, "/") {
		return prefix + "/" + path
	}
	return prefix + path
}
