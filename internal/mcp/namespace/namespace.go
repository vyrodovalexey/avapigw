// Package namespace implements the hub's primitive-namespacing scheme
// (HUB-162/163/168): it maps upstream primitive names into hub-visible
// namespaced names of the form <prefix><sep><original>, enforces the
// recommended alphabet and the ≤128-character limit with a deterministic,
// stable truncation-plus-hash shortening, and rewrites resource URIs in
// results.
package namespace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// MaxNameLen is the maximum length of a produced namespaced name (HUB-162).
const MaxNameLen = 128

// shortHashLen is the number of hex characters of the sha256 digest appended
// during deterministic shortening.
const shortHashLen = 8

// DefaultSeparator is the default namespacing separator (subset of the
// recommended alphabet A-Za-z0-9_.-).
const DefaultSeparator = "."

// ErrEmptyPrefix indicates a mapper was configured without a prefix.
var ErrEmptyPrefix = errors.New("namespace: upstream prefix is empty")

// ErrInvalidSeparator indicates the separator contains characters outside the
// recommended alphabet.
var ErrInvalidSeparator = errors.New("namespace: separator contains disallowed characters")

// Mapper maps primitive names and resource URIs between the upstream and
// hub-visible (namespaced) representations.
type Mapper interface {
	// Namespace returns the hub-visible name for an upstream primitive.
	Namespace(upstreamID, name string) (string, error)
	// Denamespace resolves a hub-visible name back to its upstream id and
	// original name. ok is false when the name is not a known namespaced
	// name.
	Denamespace(nsName string) (upstreamID, name string, ok bool)
	// RewriteResultURIs re-namespaces resource URIs carried in a result
	// (resource_link, embedded resources, structuredContent URIs).
	RewriteResultURIs(upstreamID string, result json.RawMessage) (json.RawMessage, error)
}

// mapping records the reverse lookup for a produced namespaced name.
type mapping struct {
	upstreamID string
	original   string
}

// DefaultMapper is the default Mapper implementation. It is safe for
// concurrent use.
type DefaultMapper struct {
	separator string

	mu sync.RWMutex
	// prefixes maps upstreamID -> namespace prefix.
	prefixes map[string]string
	// reverse maps a produced namespaced name -> its origin.
	reverse map[string]mapping
}

// NewDefaultMapper constructs a DefaultMapper with the given separator (empty
// uses DefaultSeparator). The separator MUST be a subset of A-Za-z0-9_.-.
func NewDefaultMapper(separator string) (*DefaultMapper, error) {
	if separator == "" {
		separator = DefaultSeparator
	}
	if !isAllowedToken(separator) {
		return nil, ErrInvalidSeparator
	}
	return &DefaultMapper{
		separator: separator,
		prefixes:  make(map[string]string),
		reverse:   make(map[string]mapping),
	}, nil
}

// Register associates an upstream id with its namespace prefix. It must be
// called before Namespace/Denamespace for that upstream.
func (m *DefaultMapper) Register(upstreamID, prefix string) error {
	if prefix == "" {
		return ErrEmptyPrefix
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prefixes[upstreamID] = prefix
	return nil
}

// Namespace returns the hub-visible name for an upstream primitive. The
// produced name is <prefix><sep><original>, deterministically shortened when
// it would exceed MaxNameLen. The reverse mapping is recorded so Denamespace
// can resolve it. The transformation is stable across restarts and replicas
// because it depends only on the inputs (HUB-162).
func (m *DefaultMapper) Namespace(upstreamID, name string) (string, error) {
	m.mu.RLock()
	prefix := m.prefixes[upstreamID]
	m.mu.RUnlock()
	if prefix == "" {
		return "", fmt.Errorf("namespace: unknown upstream %q: %w", upstreamID, ErrEmptyPrefix)
	}

	full := prefix + m.separator + name
	if len(full) > MaxNameLen {
		full = shorten(full)
	}

	m.mu.Lock()
	m.reverse[full] = mapping{upstreamID: upstreamID, original: name}
	m.mu.Unlock()
	return full, nil
}

// Denamespace resolves a hub-visible name back to its upstream id and original
// name. It first consults the recorded reverse map (authoritative, and the
// only reliable path for shortened names), then falls back to a structural
// split on the separator for names produced without shortening.
func (m *DefaultMapper) Denamespace(nsName string) (upstreamID, name string, ok bool) {
	m.mu.RLock()
	rec, found := m.reverse[nsName]
	m.mu.RUnlock()
	if found {
		return rec.upstreamID, rec.original, true
	}
	return m.structuralDenamespace(nsName)
}

// structuralDenamespace attempts to split nsName as <prefix><sep><original>
// against the registered prefixes.
func (m *DefaultMapper) structuralDenamespace(nsName string) (upstreamID, name string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, prefix := range m.prefixes {
		want := prefix + m.separator
		if strings.HasPrefix(nsName, want) {
			return id, strings.TrimPrefix(nsName, want), true
		}
	}
	return "", "", false
}

// shorten deterministically shortens a name to MaxNameLen by truncating and
// appending a separator-free short sha256 hash of the full name, so the
// result is stable and collision-resistant across restarts/replicas.
func shorten(full string) string {
	sum := sha256.Sum256([]byte(full))
	suffix := "-" + hex.EncodeToString(sum[:])[:shortHashLen]
	keep := MaxNameLen - len(suffix)
	if keep < 0 {
		keep = 0
	}
	return full[:keep] + suffix
}

// isAllowedToken reports whether s consists solely of the recommended
// tool-name alphabet A-Za-z0-9_.- and is non-empty.
func isAllowedToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

// uriBearingKeys are the JSON keys known to carry resource URIs that the hub
// re-namespaces in results (HUB-163).
var uriBearingKeys = map[string]bool{
	"uri":           true,
	"resource_link": true,
}

// RewriteResultURIs walks the result JSON and re-namespaces resource URIs
// under known URI-bearing keys ("uri", "resource_link"), including within
// resource_link objects, embedded resources and structuredContent. It is a
// best-effort walk: values it cannot interpret are left unchanged.
func (m *DefaultMapper) RewriteResultURIs(upstreamID string, result json.RawMessage) (json.RawMessage, error) {
	if len(result) == 0 {
		return result, nil
	}
	var decoded any
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, fmt.Errorf("namespace: decode result: %w", err)
	}
	rewritten, err := m.walk(upstreamID, decoded)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(rewritten)
	if err != nil {
		return nil, fmt.Errorf("namespace: encode result: %w", err)
	}
	return out, nil
}

// walk recursively rewrites URI-bearing string values in a decoded JSON tree.
func (m *DefaultMapper) walk(upstreamID string, node any) (any, error) {
	switch v := node.(type) {
	case map[string]any:
		return m.walkObject(upstreamID, v)
	case []any:
		return m.walkArray(upstreamID, v)
	default:
		return node, nil
	}
}

// walkObject rewrites URI-bearing keys within an object and recurses.
func (m *DefaultMapper) walkObject(upstreamID string, obj map[string]any) (any, error) {
	for key, val := range obj {
		if uriBearingKeys[key] {
			if s, ok := val.(string); ok {
				ns, err := m.Namespace(upstreamID, s)
				if err != nil {
					return nil, err
				}
				obj[key] = ns
				continue
			}
		}
		child, err := m.walk(upstreamID, val)
		if err != nil {
			return nil, err
		}
		obj[key] = child
	}
	return obj, nil
}

// walkArray recurses over array elements.
func (m *DefaultMapper) walkArray(upstreamID string, arr []any) (any, error) {
	for i, val := range arr {
		child, err := m.walk(upstreamID, val)
		if err != nil {
			return nil, err
		}
		arr[i] = child
	}
	return arr, nil
}
