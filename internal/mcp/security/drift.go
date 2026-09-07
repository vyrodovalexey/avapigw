package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// DriftStore detects tool-definition drift (HUB-402). It keeps a per-
// (upstream, name) canonical hash of each primitive definition and reports
// when a definition's hash changes. In require-re-approval mode a changed
// definition is excluded until its new hash is explicitly approved via
// Approve. The store is safe for concurrent use.
type DriftStore struct {
	requireReapproval bool

	mu       sync.Mutex
	hashes   map[string]string          // key -> last-seen hash
	approved map[string]map[string]bool // key -> approved hash set
}

// NewDriftStore constructs a DriftStore. When requireReapproval is true a
// changed definition is excluded from discovery until re-approved (HUB-402).
func NewDriftStore(requireReapproval bool) *DriftStore {
	return &DriftStore{
		requireReapproval: requireReapproval,
		hashes:            make(map[string]string),
		approved:          make(map[string]map[string]bool),
	}
}

// DriftResult reports the outcome of an Observe call.
type DriftResult struct {
	// Changed is true when the definition differs from the last-seen hash.
	Changed bool
	// Exclude is true when the definition must be excluded from discovery
	// pending re-approval (only in require-re-approval mode).
	Exclude bool
	// Hash is the canonical hash of the observed definition.
	Hash string
}

// Observe records a primitive definition and reports whether it drifted. The
// first observation of a (upstream, name) is not a change; a subsequent
// observation with a different canonical hash is a change. In require-re-
// approval mode a changed, unapproved definition is flagged for exclusion.
func (s *DriftStore) Observe(upstream, name string, definition json.RawMessage) DriftResult {
	hash := CanonicalHash(definition)
	key := upstream + "\x00" + name

	s.mu.Lock()
	defer s.mu.Unlock()

	prev, seen := s.hashes[key]
	s.hashes[key] = hash
	if !seen || prev == hash {
		return DriftResult{Changed: false, Exclude: false, Hash: hash}
	}
	exclude := s.requireReapproval && !s.approvedLocked(key, hash)
	return DriftResult{Changed: true, Exclude: exclude, Hash: hash}
}

// Approve marks a specific definition hash as approved so a drifted definition
// is re-admitted to discovery (HUB-402). This is the minimal in-memory
// re-approval mechanism keyed by hash.
func (s *DriftStore) Approve(upstream, name, hash string) {
	key := upstream + "\x00" + name
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.approved[key]
	if set == nil {
		set = make(map[string]bool)
		s.approved[key] = set
	}
	set[hash] = true
}

// approvedLocked reports whether a hash is approved for a key. Caller holds mu.
func (s *DriftStore) approvedLocked(key, hash string) bool {
	set := s.approved[key]
	return set != nil && set[hash]
}

// CanonicalHash returns a stable SHA-256 hash of a JSON definition that is
// independent of object key ordering and insignificant whitespace, so the same
// logical definition always hashes identically across replicas (HUB-402). A
// decode failure falls back to hashing the raw bytes.
func CanonicalHash(definition json.RawMessage) string {
	var v any
	if err := json.Unmarshal(definition, &v); err != nil {
		sum := sha256.Sum256(definition)
		return hex.EncodeToString(sum[:])
	}
	var sb strings.Builder
	canonicalize(&sb, v)
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// canonicalize writes a canonical string form of a decoded JSON value with
// object keys emitted in sorted order.
func canonicalize(sb *strings.Builder, v any) {
	switch t := v.(type) {
	case map[string]any:
		canonicalizeObject(sb, t)
	case []any:
		canonicalizeArray(sb, t)
	case string:
		sb.WriteByte('"')
		sb.WriteString(t)
		sb.WriteByte('"')
	case float64:
		sb.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	default:
		sb.WriteString("null")
	}
}

// canonicalizeObject writes an object with sorted keys.
func canonicalizeObject(sb *strings.Builder, obj map[string]any) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(k)
		sb.WriteString("\":")
		canonicalize(sb, obj[k])
	}
	sb.WriteByte('}')
}

// canonicalizeArray writes an array preserving element order.
func canonicalizeArray(sb *strings.Builder, arr []any) {
	sb.WriteByte('[')
	for i, e := range arr {
		if i > 0 {
			sb.WriteByte(',')
		}
		canonicalize(sb, e)
	}
	sb.WriteByte(']')
}
