package namespace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultMapper(t *testing.T) {
	t.Parallel()

	t.Run("empty uses default separator", func(t *testing.T) {
		t.Parallel()
		m, err := NewDefaultMapper("")
		require.NoError(t, err)
		assert.Equal(t, DefaultSeparator, m.separator)
	})

	t.Run("custom allowed separator", func(t *testing.T) {
		t.Parallel()
		m, err := NewDefaultMapper("__")
		require.NoError(t, err)
		assert.Equal(t, "__", m.separator)
	})

	t.Run("disallowed separator rejected", func(t *testing.T) {
		t.Parallel()
		for _, sep := range []string{"/", " ", ":", "!"} {
			_, err := NewDefaultMapper(sep)
			require.ErrorIs(t, err, ErrInvalidSeparator)
		}
	})
}

func TestRegister(t *testing.T) {
	t.Parallel()

	m, err := NewDefaultMapper(".")
	require.NoError(t, err)

	require.NoError(t, m.Register("up1", "prefix1"))

	err = m.Register("up2", "")
	require.ErrorIs(t, err, ErrEmptyPrefix)
}

func TestNamespaceBasic(t *testing.T) {
	t.Parallel()

	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	require.NoError(t, m.Register("up1", "svc"))

	ns, err := m.Namespace("up1", "search")
	require.NoError(t, err)
	assert.Equal(t, "svc.search", ns)

	// Round-trip via reverse map.
	id, name, ok := m.Denamespace("svc.search")
	assert.True(t, ok)
	assert.Equal(t, "up1", id)
	assert.Equal(t, "search", name)
}

func TestNamespaceUnknownUpstream(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	_, err = m.Namespace("nope", "x")
	require.ErrorIs(t, err, ErrEmptyPrefix)
}

// UT-NS-01: names >128 are deterministically truncated+hashed and stable
// across repeated calls (and, by construction, across replicas/restarts).
func TestNamespaceTruncationStable(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	require.NoError(t, m.Register("up1", "prefix"))

	longName := strings.Repeat("a", 200)

	first, err := m.Namespace("up1", longName)
	require.NoError(t, err)
	second, err := m.Namespace("up1", longName)
	require.NoError(t, err)

	assert.Equal(t, first, second, "shortening must be deterministic")
	assert.LessOrEqual(t, len(first), MaxNameLen)
	assert.Contains(t, first, "-", "short hash suffix appended")

	// A second, independent mapper produces the same output (stable across
	// replicas because it depends only on inputs).
	m2, err := NewDefaultMapper(".")
	require.NoError(t, err)
	require.NoError(t, m2.Register("up1", "prefix"))
	third, err := m2.Namespace("up1", longName)
	require.NoError(t, err)
	assert.Equal(t, first, third)

	// Round-trip via authoritative reverse map for shortened names.
	id, name, ok := m.Denamespace(first)
	assert.True(t, ok)
	assert.Equal(t, "up1", id)
	assert.Equal(t, longName, name)
}

func TestNamespaceExactBoundary(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	require.NoError(t, m.Register("up1", "p"))

	// prefix(1) + sep(1) + name = exactly MaxNameLen -> no shortening.
	name := strings.Repeat("b", MaxNameLen-2)
	ns, err := m.Namespace("up1", name)
	require.NoError(t, err)
	assert.Len(t, ns, MaxNameLen)
	assert.Equal(t, "p."+name, ns)
}

func TestDenamespaceStructuralFallback(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	require.NoError(t, m.Register("up1", "svc"))

	// Not in reverse map, but structurally splittable by registered prefix.
	id, name, ok := m.Denamespace("svc.neverNamespaced")
	assert.True(t, ok)
	assert.Equal(t, "up1", id)
	assert.Equal(t, "neverNamespaced", name)
}

func TestDenamespaceUnknown(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	require.NoError(t, m.Register("up1", "svc"))

	id, name, ok := m.Denamespace("otherprefix.tool")
	assert.False(t, ok)
	assert.Empty(t, id)
	assert.Empty(t, name)
}

func TestIsAllowedToken(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"":           false,
		"abcDEF":     true,
		"a-b_c.d":    true,
		"0123456789": true,
		"has space":  false,
		"has/slash":  false,
		"has:colon":  false,
		"unicodé":    false,
	}
	for in, want := range cases {
		in, want := in, want
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, isAllowedToken(in))
		})
	}
}

// UT-NS-02: result URI rewrite covers uri, resource_link, embedded resources
// and structuredContent URIs.
func TestRewriteResultURIs(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	require.NoError(t, m.Register("up1", "svc"))

	result := json.RawMessage(`{
		"content": [
			{"type":"resource_link","resource_link":"file://a"},
			{"type":"resource","resource":{"uri":"file://b","text":"x"}}
		],
		"structuredContent": {"items":[{"uri":"file://c"}]},
		"other": "leave-me"
	}`)

	out, err := m.RewriteResultURIs("up1", result)
	require.NoError(t, err)

	var obj map[string]any
	require.NoError(t, json.Unmarshal(out, &obj))

	content := obj["content"].([]any)
	link := content[0].(map[string]any)
	assert.Equal(t, "svc.file://a", link["resource_link"])
	embedded := content[1].(map[string]any)["resource"].(map[string]any)
	assert.Equal(t, "svc.file://b", embedded["uri"])
	assert.Equal(t, "x", embedded["text"])
	sc := obj["structuredContent"].(map[string]any)
	item := sc["items"].([]any)[0].(map[string]any)
	assert.Equal(t, "svc.file://c", item["uri"])
	// Non-URI field untouched.
	assert.Equal(t, "leave-me", obj["other"])
}

func TestRewriteResultURIsEmpty(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)

	out, err := m.RewriteResultURIs("up1", nil)
	require.NoError(t, err)
	assert.Nil(t, out)

	out, err = m.RewriteResultURIs("up1", json.RawMessage{})
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestRewriteResultURIsNonStringURI(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	require.NoError(t, m.Register("up1", "svc"))

	// uri key whose value is not a string: left unchanged, recursed into.
	result := json.RawMessage(`{"uri":{"nested":"file://x"},"arr":[1,"s",true,null]}`)
	out, err := m.RewriteResultURIs("up1", result)
	require.NoError(t, err)

	var obj map[string]any
	require.NoError(t, json.Unmarshal(out, &obj))
	// Object-valued "uri" untouched at this level (not a string).
	nested := obj["uri"].(map[string]any)
	assert.Equal(t, "file://x", nested["nested"])
}

func TestRewriteResultURIsInvalidJSON(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)

	_, err = m.RewriteResultURIs("up1", json.RawMessage(`{bad`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode result")
}

func TestRewriteResultURIsUnknownUpstream(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	// Upstream not registered => Namespace errors when a URI is encountered.
	_, err = m.RewriteResultURIs("ghost", json.RawMessage(`{"uri":"file://a"}`))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyPrefix)
}

func TestRewriteResultURIsErrorInNestedArray(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	// URI nested inside an array element with an unregistered upstream: the
	// Namespace error must propagate up through walkArray/walkObject.
	_, err = m.RewriteResultURIs("ghost", json.RawMessage(`{"list":[{"uri":"file://a"}]}`))
	require.ErrorIs(t, err, ErrEmptyPrefix)
}

func TestRewriteResultURIsErrorInNestedObject(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	// URI nested inside a non-URI object key with an unregistered upstream:
	// error must propagate through walkObject's recursion.
	_, err = m.RewriteResultURIs("ghost", json.RawMessage(`{"wrapper":{"uri":"file://a"}}`))
	require.ErrorIs(t, err, ErrEmptyPrefix)
}

func TestRewriteResultURIsScalar(t *testing.T) {
	t.Parallel()
	m, err := NewDefaultMapper(".")
	require.NoError(t, err)
	// A top-level scalar (not object/array) is returned unchanged.
	out, err := m.RewriteResultURIs("up1", json.RawMessage(`"just-a-string"`))
	require.NoError(t, err)
	assert.JSONEq(t, `"just-a-string"`, string(out))
}
