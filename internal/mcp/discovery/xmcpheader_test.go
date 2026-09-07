package discovery

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func toolWithProps(props string) map[string]json.RawMessage {
	obj := map[string]json.RawMessage{
		"inputSchema": json.RawMessage(`{"type":"object","properties":` + props + `}`),
	}
	return obj
}

func TestValidateXMcpHeader(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		props     string
		wantEmpty bool
	}{
		{
			"valid string header",
			`{"region":{"type":"string","x-mcp-header":"X-Region"}}`,
			true,
		},
		{
			"valid integer header",
			`{"n":{"type":"integer","x-mcp-header":"X-Count"}}`,
			true,
		},
		{
			"valid boolean header",
			`{"b":{"type":"boolean","x-mcp-header":"X-Flag"}}`,
			true,
		},
		{
			"no annotation is valid",
			`{"region":{"type":"string"}}`,
			true,
		},
		{
			"empty header name rejected",
			`{"region":{"type":"string","x-mcp-header":""}}`,
			false,
		},
		{
			"CRLF rejected",
			`{"region":{"type":"string","x-mcp-header":"X-Bad\r\nInjected"}}`,
			false,
		},
		{
			"invalid token rejected",
			`{"region":{"type":"string","x-mcp-header":"X Region"}}`,
			false,
		},
		{
			"number type rejected",
			`{"n":{"type":"number","x-mcp-header":"X-N"}}`,
			false,
		},
		{
			"missing type rejected",
			`{"n":{"x-mcp-header":"X-N"}}`,
			false,
		},
		{
			"non-string header value rejected",
			`{"n":{"type":"string","x-mcp-header":123}}`,
			false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reason := validateXMcpHeader(toolWithProps(tc.props))
			if tc.wantEmpty {
				assert.Empty(t, reason)
			} else {
				assert.NotEmpty(t, reason)
			}
		})
	}
}

func TestValidateXMcpHeaderDuplicate(t *testing.T) {
	t.Parallel()
	// Two properties with case-insensitively identical headers.
	obj := toolWithProps(
		`{"a":{"type":"string","x-mcp-header":"X-Dup"},"b":{"type":"string","x-mcp-header":"x-dup"}}`,
	)
	reason := validateXMcpHeader(obj)
	assert.Contains(t, reason, "duplicates")
}

func TestValidateXMcpHeaderNoSchema(t *testing.T) {
	t.Parallel()
	assert.Empty(t, validateXMcpHeader(map[string]json.RawMessage{}))
	assert.Empty(t, validateXMcpHeader(map[string]json.RawMessage{"inputSchema": json.RawMessage(`{"type":"object"}`)}))
}

func TestIsHTTPToken(t *testing.T) {
	t.Parallel()
	assert.True(t, isHTTPToken("X-Region"))
	assert.True(t, isHTTPToken("abc123!#$%&'*+-.^_`|~"))
	assert.False(t, isHTTPToken("bad space"))
	assert.False(t, isHTTPToken("bad@sign"))
}
