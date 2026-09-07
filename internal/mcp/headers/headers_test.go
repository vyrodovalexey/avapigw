package headers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

func sentinel(s string) string {
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(s)) + sentinelSuffix
}

func newReq(headers map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "/mcp", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestHeaderErrorError(t *testing.T) {
	t.Parallel()
	e := &HeaderError{Code: protocol.HeaderMismatch, Message: "boom"}
	assert.Equal(t, "mcp header error -32020: boom", e.Error())
}

// UT-HDR-02 (part): Base64 sentinel decode.
func TestDecodeSentinel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		input        string
		wantDecoded  string
		wantSentinel bool
		wantErr      bool
	}{
		{"plain value", "hello", "hello", false, false},
		{"valid sentinel", sentinel("weird value=?"), "weird value=?", true, false},
		{"empty sentinel body", sentinelPrefix + "" + sentinelSuffix, "", true, false},
		{"prefix only not suffix", "=?base64?abc", "=?base64?abc", false, false},
		{"suffix only not prefix", "abc?=", "abc?=", false, false},
		{"invalid base64 body", sentinelPrefix + "!!!" + sentinelSuffix, "", true, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			decoded, isSentinel, err := DecodeSentinel(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.True(t, isSentinel)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantDecoded, decoded)
			assert.Equal(t, tc.wantSentinel, isSentinel)
		})
	}
}

// UT-HDR-04: version gate before header policy.
func TestVersionGate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		version string
		want    bool
	}{
		{"missing version", "", false},
		{"supported version", protocol.LatestVersion, true},
		{"unsupported interop version", "2025-11-25", false},
		{"garbage version", "not-a-version", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := map[string]string{}
			if tc.version != "" {
				h[HeaderMcpProtocolVersion] = tc.version
			}
			assert.Equal(t, tc.want, VersionGate(newReq(h)))
		})
	}
}

// UT-HDR-01: require Mcp-Method; Mcp-Name on call/read/get.
func TestValidateHeadersMethodAndName(t *testing.T) {
	t.Parallel()

	t.Run("missing method header", func(t *testing.T) {
		t.Parallel()
		err := ValidateHeaders(newReq(nil), "tools/list", "", nil)
		var he *HeaderError
		require.ErrorAs(t, err, &he)
		assert.Equal(t, protocol.HeaderMismatch, he.Code)
		assert.Contains(t, he.Message, "Mcp-Method header is required")
	})

	t.Run("method mismatch", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{HeaderMcpMethod: "tools/call"})
		err := ValidateHeaders(r, "tools/list", "", nil)
		var he *HeaderError
		require.ErrorAs(t, err, &he)
		assert.Contains(t, he.Message, "does not match body method")
	})

	t.Run("name required for tools/call", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{HeaderMcpMethod: "tools/call"})
		err := ValidateHeaders(r, "tools/call", "search", nil)
		var he *HeaderError
		require.ErrorAs(t, err, &he)
		assert.Contains(t, he.Message, "Mcp-Name header is required")
	})

	t.Run("name not required for tools/list", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{HeaderMcpMethod: "tools/list"})
		require.NoError(t, ValidateHeaders(r, "tools/list", "", nil))
	})

	t.Run("name matches for resources/read", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod: "resources/read",
			HeaderMcpName:   "file://x",
		})
		require.NoError(t, ValidateHeaders(r, "resources/read", "file://x", nil))
	})

	t.Run("name via base64 sentinel for prompts/get", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod: "prompts/get",
			HeaderMcpName:   sentinel("greeting prompt"),
		})
		require.NoError(t, ValidateHeaders(r, "prompts/get", "greeting prompt", nil))
	})

	t.Run("name decode error", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod: "tools/call",
			HeaderMcpName:   sentinelPrefix + "!!!" + sentinelSuffix,
		})
		err := ValidateHeaders(r, "tools/call", "x", nil)
		var he *HeaderError
		require.ErrorAs(t, err, &he)
		assert.Contains(t, he.Message, "decode failed")
	})

	t.Run("name mismatch", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod: "tools/call",
			HeaderMcpName:   "wrong",
		})
		err := ValidateHeaders(r, "tools/call", "right", nil)
		var he *HeaderError
		require.ErrorAs(t, err, &he)
		assert.Contains(t, he.Message, "does not match body name")
	})
}

// UT-HDR-02 (part): numeric comparison for integer params.
func TestValidateParamHeaders(t *testing.T) {
	t.Parallel()

	t.Run("string param match", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:            "tools/call",
			HeaderMcpName:              "n",
			ParamHeaderPrefix + "City": "London",
		})
		params := map[string]any{"City": "London"}
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})

	t.Run("camelCase param matched case-insensitively", func(t *testing.T) {
		t.Parallel()
		// Go canonicalizes Mcp-Param-userId to Mcp-Param-Userid; the body key
		// is camelCase userId. Matching MUST be case-insensitive (HUB-142).
		r := newReq(map[string]string{
			HeaderMcpMethod:              "tools/call",
			HeaderMcpName:                "n",
			ParamHeaderPrefix + "userId": "42",
		})
		params := map[string]any{"userId": 42}
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})

	t.Run("case-insensitive numeric mismatch still caught", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:              "tools/call",
			HeaderMcpName:                "n",
			ParamHeaderPrefix + "userId": "43",
		})
		params := map[string]any{"userId": 42}
		err := ValidateHeaders(r, "tools/call", "n", params)
		var he *HeaderError
		require.ErrorAs(t, err, &he)
		assert.Equal(t, protocol.HeaderMismatch, he.Code)
	})

	t.Run("sentinel-encoded param decoded before compare", func(t *testing.T) {
		t.Parallel()
		// "=?base64?<b64(hello world)>?=" must decode and match the body.
		r := newReq(map[string]string{
			HeaderMcpMethod:              "tools/call",
			HeaderMcpName:                "n",
			ParamHeaderPrefix + "phrase": "=?base64?aGVsbG8gd29ybGQ=?=",
		})
		params := map[string]any{"phrase": "hello world"}
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})

	t.Run("numeric param compared by value", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:             "tools/call",
			HeaderMcpName:               "n",
			ParamHeaderPrefix + "Count": "1.0",
		})
		// Body has int 1; header "1.0" must compare numerically equal.
		params := map[string]any{"Count": 1}
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})

	t.Run("json.Number compared numerically", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:           "tools/call",
			HeaderMcpName:             "n",
			ParamHeaderPrefix + "Qty": "01",
		})
		params := map[string]any{"Qty": json.Number("1")}
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})

	t.Run("bool param", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:            "tools/call",
			HeaderMcpName:              "n",
			ParamHeaderPrefix + "Flag": "true",
		})
		params := map[string]any{"Flag": true}
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})

	t.Run("default type stringified", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:            "tools/call",
			HeaderMcpName:              "n",
			ParamHeaderPrefix + "Data": "[1 2 3]",
		})
		params := map[string]any{"Data": []int{1, 2, 3}}
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})

	t.Run("numeric mismatch", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:             "tools/call",
			HeaderMcpName:               "n",
			ParamHeaderPrefix + "Count": "2",
		})
		params := map[string]any{"Count": 1}
		err := ValidateHeaders(r, "tools/call", "n", params)
		var he *HeaderError
		require.ErrorAs(t, err, &he)
		assert.Contains(t, he.Message, "does not match body parameter")
	})

	t.Run("non-numeric strings fall back to string compare", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:            "tools/call",
			HeaderMcpName:              "n",
			ParamHeaderPrefix + "Code": "abc",
		})
		params := map[string]any{"Code": json.Number("abc")} // not numeric
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})

	t.Run("unrecognized param ignored", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:               "tools/call",
			HeaderMcpName:                 "n",
			ParamHeaderPrefix + "Unknown": "whatever",
		})
		params := map[string]any{"Known": "x"}
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})

	t.Run("param decode error", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:            "tools/call",
			HeaderMcpName:              "n",
			ParamHeaderPrefix + "City": sentinelPrefix + "!!!" + sentinelSuffix,
		})
		params := map[string]any{"City": "London"}
		err := ValidateHeaders(r, "tools/call", "n", params)
		var he *HeaderError
		require.ErrorAs(t, err, &he)
		assert.Contains(t, he.Message, "decode failed")
	})

	t.Run("sentinel-decoded param matches", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{
			HeaderMcpMethod:            "tools/call",
			HeaderMcpName:              "n",
			ParamHeaderPrefix + "City": sentinel("New York"),
		})
		params := map[string]any{"City": "New York"}
		require.NoError(t, ValidateHeaders(r, "tools/call", "n", params))
	})
}

func TestNumericEqual(t *testing.T) {
	t.Parallel()
	assert.True(t, numericEqual("1", "1.0"))
	assert.True(t, numericEqual("01", "1"))
	assert.True(t, numericEqual(" 2 ", "2"))
	assert.False(t, numericEqual("1", "2"))
	// Non-numeric strings compared literally.
	assert.True(t, numericEqual("abc", "abc"))
	assert.False(t, numericEqual("abc", "abd"))
}

// UT-HDR-03: re-derive headers after body rewrite; x-mcp-header mirroring;
// omit-when-absent; CopyUnrecognizedParams.
func TestDeriveUpstreamHeaders(t *testing.T) {
	t.Parallel()

	t.Run("method and name set for name-bearing method", func(t *testing.T) {
		t.Parallel()
		params := map[string]any{"city": "London", "empty": nil}
		xmap := map[string]string{"city": "City", "empty": "Empty", "absent": "Absent"}
		out := DeriveUpstreamHeaders("tools/call", "denamespaced-tool", params, xmap)

		assert.Equal(t, "tools/call", out.Get(HeaderMcpMethod))
		assert.Equal(t, "denamespaced-tool", out.Get(HeaderMcpName))
		// x-mcp-header mirrored.
		assert.Equal(t, "London", out.Get(ParamHeaderPrefix+"City"))
		// nil param omitted.
		assert.Empty(t, out.Get(ParamHeaderPrefix+"Empty"))
		// absent param omitted.
		assert.Empty(t, out.Get(ParamHeaderPrefix+"Absent"))
	})

	t.Run("name omitted for non-name-bearing method", func(t *testing.T) {
		t.Parallel()
		out := DeriveUpstreamHeaders("tools/list", "ignored", nil, nil)
		assert.Equal(t, "tools/list", out.Get(HeaderMcpMethod))
		assert.Empty(t, out.Get(HeaderMcpName))
	})

	t.Run("name omitted when empty even for name-bearing method", func(t *testing.T) {
		t.Parallel()
		out := DeriveUpstreamHeaders("tools/call", "", nil, nil)
		assert.Empty(t, out.Get(HeaderMcpName))
	})

	t.Run("numeric param stringified", func(t *testing.T) {
		t.Parallel()
		out := DeriveUpstreamHeaders("tools/call", "t",
			map[string]any{"n": 42}, map[string]string{"n": "N"})
		assert.Equal(t, "42", out.Get(ParamHeaderPrefix+"N"))
	})
}

func TestCopyUnrecognizedParams(t *testing.T) {
	t.Parallel()

	src := http.Header{}
	src.Set(ParamHeaderPrefix+"Known", "k")
	src.Set(ParamHeaderPrefix+"Unknown", "u")
	src.Add(ParamHeaderPrefix+"Multi", "a")
	src.Add(ParamHeaderPrefix+"Multi", "b")
	src.Set("Content-Type", "application/json") // non-param header ignored

	dst := http.Header{}
	dst.Set(ParamHeaderPrefix+"Unknown", "already-there") // must not be overwritten

	recognized := map[string]struct{}{"Known": {}}

	CopyUnrecognizedParams(dst, src, recognized)

	// Recognized param not copied.
	assert.Empty(t, dst.Values(ParamHeaderPrefix+"Known"))
	// Unknown already present in dst preserved (not overwritten).
	assert.Equal(t, []string{"already-there"}, dst.Values(ParamHeaderPrefix+"Unknown"))
	// Multi-valued unrecognized header copied fully.
	assert.Equal(t, []string{"a", "b"}, dst.Values(ParamHeaderPrefix+"Multi"))
	// Non-param header not copied.
	assert.Empty(t, dst.Values("Content-Type"))
}

func TestRequireMethod(t *testing.T) {
	t.Parallel()

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		r := newReq(map[string]string{HeaderMcpMethod: "tools/call"})
		m, err := RequireMethod(r)
		require.NoError(t, err)
		assert.Equal(t, "tools/call", m)
	})

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		_, err := RequireMethod(newReq(nil))
		require.ErrorIs(t, err, ErrMissingMethodHeader)
	})
}

// Empty-values header edge: a Mcp-Param-* header key with no values is skipped.
func TestValidateParamHeadersEmptyValues(t *testing.T) {
	t.Parallel()
	r := newReq(map[string]string{HeaderMcpMethod: "tools/list"})
	// Directly install an empty-value slice for a param header.
	r.Header[ParamHeaderPrefix+"X"] = []string{}
	require.NoError(t, ValidateHeaders(r, "tools/list", "", map[string]any{"X": "y"}))
}
