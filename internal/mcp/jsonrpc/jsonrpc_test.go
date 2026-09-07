package jsonrpc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestIsNotification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		req  *Request
		want bool
	}{
		{"nil request", nil, true},
		{"no id", &Request{JSONRPC: Version, Method: "x"}, true},
		{"empty id", &Request{JSONRPC: Version, ID: json.RawMessage{}, Method: "x"}, true},
		{"with numeric id", &Request{JSONRPC: Version, ID: json.RawMessage("1"), Method: "x"}, false},
		{"with string id", &Request{JSONRPC: Version, ID: json.RawMessage(`"abc"`), Method: "x"}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.req.IsNotification())
		})
	}
}

func TestErrorError(t *testing.T) {
	t.Parallel()

	var nilErr *Error
	assert.Equal(t, "<nil jsonrpc error>", nilErr.Error())

	e := &Error{Code: -32602, Message: "invalid params"}
	assert.Equal(t, "jsonrpc error -32602: invalid params", e.Error())
}

func TestNewError(t *testing.T) {
	t.Parallel()

	t.Run("nil data", func(t *testing.T) {
		t.Parallel()
		e, err := NewError(CodeInvalidParams, "boom", nil)
		require.NoError(t, err)
		assert.Equal(t, CodeInvalidParams, e.Code)
		assert.Equal(t, "boom", e.Message)
		assert.Nil(t, e.Data)
	})

	t.Run("with data", func(t *testing.T) {
		t.Parallel()
		e, err := NewError(CodeInternalError, "boom", map[string]int{"n": 5})
		require.NoError(t, err)
		assert.JSONEq(t, `{"n":5}`, string(e.Data))
	})

	t.Run("unmarshalable data", func(t *testing.T) {
		t.Parallel()
		e, err := NewError(CodeInternalError, "boom", make(chan int))
		require.Error(t, err)
		assert.Nil(t, e)
	})
}

func TestNewResponse(t *testing.T) {
	t.Parallel()

	t.Run("nil result normalizes id", func(t *testing.T) {
		t.Parallel()
		resp, err := NewResponse(nil, nil)
		require.NoError(t, err)
		assert.Equal(t, Version, resp.JSONRPC)
		assert.Equal(t, json.RawMessage("null"), resp.ID)
		assert.Nil(t, resp.Result)
	})

	t.Run("with result and id", func(t *testing.T) {
		t.Parallel()
		resp, err := NewResponse(json.RawMessage("7"), map[string]string{"ok": "yes"})
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage("7"), resp.ID)
		assert.JSONEq(t, `{"ok":"yes"}`, string(resp.Result))
	})

	t.Run("unmarshalable result", func(t *testing.T) {
		t.Parallel()
		resp, err := NewResponse(nil, make(chan int))
		require.Error(t, err)
		assert.Nil(t, resp)
	})
}

func TestNewErrorResponse(t *testing.T) {
	t.Parallel()

	t.Run("absent id becomes null", func(t *testing.T) {
		t.Parallel()
		e := &Error{Code: CodeParseError, Message: "bad"}
		resp := NewErrorResponse(nil, e)
		assert.Equal(t, Version, resp.JSONRPC)
		assert.Equal(t, json.RawMessage("null"), resp.ID)
		assert.Same(t, e, resp.Error)
	})

	t.Run("preserves id", func(t *testing.T) {
		t.Parallel()
		resp := NewErrorResponse(json.RawMessage(`"id-1"`), &Error{Code: 1, Message: "m"})
		assert.Equal(t, json.RawMessage(`"id-1"`), resp.ID)
	})
}

func TestEncodeDecode(t *testing.T) {
	t.Parallel()

	t.Run("encode ok", func(t *testing.T) {
		t.Parallel()
		out, err := Encode(map[string]int{"a": 1})
		require.NoError(t, err)
		assert.JSONEq(t, `{"a":1}`, string(out))
	})

	t.Run("encode error", func(t *testing.T) {
		t.Parallel()
		_, err := Encode(make(chan int))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "jsonrpc: encode")
	})

	t.Run("decode ok", func(t *testing.T) {
		t.Parallel()
		var v map[string]int
		require.NoError(t, Decode([]byte(`{"a":2}`), &v))
		assert.Equal(t, 2, v["a"])
	})

	t.Run("decode error", func(t *testing.T) {
		t.Parallel()
		var v map[string]int
		err := Decode([]byte(`{bad}`), &v)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "jsonrpc: decode")
	})
}

func TestParseSingle(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		input     string
		wantErr   error
		errSubstr string
		check     func(t *testing.T, r *Request)
	}{
		{
			name:  "valid request",
			input: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":1}}`,
			check: func(t *testing.T, r *Request) {
				assert.Equal(t, "tools/call", r.Method)
				assert.False(t, r.IsNotification())
				assert.JSONEq(t, `{"x":1}`, string(r.Params))
			},
		},
		{
			name:  "valid notification",
			input: `{"jsonrpc":"2.0","method":"notifications/x"}`,
			check: func(t *testing.T, r *Request) {
				assert.True(t, r.IsNotification())
			},
		},
		{
			name:  "leading whitespace trimmed",
			input: "  \n\t{\"jsonrpc\":\"2.0\",\"method\":\"m\"}",
			check: func(t *testing.T, r *Request) {
				assert.Equal(t, "m", r.Method)
			},
		},
		{
			name:    "empty",
			input:   "   ",
			wantErr: ErrEmptyMessage,
		},
		{
			name:    "batch array rejected",
			input:   `[{"jsonrpc":"2.0","method":"m"}]`,
			wantErr: ErrBatchNotSupported,
		},
		{
			name:    "batch with leading whitespace rejected",
			input:   "  [ {} ]",
			wantErr: ErrBatchNotSupported,
		},
		{
			name:      "malformed json",
			input:     `{bad`,
			errSubstr: "parse request",
		},
		{
			name:      "unsupported version",
			input:     `{"jsonrpc":"1.0","method":"m"}`,
			errSubstr: "unsupported version",
		},
		{
			name:      "missing version",
			input:     `{"method":"m"}`,
			errSubstr: "unsupported version",
		},
		{
			name:      "missing method",
			input:     `{"jsonrpc":"2.0","id":1}`,
			errSubstr: "missing method",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, err := ParseSingle([]byte(tc.input))
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, r)
			case tc.errSubstr != "":
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSubstr)
				assert.Nil(t, r)
			default:
				require.NoError(t, err)
				require.NotNil(t, r)
				if tc.check != nil {
					tc.check(t, r)
				}
			}
		})
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

func TestParseSingleReader(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		r, err := ParseSingleReader(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"m"}`))
		require.NoError(t, err)
		assert.Equal(t, "m", r.Method)
	})

	t.Run("read error", func(t *testing.T) {
		t.Parallel()
		_, err := ParseSingleReader(errReader{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read request")
	})

	t.Run("delegates batch rejection", func(t *testing.T) {
		t.Parallel()
		_, err := ParseSingleReader(strings.NewReader(`[]`))
		require.ErrorIs(t, err, ErrBatchNotSupported)
	})
}
