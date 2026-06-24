package aggregate

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func jsonResp(target string, status int, body string) *Response {
	return &Response{Target: target, StatusCode: status, Body: []byte(body), ContentType: "application/json"}
}

func newTestMerger() *Merger {
	return NewMerger(nil, nil, nil)
}

// U-MRG-1 deep merge nested objects.
func TestMerger_Combine_DeepMerge(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `{"user":{"id":1,"name":"alice"}}`),
		jsonResp("b", 200, `{"user":{"email":"a@x.io"},"extra":true}`),
	}
	out, err := m.Combine(context.Background(), &MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep}, responses)
	require.NoError(t, err)
	assert.True(t, out.Merged)
	assert.Equal(t, "application/json", out.ContentType)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	user := got["user"].(map[string]interface{})
	assert.Equal(t, float64(1), user["id"])
	assert.Equal(t, "alice", user["name"])
	assert.Equal(t, "a@x.io", user["email"])
	assert.Equal(t, true, got["extra"])
}

// U-MRG-2 shallow merge top-level only.
func TestMerger_Combine_ShallowMerge(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `{"obj":{"x":1}}`),
		jsonResp("b", 200, `{"obj":{"y":2}}`),
	}
	out, err := m.Combine(context.Background(), &MergeOptions{Enabled: true, Strategy: config.MergeStrategyShallow}, responses)
	require.NoError(t, err)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	obj := got["obj"].(map[string]interface{})
	// Shallow: source obj replaces destination obj entirely.
	_, hasX := obj["x"]
	assert.False(t, hasX)
	assert.Equal(t, float64(2), obj["y"])
}

// U-MRG-3 replace = last non-nil wins.
func TestMerger_Combine_ReplaceMerge(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `{"v":1}`),
		jsonResp("b", 200, `{"v":2}`),
	}
	out, err := m.Combine(context.Background(), &MergeOptions{Enabled: true, Strategy: config.MergeStrategyReplace}, responses)
	require.NoError(t, err)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	assert.Equal(t, float64(2), got["v"])
}

// U-MRG-4 array concatenation.
func TestMerger_Combine_ArrayConcat(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `[1,2]`),
		jsonResp("b", 200, `[3,4]`),
	}
	out, err := m.Combine(context.Background(), &MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep}, responses)
	require.NoError(t, err)
	var got []interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	assert.Equal(t, []interface{}{float64(1), float64(2), float64(3), float64(4)}, got)
}

// U-MRG-5 non-JSON body → labeled-envelope fallback (no error).
func TestMerger_Combine_NonJSONEnvelopeFallback(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		{Target: "a", StatusCode: 200, Body: []byte("plain text"), ContentType: "text/plain"},
		jsonResp("b", 200, `{"ok":true}`),
	}
	out, err := m.Combine(context.Background(), &MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep}, responses)
	require.NoError(t, err)
	assert.False(t, out.Merged)

	var envelopes []Envelope
	require.NoError(t, json.Unmarshal(out.Body, &envelopes))
	require.Len(t, envelopes, 2)
	assert.Equal(t, "a", envelopes[0].Target)
	assert.Equal(t, 200, envelopes[0].Status)
}

// Merge disabled → labeled envelope.
func TestMerger_Combine_MergeDisabled(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{jsonResp("a", 200, `{"ok":true}`)}

	out, err := m.Combine(context.Background(), nil, responses)
	require.NoError(t, err)
	assert.False(t, out.Merged)

	out2, err := m.Combine(context.Background(), &MergeOptions{Enabled: false}, responses)
	require.NoError(t, err)
	assert.False(t, out2.Merged)
}

// U-MRG-6 conflicting types (obj vs array) → source wins, deterministic, no error.
func TestMerger_Combine_TypeConflict(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `{"k":"v"}`),
		jsonResp("b", 200, `[1,2,3]`),
	}
	out, err := m.Combine(context.Background(), &MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep}, responses)
	require.NoError(t, err)
	// Source (array) wins on type conflict.
	var got []interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	assert.Equal(t, []interface{}{float64(1), float64(2), float64(3)}, got)
}

func TestMerger_envelope_RawAndStringPayload(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `{"json":true}`),
		{Target: "b", StatusCode: 502, Body: []byte("not json"), ContentType: "text/plain"},
		{Target: "c", StatusCode: 204, Body: nil},
	}
	out, err := m.Combine(context.Background(), nil, responses)
	require.NoError(t, err)

	var envelopes []Envelope
	require.NoError(t, json.Unmarshal(out.Body, &envelopes))
	require.Len(t, envelopes, 3)
	// raw JSON payload preserved
	assert.JSONEq(t, `{"json":true}`, string(envelopes[0].Payload))
	// non-JSON string-encoded
	assert.Equal(t, `"not json"`, string(envelopes[1].Payload))
}

func TestLooksLikeJSON(t *testing.T) {
	tests := []struct {
		name string
		resp *Response
		want bool
	}{
		{"empty body", &Response{Body: nil}, false},
		{"json content type", &Response{Body: []byte("x"), ContentType: "application/json"}, true},
		{"object delim", &Response{Body: []byte(`{"a":1}`)}, true},
		{"array delim", &Response{Body: []byte(`[1]`)}, true},
		{"plain text", &Response{Body: []byte("hello")}, false},
		{"whitespace only", &Response{Body: []byte("   ")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, looksLikeJSON(tt.resp))
		})
	}
}

func TestRawPayload(t *testing.T) {
	assert.Equal(t, json.RawMessage(`{"a":1}`), rawPayload([]byte(`{"a":1}`)))
	assert.Equal(t, json.RawMessage(`"plain"`), rawPayload([]byte("plain")))
}

func TestDecodeJSONDocs(t *testing.T) {
	docs, ok := decodeJSONDocs([]*Response{jsonResp("a", 200, `{"a":1}`)})
	assert.True(t, ok)
	require.Len(t, docs, 1)

	_, ok = decodeJSONDocs([]*Response{{Target: "a", Body: []byte("nope")}})
	assert.False(t, ok)

	// JSON content type but invalid body fails decode.
	_, ok = decodeJSONDocs([]*Response{{Target: "a", Body: []byte("{invalid"), ContentType: "application/json"}})
	assert.False(t, ok)
}

func TestMergeEnabled(t *testing.T) {
	assert.False(t, mergeEnabled(nil))
	assert.False(t, mergeEnabled(&MergeOptions{Enabled: false}))
	assert.True(t, mergeEnabled(&MergeOptions{Enabled: true}))
}

// Combine with an invalid strategy → merger errors → labeled-envelope fallback.
func TestMerger_Combine_MergerErrorFallback(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `{"x":1}`),
		jsonResp("b", 200, `{"y":2}`),
	}
	out, err := m.Combine(context.Background(), &MergeOptions{Enabled: true, Strategy: "invalid-strategy"}, responses)
	require.NoError(t, err)
	assert.False(t, out.Merged, "invalid strategy falls back to envelope")

	var envelopes []Envelope
	require.NoError(t, json.Unmarshal(out.Body, &envelopes))
	assert.Len(t, envelopes, 2)
}

// Single response with merge enabled passes through unchanged (merger returns it).
func TestMerger_Combine_SingleResponse(t *testing.T) {
	m := newTestMerger()
	out, err := m.Combine(context.Background(), &MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		[]*Response{jsonResp("a", 200, `{"only":1}`)})
	require.NoError(t, err)
	assert.True(t, out.Merged)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	assert.Equal(t, float64(1), got["only"])
}

// Empty responses with merge enabled produce an empty merged document.
func TestMerger_Combine_EmptyResponses(t *testing.T) {
	m := newTestMerger()
	out, err := m.Combine(context.Background(), &MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep}, nil)
	require.NoError(t, err)
	assert.NotNil(t, out)
}

func TestNewMerger_NilArgs(t *testing.T) {
	m := NewMerger(nil, nil, nil)
	assert.NotNil(t, m.logger)
	assert.NotNil(t, m.metrics)
	assert.NotNil(t, m.tracer)
}
