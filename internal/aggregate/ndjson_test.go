package aggregate

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// ndjsonResp builds a successful response with the given body and content type.
func ndjsonResp(target, ct, body string) *Response {
	return &Response{Target: target, StatusCode: 200, Body: []byte(body), ContentType: ct}
}

// ---------------------------------------------------------------------------
// 2.1 Detection: isNDJSONContentType
// ---------------------------------------------------------------------------

func TestIsNDJSONContentType(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		want bool
	}{
		{"stream+json", "application/stream+json", true},
		{"x-ndjson", "application/x-ndjson", true},
		{"jsonl", "application/jsonl", true},
		{"x-ndjson with charset", "application/x-ndjson; charset=utf-8", true},
		{"stream+json with charset and spaces", "application/stream+json ; charset=utf-8", true},
		{"uppercase", "APPLICATION/X-NDJSON", true},
		{"mixed case with param", "Application/JSONL; Charset=UTF-8", true},
		{"plain json", "application/json", false},
		{"empty", "", false},
		{"text plain", "text/plain", false},
		{"json prefix but not ndjson", "application/json; charset=utf-8", false},
		{"only param semicolon", ";", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isNDJSONContentType(tt.ct))
		})
	}
}

// ---------------------------------------------------------------------------
// 2.1 Detection: looksLikeNDJSON heuristic
// ---------------------------------------------------------------------------

func TestLooksLikeNDJSON(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"valid-per-line invalid-whole", "{\"a\":1}\n{\"a\":2}", true},
		{"single object", `{"a":1}`, false},
		{"single array", `[1,2,3]`, false},
		{"pretty multiline single object", "{\n\"a\":1\n}", false},
		{"blank lines interspersed", "{\"a\":1}\n\n{\"a\":2}\n", true},
		{"single record trailing newline", "{\"a\":1}\n", false},
		{"one invalid line", "{\"a\":1}\nnot json", false},
		{"empty body", "", false},
		{"whitespace only", "  \n \n", false},
		{"scalars per line", "1\n\"x\"\ntrue", true},
		{"crlf line endings", "{\"a\":1}\r\n{\"a\":2}\r\n", true},
		{"binary input no panic", "\x00\x01\x02\nfoo", false},
		{"two objects no trailing newline", "{\"x\":1}\n{\"y\":2}\n{\"z\":3}", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, looksLikeNDJSON([]byte(tt.body)))
		})
	}
}

// ---------------------------------------------------------------------------
// 2.1 Detection: responseIsNDJSON / allResponsesNDJSON
// ---------------------------------------------------------------------------

func TestResponseIsNDJSON(t *testing.T) {
	tests := []struct {
		name string
		resp *Response
		want bool
	}{
		{"nil response", nil, false},
		{"content-type wins (plain json body)", ndjsonResp("a", "application/x-ndjson", `{"a":1}`), true},
		{"heuristic wins (no/other content type)", ndjsonResp("a", "text/plain", "{\"a\":1}\n{\"a\":2}"), true},
		{"plain json not ndjson", ndjsonResp("a", "application/json", `{"a":1}`), false},
		{"empty body no ct", ndjsonResp("a", "", ""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, responseIsNDJSON(tt.resp))
		})
	}
}

func TestAllResponsesNDJSON(t *testing.T) {
	ndjsonBody := ndjsonResp("a", "application/x-ndjson", "{\"a\":1}\n{\"a\":2}")
	plain := ndjsonResp("b", "application/json", `{"a":1}`)

	t.Run("empty slice is false", func(t *testing.T) {
		assert.False(t, allResponsesNDJSON(nil))
		assert.False(t, allResponsesNDJSON([]*Response{}))
	})
	t.Run("all ndjson is true", func(t *testing.T) {
		assert.True(t, allResponsesNDJSON([]*Response{ndjsonBody, ndjsonBody}))
	})
	t.Run("mixed is false", func(t *testing.T) {
		assert.False(t, allResponsesNDJSON([]*Response{ndjsonBody, plain}))
	})
}

// ---------------------------------------------------------------------------
// 2.2 lineMerger.Merge
// ---------------------------------------------------------------------------

// splitLines splits a serialized NDJSON body into non-empty records.
func splitLines(t *testing.T, out *MergeOutput) []string {
	t.Helper()
	require.NotNil(t, out)
	var lines []string
	for _, l := range splitNonEmpty(string(out.Body)) {
		lines = append(lines, l)
	}
	return lines
}

func splitNonEmpty(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestLineMerger_SplitSingleTarget(t *testing.T) {
	lm := &lineMerger{}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}\n{\"i\":3}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
	assert.Equal(t, `{"i":1}`, lines[0])
	assert.Equal(t, `{"i":2}`, lines[1])
	assert.Equal(t, `{"i":3}`, lines[2])
}

func TestLineMerger_CrossTargetOrder(t *testing.T) {
	lm := &lineMerger{}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}"),
		ndjsonResp("b", "application/x-ndjson", "{\"i\":3}\n{\"i\":4}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 4)
	assert.Equal(t, []string{`{"i":1}`, `{"i":2}`, `{"i":3}`, `{"i":4}`}, lines)
}

func TestLineMerger_SortNumeric(t *testing.T) {
	lm := &lineMerger{timeField: "_time"}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"_time\":3,\"v\":\"c\"}\n{\"_time\":1,\"v\":\"a\"}\n{\"_time\":2,\"v\":\"b\"}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
	assert.Contains(t, lines[0], `"v":"a"`)
	assert.Contains(t, lines[1], `"v":"b"`)
	assert.Contains(t, lines[2], `"v":"c"`)
}

func TestLineMerger_SortRFC3339(t *testing.T) {
	lm := &lineMerger{timeField: "_time"}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson",
			"{\"_time\":\"2023-01-03T00:00:00Z\",\"v\":\"c\"}\n"+
				"{\"_time\":\"2023-01-01T00:00:00Z\",\"v\":\"a\"}\n"+
				"{\"_time\":\"2023-01-02T00:00:00Z\",\"v\":\"b\"}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
	assert.Contains(t, lines[0], `"v":"a"`)
	assert.Contains(t, lines[1], `"v":"b"`)
	assert.Contains(t, lines[2], `"v":"c"`)
}

func TestLineMerger_SortString(t *testing.T) {
	lm := &lineMerger{timeField: "_time"}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson",
			"{\"_time\":\"gamma\"}\n{\"_time\":\"alpha\"}\n{\"_time\":\"beta\"}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
	assert.Contains(t, lines[0], "alpha")
	assert.Contains(t, lines[1], "beta")
	assert.Contains(t, lines[2], "gamma")
}

func TestLineMerger_SortMixedTypesNoPanic(t *testing.T) {
	lm := &lineMerger{timeField: "_time"}
	// number vs string: total order via canonical string compare; must not panic.
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"_time\":10}\n{\"_time\":\"abc\"}\n{\"_time\":2}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
}

func TestLineMerger_SortMissingFieldLast(t *testing.T) {
	lm := &lineMerger{timeField: "_time"}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson",
			"{\"v\":\"no-time-1\"}\n{\"_time\":2,\"v\":\"has\"}\n{\"v\":\"no-time-2\"}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
	// Present sorts first; missing retain stable order after.
	assert.Contains(t, lines[0], `"has"`)
	assert.Contains(t, lines[1], "no-time-1")
	assert.Contains(t, lines[2], "no-time-2")
}

func TestLineMerger_SortDisabled(t *testing.T) {
	lm := &lineMerger{timeField: ""}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"_time\":3}\n{\"_time\":1}\n{\"_time\":2}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
	// Input order preserved (no sort).
	assert.Contains(t, lines[0], `"_time":3`)
	assert.Contains(t, lines[1], `"_time":1`)
	assert.Contains(t, lines[2], `"_time":2`)
}

func TestLineMerger_DedupeFirstWins(t *testing.T) {
	lm := &lineMerger{keyField: "id"}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson",
			"{\"id\":\"x\",\"n\":1}\n{\"id\":\"y\",\"n\":2}\n{\"id\":\"x\",\"n\":3}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], `"n":1`)
	assert.Contains(t, lines[1], `"id":"y"`)
}

func TestLineMerger_DedupeMissingKeyKept(t *testing.T) {
	lm := &lineMerger{keyField: "id"}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson",
			"{\"id\":\"x\"}\n{\"no\":\"key\"}\n{\"also\":\"nokey\"}\n{\"id\":\"x\"}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	// id=x deduped to 1; the two key-less records both kept.
	require.Len(t, lines, 3)
}

func TestLineMerger_DedupeDisabled(t *testing.T) {
	lm := &lineMerger{keyField: ""}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"id\":1}\n{\"id\":1}\n{\"id\":1}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
}

func TestLineMerger_LimitTruncates(t *testing.T) {
	lm := &lineMerger{limit: 2}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}\n{\"i\":3}\n{\"i\":4}\n{\"i\":5}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 2)
	assert.Equal(t, `{"i":1}`, lines[0])
	assert.Equal(t, `{"i":2}`, lines[1])
}

func TestLineMerger_LimitZeroUnlimited(t *testing.T) {
	lm := &lineMerger{limit: 0}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}\n{\"i\":3}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
}

func TestLineMerger_LimitGreaterThanTotal(t *testing.T) {
	lm := &lineMerger{limit: 99}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}\n{\"i\":3}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
}

func TestLineMerger_BlankLinesSkipped(t *testing.T) {
	lm := &lineMerger{}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n\n   \n{\"i\":2}\n"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 2)
}

func TestLineMerger_TrailingNewlineDeterministic(t *testing.T) {
	lm := &lineMerger{}
	// Mixed trailing newlines across targets; output has exactly one trailing \n.
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n"),
		ndjsonResp("b", "application/x-ndjson", "{\"i\":2}"),
	})
	require.NoError(t, err)
	body := string(out.Body)
	assert.Equal(t, "{\"i\":1}\n{\"i\":2}\n", body)
}

func TestLineMerger_EmptyBodyTarget(t *testing.T) {
	lm := &lineMerger{}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", ""),
		ndjsonResp("b", "application/x-ndjson", "{\"i\":1}"),
		nil,
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 1)
	assert.Equal(t, `{"i":1}`, lines[0])
}

func TestLineMerger_NoRecordsEmptyBody(t *testing.T) {
	lm := &lineMerger{}
	out, err := lm.Merge([]*Response{ndjsonResp("a", "application/x-ndjson", "\n\n")})
	require.NoError(t, err)
	assert.Empty(t, out.Body)
	assert.True(t, out.Merged)
	assert.Equal(t, "application/stream+json", out.ContentType)
}

func TestLineMerger_OutputContentType(t *testing.T) {
	lm := &lineMerger{}
	out, err := lm.Merge([]*Response{ndjsonResp("a", "application/x-ndjson", "{\"i\":1}")})
	require.NoError(t, err)
	assert.Equal(t, "application/stream+json", out.ContentType)
	assert.True(t, out.Merged)
}

func TestLineMerger_SortDedupeLimitCombined(t *testing.T) {
	lm := &lineMerger{timeField: "_time", keyField: "id", limit: 2}
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson",
			"{\"_time\":3,\"id\":\"x\"}\n"+
				"{\"_time\":1,\"id\":\"y\"}\n"+
				"{\"_time\":2,\"id\":\"x\"}\n"+
				"{\"_time\":4,\"id\":\"z\"}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	// sort by _time -> y(1),x(2),x(3),z(4); dedupe id first-wins -> y(1),x(2),z(4);
	// limit 2 -> y(1), x(2).
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], `"id":"y"`)
	assert.Contains(t, lines[1], `"_time":2`)
}

func TestLineMerger_NonObjectLineWithSort(t *testing.T) {
	lm := &lineMerger{timeField: "_time"}
	// A scalar line decodes to nil object => treated as missing field (sorts last).
	out, err := lm.Merge([]*Response{
		ndjsonResp("a", "application/x-ndjson", "42\n{\"_time\":1,\"v\":\"obj\"}"),
	})
	require.NoError(t, err)
	lines := splitLines(t, out)
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], `"obj"`)
	assert.Equal(t, "42", lines[1])
}

func TestLineMerger_Determinism(t *testing.T) {
	build := func() *MergeOutput {
		lm := &lineMerger{timeField: "_time", keyField: "id", limit: 3}
		out, err := lm.Merge([]*Response{
			ndjsonResp("a", "application/x-ndjson",
				"{\"_time\":2,\"id\":\"b\"}\n{\"_time\":1,\"id\":\"a\"}"),
			ndjsonResp("b", "application/x-ndjson",
				"{\"_time\":3,\"id\":\"a\"}\n{\"_time\":4,\"id\":\"c\"}"),
		})
		require.NoError(t, err)
		return out
	}
	first := build()
	second := build()
	assert.Equal(t, first.Body, second.Body)
}

func TestNewLineMerger(t *testing.T) {
	lm := newLineMerger(&MergeOptions{TimeField: "ts", KeyField: "k", Limit: 5})
	assert.Equal(t, "ts", lm.timeField)
	assert.Equal(t, "k", lm.keyField)
	assert.Equal(t, 5, lm.limit)
}

// ---------------------------------------------------------------------------
// Low-level helpers: scalarString / compareValues / asNumber / asTime
// ---------------------------------------------------------------------------

func TestScalarString(t *testing.T) {
	assert.Equal(t, "hello", scalarString("hello"))
	assert.Equal(t, "3.5", scalarString(3.5))
	assert.Equal(t, "7", scalarString(json.Number("7")))
	assert.Equal(t, "true", scalarString(true))
	assert.Equal(t, "null", scalarString(nil))
	assert.Equal(t, `{"a":1}`, scalarString(map[string]interface{}{"a": float64(1)}))
}

func TestCompareValues(t *testing.T) {
	assert.Equal(t, -1, compareValues(float64(1), float64(2)))
	assert.Equal(t, 1, compareValues(float64(2), float64(1)))
	assert.Equal(t, 0, compareValues(float64(1), float64(1)))
	// RFC3339 path.
	assert.Equal(t, -1, compareValues("2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z"))
	assert.Equal(t, 1, compareValues("2023-01-02T00:00:00Z", "2023-01-01T00:00:00Z"))
	assert.Equal(t, 0, compareValues("2023-01-01T00:00:00Z", "2023-01-01T00:00:00Z"))
	// String fallback.
	assert.Equal(t, -1, compareValues("a", "b"))
	// Mixed number/string -> canonical string compare, total + panic-free.
	_ = compareValues(float64(5), "x")
}

func TestAsNumber(t *testing.T) {
	v, ok := asNumber(float64(3))
	assert.True(t, ok)
	assert.Equal(t, float64(3), v)

	v, ok = asNumber(json.Number("4.5"))
	assert.True(t, ok)
	assert.Equal(t, 4.5, v)

	_, ok = asNumber(json.Number("not-a-number"))
	assert.False(t, ok)

	_, ok = asNumber("string")
	assert.False(t, ok)
}

func TestAsTime(t *testing.T) {
	_, ok := asTime("2023-01-01T00:00:00Z")
	assert.True(t, ok)
	_, ok = asTime("not-a-time")
	assert.False(t, ok)
}

func TestDecodeObject(t *testing.T) {
	assert.NotNil(t, decodeObject([]byte(`{"a":1}`)))
	assert.Nil(t, decodeObject([]byte(`[1,2]`)))
	assert.Nil(t, decodeObject([]byte(`42`)))
	assert.Nil(t, decodeObject([]byte(`not json`)))
}

func TestLookupField(t *testing.T) {
	v, ok := lookupField(map[string]interface{}{"a": 1}, "a")
	assert.True(t, ok)
	assert.Equal(t, 1, v)

	_, ok = lookupField(map[string]interface{}{"a": 1}, "b")
	assert.False(t, ok)

	_, ok = lookupField(nil, "a")
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// 2.3 Combine wiring
// ---------------------------------------------------------------------------

func TestMerger_Combine_ExplicitNDJSON_NDJSONBodies(t *testing.T) {
	m := newTestMerger()
	out, err := m.Combine(context.Background(),
		&MergeOptions{Enabled: true, Strategy: config.MergeStrategyNDJSON},
		[]*Response{
			ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}"),
			ndjsonResp("b", "application/x-ndjson", "{\"i\":3}"),
		})
	require.NoError(t, err)
	assert.True(t, out.Merged)
	assert.Equal(t, "application/stream+json", out.ContentType)
	lines := splitLines(t, out)
	require.Len(t, lines, 3)
}

func TestMerger_Combine_ExplicitNDJSON_PlainJSONBodies(t *testing.T) {
	m := newTestMerger()
	// Explicit ndjson always uses lineMerger even when bodies are whole JSON
	// objects; each whole object becomes one record.
	out, err := m.Combine(context.Background(),
		&MergeOptions{Enabled: true, Strategy: config.MergeStrategyNDJSON},
		[]*Response{
			jsonResp("a", 200, `{"i":1}`),
			jsonResp("b", 200, `{"i":2}`),
		})
	require.NoError(t, err)
	assert.True(t, out.Merged)
	assert.Equal(t, "application/stream+json", out.ContentType)
	lines := splitLines(t, out)
	require.Len(t, lines, 2)
	assert.Equal(t, `{"i":1}`, lines[0])
	assert.Equal(t, `{"i":2}`, lines[1])
}

func TestMerger_Combine_AutoPromotion(t *testing.T) {
	m := newTestMerger()
	// strategy=deep but all bodies are NDJSON (not valid JSON-as-a-whole) ->
	// auto-promotion to lineMerger.
	out, err := m.Combine(context.Background(),
		&MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		[]*Response{
			ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}"),
			ndjsonResp("b", "application/x-ndjson", "{\"i\":3}\n{\"i\":4}"),
		})
	require.NoError(t, err)
	assert.True(t, out.Merged)
	assert.Equal(t, "application/stream+json", out.ContentType)
	lines := splitLines(t, out)
	require.Len(t, lines, 4)
}

func TestMerger_Combine_NoPromotion_ValidJSONWhole(t *testing.T) {
	m := newTestMerger()
	// Baseline deep merge of valid JSON-as-a-whole bodies must NOT be promoted,
	// and must be byte-identical to a direct deep merge.
	responses := []*Response{
		jsonResp("a", 200, `{"user":{"id":1}}`),
		jsonResp("b", 200, `{"user":{"name":"x"},"extra":true}`),
	}
	out, err := m.Combine(context.Background(),
		&MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep}, responses)
	require.NoError(t, err)
	assert.True(t, out.Merged)
	assert.Equal(t, "application/json", out.ContentType)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	user := got["user"].(map[string]interface{})
	assert.Equal(t, float64(1), user["id"])
	assert.Equal(t, "x", user["name"])
	assert.Equal(t, true, got["extra"])
}

func TestMerger_Combine_MixedNDJSONAndNonJSON_Envelope(t *testing.T) {
	m := newTestMerger()
	// One NDJSON, one binary/non-JSON -> not ALL NDJSON -> envelope fallback.
	out, err := m.Combine(context.Background(),
		&MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		[]*Response{
			ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}"),
			{Target: "b", StatusCode: 200, Body: []byte("plain text"), ContentType: "text/plain"},
		})
	require.NoError(t, err)
	assert.False(t, out.Merged)
	assert.Equal(t, "application/json", out.ContentType)
	var envelopes []Envelope
	require.NoError(t, json.Unmarshal(out.Body, &envelopes))
	require.Len(t, envelopes, 2)
}

func TestMerger_Combine_MixedNDJSONAndJSONWhole_Envelope(t *testing.T) {
	m := newTestMerger()
	// decodeJSONDocs fails on the NDJSON body; envelope check then fails because
	// the JSON-whole body is not NDJSON -> labeled envelope.
	out, err := m.Combine(context.Background(),
		&MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
		[]*Response{
			ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}"),
			jsonResp("b", 200, `{"whole":true}`),
		})
	require.NoError(t, err)
	assert.False(t, out.Merged)
	assert.Equal(t, "application/json", out.ContentType)
}

func TestMerger_Combine_NDJSONDisabled_Envelope(t *testing.T) {
	m := newTestMerger()
	out, err := m.Combine(context.Background(),
		&MergeOptions{Enabled: false, Strategy: config.MergeStrategyNDJSON},
		[]*Response{ndjsonResp("a", "application/x-ndjson", "{\"i\":1}\n{\"i\":2}")})
	require.NoError(t, err)
	assert.False(t, out.Merged)
}

// ---------------------------------------------------------------------------
// merge.go helper: countNDJSONRecords
// ---------------------------------------------------------------------------

func TestCountNDJSONRecords(t *testing.T) {
	assert.Equal(t, 0, countNDJSONRecords(nil))
	assert.Equal(t, 0, countNDJSONRecords([]byte("")))
	assert.Equal(t, 0, countNDJSONRecords([]byte("\n  \n")))
	assert.Equal(t, 2, countNDJSONRecords([]byte("{\"a\":1}\n{\"b\":2}\n")))
	assert.Equal(t, 3, countNDJSONRecords([]byte("a\nb\nc")))
}
