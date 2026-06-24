package aggregate

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// U-MRG-7 GraphQL: data deep-merged, errors concatenated, extensions merged.
func TestMerger_MergeGraphQL_DataErrorsExtensions(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `{"data":{"user":{"id":1}},"errors":[{"message":"e1"}],"extensions":{"trace":"x"}}`),
		jsonResp("b", 200, `{"data":{"user":{"name":"alice"},"posts":[1,2]},"errors":[{"message":"e2"}],"extensions":{"cost":5}}`),
	}
	out, err := m.MergeGraphQL(context.Background(), responses)
	require.NoError(t, err)
	assert.True(t, out.Merged)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))

	data := got["data"].(map[string]interface{})
	user := data["user"].(map[string]interface{})
	assert.Equal(t, float64(1), user["id"])
	assert.Equal(t, "alice", user["name"])
	assert.Equal(t, []interface{}{float64(1), float64(2)}, data["posts"])

	errs := got["errors"].([]interface{})
	assert.Len(t, errs, 2)

	ext := got["extensions"].(map[string]interface{})
	assert.Equal(t, "x", ext["trace"])
	assert.Equal(t, float64(5), ext["cost"])
}

// U-AD-GQL-2: partial backend error (malformed response) surfaced as synthetic error.
func TestMerger_MergeGraphQL_PartialError(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `{"data":{"x":1}}`),
		{Target: "broken", StatusCode: 200, Body: []byte("not json")},
	}
	out, err := m.MergeGraphQL(context.Background(), responses)
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	errs := got["errors"].([]interface{})
	require.Len(t, errs, 1)
	e := errs[0].(map[string]interface{})
	ext := e["extensions"].(map[string]interface{})
	assert.Equal(t, "broken", ext["target"])
}

func TestMerger_MergeGraphQL_NoErrorsKeyWhenEmpty(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{jsonResp("a", 200, `{"data":{"x":1}}`)}
	out, err := m.MergeGraphQL(context.Background(), responses)
	require.NoError(t, err)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	_, hasErrors := got["errors"]
	assert.False(t, hasErrors)
	_, hasExt := got["extensions"]
	assert.False(t, hasExt)
}

func TestMerger_MergeGraphQL_NullDataSkipped(t *testing.T) {
	m := newTestMerger()
	responses := []*Response{
		jsonResp("a", 200, `{"data":null,"errors":[{"message":"oops"}]}`),
		jsonResp("b", 200, `{"data":{"y":2}}`),
	}
	out, err := m.MergeGraphQL(context.Background(), responses)
	require.NoError(t, err)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	data := got["data"].(map[string]interface{})
	assert.Equal(t, float64(2), data["y"])
	assert.Len(t, got["errors"].([]interface{}), 1)
}

func TestMerger_MergeGraphQL_Empty(t *testing.T) {
	m := newTestMerger()
	out, err := m.MergeGraphQL(context.Background(), nil)
	require.NoError(t, err)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	assert.Empty(t, got)
}

func TestAppendErrors(t *testing.T) {
	acc := []interface{}{}
	// non-array raw ignored
	assert.Len(t, appendErrors(acc, "not-array"), 0)
	assert.Len(t, appendErrors(acc, nil), 0)
	// array appended
	got := appendErrors(acc, []interface{}{map[string]interface{}{"message": "x"}})
	assert.Len(t, got, 1)
}

func TestSyntheticError(t *testing.T) {
	e := syntheticError("svc", "boom")
	assert.Equal(t, "boom", e["message"])
	ext := e["extensions"].(map[string]interface{})
	assert.Equal(t, "svc", ext["target"])
}

func TestDeepMergeDocs(t *testing.T) {
	m := newTestMerger()
	assert.Nil(t, m.deepMergeDocs(nil))

	got := m.deepMergeDocs([]interface{}{
		map[string]interface{}{"a": 1},
		map[string]interface{}{"b": 2},
	})
	gm := got.(map[string]interface{})
	assert.Equal(t, 1, gm["a"])
	assert.Equal(t, 2, gm["b"])
}
