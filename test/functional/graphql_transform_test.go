//go:build functional
// +build functional

// Package functional contains functional tests for the API Gateway.
// These tests verify GraphQL transformation logic in isolation.
package functional

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqltransform "github.com/vyrodovalexey/avapigw/internal/graphql/transform"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestFunctional_GraphQLTransform_StripExtensions(t *testing.T) {
	t.Parallel()

	t.Run("strip extensions from response", func(t *testing.T) {
		t.Parallel()

		transformer := graphqltransform.New(
			graphqltransform.WithTransformLogger(observability.NopLogger()),
			graphqltransform.WithStripExtensions(true),
		)

		// Create a response with extensions
		gqlResp := map[string]interface{}{
			"data": map[string]interface{}{
				"users": []interface{}{
					map[string]interface{}{"id": "1", "name": "Alice"},
				},
			},
			"extensions": map[string]interface{}{
				"tracing": map[string]interface{}{
					"duration": 42,
				},
			},
		}
		body, err := json.Marshal(gqlResp)
		require.NoError(t, err)

		// Create HTTP response
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
		}

		// Transform
		err = transformer.TransformResponse(resp)
		require.NoError(t, err)

		// Read transformed body
		transformedBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(transformedBody, &result)
		require.NoError(t, err)

		// Verify extensions are stripped
		assert.Nil(t, result["extensions"])
		assert.NotNil(t, result["data"])
	})

	t.Run("preserve extensions when strip is disabled", func(t *testing.T) {
		t.Parallel()

		transformer := graphqltransform.New(
			graphqltransform.WithTransformLogger(observability.NopLogger()),
			graphqltransform.WithStripExtensions(false),
		)

		gqlResp := map[string]interface{}{
			"data": map[string]interface{}{
				"users": []interface{}{},
			},
			"extensions": map[string]interface{}{
				"tracing": map[string]interface{}{
					"duration": 42,
				},
			},
		}
		body, err := json.Marshal(gqlResp)
		require.NoError(t, err)

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
		}

		err = transformer.TransformResponse(resp)
		require.NoError(t, err)

		// Body should be unchanged (no transformation applied)
		transformedBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(transformedBody, &result)
		require.NoError(t, err)

		// Extensions should still be present
		assert.NotNil(t, result["extensions"])
	})

	t.Run("strip extensions from error response", func(t *testing.T) {
		t.Parallel()

		transformer := graphqltransform.New(
			graphqltransform.WithTransformLogger(observability.NopLogger()),
			graphqltransform.WithStripExtensions(true),
		)

		gqlResp := map[string]interface{}{
			"errors": []interface{}{
				map[string]interface{}{
					"message": "Not found",
					"extensions": map[string]interface{}{
						"code": "NOT_FOUND",
					},
				},
			},
			"extensions": map[string]interface{}{
				"tracing": map[string]interface{}{
					"duration": 10,
				},
			},
		}
		body, err := json.Marshal(gqlResp)
		require.NoError(t, err)

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
		}

		err = transformer.TransformResponse(resp)
		require.NoError(t, err)

		transformedBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(transformedBody, &result)
		require.NoError(t, err)

		// Top-level extensions should be stripped
		assert.Nil(t, result["extensions"])
		// Errors should still be present
		assert.NotNil(t, result["errors"])
	})

	t.Run("handle nil body gracefully", func(t *testing.T) {
		t.Parallel()

		transformer := graphqltransform.New(
			graphqltransform.WithTransformLogger(observability.NopLogger()),
			graphqltransform.WithStripExtensions(true),
		)

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       nil,
			Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
		}

		err := transformer.TransformResponse(resp)
		require.NoError(t, err)
	})
}

func TestFunctional_GraphQLTransform_AddHeaders(t *testing.T) {
	t.Parallel()

	t.Run("add headers to response", func(t *testing.T) {
		t.Parallel()

		headers := map[string]string{
			"X-Gateway":       "avapigw",
			"X-Cache-Control": "no-cache",
		}

		transformer := graphqltransform.New(
			graphqltransform.WithTransformLogger(observability.NopLogger()),
			graphqltransform.WithAddHeaders(headers),
		)

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"data":null}`))),
			Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
		}

		err := transformer.TransformResponse(resp)
		require.NoError(t, err)

		assert.Equal(t, "avapigw", resp.Header.Get("X-Gateway"))
		assert.Equal(t, "no-cache", resp.Header.Get("X-Cache-Control"))
	})

	t.Run("add headers overrides existing", func(t *testing.T) {
		t.Parallel()

		headers := map[string]string{
			"X-Gateway": "avapigw-new",
		}

		transformer := graphqltransform.New(
			graphqltransform.WithTransformLogger(observability.NopLogger()),
			graphqltransform.WithAddHeaders(headers),
		)

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"X-Gateway": []string{"old-value"}, "Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"data":null}`))),
			Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
		}

		err := transformer.TransformResponse(resp)
		require.NoError(t, err)

		assert.Equal(t, "avapigw-new", resp.Header.Get("X-Gateway"))
	})

	t.Run("remove headers from response", func(t *testing.T) {
		t.Parallel()

		transformer := graphqltransform.New(
			graphqltransform.WithTransformLogger(observability.NopLogger()),
			graphqltransform.WithRemoveHeaders([]string{"X-Internal", "X-Debug"}),
		)

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"X-Internal":   []string{"secret"},
				"X-Debug":      []string{"true"},
				"X-Public":     []string{"visible"},
			},
			Body:    io.NopCloser(bytes.NewReader([]byte(`{"data":null}`))),
			Request: httptest.NewRequest(http.MethodPost, "/graphql", nil),
		}

		err := transformer.TransformResponse(resp)
		require.NoError(t, err)

		assert.Empty(t, resp.Header.Get("X-Internal"))
		assert.Empty(t, resp.Header.Get("X-Debug"))
		assert.Equal(t, "visible", resp.Header.Get("X-Public"))
	})

	t.Run("combined add and remove headers", func(t *testing.T) {
		t.Parallel()

		transformer := graphqltransform.New(
			graphqltransform.WithTransformLogger(observability.NopLogger()),
			graphqltransform.WithAddHeaders(map[string]string{"X-Gateway": "avapigw"}),
			graphqltransform.WithRemoveHeaders([]string{"X-Internal"}),
		)

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"X-Internal":   []string{"secret"},
			},
			Body:    io.NopCloser(bytes.NewReader([]byte(`{"data":null}`))),
			Request: httptest.NewRequest(http.MethodPost, "/graphql", nil),
		}

		err := transformer.TransformResponse(resp)
		require.NoError(t, err)

		assert.Equal(t, "avapigw", resp.Header.Get("X-Gateway"))
		assert.Empty(t, resp.Header.Get("X-Internal"))
	})
}

func TestFunctional_GraphQLTransform_CreateErrorResponse(t *testing.T) {
	t.Parallel()

	t.Run("create error response", func(t *testing.T) {
		t.Parallel()

		body, err := graphqltransform.CreateErrorResponse("query too complex", http.StatusBadRequest)
		require.NoError(t, err)
		require.NotEmpty(t, body)

		var resp graphqltransform.GraphQLResponse
		err = json.Unmarshal(body, &resp)
		require.NoError(t, err)

		require.Len(t, resp.Errors, 1)
		assert.Equal(t, "query too complex", resp.Errors[0].Message)
		assert.NotNil(t, resp.Errors[0].Extensions)
		assert.Equal(t, float64(http.StatusBadRequest), resp.Errors[0].Extensions["code"])
	})

	t.Run("create internal server error response", func(t *testing.T) {
		t.Parallel()

		body, err := graphqltransform.CreateErrorResponse("internal error", http.StatusInternalServerError)
		require.NoError(t, err)

		var resp graphqltransform.GraphQLResponse
		err = json.Unmarshal(body, &resp)
		require.NoError(t, err)

		require.Len(t, resp.Errors, 1)
		assert.Equal(t, "internal error", resp.Errors[0].Message)
		assert.Equal(t, float64(http.StatusInternalServerError), resp.Errors[0].Extensions["code"])
	})
}
