package transform

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []Option
	}{
		{
			name: "default transformer",
			opts: nil,
		},
		{
			name: "with logger",
			opts: []Option{WithTransformLogger(observability.NopLogger())},
		},
		{
			name: "with strip extensions",
			opts: []Option{WithStripExtensions(true)},
		},
		{
			name: "with add headers",
			opts: []Option{WithAddHeaders(map[string]string{"X-Custom": "value"})},
		},
		{
			name: "with remove headers",
			opts: []Option{WithRemoveHeaders([]string{"X-Internal"})},
		},
		{
			name: "with all options",
			opts: []Option{
				WithTransformLogger(observability.NopLogger()),
				WithStripExtensions(true),
				WithAddHeaders(map[string]string{"X-Custom": "value"}),
				WithRemoveHeaders([]string{"X-Internal"}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr := New(tt.opts...)
			require.NotNil(t, tr)
		})
	}
}

func TestTransformer_TransformResponse_HeaderManipulation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		addHeaders      map[string]string
		removeHeaders   []string
		initialHeaders  http.Header
		expectedHeaders map[string]string
		absentHeaders   []string
	}{
		{
			name:       "add headers",
			addHeaders: map[string]string{"X-Gateway": "avapigw", "X-Version": "v1"},
			initialHeaders: http.Header{
				"Content-Type": {"application/json"},
			},
			expectedHeaders: map[string]string{
				"Content-Type": "application/json",
				"X-Gateway":    "avapigw",
				"X-Version":    "v1",
			},
		},
		{
			name:          "remove headers",
			removeHeaders: []string{"X-Internal", "X-Debug"},
			initialHeaders: http.Header{
				"Content-Type": {"application/json"},
				"X-Internal":   {"secret"},
				"X-Debug":      {"true"},
			},
			expectedHeaders: map[string]string{
				"Content-Type": "application/json",
			},
			absentHeaders: []string{"X-Internal", "X-Debug"},
		},
		{
			name:          "add and remove headers",
			addHeaders:    map[string]string{"X-Gateway": "avapigw"},
			removeHeaders: []string{"X-Internal"},
			initialHeaders: http.Header{
				"Content-Type": {"application/json"},
				"X-Internal":   {"secret"},
			},
			expectedHeaders: map[string]string{
				"Content-Type": "application/json",
				"X-Gateway":    "avapigw",
			},
			absentHeaders: []string{"X-Internal"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr := New(
				WithTransformLogger(observability.NopLogger()),
				WithAddHeaders(tt.addHeaders),
				WithRemoveHeaders(tt.removeHeaders),
			)

			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     tt.initialHeaders,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"data":{}}`))),
				Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
			}

			err := tr.TransformResponse(resp)
			require.NoError(t, err)

			for key, value := range tt.expectedHeaders {
				assert.Equal(t, value, resp.Header.Get(key))
			}
			for _, key := range tt.absentHeaders {
				assert.Empty(t, resp.Header.Get(key))
			}
		})
	}
}

func TestTransformer_TransformResponse_StripExtensions(t *testing.T) {
	t.Parallel()

	tr := New(
		WithTransformLogger(observability.NopLogger()),
		WithStripExtensions(true),
	)

	body := `{"data":{"user":{"name":"test"}},"extensions":{"tracing":{"version":1}}}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
	}

	err := tr.TransformResponse(resp)
	require.NoError(t, err)

	// Read the transformed body
	transformedBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify extensions are stripped
	assert.NotContains(t, string(transformedBody), "tracing")
	assert.Contains(t, string(transformedBody), "user")
}

func TestTransformer_TransformResponse_NoStripExtensions(t *testing.T) {
	t.Parallel()

	tr := New(
		WithTransformLogger(observability.NopLogger()),
		WithStripExtensions(false),
	)

	body := `{"data":{"user":{"name":"test"}},"extensions":{"tracing":{"version":1}}}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
	}

	err := tr.TransformResponse(resp)
	require.NoError(t, err)

	// Body should not be modified when stripExtensions is false
	transformedBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(transformedBody), "tracing")
}

func TestTransformer_TransformResponse_NilBody(t *testing.T) {
	t.Parallel()

	tr := New(
		WithTransformLogger(observability.NopLogger()),
		WithStripExtensions(true),
	)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       nil,
		Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
	}

	err := tr.TransformResponse(resp)
	require.NoError(t, err)
}

func TestTransformer_TransformResponse_InvalidJSON(t *testing.T) {
	t.Parallel()

	tr := New(
		WithTransformLogger(observability.NopLogger()),
		WithStripExtensions(true),
	)

	body := `not valid json`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
	}

	err := tr.TransformResponse(resp)
	assert.Error(t, err) // Should return error for invalid JSON

	// Body should still be readable (restored as-is)
	transformedBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(transformedBody))
}

func TestTransformer_TransformResponse_WithErrors(t *testing.T) {
	t.Parallel()

	tr := New(
		WithTransformLogger(observability.NopLogger()),
		WithStripExtensions(true),
	)

	body := `{"data":null,"errors":[{"message":"not found"}],"extensions":{"code":"NOT_FOUND"}}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Request:    httptest.NewRequest(http.MethodPost, "/graphql", nil),
	}

	err := tr.TransformResponse(resp)
	require.NoError(t, err)

	transformedBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Errors should be preserved, extensions stripped
	assert.Contains(t, string(transformedBody), "not found")
	assert.NotContains(t, string(transformedBody), "NOT_FOUND")
}

func TestCreateErrorResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		message    string
		statusCode int
	}{
		{
			name:       "bad request error",
			message:    "invalid query",
			statusCode: 400,
		},
		{
			name:       "internal server error",
			message:    "internal error",
			statusCode: 500,
		},
		{
			name:       "not found error",
			message:    "route not found",
			statusCode: 404,
		},
		{
			name:       "depth limit exceeded",
			message:    "query depth exceeds maximum",
			statusCode: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body, err := CreateErrorResponse(tt.message, tt.statusCode)
			require.NoError(t, err)
			require.NotNil(t, body)

			bodyStr := string(body)
			assert.Contains(t, bodyStr, tt.message)
			assert.Contains(t, bodyStr, "errors")
		})
	}
}

func TestGraphQLResponse_Fields(t *testing.T) {
	t.Parallel()

	resp := GraphQLResponse{
		Data: map[string]interface{}{
			"user": map[string]interface{}{
				"name": "test",
			},
		},
		Errors: []GraphQLError{
			{
				Message: "field not found",
				Locations: []ErrorLocation{
					{Line: 1, Column: 5},
				},
				Path: []interface{}{"user", "email"},
				Extensions: map[string]interface{}{
					"code": "FIELD_NOT_FOUND",
				},
			},
		},
		Extensions: map[string]interface{}{
			"tracing": map[string]interface{}{
				"version": 1,
			},
		},
	}

	assert.NotNil(t, resp.Data)
	assert.Len(t, resp.Errors, 1)
	assert.Equal(t, "field not found", resp.Errors[0].Message)
	assert.Len(t, resp.Errors[0].Locations, 1)
	assert.Equal(t, 1, resp.Errors[0].Locations[0].Line)
	assert.Equal(t, 5, resp.Errors[0].Locations[0].Column)
	assert.Len(t, resp.Errors[0].Path, 2)
	assert.NotNil(t, resp.Extensions)
}

func TestTransformer_TransformResponse_ContentLength(t *testing.T) {
	t.Parallel()

	tr := New(
		WithTransformLogger(observability.NopLogger()),
		WithStripExtensions(true),
	)

	body := `{"data":{"user":"test"},"extensions":{"key":"value"}}`
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(body))),
		ContentLength: int64(len(body)),
		Request:       httptest.NewRequest(http.MethodPost, "/graphql", nil),
	}

	err := tr.TransformResponse(resp)
	require.NoError(t, err)

	// Content-Length should be updated
	transformedBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, int64(len(transformedBody)), resp.ContentLength)
}

func TestTransformer_TransformResponse_WithContext(t *testing.T) {
	t.Parallel()

	tr := New(WithTransformLogger(observability.NopLogger()))

	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req = req.WithContext(context.Background())

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"data":{}}`))),
		Request:    req,
	}

	err := tr.TransformResponse(resp)
	require.NoError(t, err)
}
