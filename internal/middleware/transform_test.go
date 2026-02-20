package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// jsonResponseHandler creates a handler that returns a JSON response.
func jsonResponseHandler(statusCode int, body interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(body)
	})
}

func TestTransformFromConfig_NilConfig(t *testing.T) {
	t.Parallel()

	mw := TransformFromConfig(nil, nil)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTransformFromConfig_NilLogger(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Request: &config.RequestTransformConfig{
			RemoveFields: []string{"secret"},
		},
	}

	// Should not panic with nil logger
	mw := TransformFromConfig(cfg, nil)
	require.NotNil(t, mw)

	body := `{"name":"test","secret":"hidden"}`
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bodyBytes)
	})

	handler := mw(backend)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTransformFromConfig_RequestTransform_RemoveFields(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Request: &config.RequestTransformConfig{
			RemoveFields: []string{"password", "secret"},
		},
	}
	logger := observability.NopLogger()

	var receivedBody map[string]interface{}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(bodyBytes, &receivedBody)
		w.WriteHeader(http.StatusOK)
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	body := `{"username":"john","password":"secret123","secret":"hidden","email":"john@example.com"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, receivedBody, "username")
	assert.Contains(t, receivedBody, "email")
	assert.NotContains(t, receivedBody, "password")
	assert.NotContains(t, receivedBody, "secret")
}

func TestTransformFromConfig_ResponseTransform_DenyFields(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Response: &config.ResponseTransformConfig{
			DenyFields: []string{"internal_id", "debug_info"},
		},
	}
	logger := observability.NopLogger()

	backend := jsonResponseHandler(http.StatusOK, map[string]interface{}{
		"name":        "test",
		"internal_id": "abc123",
		"debug_info":  "some debug",
		"public_data": "visible",
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Contains(t, result, "name")
	assert.Contains(t, result, "public_data")
	assert.NotContains(t, result, "internal_id")
	assert.NotContains(t, result, "debug_info")
}

func TestTransformFromConfig_Passthrough(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Request: &config.RequestTransformConfig{
			PassthroughBody: true,
		},
	}
	logger := observability.NopLogger()

	originalBody := `{"data":"original"}`
	var receivedBody string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.WriteHeader(http.StatusOK)
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(originalBody))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, originalBody, receivedBody)
}

func TestTransformFromConfig_EmptyBody(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Request: &config.RequestTransformConfig{
			RemoveFields: []string{"field"},
		},
	}
	logger := observability.NopLogger()

	called := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.ContentLength = 0
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTransformFromConfig_NoTransformNeeded(t *testing.T) {
	t.Parallel()

	// Config with empty request and response transforms
	cfg := &config.TransformConfig{
		Request:  &config.RequestTransformConfig{},
		Response: &config.ResponseTransformConfig{},
	}
	logger := observability.NopLogger()

	called := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "hello", rec.Body.String())
}

func TestTransformFromConfig_RequestBodyExceedsMaxSize(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Request: &config.RequestTransformConfig{
			RemoveFields: []string{"field"},
		},
	}
	logger := observability.NopLogger()

	// Create a body larger than maxTransformBodySize
	largeJSON := `{"field":"` + strings.Repeat("x", maxTransformBodySize+1) + `"}`

	var receivedBodyLen int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBodyLen = len(bodyBytes)
		w.WriteHeader(http.StatusOK)
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(largeJSON))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Body should be passed through unchanged (exceeds limit)
	assert.Greater(t, receivedBodyLen, maxTransformBodySize)
}

func TestTransformFromConfig_ResponseBodyExceedsMaxSize(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Response: &config.ResponseTransformConfig{
			DenyFields: []string{"secret"},
		},
	}
	logger := observability.NopLogger()

	// Create a large response body
	largeBody := strings.Repeat("x", maxTransformBodySize+1)
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(largeBody))
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Body should be passed through unchanged (exceeds limit)
	assert.Equal(t, largeBody, rec.Body.String())
}

func TestTransformFromConfig_NonJSONContentType(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Request: &config.RequestTransformConfig{
			RemoveFields: []string{"field"},
		},
	}
	logger := observability.NopLogger()

	originalBody := "plain text body"
	var receivedBody string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.WriteHeader(http.StatusOK)
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(originalBody))
	req.Header.Set("Content-Type", "text/plain")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Non-JSON body should be passed through unchanged
	assert.Equal(t, originalBody, receivedBody)
}

func TestTransformFromConfig_ResponseNonJSON(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Response: &config.ResponseTransformConfig{
			DenyFields: []string{"secret"},
		},
	}
	logger := observability.NopLogger()

	plainBody := "this is not JSON"
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(plainBody))
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, plainBody, rec.Body.String())
}

func TestTransformResponseRecorder_Header(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	trr := &transformResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
	}

	trr.Header().Set("X-Test", "value")
	assert.Equal(t, "value", trr.Header().Get("X-Test"))
}

func TestTransformResponseRecorder_WriteHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	trr := &transformResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
	}

	trr.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, trr.statusCode)
	assert.True(t, trr.headerWritten)

	// Duplicate call should be suppressed
	trr.WriteHeader(http.StatusBadRequest)
	assert.Equal(t, http.StatusCreated, trr.statusCode)
}

func TestTransformResponseRecorder_WriteImplicit200(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	trr := &transformResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
	}

	n, err := trr.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.True(t, trr.headerWritten)
	assert.Equal(t, http.StatusOK, trr.statusCode)
	assert.Equal(t, "hello", trr.body.String())
}

func TestTransformResponseRecorder_BufferExceeded(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	trr := &transformResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
	}

	// Write data that exceeds maxTransformBodySize
	bigChunk := make([]byte, maxTransformBodySize+1)
	for i := range bigChunk {
		bigChunk[i] = 'a'
	}

	n, err := trr.Write(bigChunk)
	require.NoError(t, err)
	assert.Equal(t, len(bigChunk), n)
	assert.True(t, trr.bufferExceeded)
}

func TestTransformResponseRecorder_BufferExceeded_SubsequentWrites(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	trr := &transformResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
	}

	// First write fills buffer close to limit
	firstChunk := make([]byte, maxTransformBodySize-10)
	_, err := trr.Write(firstChunk)
	require.NoError(t, err)
	assert.False(t, trr.bufferExceeded)

	// Second write exceeds limit
	secondChunk := make([]byte, 20)
	_, err = trr.Write(secondChunk)
	require.NoError(t, err)
	assert.True(t, trr.bufferExceeded)

	// Third write should go directly to underlying writer
	thirdChunk := []byte("more data")
	n, err := trr.Write(thirdChunk)
	require.NoError(t, err)
	assert.Equal(t, len(thirdChunk), n)
}

func TestTransformResponseRecorder_Flush(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	trr := &transformResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
	}

	// Should not panic (no-op)
	trr.Flush()
}

func TestTransformResponseRecorder_Hijack(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	trr := &transformResponseRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
	}

	// httptest.ResponseRecorder does not implement http.Hijacker
	_, _, err := trr.Hijack()
	assert.Error(t, err)
	assert.Equal(t, http.ErrNotSupported, err)
}

func TestTransformFromConfig_ResponseTransform_AllowFields(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Response: &config.ResponseTransformConfig{
			AllowFields: []string{"name", "email"},
		},
	}
	logger := observability.NopLogger()

	backend := jsonResponseHandler(http.StatusOK, map[string]interface{}{
		"name":     "John",
		"email":    "john@example.com",
		"password": "secret",
		"internal": "hidden",
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/user", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Contains(t, result, "name")
	assert.Contains(t, result, "email")
	assert.NotContains(t, result, "password")
	assert.NotContains(t, result, "internal")
}

func TestTransformFromConfig_RequestTransform_DefaultValues(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Request: &config.RequestTransformConfig{
			DefaultValues: map[string]interface{}{
				"status": "active",
				"role":   "user",
			},
		},
	}
	logger := observability.NopLogger()

	var receivedBody map[string]interface{}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(bodyBytes, &receivedBody)
		w.WriteHeader(http.StatusOK)
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	body := `{"name":"john","status":"inactive"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "john", receivedBody["name"])
	// status should remain "inactive" (not overwritten by default)
	assert.Equal(t, "inactive", receivedBody["status"])
	// role should be set to default "user"
	assert.Equal(t, "user", receivedBody["role"])
}

func TestTransformFromConfig_BothRequestAndResponse(t *testing.T) {
	t.Parallel()

	cfg := &config.TransformConfig{
		Request: &config.RequestTransformConfig{
			RemoveFields: []string{"secret"},
		},
		Response: &config.ResponseTransformConfig{
			DenyFields: []string{"internal_id"},
		},
	}
	logger := observability.NopLogger()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the transformed request body
		bodyBytes, _ := io.ReadAll(r.Body)
		var reqBody map[string]interface{}
		_ = json.Unmarshal(bodyBytes, &reqBody)

		// Verify secret was removed from request
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"name":        reqBody["name"],
			"internal_id": "abc123",
			"data":        "visible",
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	handler := TransformFromConfig(cfg, logger)(backend)

	body := `{"name":"test","secret":"hidden"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Contains(t, result, "name")
	assert.Contains(t, result, "data")
	assert.NotContains(t, result, "internal_id")
}

func TestTransformFromConfig_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cfg        *config.TransformConfig
		expectPass bool
	}{
		{
			name:       "nil config passthrough",
			cfg:        nil,
			expectPass: true,
		},
		{
			name: "empty request transform",
			cfg: &config.TransformConfig{
				Request: &config.RequestTransformConfig{},
			},
			expectPass: true,
		},
		{
			name: "empty response transform",
			cfg: &config.TransformConfig{
				Response: &config.ResponseTransformConfig{},
			},
			expectPass: true,
		},
		{
			name: "request with remove fields",
			cfg: &config.TransformConfig{
				Request: &config.RequestTransformConfig{
					RemoveFields: []string{"secret"},
				},
			},
			expectPass: true,
		},
		{
			name: "response with deny fields",
			cfg: &config.TransformConfig{
				Response: &config.ResponseTransformConfig{
					DenyFields: []string{"internal"},
				},
			},
			expectPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			mw := TransformFromConfig(tt.cfg, logger)
			require.NotNil(t, mw)

			backend := jsonResponseHandler(http.StatusOK, map[string]interface{}{
				"name":     "test",
				"internal": "hidden",
			})

			handler := mw(backend)
			rec := httptest.NewRecorder()
			body := `{"name":"test","secret":"hidden"}`
			req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)

			if tt.expectPass {
				assert.Equal(t, http.StatusOK, rec.Code)
			}
		})
	}
}
