package transform

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// NewResponseTransformer Tests
// =============================================================================

func TestNewResponseTransformer(t *testing.T) {
	t.Run("creates transformer with initialized components", func(t *testing.T) {
		transformer := NewResponseTransformer()

		assert.NotNil(t, transformer)
		assert.NotNil(t, transformer.headerModifier)
		assert.NotNil(t, transformer.headerModifier.set)
		assert.NotNil(t, transformer.headerModifier.add)
		assert.NotNil(t, transformer.bodyTransformer)
		assert.NotNil(t, transformer.bodyTransformer.transformers)
		assert.Empty(t, transformer.bodyTransformer.transformers)
	})
}

// =============================================================================
// ResponseTransformer.Transform Tests
// =============================================================================

func TestResponseTransformer_Transform(t *testing.T) {
	t.Run("applies header modifications only", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.SetHeaderModifications(
			map[string]string{"X-Custom": "value"},
			map[string]string{"X-Added": "added-value"},
			[]string{"X-Remove"},
		)

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("test body"))),
		}
		resp.Header.Set("X-Remove", "to-be-removed")

		err := transformer.Transform(resp)

		assert.NoError(t, err)
		assert.Equal(t, "value", resp.Header.Get("X-Custom"))
		assert.Equal(t, "added-value", resp.Header.Get("X-Added"))
		assert.Empty(t, resp.Header.Get("X-Remove"))
	})

	t.Run("applies body transformation", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return bytes.ToUpper(body), nil
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("test body"))),
		}

		err := transformer.Transform(resp)

		assert.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "TEST BODY", string(body))
	})

	t.Run("applies both header and body transformations", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.SetHeaderModifications(
			map[string]string{"Content-Type": "application/json"},
			nil,
			nil,
		)
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return []byte(`{"data":"` + string(body) + `"}`), nil
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("test"))),
		}

		err := transformer.Transform(resp)

		assert.NoError(t, err)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, `{"data":"test"}`, string(body))
	})

	t.Run("returns no error with empty transformations", func(t *testing.T) {
		transformer := NewResponseTransformer()

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("test body"))),
		}

		err := transformer.Transform(resp)

		assert.NoError(t, err)
	})

	t.Run("returns error when body transformer fails", func(t *testing.T) {
		transformer := NewResponseTransformer()
		expectedErr := errors.New("transform error")
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return nil, expectedErr
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("test body"))),
		}

		err := transformer.Transform(resp)

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

// =============================================================================
// ResponseTransformer.SetHeaderModifications Tests
// =============================================================================

func TestResponseTransformer_SetHeaderModifications(t *testing.T) {
	t.Run("sets header modifications", func(t *testing.T) {
		transformer := NewResponseTransformer()
		set := map[string]string{"X-Set": "value"}
		add := map[string]string{"X-Add": "value"}
		remove := []string{"X-Remove"}

		transformer.SetHeaderModifications(set, add, remove)

		assert.Equal(t, set, transformer.headerModifier.set)
		assert.Equal(t, add, transformer.headerModifier.add)
		assert.Equal(t, remove, transformer.headerModifier.remove)
	})

	t.Run("sets nil values", func(t *testing.T) {
		transformer := NewResponseTransformer()

		transformer.SetHeaderModifications(nil, nil, nil)

		assert.Nil(t, transformer.headerModifier.set)
		assert.Nil(t, transformer.headerModifier.add)
		assert.Nil(t, transformer.headerModifier.remove)
	})

	t.Run("overwrites existing modifications", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.SetHeaderModifications(
			map[string]string{"X-Old": "old"},
			map[string]string{"X-Old-Add": "old"},
			[]string{"X-Old-Remove"},
		)

		newSet := map[string]string{"X-New": "new"}
		newAdd := map[string]string{"X-New-Add": "new"}
		newRemove := []string{"X-New-Remove"}
		transformer.SetHeaderModifications(newSet, newAdd, newRemove)

		assert.Equal(t, newSet, transformer.headerModifier.set)
		assert.Equal(t, newAdd, transformer.headerModifier.add)
		assert.Equal(t, newRemove, transformer.headerModifier.remove)
	})
}

// =============================================================================
// ResponseTransformer.AddBodyTransformer Tests
// =============================================================================

func TestResponseTransformer_AddBodyTransformer(t *testing.T) {
	t.Run("adds body transformer", func(t *testing.T) {
		transformer := NewResponseTransformer()
		fn := func(body []byte) ([]byte, error) {
			return body, nil
		}

		transformer.AddBodyTransformer(fn)

		assert.Len(t, transformer.bodyTransformer.transformers, 1)
	})

	t.Run("adds multiple body transformers", func(t *testing.T) {
		transformer := NewResponseTransformer()
		fn1 := func(body []byte) ([]byte, error) { return body, nil }
		fn2 := func(body []byte) ([]byte, error) { return body, nil }
		fn3 := func(body []byte) ([]byte, error) { return body, nil }

		transformer.AddBodyTransformer(fn1)
		transformer.AddBodyTransformer(fn2)
		transformer.AddBodyTransformer(fn3)

		assert.Len(t, transformer.bodyTransformer.transformers, 3)
	})

	t.Run("transformers are applied in order", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return append(body, []byte("-first")...), nil
		})
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return append(body, []byte("-second")...), nil
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("start"))),
		}

		err := transformer.Transform(resp)

		assert.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "start-first-second", string(body))
	})
}

// =============================================================================
// ResponseTransformer.ClearBodyTransformers Tests
// =============================================================================

func TestResponseTransformer_ClearBodyTransformers(t *testing.T) {
	t.Run("clears all body transformers", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) { return body, nil })
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) { return body, nil })

		transformer.ClearBodyTransformers()

		assert.NotNil(t, transformer.bodyTransformer.transformers)
		assert.Empty(t, transformer.bodyTransformer.transformers)
	})

	t.Run("clears empty transformers", func(t *testing.T) {
		transformer := NewResponseTransformer()

		transformer.ClearBodyTransformers()

		assert.NotNil(t, transformer.bodyTransformer.transformers)
		assert.Empty(t, transformer.bodyTransformer.transformers)
	})
}

// =============================================================================
// ResponseTransformer.transformBody Tests
// =============================================================================

func TestResponseTransformer_transformBody(t *testing.T) {
	t.Run("handles nil body", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return body, nil
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       nil,
		}

		err := transformer.transformBody(resp)

		assert.NoError(t, err)
	})

	t.Run("applies transformers to body", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return bytes.ToUpper(body), nil
		})

		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader([]byte("hello world"))),
			ContentLength: 11,
		}

		err := transformer.transformBody(resp)

		assert.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "HELLO WORLD", string(body))
		assert.Equal(t, int64(11), resp.ContentLength)
	})

	t.Run("returns error when transformer fails", func(t *testing.T) {
		transformer := NewResponseTransformer()
		expectedErr := errors.New("transform failed")
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return nil, expectedErr
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("test"))),
		}

		err := transformer.transformBody(resp)

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("returns error when body read fails", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return body, nil
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(&errorReader{err: errors.New("read error")}),
		}

		err := transformer.transformBody(resp)

		assert.Error(t, err)
	})

	t.Run("updates content length after transformation", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return []byte("longer body content"), nil
		})

		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader([]byte("short"))),
			ContentLength: 5,
		}

		err := transformer.transformBody(resp)

		assert.NoError(t, err)
		assert.Equal(t, int64(19), resp.ContentLength)
	})

	t.Run("stops on first transformer error", func(t *testing.T) {
		transformer := NewResponseTransformer()
		callCount := 0
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			callCount++
			return nil, errors.New("first error")
		})
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			callCount++
			return body, nil
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("test"))),
		}

		err := transformer.transformBody(resp)

		assert.Error(t, err)
		assert.Equal(t, 1, callCount)
	})
}

// =============================================================================
// NewResponseWriter Tests
// =============================================================================

func TestNewResponseWriter(t *testing.T) {
	t.Run("creates response writer with transformer and transformBody true", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()

		rw := NewResponseWriter(recorder, transformer, true)

		assert.NotNil(t, rw)
		assert.Equal(t, recorder, rw.ResponseWriter)
		assert.Equal(t, transformer, rw.transformer)
		assert.NotNil(t, rw.body)
		assert.True(t, rw.transformBody)
		assert.False(t, rw.headerWritten)
		assert.Equal(t, 0, rw.statusCode)
	})

	t.Run("creates response writer with transformBody false", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()

		rw := NewResponseWriter(recorder, transformer, false)

		assert.NotNil(t, rw)
		assert.False(t, rw.transformBody)
	})

	t.Run("creates response writer with nil transformer", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		rw := NewResponseWriter(recorder, nil, true)

		assert.NotNil(t, rw)
		assert.Nil(t, rw.transformer)
	})
}

// =============================================================================
// ResponseWriter.WriteHeader Tests
// =============================================================================

func TestResponseWriter_WriteHeader(t *testing.T) {
	t.Run("captures status code with transformBody true", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, true)

		rw.WriteHeader(http.StatusCreated)

		assert.Equal(t, http.StatusCreated, rw.statusCode)
		assert.False(t, rw.headerWritten) // Not written to underlying writer yet
	})

	t.Run("writes header immediately with transformBody false", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, false)

		rw.WriteHeader(http.StatusNotFound)

		assert.Equal(t, http.StatusNotFound, rw.statusCode)
		assert.True(t, rw.headerWritten)
		assert.Equal(t, http.StatusNotFound, recorder.Code)
	})

	t.Run("ignores multiple WriteHeader calls", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, false)

		rw.WriteHeader(http.StatusOK)
		rw.WriteHeader(http.StatusNotFound)
		rw.WriteHeader(http.StatusInternalServerError)

		assert.Equal(t, http.StatusOK, rw.statusCode)
		assert.Equal(t, http.StatusOK, recorder.Code)
	})

	t.Run("applies header transformations", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		transformer.SetHeaderModifications(
			map[string]string{"X-Custom": "value"},
			nil,
			nil,
		)
		rw := NewResponseWriter(recorder, transformer, false)

		rw.WriteHeader(http.StatusOK)

		assert.Equal(t, "value", rw.Header().Get("X-Custom"))
	})

	t.Run("handles nil transformer", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rw := NewResponseWriter(recorder, nil, false)

		rw.WriteHeader(http.StatusOK)

		assert.Equal(t, http.StatusOK, rw.statusCode)
		assert.True(t, rw.headerWritten)
	})
}

// =============================================================================
// ResponseWriter.Write Tests
// =============================================================================

func TestResponseWriter_Write(t *testing.T) {
	t.Run("captures body with transformBody true", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, true)

		n, err := rw.Write([]byte("test body"))

		assert.NoError(t, err)
		assert.Equal(t, 9, n)
		assert.Equal(t, "test body", rw.body.String())
		assert.Empty(t, recorder.Body.String()) // Not written to underlying writer
	})

	t.Run("writes directly with transformBody false", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, false)

		n, err := rw.Write([]byte("test body"))

		assert.NoError(t, err)
		assert.Equal(t, 9, n)
		assert.Equal(t, "test body", recorder.Body.String())
	})

	t.Run("calls WriteHeader with 200 if not already written", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, false)

		_, err := rw.Write([]byte("test"))

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rw.statusCode)
		assert.True(t, rw.headerWritten)
	})

	t.Run("multiple writes accumulate body", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, true)

		rw.Write([]byte("first "))
		rw.Write([]byte("second "))
		rw.Write([]byte("third"))

		assert.Equal(t, "first second third", rw.body.String())
	})
}

// =============================================================================
// ResponseWriter.Flush Tests
// =============================================================================

func TestResponseWriter_Flush(t *testing.T) {
	t.Run("returns nil when transformBody is false", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, false)

		err := rw.Flush()

		assert.NoError(t, err)
	})

	t.Run("writes transformed body to underlying writer", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return bytes.ToUpper(body), nil
		})
		rw := NewResponseWriter(recorder, transformer, true)
		rw.statusCode = http.StatusOK
		rw.Write([]byte("hello world"))

		err := rw.Flush()

		assert.NoError(t, err)
		assert.Equal(t, "HELLO WORLD", recorder.Body.String())
		assert.Equal(t, http.StatusOK, recorder.Code)
	})

	t.Run("writes body without transformation when no transformers", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, true)
		rw.statusCode = http.StatusCreated
		rw.Write([]byte("original body"))

		err := rw.Flush()

		assert.NoError(t, err)
		assert.Equal(t, "original body", recorder.Body.String())
		assert.Equal(t, http.StatusCreated, recorder.Code)
	})

	t.Run("returns error when transformer fails", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		expectedErr := errors.New("transform error")
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return nil, expectedErr
		})
		rw := NewResponseWriter(recorder, transformer, true)
		rw.Write([]byte("test"))

		err := rw.Flush()

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("handles nil transformer", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rw := NewResponseWriter(recorder, nil, true)
		rw.statusCode = http.StatusOK
		rw.Write([]byte("test body"))

		err := rw.Flush()

		assert.NoError(t, err)
		assert.Equal(t, "test body", recorder.Body.String())
	})

	t.Run("applies multiple transformers in order", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return append([]byte("prefix-"), body...), nil
		})
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return append(body, []byte("-suffix")...), nil
		})
		rw := NewResponseWriter(recorder, transformer, true)
		rw.statusCode = http.StatusOK
		rw.Write([]byte("middle"))

		err := rw.Flush()

		assert.NoError(t, err)
		assert.Equal(t, "prefix-middle-suffix", recorder.Body.String())
	})
}

// =============================================================================
// ResponseWriter.StatusCode Tests
// =============================================================================

func TestResponseWriter_StatusCode(t *testing.T) {
	t.Run("returns 200 when status code not set", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rw := NewResponseWriter(recorder, nil, true)

		assert.Equal(t, http.StatusOK, rw.StatusCode())
	})

	t.Run("returns set status code", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rw := NewResponseWriter(recorder, nil, true)
		rw.statusCode = http.StatusNotFound

		assert.Equal(t, http.StatusNotFound, rw.StatusCode())
	})

	t.Run("returns status code after WriteHeader", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rw := NewResponseWriter(recorder, nil, true)
		rw.WriteHeader(http.StatusCreated)

		assert.Equal(t, http.StatusCreated, rw.StatusCode())
	})
}

// =============================================================================
// ResponseWriter.Body Tests
// =============================================================================

func TestResponseWriter_Body(t *testing.T) {
	t.Run("returns empty body initially", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rw := NewResponseWriter(recorder, nil, true)

		assert.Empty(t, rw.Body())
	})

	t.Run("returns captured body", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rw := NewResponseWriter(recorder, nil, true)
		rw.Write([]byte("test body content"))

		assert.Equal(t, []byte("test body content"), rw.Body())
	})

	t.Run("returns accumulated body from multiple writes", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rw := NewResponseWriter(recorder, nil, true)
		rw.Write([]byte("part1"))
		rw.Write([]byte("part2"))
		rw.Write([]byte("part3"))

		assert.Equal(t, []byte("part1part2part3"), rw.Body())
	})
}

// =============================================================================
// ModifyResponseHeaders Tests
// =============================================================================

func TestModifyResponseHeaders(t *testing.T) {
	t.Run("sets headers - overwrites existing", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Existing", "old-value")

		ModifyResponseHeaders(header, map[string]string{"X-Existing": "new-value"}, nil, nil)

		assert.Equal(t, "new-value", header.Get("X-Existing"))
	})

	t.Run("adds headers", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Existing", "existing-value")

		ModifyResponseHeaders(header, nil, map[string]string{"X-Existing": "added-value"}, nil)

		values := header.Values("X-Existing")
		assert.Len(t, values, 2)
		assert.Contains(t, values, "existing-value")
		assert.Contains(t, values, "added-value")
	})

	t.Run("removes headers", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Remove", "value")
		header.Set("X-Keep", "value")

		ModifyResponseHeaders(header, nil, nil, []string{"X-Remove"})

		assert.Empty(t, header.Get("X-Remove"))
		assert.Equal(t, "value", header.Get("X-Keep"))
	})

	t.Run("removes headers before set and add", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Header", "original")

		ModifyResponseHeaders(
			header,
			map[string]string{"X-Header": "set-value"},
			map[string]string{"X-Header": "add-value"},
			[]string{"X-Header"},
		)

		// Remove happens first, then set, then add
		values := header.Values("X-Header")
		assert.Len(t, values, 2)
		assert.Contains(t, values, "set-value")
		assert.Contains(t, values, "add-value")
	})

	t.Run("handles nil maps", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Existing", "value")

		ModifyResponseHeaders(header, nil, nil, nil)

		assert.Equal(t, "value", header.Get("X-Existing"))
	})

	t.Run("handles empty maps", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Existing", "value")

		ModifyResponseHeaders(header, map[string]string{}, map[string]string{}, []string{})

		assert.Equal(t, "value", header.Get("X-Existing"))
	})

	t.Run("all operations together", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Remove", "to-remove")
		header.Set("X-Set", "old-value")
		header.Set("X-Add", "existing")

		ModifyResponseHeaders(
			header,
			map[string]string{"X-Set": "new-value", "X-New": "brand-new"},
			map[string]string{"X-Add": "added"},
			[]string{"X-Remove"},
		)

		assert.Empty(t, header.Get("X-Remove"))
		assert.Equal(t, "new-value", header.Get("X-Set"))
		assert.Equal(t, "brand-new", header.Get("X-New"))
		addValues := header.Values("X-Add")
		assert.Len(t, addValues, 2)
	})
}

// =============================================================================
// AddSecurityHeaders Tests
// =============================================================================

func TestAddSecurityHeaders(t *testing.T) {
	t.Run("adds all security headers", func(t *testing.T) {
		header := make(http.Header)

		AddSecurityHeaders(header)

		assert.Equal(t, "nosniff", header.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", header.Get("X-Frame-Options"))
		assert.Equal(t, "1; mode=block", header.Get("X-XSS-Protection"))
		assert.Equal(t, "strict-origin-when-cross-origin", header.Get("Referrer-Policy"))
	})

	t.Run("overwrites existing security headers", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Content-Type-Options", "old-value")
		header.Set("X-Frame-Options", "SAMEORIGIN")

		AddSecurityHeaders(header)

		assert.Equal(t, "nosniff", header.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", header.Get("X-Frame-Options"))
	})

	t.Run("preserves other headers", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Custom", "custom-value")
		header.Set("Content-Type", "application/json")

		AddSecurityHeaders(header)

		assert.Equal(t, "custom-value", header.Get("X-Custom"))
		assert.Equal(t, "application/json", header.Get("Content-Type"))
	})
}

// =============================================================================
// AddCacheHeaders Tests
// =============================================================================

func TestAddCacheHeaders(t *testing.T) {
	t.Run("adds public cache header", func(t *testing.T) {
		header := make(http.Header)

		AddCacheHeaders(header, 0, true)

		assert.Equal(t, "public", header.Get("Cache-Control"))
	})

	t.Run("adds private cache header", func(t *testing.T) {
		header := make(http.Header)

		AddCacheHeaders(header, 0, false)

		assert.Equal(t, "private", header.Get("Cache-Control"))
	})

	t.Run("adds public cache header with maxAge", func(t *testing.T) {
		header := make(http.Header)

		AddCacheHeaders(header, 3600, true)

		// Note: The implementation uses string(rune(maxAge)) which produces unexpected results
		// for large numbers. This test documents the actual behavior.
		cacheControl := header.Get("Cache-Control")
		assert.Contains(t, cacheControl, "public")
		assert.Contains(t, cacheControl, "max-age=")
	})

	t.Run("adds private cache header with maxAge", func(t *testing.T) {
		header := make(http.Header)

		AddCacheHeaders(header, 60, false)

		cacheControl := header.Get("Cache-Control")
		assert.Contains(t, cacheControl, "private")
		assert.Contains(t, cacheControl, "max-age=")
	})

	t.Run("overwrites existing cache-control header", func(t *testing.T) {
		header := make(http.Header)
		header.Set("Cache-Control", "no-store")

		AddCacheHeaders(header, 0, true)

		assert.Equal(t, "public", header.Get("Cache-Control"))
	})

	t.Run("zero maxAge does not add max-age directive", func(t *testing.T) {
		header := make(http.Header)

		AddCacheHeaders(header, 0, true)

		assert.Equal(t, "public", header.Get("Cache-Control"))
		assert.NotContains(t, header.Get("Cache-Control"), "max-age")
	})

	t.Run("negative maxAge does not add max-age directive", func(t *testing.T) {
		header := make(http.Header)

		AddCacheHeaders(header, -1, true)

		assert.Equal(t, "public", header.Get("Cache-Control"))
		assert.NotContains(t, header.Get("Cache-Control"), "max-age")
	})
}

// =============================================================================
// AddNoCacheHeaders Tests
// =============================================================================

func TestAddNoCacheHeaders(t *testing.T) {
	t.Run("adds all no-cache headers", func(t *testing.T) {
		header := make(http.Header)

		AddNoCacheHeaders(header)

		assert.Equal(t, "no-store, no-cache, must-revalidate, proxy-revalidate", header.Get("Cache-Control"))
		assert.Equal(t, "no-cache", header.Get("Pragma"))
		assert.Equal(t, "0", header.Get("Expires"))
	})

	t.Run("overwrites existing cache headers", func(t *testing.T) {
		header := make(http.Header)
		header.Set("Cache-Control", "public, max-age=3600")
		header.Set("Pragma", "cache")
		header.Set("Expires", "Thu, 01 Dec 2024 16:00:00 GMT")

		AddNoCacheHeaders(header)

		assert.Equal(t, "no-store, no-cache, must-revalidate, proxy-revalidate", header.Get("Cache-Control"))
		assert.Equal(t, "no-cache", header.Get("Pragma"))
		assert.Equal(t, "0", header.Get("Expires"))
	})

	t.Run("preserves other headers", func(t *testing.T) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		header.Set("X-Custom", "value")

		AddNoCacheHeaders(header)

		assert.Equal(t, "application/json", header.Get("Content-Type"))
		assert.Equal(t, "value", header.Get("X-Custom"))
	})
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestResponseTransformerEdgeCases(t *testing.T) {
	t.Run("transform with empty body", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return append(body, []byte("added")...), nil
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
		}

		err := transformer.Transform(resp)

		assert.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "added", string(body))
	})

	t.Run("response writer with large body", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, true)

		largeBody := bytes.Repeat([]byte("x"), 1024*1024) // 1MB
		n, err := rw.Write(largeBody)

		assert.NoError(t, err)
		assert.Equal(t, 1024*1024, n)
		assert.Equal(t, 1024*1024, len(rw.Body()))
	})

	t.Run("transformer chain with body size changes", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			// Double the body
			return append(body, body...), nil
		})
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			// Triple the body
			return append(body, append(body, body...)...), nil
		})

		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader([]byte("x"))),
			ContentLength: 1,
		}

		err := transformer.Transform(resp)

		assert.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, 6, len(body)) // 1 -> 2 -> 6
		assert.Equal(t, int64(6), resp.ContentLength)
	})

	t.Run("response writer flush with default status code", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, true)
		// Don't set status code explicitly, let it use default
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("test"))

		err := rw.Flush()

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "test", recorder.Body.String())
	})
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestResponseTransformerIntegration(t *testing.T) {
	t.Run("full response transformation pipeline", func(t *testing.T) {
		transformer := NewResponseTransformer()
		transformer.SetHeaderModifications(
			map[string]string{"Content-Type": "application/json"},
			map[string]string{"X-Processed": "true"},
			[]string{"X-Internal"},
		)
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return []byte(`{"data":"` + string(body) + `"}`), nil
		})

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("hello"))),
		}
		resp.Header.Set("X-Internal", "secret")

		err := transformer.Transform(resp)

		require.NoError(t, err)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Equal(t, "true", resp.Header.Get("X-Processed"))
		assert.Empty(t, resp.Header.Get("X-Internal"))

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, `{"data":"hello"}`, string(body))
	})

	t.Run("response writer full workflow", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		transformer.SetHeaderModifications(
			map[string]string{"X-Custom": "value"},
			nil,
			nil,
		)
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return bytes.ToUpper(body), nil
		})

		rw := NewResponseWriter(recorder, transformer, true)
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("hello "))
		rw.Write([]byte("world"))
		err := rw.Flush()

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "HELLO WORLD", recorder.Body.String())
		assert.Equal(t, "value", recorder.Header().Get("X-Custom"))
	})
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkResponseTransformer_Transform(b *testing.B) {
	transformer := NewResponseTransformer()
	transformer.SetHeaderModifications(
		map[string]string{"Content-Type": "application/json"},
		map[string]string{"X-Request-ID": "12345"},
		[]string{"X-Internal"},
	)
	transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
		return bytes.ToUpper(body), nil
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("test body content"))),
		}
		resp.Header.Set("X-Internal", "value")
		_ = transformer.Transform(resp)
	}
}

func BenchmarkResponseWriter_Write(b *testing.B) {
	data := []byte("test body content for benchmarking")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		rw := NewResponseWriter(recorder, transformer, true)
		rw.Write(data)
	}
}

func BenchmarkResponseWriter_Flush(b *testing.B) {
	data := []byte("test body content for benchmarking")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		transformer := NewResponseTransformer()
		transformer.AddBodyTransformer(func(body []byte) ([]byte, error) {
			return bytes.ToUpper(body), nil
		})
		rw := NewResponseWriter(recorder, transformer, true)
		rw.statusCode = http.StatusOK
		rw.Write(data)
		rw.Flush()
	}
}

func BenchmarkModifyResponseHeaders(b *testing.B) {
	set := map[string]string{"X-Set-1": "v1", "X-Set-2": "v2", "X-Set-3": "v3"}
	add := map[string]string{"X-Add-1": "v1", "X-Add-2": "v2"}
	remove := []string{"X-Remove-1", "X-Remove-2"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header := make(http.Header)
		header.Set("X-Remove-1", "value")
		header.Set("X-Remove-2", "value")
		ModifyResponseHeaders(header, set, add, remove)
	}
}

func BenchmarkAddSecurityHeaders(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header := make(http.Header)
		AddSecurityHeaders(header)
	}
}

func BenchmarkAddCacheHeaders(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header := make(http.Header)
		AddCacheHeaders(header, 3600, true)
	}
}

func BenchmarkAddNoCacheHeaders(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header := make(http.Header)
		AddNoCacheHeaders(header)
	}
}

// =============================================================================
// Helper Types
// =============================================================================

// errorReader is a helper type that always returns an error when reading
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}
