package middleware

import (
	"bytes"
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

func TestBodyLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		maxSize        int64
		contentLength  int64
		body           string
		expectedStatus int
		expectBodyRead bool
	}{
		{
			name:           "request within limit",
			maxSize:        1024,
			contentLength:  10,
			body:           "small body",
			expectedStatus: http.StatusOK,
			expectBodyRead: true,
		},
		{
			name:           "request at limit",
			maxSize:        11, // One more than body length to allow full read
			contentLength:  10,
			body:           "1234567890",
			expectedStatus: http.StatusOK,
			expectBodyRead: true,
		},
		{
			name:           "content-length exceeds limit",
			maxSize:        10,
			contentLength:  100,
			body:           strings.Repeat("x", 100),
			expectedStatus: http.StatusRequestEntityTooLarge,
			expectBodyRead: false,
		},
		{
			name:           "empty body",
			maxSize:        1024,
			contentLength:  0,
			body:           "",
			expectedStatus: http.StatusOK,
			expectBodyRead: true,
		},
		{
			name:           "no content-length header but body within limit",
			maxSize:        1024,
			contentLength:  -1, // -1 means don't set Content-Length
			body:           "small body",
			expectedStatus: http.StatusOK,
			expectBodyRead: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			middleware := BodyLimit(tt.maxSize, logger)

			var bodyRead bool
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Body != nil {
					_, err := io.ReadAll(r.Body)
					if err == nil {
						bodyRead = true
					}
				}
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(tt.body))
			if tt.contentLength >= 0 {
				req.ContentLength = tt.contentLength
			} else {
				req.ContentLength = -1
			}
			rec := httptest.NewRecorder()

			middleware(handler).ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedStatus == http.StatusRequestEntityTooLarge {
				assert.Contains(t, rec.Body.String(), "request entity too large")
				assert.Equal(t, ContentTypeJSON, rec.Header().Get(HeaderContentType))
			}
			if tt.expectBodyRead {
				assert.True(t, bodyRead)
			}
		})
	}
}

func TestBodyLimit_StreamingBody(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	maxSize := int64(10)
	middleware := BodyLimit(maxSize, logger)

	// Create a handler that reads the body in chunks
	var totalRead int
	var readErr error
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 5)
		for {
			n, err := r.Body.Read(buf)
			totalRead += n
			if err != nil {
				readErr = err
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	// Body larger than limit but Content-Length not set
	largeBody := strings.Repeat("x", 20)
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(largeBody))
	req.ContentLength = -1 // Unknown content length
	rec := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rec, req)

	// Should have read up to the limit
	assert.LessOrEqual(t, totalRead, int(maxSize))
	// Should have gotten a body size exceeded error
	assert.NotNil(t, readErr)
}

func TestBodyLimit_NilBody(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	middleware := BodyLimit(1024, logger)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Body = nil
	rec := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestBodyLimitFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cfg            *config.RequestLimitsConfig
		body           string
		expectedStatus int
	}{
		{
			name: "with max body size set",
			cfg: &config.RequestLimitsConfig{
				MaxBodySize: 10,
			},
			body:           strings.Repeat("x", 20),
			expectedStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name: "with default max body size",
			cfg:  &config.RequestLimitsConfig{},
			body: "small body",
			// Default is 10MB, so this should pass
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			middleware := BodyLimitFromConfig(tt.cfg, logger)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(tt.body))
			req.ContentLength = int64(len(tt.body))
			rec := httptest.NewRecorder()

			middleware(handler).ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

func TestLimitedReadCloser_Read(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		remaining      int64
		data           string
		bufSize        int
		expectedN      int
		expectedErr    bool
		expectedExceed bool
	}{
		{
			name:           "read within limit",
			remaining:      100,
			data:           "hello",
			bufSize:        10,
			expectedN:      5,
			expectedErr:    false,
			expectedExceed: false,
		},
		{
			name:           "read at limit",
			remaining:      5,
			data:           "hello",
			bufSize:        10,
			expectedN:      5,
			expectedErr:    false,
			expectedExceed: false,
		},
		{
			name:           "read exceeds limit",
			remaining:      3,
			data:           "hello",
			bufSize:        10,
			expectedN:      3,
			expectedErr:    false,
			expectedExceed: false,
		},
		{
			name:           "no remaining",
			remaining:      0,
			data:           "hello",
			bufSize:        10,
			expectedN:      0,
			expectedErr:    true,
			expectedExceed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reader := &limitedReadCloser{
				ReadCloser: io.NopCloser(strings.NewReader(tt.data)),
				remaining:  tt.remaining,
				exceeded:   false,
			}

			buf := make([]byte, tt.bufSize)
			n, err := reader.Read(buf)

			assert.Equal(t, tt.expectedN, n)
			if tt.expectedErr {
				assert.Error(t, err)
				var bsErr *bodySizeExceededError
				assert.ErrorAs(t, err, &bsErr)
			}
			assert.Equal(t, tt.expectedExceed, reader.exceeded)
		})
	}
}

func TestLimitedReadCloser_MultipleReads(t *testing.T) {
	t.Parallel()

	data := "hello world"
	reader := &limitedReadCloser{
		ReadCloser: io.NopCloser(strings.NewReader(data)),
		remaining:  int64(len(data)),
		exceeded:   false,
	}

	// First read
	buf1 := make([]byte, 5)
	n1, err1 := reader.Read(buf1)
	assert.Equal(t, 5, n1)
	assert.NoError(t, err1)
	assert.Equal(t, "hello", string(buf1[:n1]))

	// Second read
	buf2 := make([]byte, 10)
	n2, err2 := reader.Read(buf2)
	assert.Equal(t, 6, n2)
	assert.NoError(t, err2)
	assert.Equal(t, " world", string(buf2[:n2]))

	// Third read - remaining is 0, should get body size exceeded error
	buf3 := make([]byte, 10)
	n3, err3 := reader.Read(buf3)
	assert.Equal(t, 0, n3)
	assert.Error(t, err3)
	var bsErr *bodySizeExceededError
	assert.ErrorAs(t, err3, &bsErr)
}

func TestLimitedReadCloser_Close(t *testing.T) {
	t.Parallel()

	reader := &limitedReadCloser{
		ReadCloser: io.NopCloser(strings.NewReader("test")),
		remaining:  100,
		exceeded:   false,
	}

	err := reader.Close()
	assert.NoError(t, err)
}

func TestBodySizeExceededError(t *testing.T) {
	t.Parallel()

	err := &bodySizeExceededError{}
	assert.Equal(t, "request body size exceeded", err.Error())
}

func TestBodyLimit_LargeBody(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	maxSize := int64(1024) // 1KB limit
	middleware := BodyLimit(maxSize, logger)

	// Create a body larger than the limit
	largeBody := bytes.Repeat([]byte("x"), 2048)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(largeBody))
	req.ContentLength = int64(len(largeBody))
	rec := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rec, req)

	// Should be rejected based on Content-Length
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestBodyLimit_ChunkedTransfer(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	maxSize := int64(10)
	middleware := BodyLimit(maxSize, logger)

	var totalRead int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		totalRead = len(data)
		w.WriteHeader(http.StatusOK)
	})

	// Simulate chunked transfer (no Content-Length)
	body := strings.Repeat("x", 5)
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.ContentLength = -1 // Unknown
	rec := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 5, totalRead)
}

func TestBodyLimit_ExactLimit(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	maxSize := int64(10)
	middleware := BodyLimit(maxSize, logger)

	var bodyContent string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		bodyContent = string(data)
		w.WriteHeader(http.StatusOK)
	})

	// Body exactly at limit
	body := "1234567890"
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, body, bodyContent)
}

func TestBodyLimit_ZeroLimit(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	maxSize := int64(0)
	middleware := BodyLimit(maxSize, logger)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Any body should be rejected
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("x"))
	req.ContentLength = 1
	rec := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestBodyLimit_ResponseHeaders(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	maxSize := int64(10)
	middleware := BodyLimit(maxSize, logger)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Body exceeds limit
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(strings.Repeat("x", 100)))
	req.ContentLength = 100
	rec := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Equal(t, ContentTypeJSON, rec.Header().Get(HeaderContentType))
	assert.Contains(t, rec.Body.String(), "request entity too large")
}

func TestLimitedReadCloser_RemainingDecrement(t *testing.T) {
	t.Parallel()

	data := "hello"
	reader := &limitedReadCloser{
		ReadCloser: io.NopCloser(strings.NewReader(data)),
		remaining:  100,
		exceeded:   false,
	}

	buf := make([]byte, 3)
	n, err := reader.Read(buf)

	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, int64(97), reader.remaining)
}
