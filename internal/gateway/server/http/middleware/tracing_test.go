package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// setupTracingTest creates a test tracer provider and returns it along with a span recorder
func setupTracingTest() (*sdktrace.TracerProvider, *tracetest.SpanRecorder) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	return tp, spanRecorder
}

func TestTracing(t *testing.T) {
	tests := []struct {
		name           string
		serviceName    string
		method         string
		path           string
		expectedStatus int
		checkSpan      func(t *testing.T, spans []sdktrace.ReadOnlySpan)
	}{
		{
			name:           "creates span for GET request",
			serviceName:    "test-service",
			method:         http.MethodGet,
			path:           "/api/users",
			expectedStatus: http.StatusOK,
			checkSpan: func(t *testing.T, spans []sdktrace.ReadOnlySpan) {
				require.Len(t, spans, 1)
				span := spans[0]
				assert.Equal(t, "GET /api/users", span.Name())
				assert.Equal(t, trace.SpanKindServer, span.SpanKind())

				attrs := span.Attributes()
				assertAttributeExists(t, attrs, "http.method", "GET")
				assertAttributeExists(t, attrs, "http.target", "/api/users")
			},
		},
		{
			name:           "creates span for POST request",
			serviceName:    "test-service",
			method:         http.MethodPost,
			path:           "/api/items",
			expectedStatus: http.StatusCreated,
			checkSpan: func(t *testing.T, spans []sdktrace.ReadOnlySpan) {
				require.Len(t, spans, 1)
				span := spans[0]
				assert.Equal(t, "POST /api/items", span.Name())
			},
		},
		{
			name:           "uses default service name when empty",
			serviceName:    "",
			method:         http.MethodGet,
			path:           "/test",
			expectedStatus: http.StatusOK,
			checkSpan: func(t *testing.T, spans []sdktrace.ReadOnlySpan) {
				require.Len(t, spans, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, spanRecorder := setupTracingTest()
			defer tp.Shutdown(context.Background())

			router := gin.New()
			router.Use(TracingWithConfig(TracingConfig{
				TracerProvider: tp,
				ServiceName:    tt.serviceName,
			}))

			router.Any("/*path", func(c *gin.Context) {
				if tt.method == http.MethodPost {
					c.Status(http.StatusCreated)
				} else {
					c.Status(http.StatusOK)
				}
			})

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			// Force flush spans
			tp.ForceFlush(context.Background())

			spans := spanRecorder.Ended()
			tt.checkSpan(t, spans)
		})
	}
}

func TestTracingWithConfig(t *testing.T) {
	t.Run("uses default tracer provider when nil", func(t *testing.T) {
		router := gin.New()
		router.Use(TracingWithConfig(TracingConfig{
			ServiceName: "test",
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("uses default propagators when nil", func(t *testing.T) {
		tp, _ := setupTracingTest()
		defer tp.Shutdown(context.Background())

		router := gin.New()
		router.Use(TracingWithConfig(TracingConfig{
			TracerProvider: tp,
			ServiceName:    "test",
			// Propagators is nil
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("uses custom propagators", func(t *testing.T) {
		tp, spanRecorder := setupTracingTest()
		defer tp.Shutdown(context.Background())

		propagators := propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		)

		router := gin.New()
		router.Use(TracingWithConfig(TracingConfig{
			TracerProvider: tp,
			Propagators:    propagators,
			ServiceName:    "test",
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// Add trace context headers
		req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		tp.ForceFlush(context.Background())
		spans := spanRecorder.Ended()
		require.Len(t, spans, 1)
	})

	t.Run("skips configured paths", func(t *testing.T) {
		tp, spanRecorder := setupTracingTest()
		defer tp.Shutdown(context.Background())

		router := gin.New()
		router.Use(TracingWithConfig(TracingConfig{
			TracerProvider: tp,
			ServiceName:    "test",
			SkipPaths:      []string{"/health", "/ready"},
		}))
		router.GET("/health", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		router.GET("/ready", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		router.GET("/api/data", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		// Request to skipped path - should not create span
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Request to another skipped path
		req = httptest.NewRequest(http.MethodGet, "/ready", nil)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Request to non-skipped path - should create span
		req = httptest.NewRequest(http.MethodGet, "/api/data", nil)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		tp.ForceFlush(context.Background())
		spans := spanRecorder.Ended()
		// Only one span for /api/data
		require.Len(t, spans, 1)
		assert.Equal(t, "GET /api/data", spans[0].Name())
	})

	t.Run("records request ID in span", func(t *testing.T) {
		tp, spanRecorder := setupTracingTest()
		defer tp.Shutdown(context.Background())

		router := gin.New()
		// Add request ID middleware before tracing
		router.Use(func(c *gin.Context) {
			c.Set(RequestIDKey, "test-request-id-123")
			c.Next()
		})
		router.Use(TracingWithConfig(TracingConfig{
			TracerProvider: tp,
			ServiceName:    "test",
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		tp.ForceFlush(context.Background())
		spans := spanRecorder.Ended()
		require.Len(t, spans, 1)

		attrs := spans[0].Attributes()
		assertAttributeExists(t, attrs, "request.id", "test-request-id-123")
	})

	t.Run("records response status code", func(t *testing.T) {
		tp, spanRecorder := setupTracingTest()
		defer tp.Shutdown(context.Background())

		router := gin.New()
		router.Use(TracingWithConfig(TracingConfig{
			TracerProvider: tp,
			ServiceName:    "test",
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusAccepted)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusAccepted, w.Code)

		tp.ForceFlush(context.Background())
		spans := spanRecorder.Ended()
		require.Len(t, spans, 1)

		attrs := spans[0].Attributes()
		assertAttributeExistsInt(t, attrs, "http.status_code", 202)
	})

	t.Run("records errors from gin context", func(t *testing.T) {
		tp, spanRecorder := setupTracingTest()
		defer tp.Shutdown(context.Background())

		router := gin.New()
		router.Use(TracingWithConfig(TracingConfig{
			TracerProvider: tp,
			ServiceName:    "test",
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Error(errors.New("test error"))
			c.Status(http.StatusInternalServerError)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		tp.ForceFlush(context.Background())
		spans := spanRecorder.Ended()
		require.Len(t, spans, 1)

		// Check that error was recorded
		events := spans[0].Events()
		hasErrorEvent := false
		for _, event := range events {
			if event.Name == "exception" {
				hasErrorEvent = true
				break
			}
		}
		assert.True(t, hasErrorEvent, "expected error event to be recorded")
	})

	t.Run("marks span as error for 5xx status", func(t *testing.T) {
		tp, spanRecorder := setupTracingTest()
		defer tp.Shutdown(context.Background())

		router := gin.New()
		router.Use(TracingWithConfig(TracingConfig{
			TracerProvider: tp,
			ServiceName:    "test",
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusServiceUnavailable)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)

		tp.ForceFlush(context.Background())
		spans := spanRecorder.Ended()
		require.Len(t, spans, 1)

		attrs := spans[0].Attributes()
		assertAttributeExistsBool(t, attrs, "error", true)
	})

	t.Run("stores span in gin context", func(t *testing.T) {
		tp, _ := setupTracingTest()
		defer tp.Shutdown(context.Background())

		var capturedSpan trace.Span

		router := gin.New()
		router.Use(TracingWithConfig(TracingConfig{
			TracerProvider: tp,
			ServiceName:    "test",
		}))
		router.GET("/test", func(c *gin.Context) {
			capturedSpan = GetSpan(c)
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotNil(t, capturedSpan)
	})
}

func TestTracing_Simple(t *testing.T) {
	// Test the simple Tracing() function which uses default tracer provider
	router := gin.New()
	router.Use(Tracing("simple-service"))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetSpan(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(c *gin.Context)
		expected bool
	}{
		{
			name: "returns span when present",
			setup: func(c *gin.Context) {
				tp, _ := setupTracingTest()
				tracer := tp.Tracer("test")
				_, span := tracer.Start(context.Background(), "test-span")
				c.Set(SpanKey, span)
			},
			expected: true,
		},
		{
			name: "returns nil when span not present",
			setup: func(c *gin.Context) {
				// Don't set any span
			},
			expected: false,
		},
		{
			name: "returns nil when wrong type stored",
			setup: func(c *gin.Context) {
				c.Set(SpanKey, "not-a-span")
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			tt.setup(c)

			span := GetSpan(c)
			if tt.expected {
				assert.NotNil(t, span)
			} else {
				assert.Nil(t, span)
			}
		})
	}
}

func TestAddSpanAttribute(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     interface{}
		hasSpan   bool
		checkAttr func(t *testing.T, span sdktrace.ReadOnlySpan)
	}{
		{
			name:    "adds string attribute",
			key:     "test.string",
			value:   "test-value",
			hasSpan: true,
			checkAttr: func(t *testing.T, span sdktrace.ReadOnlySpan) {
				assertAttributeExists(t, span.Attributes(), "test.string", "test-value")
			},
		},
		{
			name:    "adds int attribute",
			key:     "test.int",
			value:   42,
			hasSpan: true,
			checkAttr: func(t *testing.T, span sdktrace.ReadOnlySpan) {
				assertAttributeExistsInt(t, span.Attributes(), "test.int", 42)
			},
		},
		{
			name:    "adds int64 attribute",
			key:     "test.int64",
			value:   int64(9999999999),
			hasSpan: true,
			checkAttr: func(t *testing.T, span sdktrace.ReadOnlySpan) {
				assertAttributeExistsInt64(t, span.Attributes(), "test.int64", 9999999999)
			},
		},
		{
			name:    "adds float64 attribute",
			key:     "test.float",
			value:   3.14,
			hasSpan: true,
			checkAttr: func(t *testing.T, span sdktrace.ReadOnlySpan) {
				assertAttributeExistsFloat64(t, span.Attributes(), "test.float", 3.14)
			},
		},
		{
			name:    "adds bool attribute",
			key:     "test.bool",
			value:   true,
			hasSpan: true,
			checkAttr: func(t *testing.T, span sdktrace.ReadOnlySpan) {
				assertAttributeExistsBool(t, span.Attributes(), "test.bool", true)
			},
		},
		{
			name:    "converts unknown type to string",
			key:     "test.unknown",
			value:   struct{ Name string }{Name: "test"},
			hasSpan: true,
			checkAttr: func(t *testing.T, span sdktrace.ReadOnlySpan) {
				assertAttributeExists(t, span.Attributes(), "test.unknown", "{test}")
			},
		},
		{
			name:      "does nothing when no span",
			key:       "test.key",
			value:     "value",
			hasSpan:   false,
			checkAttr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, spanRecorder := setupTracingTest()
			defer tp.Shutdown(context.Background())

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			if tt.hasSpan {
				tracer := tp.Tracer("test")
				_, span := tracer.Start(context.Background(), "test-span")
				c.Set(SpanKey, span)

				AddSpanAttribute(c, tt.key, tt.value)

				span.End()
				tp.ForceFlush(context.Background())

				spans := spanRecorder.Ended()
				require.Len(t, spans, 1)
				if tt.checkAttr != nil {
					tt.checkAttr(t, spans[0])
				}
			} else {
				// Should not panic when no span
				AddSpanAttribute(c, tt.key, tt.value)
			}
		})
	}
}

func TestAddSpanEvent(t *testing.T) {
	tests := []struct {
		name       string
		eventName  string
		attrs      []attribute.KeyValue
		hasSpan    bool
		checkEvent func(t *testing.T, span sdktrace.ReadOnlySpan)
	}{
		{
			name:      "adds event without attributes",
			eventName: "test-event",
			attrs:     nil,
			hasSpan:   true,
			checkEvent: func(t *testing.T, span sdktrace.ReadOnlySpan) {
				events := span.Events()
				require.Len(t, events, 1)
				assert.Equal(t, "test-event", events[0].Name)
			},
		},
		{
			name:      "adds event with attributes",
			eventName: "user-action",
			attrs: []attribute.KeyValue{
				attribute.String("action", "click"),
				attribute.Int("count", 5),
			},
			hasSpan: true,
			checkEvent: func(t *testing.T, span sdktrace.ReadOnlySpan) {
				events := span.Events()
				require.Len(t, events, 1)
				assert.Equal(t, "user-action", events[0].Name)
				assert.Len(t, events[0].Attributes, 2)
			},
		},
		{
			name:       "does nothing when no span",
			eventName:  "test-event",
			attrs:      nil,
			hasSpan:    false,
			checkEvent: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, spanRecorder := setupTracingTest()
			defer tp.Shutdown(context.Background())

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			if tt.hasSpan {
				tracer := tp.Tracer("test")
				_, span := tracer.Start(context.Background(), "test-span")
				c.Set(SpanKey, span)

				AddSpanEvent(c, tt.eventName, tt.attrs...)

				span.End()
				tp.ForceFlush(context.Background())

				spans := spanRecorder.Ended()
				require.Len(t, spans, 1)
				if tt.checkEvent != nil {
					tt.checkEvent(t, spans[0])
				}
			} else {
				// Should not panic when no span
				AddSpanEvent(c, tt.eventName, tt.attrs...)
			}
		})
	}
}

func TestRecordSpanError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		hasSpan    bool
		checkError func(t *testing.T, span sdktrace.ReadOnlySpan)
	}{
		{
			name:    "records error on span",
			err:     errors.New("test error"),
			hasSpan: true,
			checkError: func(t *testing.T, span sdktrace.ReadOnlySpan) {
				events := span.Events()
				hasErrorEvent := false
				for _, event := range events {
					if event.Name == "exception" {
						hasErrorEvent = true
						break
					}
				}
				assert.True(t, hasErrorEvent, "expected exception event")
			},
		},
		{
			name:       "does nothing when no span",
			err:        errors.New("test error"),
			hasSpan:    false,
			checkError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, spanRecorder := setupTracingTest()
			defer tp.Shutdown(context.Background())

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			if tt.hasSpan {
				tracer := tp.Tracer("test")
				_, span := tracer.Start(context.Background(), "test-span")
				c.Set(SpanKey, span)

				RecordSpanError(c, tt.err)

				span.End()
				tp.ForceFlush(context.Background())

				spans := spanRecorder.Ended()
				require.Len(t, spans, 1)
				if tt.checkError != nil {
					tt.checkError(t, spans[0])
				}
			} else {
				// Should not panic when no span
				RecordSpanError(c, tt.err)
			}
		})
	}
}

func TestTracingConstants(t *testing.T) {
	assert.Equal(t, "avapigw", TracerName)
	assert.Equal(t, "otel-span", SpanKey)
}

func TestTracingWithConfig_SpanStatus(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		expectError  bool
		expectStatus codes.Code
	}{
		{
			name:        "200 OK - no error",
			statusCode:  http.StatusOK,
			expectError: false,
		},
		{
			name:        "201 Created - no error",
			statusCode:  http.StatusCreated,
			expectError: false,
		},
		{
			name:        "400 Bad Request - no error attribute",
			statusCode:  http.StatusBadRequest,
			expectError: false,
		},
		{
			name:        "404 Not Found - no error attribute",
			statusCode:  http.StatusNotFound,
			expectError: false,
		},
		{
			name:        "500 Internal Server Error - error attribute set",
			statusCode:  http.StatusInternalServerError,
			expectError: true,
		},
		{
			name:        "502 Bad Gateway - error attribute set",
			statusCode:  http.StatusBadGateway,
			expectError: true,
		},
		{
			name:        "503 Service Unavailable - error attribute set",
			statusCode:  http.StatusServiceUnavailable,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, spanRecorder := setupTracingTest()
			defer tp.Shutdown(context.Background())

			router := gin.New()
			router.Use(TracingWithConfig(TracingConfig{
				TracerProvider: tp,
				ServiceName:    "test",
			}))
			router.GET("/test", func(c *gin.Context) {
				c.Status(tt.statusCode)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.statusCode, w.Code)

			tp.ForceFlush(context.Background())
			spans := spanRecorder.Ended()
			require.Len(t, spans, 1)

			if tt.expectError {
				attrs := spans[0].Attributes()
				assertAttributeExistsBool(t, attrs, "error", true)
			}
		})
	}
}

func TestTracingWithConfig_HTTPAttributes(t *testing.T) {
	tp, spanRecorder := setupTracingTest()
	defer tp.Shutdown(context.Background())

	router := gin.New()
	router.Use(TracingWithConfig(TracingConfig{
		TracerProvider: tp,
		ServiceName:    "test",
	}))
	router.GET("/api/users", func(c *gin.Context) {
		c.String(http.StatusOK, "response body")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users?query=test", nil)
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.Host = "example.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	tp.ForceFlush(context.Background())
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	attrs := spans[0].Attributes()
	assertAttributeExists(t, attrs, "http.method", "GET")
	assertAttributeExists(t, attrs, "http.target", "/api/users")
	assertAttributeExists(t, attrs, "http.host", "example.com")
	assertAttributeExists(t, attrs, "http.user_agent", "test-agent/1.0")
}

// Helper functions for attribute assertions
func assertAttributeExists(t *testing.T, attrs []attribute.KeyValue, key, expectedValue string) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			assert.Equal(t, expectedValue, attr.Value.AsString())
			return
		}
	}
	t.Errorf("attribute %s not found", key)
}

func assertAttributeExistsInt(t *testing.T, attrs []attribute.KeyValue, key string, expectedValue int) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			assert.Equal(t, int64(expectedValue), attr.Value.AsInt64())
			return
		}
	}
	t.Errorf("attribute %s not found", key)
}

func assertAttributeExistsInt64(t *testing.T, attrs []attribute.KeyValue, key string, expectedValue int64) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			assert.Equal(t, expectedValue, attr.Value.AsInt64())
			return
		}
	}
	t.Errorf("attribute %s not found", key)
}

func assertAttributeExistsFloat64(t *testing.T, attrs []attribute.KeyValue, key string, expectedValue float64) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			assert.InDelta(t, expectedValue, attr.Value.AsFloat64(), 0.001)
			return
		}
	}
	t.Errorf("attribute %s not found", key)
}

func assertAttributeExistsBool(t *testing.T, attrs []attribute.KeyValue, key string, expectedValue bool) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			assert.Equal(t, expectedValue, attr.Value.AsBool())
			return
		}
	}
	t.Errorf("attribute %s not found", key)
}
