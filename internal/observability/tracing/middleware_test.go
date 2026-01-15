// Package tracing provides OpenTelemetry tracing for the API Gateway.
package tracing

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// setupMiddlewareTestTracer sets up a test tracer provider for middleware tests.
func setupMiddlewareTestTracer(t *testing.T) (*tracetest.InMemoryExporter, *sdktrace.TracerProvider, func()) {
	t.Helper()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Save original provider and propagator
	originalProvider := otel.GetTracerProvider()
	originalPropagator := otel.GetTextMapPropagator()

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	cleanup := func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(originalProvider)
		otel.SetTextMapPropagator(originalPropagator)
	}

	return exporter, tp, cleanup
}

// TestDefaultHTTPMiddlewareConfig tests default config.
func TestDefaultHTTPMiddlewareConfig(t *testing.T) {
	tests := []struct {
		name     string
		validate func(t *testing.T, cfg *HTTPMiddlewareConfig)
	}{
		{
			name: "returns non-nil config",
			validate: func(t *testing.T, cfg *HTTPMiddlewareConfig) {
				assert.NotNil(t, cfg)
			},
		},
		{
			name: "has service name",
			validate: func(t *testing.T, cfg *HTTPMiddlewareConfig) {
				assert.Equal(t, TracerName, cfg.ServiceName)
			},
		},
		{
			name: "has span name formatter",
			validate: func(t *testing.T, cfg *HTTPMiddlewareConfig) {
				assert.NotNil(t, cfg.SpanNameFormatter)
			},
		},
		{
			name: "span name formatter works",
			validate: func(t *testing.T, cfg *HTTPMiddlewareConfig) {
				req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
				name := cfg.SpanNameFormatter(req)
				assert.Equal(t, "GET /api/test", name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultHTTPMiddlewareConfig()
			tt.validate(t, cfg)
		})
	}
}

// TestHTTPMiddleware tests HTTP middleware.
func TestHTTPMiddleware(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	tests := []struct {
		name           string
		method         string
		path           string
		handler        http.HandlerFunc
		expectedStatus int
	}{
		{
			name:   "successful request",
			method: http.MethodGet,
			path:   "/api/test",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "error request",
			method: http.MethodPost,
			path:   "/api/error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("Error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:   "not found request",
			method: http.MethodGet,
			path:   "/api/notfound",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			middleware := HTTPMiddleware("test-service")
			handler := middleware(tt.handler)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)
		})
	}
}

// TestHTTPMiddlewareWithConfig tests with config.
func TestHTTPMiddlewareWithConfig(t *testing.T) {
	exporter, tp, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	tests := []struct {
		name           string
		config         *HTTPMiddlewareConfig
		method         string
		path           string
		expectSpan     bool
		expectedStatus int
	}{
		{
			name:           "nil config uses defaults",
			config:         nil,
			method:         http.MethodGet,
			path:           "/api/test",
			expectSpan:     true,
			expectedStatus: http.StatusOK,
		},
		{
			name: "skip paths",
			config: &HTTPMiddlewareConfig{
				ServiceName: "test",
				SkipPaths:   []string{"/health", "/ready"},
			},
			method:         http.MethodGet,
			path:           "/health",
			expectSpan:     false,
			expectedStatus: http.StatusOK,
		},
		{
			name: "filter returns false",
			config: &HTTPMiddlewareConfig{
				ServiceName: "test",
				Filter: func(r *http.Request) bool {
					return r.URL.Path != "/skip"
				},
			},
			method:         http.MethodGet,
			path:           "/skip",
			expectSpan:     false,
			expectedStatus: http.StatusOK,
		},
		{
			name: "filter returns true",
			config: &HTTPMiddlewareConfig{
				ServiceName: "test",
				Filter: func(r *http.Request) bool {
					return true
				},
			},
			method:         http.MethodGet,
			path:           "/api/test",
			expectSpan:     true,
			expectedStatus: http.StatusOK,
		},
		{
			name: "custom tracer provider",
			config: &HTTPMiddlewareConfig{
				ServiceName:    "test",
				TracerProvider: tp,
			},
			method:         http.MethodGet,
			path:           "/api/test",
			expectSpan:     true,
			expectedStatus: http.StatusOK,
		},
		{
			name: "custom propagators",
			config: &HTTPMiddlewareConfig{
				ServiceName: "test",
				Propagators: propagation.TraceContext{},
			},
			method:         http.MethodGet,
			path:           "/api/test",
			expectSpan:     true,
			expectedStatus: http.StatusOK,
		},
		{
			name: "custom span name formatter",
			config: &HTTPMiddlewareConfig{
				ServiceName: "test",
				SpanNameFormatter: func(r *http.Request) string {
					return "custom-" + r.Method
				},
			},
			method:         http.MethodGet,
			path:           "/api/test",
			expectSpan:     true,
			expectedStatus: http.StatusOK,
		},
		{
			name: "empty service name uses default",
			config: &HTTPMiddlewareConfig{
				ServiceName: "",
			},
			method:         http.MethodGet,
			path:           "/api/test",
			expectSpan:     true,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			handler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}

			middleware := HTTPMiddlewareWithConfig(tt.config)
			wrappedHandler := middleware(http.HandlerFunc(handler))

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			spans := exporter.GetSpans()
			if tt.expectSpan {
				require.NotEmpty(t, spans)
			} else {
				assert.Empty(t, spans)
			}
		})
	}
}

// TestHTTPMiddleware_StatusCodes tests status code handling.
func TestHTTPMiddleware_StatusCodes(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	tests := []struct {
		name         string
		statusCode   int
		expectedCode codes.Code
	}{
		{
			name:         "200 OK",
			statusCode:   http.StatusOK,
			expectedCode: codes.Ok,
		},
		{
			name:         "201 Created",
			statusCode:   http.StatusCreated,
			expectedCode: codes.Ok,
		},
		{
			name:         "400 Bad Request",
			statusCode:   http.StatusBadRequest,
			expectedCode: codes.Error,
		},
		{
			name:         "404 Not Found",
			statusCode:   http.StatusNotFound,
			expectedCode: codes.Error,
		},
		{
			name:         "500 Internal Server Error",
			statusCode:   http.StatusInternalServerError,
			expectedCode: codes.Error,
		},
		{
			name:         "503 Service Unavailable",
			statusCode:   http.StatusServiceUnavailable,
			expectedCode: codes.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			handler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}

			middleware := HTTPMiddleware("test-service")
			wrappedHandler := middleware(http.HandlerFunc(handler))

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			rec := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rec, req)

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.Equal(t, tt.expectedCode, spans[0].Status.Code)
		})
	}
}

// TestGinMiddleware tests Gin middleware.
func TestGinMiddleware(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		method         string
		path           string
		handler        gin.HandlerFunc
		expectedStatus int
	}{
		{
			name:   "successful request",
			method: http.MethodGet,
			path:   "/api/test",
			handler: func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "error request",
			method: http.MethodPost,
			path:   "/api/error",
			handler: func(c *gin.Context) {
				c.String(http.StatusInternalServerError, "Error")
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			router := gin.New()
			router.Use(GinMiddleware("test-service"))
			router.Handle(tt.method, tt.path, tt.handler)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)
		})
	}
}

// TestGinMiddlewareWithConfig tests with config.
func TestGinMiddlewareWithConfig(t *testing.T) {
	exporter, tp, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		config     *HTTPMiddlewareConfig
		path       string
		expectSpan bool
	}{
		{
			name:       "nil config uses defaults",
			config:     nil,
			path:       "/api/test",
			expectSpan: true,
		},
		{
			name: "skip paths",
			config: &HTTPMiddlewareConfig{
				ServiceName: "test",
				SkipPaths:   []string{"/health"},
			},
			path:       "/health",
			expectSpan: false,
		},
		{
			name: "filter returns false",
			config: &HTTPMiddlewareConfig{
				ServiceName: "test",
				Filter: func(r *http.Request) bool {
					return r.URL.Path != "/skip"
				},
			},
			path:       "/skip",
			expectSpan: false,
		},
		{
			name: "custom tracer provider",
			config: &HTTPMiddlewareConfig{
				ServiceName:    "test",
				TracerProvider: tp,
			},
			path:       "/api/test",
			expectSpan: true,
		},
		{
			name: "empty service name uses default",
			config: &HTTPMiddlewareConfig{
				ServiceName: "",
			},
			path:       "/api/test",
			expectSpan: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			router := gin.New()
			router.Use(GinMiddlewareWithConfig(tt.config))
			router.GET(tt.path, func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			spans := exporter.GetSpans()
			if tt.expectSpan {
				require.NotEmpty(t, spans)
			} else {
				assert.Empty(t, spans)
			}
		})
	}
}

// TestGinMiddleware_WithErrors tests Gin middleware with errors.
func TestGinMiddleware_WithErrors(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(GinMiddlewareWithConfig(nil))
	router.GET("/api/error", func(c *gin.Context) {
		_ = c.Error(errors.New("test error"))
		c.String(http.StatusInternalServerError, "Error")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/error", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)
}

// TestGetSpanFromGin tests getting span from Gin context.
func TestGetSpanFromGin(t *testing.T) {
	_, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		setupCtx   func(c *gin.Context)
		expectSpan bool
	}{
		{
			name: "span exists in context",
			setupCtx: func(c *gin.Context) {
				_, span := StartSpan(context.Background(), "test-span")
				c.Set(SpanContextKey, span)
			},
			expectSpan: true,
		},
		{
			name: "span does not exist",
			setupCtx: func(c *gin.Context) {
				// Don't set span
			},
			expectSpan: false,
		},
		{
			name: "wrong type in context",
			setupCtx: func(c *gin.Context) {
				c.Set(SpanContextKey, "not a span")
			},
			expectSpan: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			tt.setupCtx(c)

			span := GetSpanFromGin(c)
			if tt.expectSpan {
				assert.NotNil(t, span)
			} else {
				assert.Nil(t, span)
			}
		})
	}
}

// TestUnaryServerInterceptor tests unary server interceptor.
func TestUnaryServerInterceptor(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	tests := []struct {
		name        string
		fullMethod  string
		handlerErr  error
		expectError bool
	}{
		{
			name:        "successful call",
			fullMethod:  "/test.Service/Method",
			handlerErr:  nil,
			expectError: false,
		},
		{
			name:        "error call",
			fullMethod:  "/test.Service/ErrorMethod",
			handlerErr:  errors.New("handler error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			interceptor := UnaryServerInterceptor("test-service")

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return "response", tt.handlerErr
			}

			info := &grpc.UnaryServerInfo{
				FullMethod: tt.fullMethod,
			}

			ctx := context.Background()
			// Add metadata to context
			md := metadata.MD{}
			ctx = metadata.NewIncomingContext(ctx, md)

			resp, err := interceptor(ctx, "request", info, handler)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "response", resp)
			}

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)
		})
	}
}

// TestUnaryServerInterceptor_NoMetadata tests interceptor without metadata.
func TestUnaryServerInterceptor_NoMetadata(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	interceptor := UnaryServerInterceptor("test-service")

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	// Context without metadata
	ctx := context.Background()

	resp, err := interceptor(ctx, "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "response", resp)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
}

// TestStreamServerInterceptor tests stream server interceptor.
func TestStreamServerInterceptor(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	tests := []struct {
		name        string
		fullMethod  string
		handlerErr  error
		expectError bool
	}{
		{
			name:        "successful stream",
			fullMethod:  "/test.Service/StreamMethod",
			handlerErr:  nil,
			expectError: false,
		},
		{
			name:        "error stream",
			fullMethod:  "/test.Service/ErrorStream",
			handlerErr:  errors.New("stream error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			interceptor := StreamServerInterceptor("test-service")

			handler := func(srv interface{}, stream grpc.ServerStream) error {
				return tt.handlerErr
			}

			info := &grpc.StreamServerInfo{
				FullMethod:     tt.fullMethod,
				IsClientStream: true,
				IsServerStream: true,
			}

			// Create mock server stream
			ctx := context.Background()
			md := metadata.MD{}
			ctx = metadata.NewIncomingContext(ctx, md)
			mockStream := &mockServerStream{ctx: ctx}

			err := interceptor(nil, mockStream, info, handler)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.Equal(t, trace.SpanKindServer, spans[0].SpanKind)
		})
	}
}

// TestStreamServerInterceptor_NoMetadata tests stream interceptor without metadata.
func TestStreamServerInterceptor_NoMetadata(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	interceptor := StreamServerInterceptor("test-service")

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	// Context without metadata
	mockStream := &mockServerStream{ctx: context.Background()}

	err := interceptor(nil, mockStream, info, handler)

	assert.NoError(t, err)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
}

// TestUnaryClientInterceptor tests unary client interceptor.
func TestUnaryClientInterceptor(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	tests := []struct {
		name        string
		method      string
		invokerErr  error
		expectError bool
	}{
		{
			name:        "successful call",
			method:      "/test.Service/Method",
			invokerErr:  nil,
			expectError: false,
		},
		{
			name:        "error call",
			method:      "/test.Service/ErrorMethod",
			invokerErr:  errors.New("invoker error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter.Reset()

			interceptor := UnaryClientInterceptor("test-service")

			invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
				return tt.invokerErr
			}

			ctx := context.Background()
			err := interceptor(ctx, tt.method, "request", "reply", nil, invoker)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			spans := exporter.GetSpans()
			require.Len(t, spans, 1)
			assert.Equal(t, trace.SpanKindClient, spans[0].SpanKind)
		})
	}
}

// TestUnaryClientInterceptor_WithOutgoingMetadata tests client interceptor with existing metadata.
func TestUnaryClientInterceptor_WithOutgoingMetadata(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	interceptor := UnaryClientInterceptor("test-service")

	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		// Verify metadata was injected
		md, ok := metadata.FromOutgoingContext(ctx)
		assert.True(t, ok)
		assert.NotEmpty(t, md)
		return nil
	}

	// Context with existing metadata
	ctx := context.Background()
	md := metadata.MD{"existing-key": []string{"existing-value"}}
	ctx = metadata.NewOutgoingContext(ctx, md)

	err := interceptor(ctx, "/test.Service/Method", "request", "reply", nil, invoker)

	assert.NoError(t, err)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
}

// TestStreamClientInterceptor tests stream client interceptor.
func TestStreamClientInterceptor(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	t.Run("successful stream", func(t *testing.T) {
		exporter.Reset()

		interceptor := StreamClientInterceptor("test-service")

		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return &mockClientStream{}, nil
		}

		desc := &grpc.StreamDesc{
			ClientStreams: true,
			ServerStreams: true,
		}

		ctx := context.Background()
		stream, err := interceptor(ctx, desc, nil, "/test.Service/StreamMethod", streamer)

		assert.NoError(t, err)
		assert.NotNil(t, stream)

		// The span is not ended until RecvMsg returns an error (like io.EOF)
		// So we need to trigger that to see the span
		tracedStream, ok := stream.(*tracedClientStream)
		require.True(t, ok)
		tracedStream.span.End() // Manually end for testing

		spans := exporter.GetSpans()
		require.Len(t, spans, 1)
		assert.Equal(t, trace.SpanKindClient, spans[0].SpanKind)
	})

	t.Run("error stream", func(t *testing.T) {
		exporter.Reset()

		interceptor := StreamClientInterceptor("test-service")

		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return nil, errors.New("streamer error")
		}

		desc := &grpc.StreamDesc{
			ClientStreams: true,
			ServerStreams: true,
		}

		ctx := context.Background()
		stream, err := interceptor(ctx, desc, nil, "/test.Service/ErrorStream", streamer)

		assert.Error(t, err)
		assert.Nil(t, stream)

		spans := exporter.GetSpans()
		require.Len(t, spans, 1)
		assert.Equal(t, trace.SpanKindClient, spans[0].SpanKind)
	})
}

// TestStreamClientInterceptor_WithOutgoingMetadata tests stream client interceptor with existing metadata.
func TestStreamClientInterceptor_WithOutgoingMetadata(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	interceptor := StreamClientInterceptor("test-service")

	streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		// Verify metadata was injected
		md, ok := metadata.FromOutgoingContext(ctx)
		assert.True(t, ok)
		assert.NotEmpty(t, md)
		return &mockClientStream{}, nil
	}

	desc := &grpc.StreamDesc{}

	// Context with existing metadata
	ctx := context.Background()
	md := metadata.MD{"existing-key": []string{"existing-value"}}
	ctx = metadata.NewOutgoingContext(ctx, md)

	stream, err := interceptor(ctx, desc, nil, "/test.Service/Method", streamer)

	assert.NoError(t, err)
	assert.NotNil(t, stream)

	// The span is not ended until RecvMsg returns an error
	// So we need to manually end it for testing
	tracedStream, ok := stream.(*tracedClientStream)
	require.True(t, ok)
	tracedStream.span.End()

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
}

// TestParseFullMethod tests parsing gRPC method.
func TestParseFullMethod(t *testing.T) {
	tests := []struct {
		name           string
		fullMethod     string
		expectedSvc    string
		expectedMethod string
	}{
		{
			name:           "standard format",
			fullMethod:     "/package.Service/Method",
			expectedSvc:    "package.Service",
			expectedMethod: "Method",
		},
		{
			name:           "simple service",
			fullMethod:     "/Service/Method",
			expectedSvc:    "Service",
			expectedMethod: "Method",
		},
		{
			name:           "nested package",
			fullMethod:     "/com.example.api.v1.Service/GetUser",
			expectedSvc:    "com.example.api.v1.Service",
			expectedMethod: "GetUser",
		},
		{
			name:           "invalid format - no slashes",
			fullMethod:     "ServiceMethod",
			expectedSvc:    "",
			expectedMethod: "ServiceMethod",
		},
		{
			name:           "invalid format - single slash",
			fullMethod:     "/ServiceMethod",
			expectedSvc:    "",
			expectedMethod: "/ServiceMethod",
		},
		{
			name:           "empty string",
			fullMethod:     "",
			expectedSvc:    "",
			expectedMethod: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, method := parseFullMethod(tt.fullMethod)
			assert.Equal(t, tt.expectedSvc, svc)
			assert.Equal(t, tt.expectedMethod, method)
		})
	}
}

// TestGetClientIP tests getting client IP.
func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:       "X-Forwarded-For header",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.1, 10.0.0.1"},
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For single IP",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.1"},
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Real-IP header",
			headers:    map[string]string{"X-Real-IP": "10.0.0.1"},
			remoteAddr: "127.0.0.1:8080",
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.1", "X-Real-IP": "10.0.0.1"},
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.1",
		},
		{
			name:       "fallback to RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "127.0.0.1:8080",
			expected:   "127.0.0.1:8080",
		},
		{
			name:       "X-Forwarded-For with spaces",
			headers:    map[string]string{"X-Forwarded-For": "  192.168.1.1  , 10.0.0.1"},
			remoteAddr: "127.0.0.1:8080",
			expected:   "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := getClientIP(req)
			assert.Equal(t, tt.expected, ip)
		})
	}
}

// TestResponseWriter tests response writer wrapper.
func TestResponseWriter(t *testing.T) {
	t.Run("WriteHeader captures status code", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rw := &responseWriter{
			ResponseWriter: rec,
			statusCode:     http.StatusOK,
		}

		rw.WriteHeader(http.StatusNotFound)

		assert.Equal(t, http.StatusNotFound, rw.statusCode)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("Write captures size", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rw := &responseWriter{
			ResponseWriter: rec,
			statusCode:     http.StatusOK,
		}

		n, err := rw.Write([]byte("Hello, World!"))

		assert.NoError(t, err)
		assert.Equal(t, 13, n)
		assert.Equal(t, 13, rw.size)
	})

	t.Run("multiple writes accumulate size", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rw := &responseWriter{
			ResponseWriter: rec,
			statusCode:     http.StatusOK,
		}

		_, _ = rw.Write([]byte("Hello"))
		_, _ = rw.Write([]byte(", World!"))

		assert.Equal(t, 13, rw.size)
	})
}

// TestTracedServerStream tests traced server stream.
func TestTracedServerStream(t *testing.T) {
	ctx := context.Background()
	mockStream := &mockServerStream{ctx: context.Background()}

	tracedStream := &tracedServerStream{
		ServerStream: mockStream,
		ctx:          ctx,
	}

	assert.Equal(t, ctx, tracedStream.Context())
}

// TestTracedClientStream tests traced client stream.
func TestTracedClientStream(t *testing.T) {
	exporter, _, cleanup := setupMiddlewareTestTracer(t)
	defer cleanup()

	t.Run("CloseSend without error", func(t *testing.T) {
		exporter.Reset()

		_, span := StartSpan(context.Background(), "test-span")
		mockStream := &mockClientStream{}
		tracedStream := &tracedClientStream{
			ClientStream: mockStream,
			span:         span,
		}

		err := tracedStream.CloseSend()
		assert.NoError(t, err)
	})

	t.Run("CloseSend with error", func(t *testing.T) {
		exporter.Reset()

		_, span := StartSpan(context.Background(), "test-span")
		mockStream := &mockClientStream{closeSendErr: errors.New("close error")}
		tracedStream := &tracedClientStream{
			ClientStream: mockStream,
			span:         span,
		}

		err := tracedStream.CloseSend()
		assert.Error(t, err)
	})

	t.Run("RecvMsg without error", func(t *testing.T) {
		exporter.Reset()

		_, span := StartSpan(context.Background(), "test-span")
		mockStream := &mockClientStream{}
		tracedStream := &tracedClientStream{
			ClientStream: mockStream,
			span:         span,
		}

		err := tracedStream.RecvMsg(nil)
		assert.NoError(t, err)
	})

	t.Run("RecvMsg with error", func(t *testing.T) {
		exporter.Reset()

		_, span := StartSpan(context.Background(), "test-span")
		mockStream := &mockClientStream{recvMsgErr: io.EOF}
		tracedStream := &tracedClientStream{
			ClientStream: mockStream,
			span:         span,
		}

		err := tracedStream.RecvMsg(nil)
		assert.Error(t, err)
		span.End()
	})
}

// TestConstants tests middleware constants.
func TestConstants(t *testing.T) {
	assert.Equal(t, "avapigw", TracerName)
	assert.Equal(t, "otel-span", SpanContextKey)
}

// mockServerStream is a mock implementation of grpc.ServerStream.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

// mockClientStream is a mock implementation of grpc.ClientStream.
type mockClientStream struct {
	grpc.ClientStream
	closeSendErr error
	recvMsgErr   error
}

func (m *mockClientStream) CloseSend() error {
	return m.closeSendErr
}

func (m *mockClientStream) RecvMsg(msg interface{}) error {
	return m.recvMsgErr
}
