// Package logging provides structured logging for the API Gateway.
package logging

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewContextFields(t *testing.T) {
	cf := NewContextFields()
	assert.NotNil(t, cf)
	assert.NotNil(t, cf.fields)
	assert.Empty(t, cf.fields)
}

func TestContextFields_Set(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value interface{}
	}{
		{
			name:  "set string value",
			key:   "key1",
			value: "value1",
		},
		{
			name:  "set int value",
			key:   "key2",
			value: 42,
		},
		{
			name:  "set bool value",
			key:   "key3",
			value: true,
		},
		{
			name:  "set nil value",
			key:   "key4",
			value: nil,
		},
		{
			name:  "set slice value",
			key:   "key5",
			value: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := NewContextFields()
			result := cf.Set(tt.key, tt.value)

			// Should return self for chaining
			assert.Same(t, cf, result)

			// Value should be stored
			val, ok := cf.fields[tt.key]
			assert.True(t, ok)
			assert.Equal(t, tt.value, val)
		})
	}
}

func TestContextFields_Get(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*ContextFields)
		key     string
		wantVal interface{}
		wantOk  bool
	}{
		{
			name: "get existing key",
			setup: func(cf *ContextFields) {
				cf.Set("key1", "value1")
			},
			key:     "key1",
			wantVal: "value1",
			wantOk:  true,
		},
		{
			name:    "get non-existing key",
			setup:   func(cf *ContextFields) {},
			key:     "nonexistent",
			wantVal: nil,
			wantOk:  false,
		},
		{
			name: "get nil value",
			setup: func(cf *ContextFields) {
				cf.Set("nilkey", nil)
			},
			key:     "nilkey",
			wantVal: nil,
			wantOk:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := NewContextFields()
			tt.setup(cf)

			val, ok := cf.Get(tt.key)
			assert.Equal(t, tt.wantOk, ok)
			assert.Equal(t, tt.wantVal, val)
		})
	}
}

func TestContextFields_Delete(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*ContextFields)
		key   string
	}{
		{
			name: "delete existing key",
			setup: func(cf *ContextFields) {
				cf.Set("key1", "value1")
			},
			key: "key1",
		},
		{
			name:  "delete non-existing key",
			setup: func(cf *ContextFields) {},
			key:   "nonexistent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := NewContextFields()
			tt.setup(cf)

			result := cf.Delete(tt.key)

			// Should return self for chaining
			assert.Same(t, cf, result)

			// Key should not exist
			_, ok := cf.fields[tt.key]
			assert.False(t, ok)
		})
	}
}

func TestContextFields_ToZapFields(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*ContextFields)
		wantLen int
	}{
		{
			name:    "empty fields",
			setup:   func(cf *ContextFields) {},
			wantLen: 0,
		},
		{
			name: "single field",
			setup: func(cf *ContextFields) {
				cf.Set("key1", "value1")
			},
			wantLen: 1,
		},
		{
			name: "multiple fields",
			setup: func(cf *ContextFields) {
				cf.Set("key1", "value1")
				cf.Set("key2", 42)
				cf.Set("key3", true)
			},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := NewContextFields()
			tt.setup(cf)

			fields := cf.ToZapFields()
			assert.Len(t, fields, tt.wantLen)
		})
	}
}

func TestContextWithFields(t *testing.T) {
	cf := NewContextFields()
	cf.Set("request_id", "123")

	ctx := context.Background()
	ctxWithFields := ContextWithFields(ctx, cf)

	assert.NotNil(t, ctxWithFields)
	assert.NotEqual(t, ctx, ctxWithFields)

	// Verify fields can be retrieved
	retrieved := ctxWithFields.Value(fieldsKey)
	assert.NotNil(t, retrieved)
	assert.Same(t, cf, retrieved)
}

func TestFieldsFromContext(t *testing.T) {
	tests := []struct {
		name     string
		setupCtx func() context.Context
		wantLen  int
	}{
		{
			name: "with context fields",
			setupCtx: func() context.Context {
				cf := NewContextFields()
				cf.Set("key1", "value1")
				cf.Set("key2", 42)
				return ContextWithFields(context.Background(), cf)
			},
			wantLen: 2,
		},
		{
			name: "without context fields",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			fields := FieldsFromContext(ctx)

			if tt.wantLen == 0 {
				assert.Nil(t, fields)
			} else {
				assert.Len(t, fields, tt.wantLen)
			}
		})
	}
}

func TestGetContextFields(t *testing.T) {
	tests := []struct {
		name     string
		setupCtx func() context.Context
		wantNew  bool
	}{
		{
			name: "returns existing fields",
			setupCtx: func() context.Context {
				cf := NewContextFields()
				cf.Set("key1", "value1")
				return ContextWithFields(context.Background(), cf)
			},
			wantNew: false,
		},
		{
			name: "returns new fields when not in context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantNew: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			cf := GetContextFields(ctx)

			assert.NotNil(t, cf)
			if tt.wantNew {
				assert.Empty(t, cf.fields)
			}
		})
	}
}

func TestAddField(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value interface{}
	}{
		{
			name:  "add string field",
			key:   "request_id",
			value: "123",
		},
		{
			name:  "add int field",
			key:   "count",
			value: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			newCtx := AddField(ctx, tt.key, tt.value)

			assert.NotEqual(t, ctx, newCtx)

			cf := GetContextFields(newCtx)
			val, ok := cf.Get(tt.key)
			assert.True(t, ok)
			assert.Equal(t, tt.value, val)
		})
	}
}

func TestFieldConstructors(t *testing.T) {
	t.Run("RequestID", func(t *testing.T) {
		field := RequestID("test-123")
		assert.Equal(t, FieldRequestID, field.Key)
	})

	t.Run("Method", func(t *testing.T) {
		field := Method("GET")
		assert.Equal(t, FieldMethod, field.Key)
	})

	t.Run("Path", func(t *testing.T) {
		field := Path("/api/v1/users")
		assert.Equal(t, FieldPath, field.Key)
	})

	t.Run("Query", func(t *testing.T) {
		field := Query("page=1&limit=10")
		assert.Equal(t, FieldQuery, field.Key)
	})

	t.Run("ClientIP", func(t *testing.T) {
		field := ClientIP("192.168.1.1")
		assert.Equal(t, FieldClientIP, field.Key)
	})

	t.Run("UserAgent", func(t *testing.T) {
		field := UserAgent("Mozilla/5.0")
		assert.Equal(t, FieldUserAgent, field.Key)
	})

	t.Run("Host", func(t *testing.T) {
		field := Host("example.com")
		assert.Equal(t, FieldHost, field.Key)
	})

	t.Run("Scheme", func(t *testing.T) {
		field := Scheme("https")
		assert.Equal(t, FieldScheme, field.Key)
	})

	t.Run("Protocol", func(t *testing.T) {
		field := Protocol("HTTP/1.1")
		assert.Equal(t, FieldProtocol, field.Key)
	})

	t.Run("ContentLength", func(t *testing.T) {
		field := ContentLength(1024)
		assert.Equal(t, FieldContentLength, field.Key)
	})

	t.Run("ContentType", func(t *testing.T) {
		field := ContentType("application/json")
		assert.Equal(t, FieldContentType, field.Key)
	})

	t.Run("StatusCode", func(t *testing.T) {
		field := StatusCode(200)
		assert.Equal(t, FieldStatusCode, field.Key)
	})

	t.Run("ResponseSize", func(t *testing.T) {
		field := ResponseSize(512)
		assert.Equal(t, FieldResponseSize, field.Key)
	})

	t.Run("Latency", func(t *testing.T) {
		field := Latency(100 * time.Millisecond)
		assert.Equal(t, FieldLatency, field.Key)
	})

	t.Run("LatencyMS", func(t *testing.T) {
		field := LatencyMS(100 * time.Millisecond)
		assert.Equal(t, FieldLatencyMS, field.Key)
	})

	t.Run("TraceID", func(t *testing.T) {
		field := TraceID("trace-123")
		assert.Equal(t, FieldTraceID, field.Key)
	})

	t.Run("SpanID", func(t *testing.T) {
		field := SpanID("span-456")
		assert.Equal(t, FieldSpanID, field.Key)
	})

	t.Run("Err", func(t *testing.T) {
		field := Err(errors.New("test error"))
		assert.Equal(t, "error", field.Key)
	})

	t.Run("ErrorType", func(t *testing.T) {
		field := ErrorType("validation_error")
		assert.Equal(t, FieldErrorType, field.Key)
	})

	t.Run("ErrorStack", func(t *testing.T) {
		field := ErrorStack("stack trace here")
		assert.Equal(t, FieldErrorStack, field.Key)
	})

	t.Run("Service", func(t *testing.T) {
		field := Service("user-service")
		assert.Equal(t, FieldService, field.Key)
	})

	t.Run("Version", func(t *testing.T) {
		field := Version("1.0.0")
		assert.Equal(t, FieldVersion, field.Key)
	})

	t.Run("Environment", func(t *testing.T) {
		field := Environment("production")
		assert.Equal(t, FieldEnvironment, field.Key)
	})

	t.Run("Component", func(t *testing.T) {
		field := Component("gateway")
		assert.Equal(t, FieldComponent, field.Key)
	})

	t.Run("Backend", func(t *testing.T) {
		field := Backend("backend-service")
		assert.Equal(t, FieldBackend, field.Key)
	})

	t.Run("BackendHost", func(t *testing.T) {
		field := BackendHost("backend.example.com")
		assert.Equal(t, FieldBackendHost, field.Key)
	})

	t.Run("BackendLatency", func(t *testing.T) {
		field := BackendLatency(50 * time.Millisecond)
		assert.Equal(t, FieldBackendLatency, field.Key)
	})

	t.Run("UserID", func(t *testing.T) {
		field := UserID("user-123")
		assert.Equal(t, FieldUserID, field.Key)
	})

	t.Run("Username", func(t *testing.T) {
		field := Username("john.doe")
		assert.Equal(t, FieldUsername, field.Key)
	})

	t.Run("AuthType", func(t *testing.T) {
		field := AuthType("jwt")
		assert.Equal(t, FieldAuthType, field.Key)
	})

	t.Run("Roles", func(t *testing.T) {
		field := Roles([]string{"admin", "user"})
		assert.Equal(t, FieldRoles, field.Key)
	})

	t.Run("GRPCService", func(t *testing.T) {
		field := GRPCService("UserService")
		assert.Equal(t, FieldGRPCService, field.Key)
	})

	t.Run("GRPCMethod", func(t *testing.T) {
		field := GRPCMethod("GetUser")
		assert.Equal(t, FieldGRPCMethod, field.Key)
	})

	t.Run("GRPCCode", func(t *testing.T) {
		field := GRPCCode(0)
		assert.Equal(t, FieldGRPCCode, field.Key)
	})
}

func TestHTTPRequestFields(t *testing.T) {
	tests := []struct {
		name        string
		setupReq    func() *http.Request
		minFields   int
		checkFields func(t *testing.T, fields []zap.Field)
	}{
		{
			name: "basic GET request",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/v1/users", nil)
				req.Header.Set("User-Agent", "test-agent")
				return req
			},
			minFields: 5, // method, path, host, user_agent, protocol
			checkFields: func(t *testing.T, fields []zap.Field) {
				hasMethod := false
				hasPath := false
				for _, f := range fields {
					if f.Key == FieldMethod {
						hasMethod = true
					}
					if f.Key == FieldPath {
						hasPath = true
					}
				}
				assert.True(t, hasMethod)
				assert.True(t, hasPath)
			},
		},
		{
			name: "request with query string",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/v1/users?page=1&limit=10", nil)
				return req
			},
			minFields: 5,
			checkFields: func(t *testing.T, fields []zap.Field) {
				hasQuery := false
				for _, f := range fields {
					if f.Key == FieldQuery {
						hasQuery = true
					}
				}
				assert.True(t, hasQuery)
			},
		},
		{
			name: "request with content length",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("POST", "/api/v1/users", nil)
				req.ContentLength = 1024
				return req
			},
			minFields: 5,
			checkFields: func(t *testing.T, fields []zap.Field) {
				hasContentLength := false
				for _, f := range fields {
					if f.Key == FieldContentLength {
						hasContentLength = true
					}
				}
				assert.True(t, hasContentLength)
			},
		},
		{
			name: "request with content type",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("POST", "/api/v1/users", nil)
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			minFields: 5,
			checkFields: func(t *testing.T, fields []zap.Field) {
				hasContentType := false
				for _, f := range fields {
					if f.Key == FieldContentType {
						hasContentType = true
					}
				}
				assert.True(t, hasContentType)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			fields := HTTPRequestFields(req)

			assert.GreaterOrEqual(t, len(fields), tt.minFields)
			tt.checkFields(t, fields)
		})
	}
}

func TestHTTPResponseFields(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		responseSize int
		latency      time.Duration
	}{
		{
			name:         "successful response",
			statusCode:   200,
			responseSize: 1024,
			latency:      100 * time.Millisecond,
		},
		{
			name:         "error response",
			statusCode:   500,
			responseSize: 64,
			latency:      5 * time.Second,
		},
		{
			name:         "not found response",
			statusCode:   404,
			responseSize: 32,
			latency:      10 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := HTTPResponseFields(tt.statusCode, tt.responseSize, tt.latency)

			require.Len(t, fields, 4) // status_code, response_size, latency, latency_ms

			hasStatusCode := false
			hasResponseSize := false
			hasLatency := false
			hasLatencyMS := false

			for _, f := range fields {
				switch f.Key {
				case FieldStatusCode:
					hasStatusCode = true
				case FieldResponseSize:
					hasResponseSize = true
				case FieldLatency:
					hasLatency = true
				case FieldLatencyMS:
					hasLatencyMS = true
				}
			}

			assert.True(t, hasStatusCode)
			assert.True(t, hasResponseSize)
			assert.True(t, hasLatency)
			assert.True(t, hasLatencyMS)
		})
	}
}

func TestGenericFieldConstructors(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		field := String("custom_key", "custom_value")
		assert.Equal(t, "custom_key", field.Key)
	})

	t.Run("Int", func(t *testing.T) {
		field := Int("count", 42)
		assert.Equal(t, "count", field.Key)
	})

	t.Run("Int64", func(t *testing.T) {
		field := Int64("big_count", 9223372036854775807)
		assert.Equal(t, "big_count", field.Key)
	})

	t.Run("Float64", func(t *testing.T) {
		field := Float64("ratio", 3.14159)
		assert.Equal(t, "ratio", field.Key)
	})

	t.Run("Bool", func(t *testing.T) {
		field := Bool("enabled", true)
		assert.Equal(t, "enabled", field.Key)
	})

	t.Run("Duration", func(t *testing.T) {
		field := Duration("timeout", 30*time.Second)
		assert.Equal(t, "timeout", field.Key)
	})

	t.Run("Time", func(t *testing.T) {
		now := time.Now()
		field := Time("timestamp", now)
		assert.Equal(t, "timestamp", field.Key)
	})

	t.Run("Any", func(t *testing.T) {
		field := Any("data", map[string]int{"a": 1, "b": 2})
		assert.Equal(t, "data", field.Key)
	})

	t.Run("Strings", func(t *testing.T) {
		field := Strings("tags", []string{"tag1", "tag2"})
		assert.Equal(t, "tags", field.Key)
	})

	t.Run("Ints", func(t *testing.T) {
		field := Ints("ids", []int{1, 2, 3})
		assert.Equal(t, "ids", field.Key)
	})
}

type testStringer struct {
	value string
}

func (ts testStringer) String() string {
	return ts.value
}

func TestStringer(t *testing.T) {
	ts := testStringer{value: "test-value"}
	field := Stringer("stringer_field", ts)
	assert.Equal(t, "stringer_field", field.Key)
}

func TestContextFields_Chaining(t *testing.T) {
	cf := NewContextFields()

	// Test method chaining
	result := cf.
		Set("key1", "value1").
		Set("key2", 42).
		Set("key3", true).
		Delete("key2").
		Set("key4", "value4")

	assert.Same(t, cf, result)

	// Verify final state
	_, ok := cf.Get("key1")
	assert.True(t, ok)

	_, ok = cf.Get("key2")
	assert.False(t, ok)

	_, ok = cf.Get("key3")
	assert.True(t, ok)

	_, ok = cf.Get("key4")
	assert.True(t, ok)
}
