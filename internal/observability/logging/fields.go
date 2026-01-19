// Package logging provides structured logging for the API Gateway.
package logging

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Standard field keys
const (
	// Request fields
	FieldRequestID     = "request_id"
	FieldMethod        = "method"
	FieldPath          = "path"
	FieldQuery         = "query"
	FieldClientIP      = "client_ip"
	FieldUserAgent     = "user_agent"
	FieldHost          = "host"
	FieldScheme        = "scheme"
	FieldProtocol      = "protocol"
	FieldContentLength = "content_length"
	FieldContentType   = "content_type"

	// Response fields
	FieldStatusCode   = "status_code"
	FieldResponseSize = "response_size"
	FieldLatency      = "latency"
	FieldLatencyMS    = "latency_ms"

	// Tracing fields
	FieldTraceID = "trace_id"
	FieldSpanID  = "span_id"

	// Error fields
	FieldError      = "error"
	FieldErrorType  = "error_type"
	FieldErrorStack = "error_stack"

	// Service fields
	FieldService     = "service"
	FieldVersion     = "version"
	FieldEnvironment = "environment"
	FieldComponent   = "component"

	// Backend fields
	FieldBackend        = "backend"
	FieldBackendHost    = "backend_host"
	FieldBackendLatency = "backend_latency"

	// Auth fields
	FieldUserID   = "user_id"
	FieldUsername = "username"
	FieldAuthType = "auth_type"
	FieldRoles    = "roles"

	// gRPC fields
	FieldGRPCService = "grpc_service"
	FieldGRPCMethod  = "grpc_method"
	FieldGRPCCode    = "grpc_code"
)

// Context keys for storing fields
type contextFieldsKey struct{}

var fieldsKey = contextFieldsKey{}

// ContextFields holds fields to be added to log entries.
type ContextFields struct {
	fields map[string]interface{}
}

// NewContextFields creates a new ContextFields.
func NewContextFields() *ContextFields {
	return &ContextFields{
		fields: make(map[string]interface{}),
	}
}

// Set sets a field value.
func (cf *ContextFields) Set(key string, value interface{}) *ContextFields {
	cf.fields[key] = value
	return cf
}

// Get returns a field value.
func (cf *ContextFields) Get(key string) (interface{}, bool) {
	v, ok := cf.fields[key]
	return v, ok
}

// Delete removes a field.
func (cf *ContextFields) Delete(key string) *ContextFields {
	delete(cf.fields, key)
	return cf
}

// ToZapFields converts to zap fields.
func (cf *ContextFields) ToZapFields() []zap.Field {
	fields := make([]zap.Field, 0, len(cf.fields))
	for k, v := range cf.fields {
		fields = append(fields, zap.Any(k, v))
	}
	return fields
}

// ContextWithFields returns a new context with the fields.
func ContextWithFields(ctx context.Context, fields *ContextFields) context.Context {
	return context.WithValue(ctx, fieldsKey, fields)
}

// FieldsFromContext returns the fields from the context.
func FieldsFromContext(ctx context.Context) []zap.Field {
	if cf, ok := ctx.Value(fieldsKey).(*ContextFields); ok {
		return cf.ToZapFields()
	}
	return nil
}

// GetContextFields returns the ContextFields from the context.
func GetContextFields(ctx context.Context) *ContextFields {
	if cf, ok := ctx.Value(fieldsKey).(*ContextFields); ok {
		return cf
	}
	return NewContextFields()
}

// AddField adds a field to the context.
func AddField(ctx context.Context, key string, value interface{}) context.Context {
	cf := GetContextFields(ctx)
	cf.Set(key, value)
	return ContextWithFields(ctx, cf)
}

// Standard field constructors

// RequestID creates a request ID field.
func RequestID(id string) zap.Field {
	return zap.String(FieldRequestID, id)
}

// Method creates a method field.
func Method(method string) zap.Field {
	return zap.String(FieldMethod, method)
}

// Path creates a path field.
func Path(path string) zap.Field {
	return zap.String(FieldPath, path)
}

// Query creates a query field.
func Query(query string) zap.Field {
	return zap.String(FieldQuery, query)
}

// ClientIP creates a client IP field.
func ClientIP(ip string) zap.Field {
	return zap.String(FieldClientIP, ip)
}

// UserAgent creates a user agent field.
func UserAgent(ua string) zap.Field {
	return zap.String(FieldUserAgent, ua)
}

// Host creates a host field.
func Host(host string) zap.Field {
	return zap.String(FieldHost, host)
}

// Scheme creates a scheme field.
func Scheme(scheme string) zap.Field {
	return zap.String(FieldScheme, scheme)
}

// Protocol creates a protocol field.
func Protocol(proto string) zap.Field {
	return zap.String(FieldProtocol, proto)
}

// ContentLength creates a content length field.
func ContentLength(length int64) zap.Field {
	return zap.Int64(FieldContentLength, length)
}

// ContentType creates a content type field.
func ContentType(ct string) zap.Field {
	return zap.String(FieldContentType, ct)
}

// StatusCode creates a status code field.
func StatusCode(code int) zap.Field {
	return zap.Int(FieldStatusCode, code)
}

// ResponseSize creates a response size field.
func ResponseSize(size int) zap.Field {
	return zap.Int(FieldResponseSize, size)
}

// Latency creates a latency field.
func Latency(d time.Duration) zap.Field {
	return zap.Duration(FieldLatency, d)
}

// LatencyMS creates a latency field in milliseconds.
func LatencyMS(d time.Duration) zap.Field {
	return zap.Float64(FieldLatencyMS, float64(d.Milliseconds()))
}

// TraceID creates a trace ID field.
func TraceID(id string) zap.Field {
	return zap.String(FieldTraceID, id)
}

// SpanID creates a span ID field.
func SpanID(id string) zap.Field {
	return zap.String(FieldSpanID, id)
}

// Err creates an error field.
func Err(err error) zap.Field {
	return zap.Error(err)
}

// ErrorType creates an error type field.
func ErrorType(errType string) zap.Field {
	return zap.String(FieldErrorType, errType)
}

// ErrorStack creates an error stack field.
func ErrorStack(stack string) zap.Field {
	return zap.String(FieldErrorStack, stack)
}

// Service creates a service field.
func Service(name string) zap.Field {
	return zap.String(FieldService, name)
}

// Version creates a version field.
func Version(version string) zap.Field {
	return zap.String(FieldVersion, version)
}

// Environment creates an environment field.
func Environment(env string) zap.Field {
	return zap.String(FieldEnvironment, env)
}

// Component creates a component field.
func Component(name string) zap.Field {
	return zap.String(FieldComponent, name)
}

// Backend creates a backend field.
func Backend(name string) zap.Field {
	return zap.String(FieldBackend, name)
}

// BackendHost creates a backend host field.
func BackendHost(host string) zap.Field {
	return zap.String(FieldBackendHost, host)
}

// BackendLatency creates a backend latency field.
func BackendLatency(d time.Duration) zap.Field {
	return zap.Duration(FieldBackendLatency, d)
}

// UserID creates a user ID field.
func UserID(id string) zap.Field {
	return zap.String(FieldUserID, id)
}

// Username creates a username field.
func Username(name string) zap.Field {
	return zap.String(FieldUsername, name)
}

// AuthType creates an auth type field.
func AuthType(authType string) zap.Field {
	return zap.String(FieldAuthType, authType)
}

// Roles creates a roles field.
func Roles(roles []string) zap.Field {
	return zap.Strings(FieldRoles, roles)
}

// GRPCService creates a gRPC service field.
func GRPCService(service string) zap.Field {
	return zap.String(FieldGRPCService, service)
}

// GRPCMethod creates a gRPC method field.
func GRPCMethod(method string) zap.Field {
	return zap.String(FieldGRPCMethod, method)
}

// GRPCCode creates a gRPC code field.
func GRPCCode(code int) zap.Field {
	return zap.Int(FieldGRPCCode, code)
}

// HTTPRequestFields extracts standard fields from an HTTP request.
func HTTPRequestFields(r *http.Request) []zap.Field {
	fields := []zap.Field{
		Method(r.Method),
		Path(r.URL.Path),
		Host(r.Host),
		UserAgent(r.UserAgent()),
		Protocol(r.Proto),
	}

	if r.URL.RawQuery != "" {
		fields = append(fields, Query(r.URL.RawQuery))
	}

	if r.ContentLength > 0 {
		fields = append(fields, ContentLength(r.ContentLength))
	}

	if ct := r.Header.Get("Content-Type"); ct != "" {
		fields = append(fields, ContentType(ct))
	}

	return fields
}

// HTTPResponseFields creates standard fields for an HTTP response.
func HTTPResponseFields(statusCode, responseSize int, latency time.Duration) []zap.Field {
	return []zap.Field{
		StatusCode(statusCode),
		ResponseSize(responseSize),
		Latency(latency),
		LatencyMS(latency),
	}
}

// String creates a string field.
func String(key, value string) zap.Field {
	return zap.String(key, value)
}

// Int creates an int field.
func Int(key string, value int) zap.Field {
	return zap.Int(key, value)
}

// Int64 creates an int64 field.
func Int64(key string, value int64) zap.Field {
	return zap.Int64(key, value)
}

// Float64 creates a float64 field.
func Float64(key string, value float64) zap.Field {
	return zap.Float64(key, value)
}

// Bool creates a bool field.
func Bool(key string, value bool) zap.Field {
	return zap.Bool(key, value)
}

// Duration creates a duration field.
func Duration(key string, value time.Duration) zap.Field {
	return zap.Duration(key, value)
}

// Time creates a time field.
func Time(key string, value time.Time) zap.Field {
	return zap.Time(key, value)
}

// Any creates a field with any value.
func Any(key string, value interface{}) zap.Field {
	return zap.Any(key, value)
}

// Stringer creates a field from a fmt.Stringer.
func Stringer(key string, value fmt.Stringer) zap.Field {
	return zap.Stringer(key, value)
}

// Strings creates a string slice field.
func Strings(key string, value []string) zap.Field {
	return zap.Strings(key, value)
}

// Ints creates an int slice field.
func Ints(key string, value []int) zap.Field {
	return zap.Ints(key, value)
}
