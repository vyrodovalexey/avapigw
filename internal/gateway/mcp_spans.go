package gateway

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// MCP span attribute keys (HUB-506 / T-62). Kept as constants so the
// downstream and upstream spans agree on attribute names.
const (
	spanAttrMethod          = "mcp.method"
	spanAttrName            = "mcp.name"
	spanAttrProtocolVersion = "mcp.protocol_version"
	spanAttrUpstream        = "mcp.upstream"
	spanAttrResultType      = "mcp.result_type"
	spanAttrOutcome         = "outcome"
	spanAttrOperationID     = "mcp.operation_id"
)

// annotateRequestSpan stamps the per-request MCP attributes onto the span in
// r's context (T-62). It is a no-op when the span is not recording so the hot
// path is cheap when tracing is disabled.
func annotateRequestSpan(r *http.Request, method, name, version string) {
	span := trace.SpanFromContext(r.Context())
	if !span.IsRecording() {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String(spanAttrMethod, method),
		attribute.String(spanAttrProtocolVersion, version),
	}
	if name != "" {
		attrs = append(attrs, attribute.String(spanAttrName, name))
	}
	span.SetAttributes(attrs...)
}

// annotateOutcomeSpan stamps the upstream, result-type and outcome attributes
// onto the request span once the broker resolves them (T-62).
func annotateOutcomeSpan(r *http.Request, upstream, resultType, outcome string) {
	span := trace.SpanFromContext(r.Context())
	if !span.IsRecording() {
		return
	}
	attrs := make([]attribute.KeyValue, 0, 3)
	if upstream != "" {
		attrs = append(attrs, attribute.String(spanAttrUpstream, upstream))
	}
	if resultType != "" {
		attrs = append(attrs, attribute.String(spanAttrResultType, resultType))
	}
	if outcome != "" {
		attrs = append(attrs, attribute.String(spanAttrOutcome, outcome))
	}
	span.SetAttributes(attrs...)
}

// annotateOperationSpan stamps the MRTR operation id onto the request span so
// rounds of the same operation share a correlatable attribute (T-62 / HUB-506).
func annotateOperationSpan(r *http.Request, operationID string) {
	if operationID == "" {
		return
	}
	span := trace.SpanFromContext(r.Context())
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(attribute.String(spanAttrOperationID, operationID))
}
