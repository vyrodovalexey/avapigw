// Package jsonrpc provides JSON-RPC 2.0 wire types and helpers for the MCP
// hub. The MCP transport (Streamable HTTP) carries exactly one JSON-RPC
// request or notification per POST (HUB-102); batch requests are rejected.
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the JSON-RPC protocol version string.
const Version = "2.0"

// Standard JSON-RPC 2.0 error codes.
const (
	// CodeParseError indicates invalid JSON was received.
	CodeParseError = -32700
	// CodeInvalidRequest indicates the JSON is not a valid Request object.
	CodeInvalidRequest = -32600
	// CodeMethodNotFound indicates the method does not exist / is unavailable.
	CodeMethodNotFound = -32601
	// CodeInvalidParams indicates invalid method parameters.
	CodeInvalidParams = -32602
	// CodeInternalError indicates an internal JSON-RPC error.
	CodeInternalError = -32603
)

// ErrBatchNotSupported is returned when a batch (JSON array) payload is
// received. Per HUB-102 the hub accepts exactly one request or notification
// per POST.
var ErrBatchNotSupported = errors.New("jsonrpc: batch requests are not supported")

// ErrEmptyMessage is returned when the payload is empty.
var ErrEmptyMessage = errors.New("jsonrpc: empty message")

// Request represents a JSON-RPC 2.0 request or notification. A notification
// is a Request with a nil ID.
type Request struct {
	// JSONRPC MUST be "2.0".
	JSONRPC string `json:"jsonrpc"`
	// ID is the request identifier. It is nil for notifications.
	ID json.RawMessage `json:"id,omitempty"`
	// Method is the invoked method name.
	Method string `json:"method"`
	// Params carries the method parameters (may be nil).
	Params json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the request is a notification (no ID).
func (r *Request) IsNotification() bool {
	return r == nil || len(r.ID) == 0
}

// Response represents a JSON-RPC 2.0 response. Exactly one of Result or Error
// is set on a well-formed response.
type Response struct {
	// JSONRPC MUST be "2.0".
	JSONRPC string `json:"jsonrpc"`
	// ID echoes the request identifier (null for parse/invalid-request errors).
	ID json.RawMessage `json:"id"`
	// Result carries a successful result.
	Result json.RawMessage `json:"result,omitempty"`
	// Error carries an error when the call failed.
	Error *Error `json:"error,omitempty"`
}

// Error represents a JSON-RPC 2.0 error object.
type Error struct {
	// Code is the numeric error code.
	Code int `json:"code"`
	// Message is a short human-readable description.
	Message string `json:"message"`
	// Data carries optional structured error data.
	Data json.RawMessage `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e == nil {
		return "<nil jsonrpc error>"
	}
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// NewError constructs a JSON-RPC Error. The data argument, when non-nil, is
// JSON-encoded and stored in the Data field.
func NewError(code int, message string, data any) (*Error, error) {
	e := &Error{Code: code, Message: message}
	if data != nil {
		raw, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("jsonrpc: encode error data: %w", err)
		}
		e.Data = raw
	}
	return e, nil
}

// NewResponse builds a successful Response for the given id and result. The
// result is JSON-encoded; a nil result yields an empty Result field.
func NewResponse(id json.RawMessage, result any) (*Response, error) {
	resp := &Response{JSONRPC: Version, ID: normalizeID(id)}
	if result != nil {
		raw, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("jsonrpc: encode result: %w", err)
		}
		resp.Result = raw
	}
	return resp, nil
}

// NewErrorResponse builds an error Response for the given id.
func NewErrorResponse(id json.RawMessage, e *Error) *Response {
	return &Response{JSONRPC: Version, ID: normalizeID(id), Error: e}
}

// normalizeID returns a JSON null for an absent id so error responses carry an
// explicit null per the JSON-RPC spec.
func normalizeID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

// Encode marshals a value to JSON bytes.
func Encode(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jsonrpc: encode: %w", err)
	}
	return raw, nil
}

// Decode unmarshals JSON bytes into the provided value.
func Decode(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("jsonrpc: decode: %w", err)
	}
	return nil
}

// ParseSingle parses exactly one JSON-RPC request or notification from data.
// A JSON array (batch) is rejected with ErrBatchNotSupported (HUB-102). The
// returned Request has its JSONRPC field validated to equal "2.0".
func ParseSingle(data []byte) (*Request, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, ErrEmptyMessage
	}
	if trimmed[0] == '[' {
		return nil, ErrBatchNotSupported
	}

	var req Request
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return nil, fmt.Errorf("jsonrpc: parse request: %w", err)
	}
	if req.JSONRPC != Version {
		return nil, fmt.Errorf("jsonrpc: unsupported version %q (want %q)", req.JSONRPC, Version)
	}
	if req.Method == "" {
		return nil, fmt.Errorf("jsonrpc: missing method")
	}
	return &req, nil
}

// ParseSingleReader reads all bytes from r and delegates to ParseSingle. The
// caller is responsible for bounding the reader (e.g. http.MaxBytesReader).
func ParseSingleReader(r io.Reader) (*Request, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("jsonrpc: read request: %w", err)
	}
	return ParseSingle(data)
}
