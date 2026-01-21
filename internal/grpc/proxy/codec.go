package proxy

import (
	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/proto"
)

// codecName is the name of the raw codec.
const codecName = "proto"

// rawCodec is a codec that passes through raw bytes without unmarshaling.
// This enables transparent proxying of gRPC messages.
type rawCodec struct{}

// Frame holds raw bytes for transparent proxying.
type Frame struct {
	payload []byte
}

// Marshal returns the payload bytes.
func (c *rawCodec) Marshal(v interface{}) ([]byte, error) {
	// If it's a Frame, return the raw payload
	if frame, ok := v.(*Frame); ok {
		return frame.payload, nil
	}

	// Otherwise, use proto marshaling
	if msg, ok := v.(proto.Message); ok {
		return proto.Marshal(msg)
	}

	// Fallback for other types
	return nil, nil
}

// Unmarshal stores the data in a Frame.
func (c *rawCodec) Unmarshal(data []byte, v interface{}) error {
	// If it's a Frame, store the raw payload
	if frame, ok := v.(*Frame); ok {
		frame.payload = data
		return nil
	}

	// Otherwise, use proto unmarshaling
	if msg, ok := v.(proto.Message); ok {
		return proto.Unmarshal(data, msg)
	}

	return nil
}

// Name returns the codec name.
func (c *rawCodec) Name() string {
	return codecName
}

// String returns the codec name.
func (c *rawCodec) String() string {
	return codecName
}

// init registers the raw codec with gRPC.
func init() {
	encoding.RegisterCodec(&rawCodec{})
}

// NewFrame creates a new Frame with the given payload.
func NewFrame(payload []byte) *Frame {
	return &Frame{payload: payload}
}

// Payload returns the frame payload.
func (f *Frame) Payload() []byte {
	return f.payload
}

// SetPayload sets the frame payload.
func (f *Frame) SetPayload(payload []byte) {
	f.payload = payload
}

// Reset resets the frame payload.
func (f *Frame) Reset() {
	f.payload = nil
}

// ProtoMessage implements proto.Message interface for compatibility.
func (f *Frame) ProtoMessage() {}

// ProtoReflect implements proto.Message interface for compatibility.
func (f *Frame) ProtoReflect() protoreflect {
	return nil
}

// protoreflect is a placeholder for proto.Message interface.
type protoreflect interface{}
