package grpc

import (
	"fmt"

	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/proto"
)

// RawCodec is a codec that passes through raw bytes without marshaling.
// This is used for transparent proxying where we don't need to understand
// the message content.
type RawCodec struct{}

// RawFrame represents a raw gRPC message frame.
type RawFrame struct {
	Data []byte
}

// Marshal implements the encoding.Codec interface.
func (c *RawCodec) Marshal(v interface{}) ([]byte, error) {
	switch msg := v.(type) {
	case *RawFrame:
		return msg.Data, nil
	case []byte:
		return msg, nil
	case proto.Message:
		return proto.Marshal(msg)
	default:
		return nil, fmt.Errorf("RawCodec: unsupported type %T", v)
	}
}

// Unmarshal implements the encoding.Codec interface.
func (c *RawCodec) Unmarshal(data []byte, v interface{}) error {
	switch msg := v.(type) {
	case *RawFrame:
		msg.Data = data
		return nil
	case *[]byte:
		*msg = data
		return nil
	case proto.Message:
		return proto.Unmarshal(data, msg)
	default:
		return fmt.Errorf("RawCodec: unsupported type %T", v)
	}
}

// Name returns the name of the codec.
func (c *RawCodec) Name() string {
	return "raw"
}

// String returns the string representation of the codec.
func (c *RawCodec) String() string {
	return "raw"
}

// Ensure RawCodec implements encoding.Codec
var _ encoding.Codec = (*RawCodec)(nil)

// ProtoCodec is a codec that uses protobuf for marshaling.
type ProtoCodec struct{}

// Marshal implements the encoding.Codec interface.
func (c *ProtoCodec) Marshal(v interface{}) ([]byte, error) {
	switch msg := v.(type) {
	case proto.Message:
		return proto.Marshal(msg)
	case *RawFrame:
		return msg.Data, nil
	case []byte:
		return msg, nil
	default:
		return nil, fmt.Errorf("ProtoCodec: unsupported type %T", v)
	}
}

// Unmarshal implements the encoding.Codec interface.
func (c *ProtoCodec) Unmarshal(data []byte, v interface{}) error {
	switch msg := v.(type) {
	case proto.Message:
		return proto.Unmarshal(data, msg)
	case *RawFrame:
		msg.Data = data
		return nil
	case *[]byte:
		*msg = data
		return nil
	default:
		return fmt.Errorf("ProtoCodec: unsupported type %T", v)
	}
}

// Name returns the name of the codec.
func (c *ProtoCodec) Name() string {
	return "proto"
}

// Ensure ProtoCodec implements encoding.Codec
var _ encoding.Codec = (*ProtoCodec)(nil)

// init registers the raw codec with gRPC.
func init() {
	encoding.RegisterCodec(&RawCodec{})
}
