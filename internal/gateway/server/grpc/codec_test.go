package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestRawCodecMarshal tests RawCodec.Marshal
func TestRawCodecMarshal(t *testing.T) {
	t.Parallel()

	codec := &RawCodec{}

	t.Run("marshals RawFrame", func(t *testing.T) {
		frame := &RawFrame{Data: []byte("test data")}
		data, err := codec.Marshal(frame)

		assert.NoError(t, err)
		assert.Equal(t, []byte("test data"), data)
	})

	t.Run("marshals byte slice", func(t *testing.T) {
		input := []byte("raw bytes")
		data, err := codec.Marshal(input)

		assert.NoError(t, err)
		assert.Equal(t, []byte("raw bytes"), data)
	})

	t.Run("marshals proto message", func(t *testing.T) {
		msg := wrapperspb.String("test string")
		data, err := codec.Marshal(msg)

		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify we can unmarshal it back
		result := &wrapperspb.StringValue{}
		err = proto.Unmarshal(data, result)
		assert.NoError(t, err)
		assert.Equal(t, "test string", result.Value)
	})

	t.Run("returns error for unsupported type", func(t *testing.T) {
		_, err := codec.Marshal("string type")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported type")
	})

	t.Run("returns error for int type", func(t *testing.T) {
		_, err := codec.Marshal(123)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported type")
	})
}

// TestRawCodecUnmarshal tests RawCodec.Unmarshal
func TestRawCodecUnmarshal(t *testing.T) {
	t.Parallel()

	codec := &RawCodec{}

	t.Run("unmarshals to RawFrame", func(t *testing.T) {
		data := []byte("test data")
		frame := &RawFrame{}

		err := codec.Unmarshal(data, frame)

		assert.NoError(t, err)
		assert.Equal(t, []byte("test data"), frame.Data)
	})

	t.Run("unmarshals to byte slice pointer", func(t *testing.T) {
		data := []byte("raw bytes")
		var result []byte

		err := codec.Unmarshal(data, &result)

		assert.NoError(t, err)
		assert.Equal(t, []byte("raw bytes"), result)
	})

	t.Run("unmarshals to proto message", func(t *testing.T) {
		msg := wrapperspb.String("test string")
		data, err := proto.Marshal(msg)
		require.NoError(t, err)

		result := &wrapperspb.StringValue{}
		err = codec.Unmarshal(data, result)

		assert.NoError(t, err)
		assert.Equal(t, "test string", result.Value)
	})

	t.Run("returns error for unsupported type", func(t *testing.T) {
		data := []byte("test")
		var result string

		err := codec.Unmarshal(data, &result)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported type")
	})
}

// TestRawCodecName tests RawCodec.Name
func TestRawCodecName(t *testing.T) {
	t.Parallel()

	codec := &RawCodec{}

	assert.Equal(t, "raw", codec.Name())
}

// TestRawCodecString tests RawCodec.String
func TestRawCodecString(t *testing.T) {
	t.Parallel()

	codec := &RawCodec{}

	assert.Equal(t, "raw", codec.String())
}

// TestRawFrame tests the RawFrame struct
func TestRawFrame(t *testing.T) {
	t.Parallel()

	t.Run("empty frame", func(t *testing.T) {
		frame := &RawFrame{}
		assert.Nil(t, frame.Data)
	})

	t.Run("frame with data", func(t *testing.T) {
		frame := &RawFrame{Data: []byte("test")}
		assert.Equal(t, []byte("test"), frame.Data)
	})

	t.Run("frame data can be modified", func(t *testing.T) {
		frame := &RawFrame{Data: []byte("original")}
		frame.Data = []byte("modified")
		assert.Equal(t, []byte("modified"), frame.Data)
	})
}

// TestProtoCodecMarshal tests ProtoCodec.Marshal
func TestProtoCodecMarshal(t *testing.T) {
	t.Parallel()

	codec := &ProtoCodec{}

	t.Run("marshals proto message", func(t *testing.T) {
		msg := wrapperspb.String("test string")
		data, err := codec.Marshal(msg)

		assert.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("marshals RawFrame", func(t *testing.T) {
		frame := &RawFrame{Data: []byte("test data")}
		data, err := codec.Marshal(frame)

		assert.NoError(t, err)
		assert.Equal(t, []byte("test data"), data)
	})

	t.Run("marshals byte slice", func(t *testing.T) {
		input := []byte("raw bytes")
		data, err := codec.Marshal(input)

		assert.NoError(t, err)
		assert.Equal(t, []byte("raw bytes"), data)
	})

	t.Run("returns error for unsupported type", func(t *testing.T) {
		_, err := codec.Marshal("string type")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported type")
	})
}

// TestProtoCodecUnmarshal tests ProtoCodec.Unmarshal
func TestProtoCodecUnmarshal(t *testing.T) {
	t.Parallel()

	codec := &ProtoCodec{}

	t.Run("unmarshals to proto message", func(t *testing.T) {
		msg := wrapperspb.String("test string")
		data, err := proto.Marshal(msg)
		require.NoError(t, err)

		result := &wrapperspb.StringValue{}
		err = codec.Unmarshal(data, result)

		assert.NoError(t, err)
		assert.Equal(t, "test string", result.Value)
	})

	t.Run("unmarshals to RawFrame", func(t *testing.T) {
		data := []byte("test data")
		frame := &RawFrame{}

		err := codec.Unmarshal(data, frame)

		assert.NoError(t, err)
		assert.Equal(t, []byte("test data"), frame.Data)
	})

	t.Run("unmarshals to byte slice pointer", func(t *testing.T) {
		data := []byte("raw bytes")
		var result []byte

		err := codec.Unmarshal(data, &result)

		assert.NoError(t, err)
		assert.Equal(t, []byte("raw bytes"), result)
	})

	t.Run("returns error for unsupported type", func(t *testing.T) {
		data := []byte("test")
		var result string

		err := codec.Unmarshal(data, &result)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported type")
	})
}

// TestProtoCodecName tests ProtoCodec.Name
func TestProtoCodecName(t *testing.T) {
	t.Parallel()

	codec := &ProtoCodec{}

	assert.Equal(t, "proto", codec.Name())
}

// TestCodecRoundTrip tests round-trip encoding/decoding
func TestCodecRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("RawCodec round trip with RawFrame", func(t *testing.T) {
		codec := &RawCodec{}
		original := &RawFrame{Data: []byte("round trip test")}

		data, err := codec.Marshal(original)
		require.NoError(t, err)

		result := &RawFrame{}
		err = codec.Unmarshal(data, result)
		require.NoError(t, err)

		assert.Equal(t, original.Data, result.Data)
	})

	t.Run("ProtoCodec round trip with proto message", func(t *testing.T) {
		codec := &ProtoCodec{}
		original := wrapperspb.Int64(12345)

		data, err := codec.Marshal(original)
		require.NoError(t, err)

		result := &wrapperspb.Int64Value{}
		err = codec.Unmarshal(data, result)
		require.NoError(t, err)

		assert.Equal(t, original.Value, result.Value)
	})
}

// TestCodecEmptyData tests handling of empty data
func TestCodecEmptyData(t *testing.T) {
	t.Parallel()

	t.Run("RawCodec with empty RawFrame", func(t *testing.T) {
		codec := &RawCodec{}
		frame := &RawFrame{Data: []byte{}}

		data, err := codec.Marshal(frame)
		assert.NoError(t, err)
		assert.Empty(t, data)

		result := &RawFrame{}
		err = codec.Unmarshal(data, result)
		assert.NoError(t, err)
		assert.Empty(t, result.Data)
	})

	t.Run("RawCodec with nil data", func(t *testing.T) {
		codec := &RawCodec{}
		frame := &RawFrame{Data: nil}

		data, err := codec.Marshal(frame)
		assert.NoError(t, err)
		assert.Nil(t, data)
	})
}

// TestCodecLargeData tests handling of large data
func TestCodecLargeData(t *testing.T) {
	t.Parallel()

	codec := &RawCodec{}

	// Create 1MB of data
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	frame := &RawFrame{Data: largeData}

	data, err := codec.Marshal(frame)
	require.NoError(t, err)
	assert.Len(t, data, len(largeData))

	result := &RawFrame{}
	err = codec.Unmarshal(data, result)
	require.NoError(t, err)
	assert.Equal(t, largeData, result.Data)
}

// TestCodecBinaryData tests handling of binary data
func TestCodecBinaryData(t *testing.T) {
	t.Parallel()

	codec := &RawCodec{}

	// Binary data with all byte values
	binaryData := make([]byte, 256)
	for i := 0; i < 256; i++ {
		binaryData[i] = byte(i)
	}

	frame := &RawFrame{Data: binaryData}

	data, err := codec.Marshal(frame)
	require.NoError(t, err)

	result := &RawFrame{}
	err = codec.Unmarshal(data, result)
	require.NoError(t, err)

	assert.Equal(t, binaryData, result.Data)
}
