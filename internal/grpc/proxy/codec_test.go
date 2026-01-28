package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawCodec_Marshal_Frame(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}
	payload := []byte("test payload data")
	frame := NewFrame(payload)

	data, err := codec.Marshal(frame)
	require.NoError(t, err)
	assert.Equal(t, payload, data)
}

func TestRawCodec_Marshal_NilFrame(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}
	frame := &Frame{payload: nil}

	data, err := codec.Marshal(frame)
	require.NoError(t, err)
	assert.Nil(t, data)
}

func TestRawCodec_Marshal_EmptyFrame(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}
	frame := NewFrame([]byte{})

	data, err := codec.Marshal(frame)
	require.NoError(t, err)
	assert.Empty(t, data)
}

func TestRawCodec_Marshal_NonFrame(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}

	// Non-frame, non-proto types return nil
	data, err := codec.Marshal("string")
	require.NoError(t, err)
	assert.Nil(t, data)
}

func TestRawCodec_Unmarshal_Frame(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}
	payload := []byte("test payload data")
	frame := &Frame{}

	err := codec.Unmarshal(payload, frame)
	require.NoError(t, err)
	assert.Equal(t, payload, frame.payload)
}

func TestRawCodec_Unmarshal_EmptyData(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}
	frame := &Frame{}

	err := codec.Unmarshal([]byte{}, frame)
	require.NoError(t, err)
	assert.Empty(t, frame.payload)
}

func TestRawCodec_Unmarshal_NilData(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}
	frame := &Frame{}

	err := codec.Unmarshal(nil, frame)
	require.NoError(t, err)
	assert.Nil(t, frame.payload)
}

func TestRawCodec_Unmarshal_NonFrame(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}
	var s string

	// Non-frame, non-proto types return nil error
	err := codec.Unmarshal([]byte("data"), &s)
	require.NoError(t, err)
}

func TestRawCodec_Name(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}
	assert.Equal(t, "proto", codec.Name())
}

func TestRawCodec_String(t *testing.T) {
	t.Parallel()

	codec := &rawCodec{}
	assert.Equal(t, "proto", codec.String())
}

func TestNewFrame(t *testing.T) {
	t.Parallel()

	payload := []byte("test data")
	frame := NewFrame(payload)

	assert.NotNil(t, frame)
	assert.Equal(t, payload, frame.payload)
}

func TestNewFrame_Nil(t *testing.T) {
	t.Parallel()

	frame := NewFrame(nil)
	assert.NotNil(t, frame)
	assert.Nil(t, frame.payload)
}

func TestFrame_Payload(t *testing.T) {
	t.Parallel()

	payload := []byte("test data")
	frame := NewFrame(payload)

	assert.Equal(t, payload, frame.Payload())
}

func TestFrame_SetPayload(t *testing.T) {
	t.Parallel()

	frame := NewFrame([]byte("initial"))
	newPayload := []byte("updated")

	frame.SetPayload(newPayload)
	assert.Equal(t, newPayload, frame.Payload())
}

func TestFrame_Reset(t *testing.T) {
	t.Parallel()

	frame := NewFrame([]byte("data"))
	frame.Reset()

	assert.Nil(t, frame.Payload())
}

func TestFrame_ProtoMessage(t *testing.T) {
	t.Parallel()

	frame := NewFrame([]byte("data"))
	// Should not panic
	frame.ProtoMessage()
}

func TestFrame_ProtoReflect(t *testing.T) {
	t.Parallel()

	frame := NewFrame([]byte("data"))
	// Should return nil
	assert.Nil(t, frame.ProtoReflect())
}

func TestCodecName_Constant(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "proto", codecName)
}

func BenchmarkRawCodec_Marshal(b *testing.B) {
	codec := &rawCodec{}
	payload := make([]byte, 1024)
	frame := NewFrame(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = codec.Marshal(frame)
	}
}

func BenchmarkRawCodec_Unmarshal(b *testing.B) {
	codec := &rawCodec{}
	payload := make([]byte, 1024)
	frame := &Frame{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = codec.Unmarshal(payload, frame)
	}
}
