package discovery

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
)

func newSealer(t *testing.T) envelope.Sealer {
	t.Helper()
	key := make([]byte, envelope.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	s, err := envelope.NewAEADSealer(key)
	require.NoError(t, err)
	return s
}

func TestNewCursorCodecNilSealer(t *testing.T) {
	t.Parallel()
	_, err := NewCursorCodec(nil)
	assert.Error(t, err)
}

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()
	codec, err := NewCursorCodec(newSealer(t))
	require.NoError(t, err)

	state := &CursorState{Method: "tools/list", Upstreams: map[string]string{"up1": "c1", "up2": "c2"}}
	token, err := codec.Encode(context.Background(), state)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	got, err := codec.Decode(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "tools/list", got.Method)
	assert.Equal(t, "c1", got.cursorFor("up1"))
	assert.Equal(t, "c2", got.cursorFor("up2"))
}

func TestCursorTampered(t *testing.T) {
	t.Parallel()
	codec, err := NewCursorCodec(newSealer(t))
	require.NoError(t, err)
	token, err := codec.Encode(context.Background(), &CursorState{Method: "tools/list"})
	require.NoError(t, err)

	// Flip characters to tamper the token.
	tampered := "AAAA" + token[4:]
	_, err = codec.Decode(context.Background(), tampered)
	assert.ErrorIs(t, err, ErrCursorRestart)
}

func TestCursorCrossKeyRejected(t *testing.T) {
	t.Parallel()
	codec1, err := NewCursorCodec(newSealer(t))
	require.NoError(t, err)
	token, err := codec1.Encode(context.Background(), &CursorState{Method: "tools/list"})
	require.NoError(t, err)

	// A codec with a DIFFERENT key cannot open the token.
	key2 := make([]byte, envelope.KeySize)
	for i := range key2 {
		key2[i] = byte(200 - i)
	}
	s2, err := envelope.NewAEADSealer(key2)
	require.NoError(t, err)
	codec2, err := NewCursorCodec(s2)
	require.NoError(t, err)

	_, err = codec2.Decode(context.Background(), token)
	assert.ErrorIs(t, err, ErrCursorRestart)
}

func TestCursorStateHelpersNilSafe(t *testing.T) {
	t.Parallel()
	var s *CursorState
	assert.Equal(t, "", s.cursorFor("up1"))

	st := &CursorState{}
	assert.Equal(t, "", st.cursorFor("missing"))
	st.set("up1", "c1")
	assert.Equal(t, "c1", st.cursorFor("up1"))
}
