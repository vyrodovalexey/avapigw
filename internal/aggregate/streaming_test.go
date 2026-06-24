package aggregate

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingSink captures frames written through the mux.
type recordingSink struct {
	mu     sync.Mutex
	frames []*Frame
	err    error
}

func (s *recordingSink) WriteFrame(_ context.Context, frame *Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.frames = append(s.frames, frame)
	return nil
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.frames)
}

// U-AD-STREAM-1/2: framed interleave — frames labeled per target.
func TestStreamMux_Push_InterleavedFrames(t *testing.T) {
	sink := &recordingSink{}
	mux := NewStreamMux(sink, &Config{}, nil, nil)

	require.NoError(t, mux.Push(context.Background(), "a", 200, []byte(`{"m":1}`)))
	require.NoError(t, mux.Push(context.Background(), "b", 200, []byte("raw")))

	require.Equal(t, 2, sink.count())
	assert.Equal(t, "a", sink.frames[0].Target)
	assert.JSONEq(t, `{"m":1}`, string(sink.frames[0].Payload))
	assert.Equal(t, "b", sink.frames[1].Target)
	assert.Equal(t, `"raw"`, string(sink.frames[1].Payload))
}

// Concurrent multi-target push interleaving is race-safe.
func TestStreamMux_Push_Concurrent(t *testing.T) {
	sink := &recordingSink{}
	mux := NewStreamMux(sink, &Config{PerMessageMerge: true, Merge: &MergeOptions{Strategy: "deep"}}, nil, nil)

	var wg sync.WaitGroup
	for _, target := range []string{"a", "b", "c"} {
		tg := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				_ = mux.Push(context.Background(), tg, 200, []byte(`{"x":1}`))
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 30, sink.count())
}

// U-AD-STREAM-3: one stream errors → Push returns the sink error (terminating
// that target's pump) while the mux remains usable for others.
func TestStreamMux_Push_SinkError(t *testing.T) {
	sink := &recordingSink{err: errors.New("write failed")}
	mux := NewStreamMux(sink, nil, nil, nil)

	err := mux.Push(context.Background(), "a", 200, []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write failed")
}

// U-AD-STREAM-4: client disconnect (context cancel) stops pushes, no leak.
func TestStreamMux_Push_ContextCancelled(t *testing.T) {
	sink := &recordingSink{}
	mux := NewStreamMux(sink, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := mux.Push(ctx, "a", 200, []byte("x"))
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, sink.count())
}

func TestStreamMux_Close_Idempotent(t *testing.T) {
	mux := NewStreamMux(&recordingSink{}, nil, nil, nil)
	assert.False(t, mux.Closed())
	mux.Close()
	assert.True(t, mux.Closed())
	assert.NotPanics(t, func() { mux.Close() })
	assert.True(t, mux.Closed())
}

func TestStreamMux_Close_ConcurrentRace(t *testing.T) {
	mux := NewStreamMux(&recordingSink{}, nil, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mux.Close()
			_ = mux.Closed()
		}()
	}
	wg.Wait()
	assert.True(t, mux.Closed())
}

func TestNewStreamMux_ConfigDefaults(t *testing.T) {
	mux := NewStreamMux(&recordingSink{}, nil, nil, nil)
	assert.NotNil(t, mux.logger)
	assert.False(t, mux.perMessageMerge)
	assert.Empty(t, mux.mergeStrategy)

	mux2 := NewStreamMux(&recordingSink{}, &Config{
		PerMessageMerge: true,
		Merge:           &MergeOptions{Strategy: "shallow"},
	}, nil, nil)
	assert.True(t, mux2.perMessageMerge)
	assert.Equal(t, "shallow", mux2.mergeStrategy)
}

func TestEncodeFrame(t *testing.T) {
	frame := &Frame{Target: "a", Status: 200, Payload: json.RawMessage(`{"k":1}`)}
	data, err := EncodeFrame(frame)
	require.NoError(t, err)

	var got Frame
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, "a", got.Target)
	assert.Equal(t, 200, got.Status)
	assert.JSONEq(t, `{"k":1}`, string(got.Payload))
}
