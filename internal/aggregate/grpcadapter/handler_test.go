package grpcadapter

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

type stubInvoker struct {
	bodies map[string]string
	fail   map[string]bool
}

func (s *stubInvoker) Invoke(_ context.Context, target aggregate.Target, _ *aggregate.Request) (*aggregate.Response, error) {
	if s.fail[target.Name] {
		return &aggregate.Response{Target: target.Name, Err: errDown}, errDown
	}
	return &aggregate.Response{
		Target:      target.Name,
		StatusCode:  200,
		Body:        []byte(s.bodies[target.Name]),
		ContentType: "application/json",
	}, nil
}

type downErr struct{}

func (downErr) Error() string { return "down" }

var errDown = downErr{}

func cfgWith(merge bool, names ...string) *config.AggregateConfig {
	targets := make([]config.AggregateTarget, 0, len(names))
	for i, n := range names {
		targets = append(targets, config.AggregateTarget{
			Name:        n,
			Destination: config.Destination{Host: "h", Port: 9090 + i},
		})
	}
	cfg := &config.AggregateConfig{Enabled: true, FailMode: config.FailModeAny, Targets: targets}
	if merge {
		cfg.Merge = &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep}
	}
	return cfg
}

// U-AD-GRPC-1: unary descriptor (JSON-mappable) merge.
func TestUnaryHandler_Aggregate_DescriptorMerge(t *testing.T) {
	inv := &stubInvoker{bodies: map[string]string{
		"a": `{"x":1}`,
		"b": `{"y":2}`,
	}}
	h := NewUnaryHandler(inv, nil, nil, nil)
	out, err := h.Aggregate(context.Background(), cfgWith(true, "a", "b"), &aggregate.Request{})
	require.NoError(t, err)
	assert.True(t, out.Merged)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	assert.Equal(t, float64(1), got["x"])
	assert.Equal(t, float64(2), got["y"])
}

// U-AD-GRPC-2: opaque last-wins / labeled envelope when merge disabled.
func TestUnaryHandler_Aggregate_EnvelopeWhenNoMerge(t *testing.T) {
	inv := &stubInvoker{bodies: map[string]string{
		"a": `{"x":1}`,
		"b": `{"y":2}`,
	}}
	h := NewUnaryHandler(inv, nil, nil, nil)
	out, err := h.Aggregate(context.Background(), cfgWith(false, "a", "b"), &aggregate.Request{})
	require.NoError(t, err)
	assert.False(t, out.Merged)

	var envelopes []map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &envelopes))
	assert.Len(t, envelopes, 2)
}

// U-AD-GRPC-2: last-wins via replace strategy.
func TestUnaryHandler_Aggregate_LastWins(t *testing.T) {
	inv := &stubInvoker{bodies: map[string]string{
		"a": `{"v":1}`,
		"b": `{"v":2}`,
	}}
	cfg := cfgWith(true, "a", "b")
	cfg.Merge.Strategy = config.MergeStrategyReplace
	h := NewUnaryHandler(inv, nil, nil, nil)
	out, err := h.Aggregate(context.Background(), cfg, &aggregate.Request{})
	require.NoError(t, err)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Body, &got))
	assert.Equal(t, float64(2), got["v"])
}

func TestUnaryHandler_Aggregate_NoTargets(t *testing.T) {
	h := NewUnaryHandler(&stubInvoker{}, nil, nil, nil)
	_, err := h.Aggregate(context.Background(), &config.AggregateConfig{Enabled: false}, &aggregate.Request{})
	assert.ErrorIs(t, err, aggregate.ErrNoTargets)
}

func TestUnaryHandler_Aggregate_FanoutFails(t *testing.T) {
	inv := &stubInvoker{fail: map[string]bool{"a": true}}
	cfg := cfgWith(false, "a")
	cfg.FailMode = config.FailModeAll
	h := NewUnaryHandler(inv, nil, nil, nil)
	_, err := h.Aggregate(context.Background(), cfg, &aggregate.Request{})
	require.Error(t, err)
}

func TestNewUnaryHandler_NilLogger(t *testing.T) {
	h := NewUnaryHandler(&stubInvoker{}, nil, nil, nil)
	require.NotNil(t, h)
}
