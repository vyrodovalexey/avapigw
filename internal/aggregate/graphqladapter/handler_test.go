package graphqladapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// stubInvoker returns a canned response per target name.
type stubInvoker struct {
	bodies map[string]string
	fail   map[string]bool
}

func (s *stubInvoker) Invoke(_ context.Context, target aggregate.Target, _ *aggregate.Request) (*aggregate.Response, error) {
	if s.fail[target.Name] {
		return &aggregate.Response{Target: target.Name, Err: assertErr}, assertErr
	}
	return &aggregate.Response{
		Target:      target.Name,
		StatusCode:  200,
		Body:        []byte(s.bodies[target.Name]),
		ContentType: "application/json",
	}, nil
}

type stubErr struct{}

func (stubErr) Error() string { return "down" }

var assertErr = stubErr{}

func cfgWith(names ...string) *config.AggregateConfig {
	targets := make([]config.AggregateTarget, 0, len(names))
	for i, n := range names {
		targets = append(targets, config.AggregateTarget{
			Name:        n,
			Destination: config.Destination{Host: "h", Port: 8080 + i},
		})
	}
	return &config.AggregateConfig{Enabled: true, FailMode: config.FailModeAny, Targets: targets}
}

// U-AD-GQL-1: merge data/errors.
func TestHandler_ServeAggregate_MergeDataErrors(t *testing.T) {
	inv := &stubInvoker{bodies: map[string]string{
		"a": `{"data":{"user":{"id":1}},"errors":[{"message":"e1"}]}`,
		"b": `{"data":{"user":{"name":"x"}}}`,
	}}
	h := NewHandler(inv, nil, nil, nil)
	cfg := cfgWith("a", "b")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{user{id}}"}`))
	require.NoError(t, h.ServeAggregate(rr, req, cfg))

	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	data := got["data"].(map[string]interface{})
	user := data["user"].(map[string]interface{})
	assert.Equal(t, float64(1), user["id"])
	assert.Equal(t, "x", user["name"])
	assert.Len(t, got["errors"].([]interface{}), 1)
}

// U-AD-GQL-2: partial backend error surfaced.
func TestHandler_ServeAggregate_PartialError(t *testing.T) {
	inv := &stubInvoker{
		bodies: map[string]string{"a": `{"data":{"ok":true}}`},
		fail:   map[string]bool{"b": true},
	}
	h := NewHandler(inv, nil, nil, nil)
	cfg := cfgWith("a", "b")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{}`))
	require.NoError(t, h.ServeAggregate(rr, req, cfg))

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	// Only the successful target's data is present; failed target dropped.
	data := got["data"].(map[string]interface{})
	assert.Equal(t, true, data["ok"])
}

func TestHandler_ServeAggregate_NoTargets(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	err := h.ServeAggregate(rr, req, &config.AggregateConfig{Enabled: false})
	assert.ErrorIs(t, err, aggregate.ErrNoTargets)
}

func TestHandler_ServeAggregate_FanoutFails(t *testing.T) {
	inv := &stubInvoker{fail: map[string]bool{"a": true}}
	h := NewHandler(inv, nil, nil, nil)
	cfg := cfgWith("a")
	cfg.FailMode = config.FailModeAll

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	err := h.ServeAggregate(rr, req, cfg)
	require.Error(t, err)
}

func TestHandler_DefaultInvoker(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)
	require.NotNil(t, h)
}

func TestBuildRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/graphql?x=1", strings.NewReader(`{"query":"x"}`))
	req.Header.Set("X-Keep", "v")
	req.Header.Set("Host", "drop")
	out, err := buildRequest(req)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, out.Method)
	assert.Equal(t, "/graphql?x=1", out.Path)
	assert.Equal(t, `{"query":"x"}`, string(out.Body))
	assert.Contains(t, out.Headers, "X-Keep")
	assert.NotContains(t, out.Headers, "Host")
}

func TestBuildRequest_NilBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Body = http.NoBody
	out, err := buildRequest(req)
	require.NoError(t, err)
	assert.NotNil(t, out)
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, assertErr }

func TestBuildRequest_BodyReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/graphql", failReader{})
	_, err := buildRequest(req)
	require.Error(t, err)
}

func TestCloneHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "x")
	h.Set("Content-Length", "1")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("X-Custom", "keep")
	out := cloneHeaders(h)
	assert.NotContains(t, out, "Connection")
	assert.NotContains(t, out, "Content-Length")
	assert.NotContains(t, out, "Transfer-Encoding")
	assert.Contains(t, out, "X-Custom")
}
