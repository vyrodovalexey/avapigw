package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// newTestServer returns an httptest server echoing a JSON body and recording the
// last request for assertions.
func newTestServer(t *testing.T, body string, status int, capture *http.Request) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture != nil {
			*capture = *r.Clone(context.Background())
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func targetFor(t *testing.T, name string, srv *httptest.Server) aggregate.Target {
	t.Helper()
	host, port := splitHostPort(t, srv.URL)
	return aggregate.Target{Name: name, Host: host, Port: port}
}

func splitHostPort(t *testing.T, url string) (string, int) {
	t.Helper()
	trimmed := strings.TrimPrefix(url, "http://")
	parts := strings.Split(trimmed, ":")
	require.Len(t, parts, 2)
	var port int
	_, err := fmtSscan(parts[1], &port)
	require.NoError(t, err)
	return parts[0], port
}

func fmtSscan(s string, p *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	*p = n
	return 1, nil
}

func TestInvoker_Invoke_Success(t *testing.T) {
	var captured http.Request
	srv := newTestServer(t, `{"ok":true}`, 200, &captured)
	inv := NewInvoker()
	target := targetFor(t, "a", srv)

	resp, err := inv.Invoke(context.Background(), target, &aggregate.Request{
		Method:  http.MethodPost,
		Path:    "/v1/data",
		Body:    []byte(`{"q":1}`),
		Headers: map[string][]string{"X-Test": {"yes"}},
	})
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.JSONEq(t, `{"ok":true}`, string(resp.Body))
	assert.Equal(t, "application/json", resp.ContentType)
	assert.Equal(t, "/v1/data", captured.URL.Path)
	assert.Equal(t, "yes", captured.Header.Get("X-Test"))
}

func TestInvoker_Invoke_DefaultMethodAndPath(t *testing.T) {
	var captured http.Request
	srv := newTestServer(t, `{}`, 200, &captured)
	inv := NewInvoker()
	resp, err := inv.Invoke(context.Background(), targetFor(t, "a", srv), &aggregate.Request{})
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, http.MethodGet, captured.Method)
	assert.Equal(t, "/", captured.URL.Path)
}

func TestInvoker_Invoke_BasicAuth(t *testing.T) {
	var captured http.Request
	srv := newTestServer(t, `{}`, 200, &captured)
	inv := NewInvoker()
	target := targetFor(t, "a", srv)
	target.Auth = &config.BackendAuthConfig{
		Type:  "basic",
		Basic: &config.BackendBasicAuthConfig{Enabled: true, Username: "u", Password: "p"},
	}
	_, err := inv.Invoke(context.Background(), target, &aggregate.Request{})
	require.NoError(t, err)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	assert.Equal(t, want, captured.Header.Get("Authorization"))
}

func TestInvoker_Invoke_JWTAuth(t *testing.T) {
	var captured http.Request
	srv := newTestServer(t, `{}`, 200, &captured)
	inv := NewInvoker()
	target := targetFor(t, "a", srv)
	target.Auth = &config.BackendAuthConfig{
		Type: "jwt",
		JWT:  &config.BackendJWTAuthConfig{Enabled: true, StaticToken: "tok"},
	}
	_, err := inv.Invoke(context.Background(), target, &aggregate.Request{})
	require.NoError(t, err)
	assert.Equal(t, "Bearer tok", captured.Header.Get("Authorization"))
}

func TestInvoker_Invoke_JWTCustomHeader(t *testing.T) {
	var captured http.Request
	srv := newTestServer(t, `{}`, 200, &captured)
	inv := NewInvoker()
	target := targetFor(t, "a", srv)
	target.Auth = &config.BackendAuthConfig{
		Type: "jwt",
		JWT: &config.BackendJWTAuthConfig{
			Enabled: true, StaticToken: "tok",
			HeaderName: "X-Token", HeaderPrefix: "Token",
		},
	}
	_, err := inv.Invoke(context.Background(), target, &aggregate.Request{})
	require.NoError(t, err)
	assert.Equal(t, "Token tok", captured.Header.Get("X-Token"))
}

func TestInvoker_Invoke_NoAuthAndUnknownType(t *testing.T) {
	var captured http.Request
	srv := newTestServer(t, `{}`, 200, &captured)
	inv := NewInvoker()

	// nil auth
	_, err := inv.Invoke(context.Background(), targetFor(t, "a", srv), &aggregate.Request{})
	require.NoError(t, err)
	assert.Empty(t, captured.Header.Get("Authorization"))

	// unknown auth type passes through
	target := targetFor(t, "b", srv)
	target.Auth = &config.BackendAuthConfig{Type: "exotic"}
	_, err = inv.Invoke(context.Background(), target, &aggregate.Request{})
	require.NoError(t, err)
}

func TestInvoker_Invoke_DisabledAuthSkipped(t *testing.T) {
	var captured http.Request
	srv := newTestServer(t, `{}`, 200, &captured)
	inv := NewInvoker()
	target := targetFor(t, "a", srv)
	target.Auth = &config.BackendAuthConfig{
		Type:  "basic",
		Basic: &config.BackendBasicAuthConfig{Enabled: false, Username: "u"},
	}
	_, err := inv.Invoke(context.Background(), target, &aggregate.Request{})
	require.NoError(t, err)
	assert.Empty(t, captured.Header.Get("Authorization"))
}

func TestInvoker_Invoke_TransportError(t *testing.T) {
	inv := NewInvoker()
	// Port 1 is unroutable in test env; connection should fail fast.
	target := aggregate.Target{Name: "dead", Host: "127.0.0.1", Port: 1}
	resp, err := inv.Invoke(context.Background(), target, &aggregate.Request{})
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "dead", resp.Target)
	assert.Error(t, resp.Err)
}

func TestInvoker_ClientCachedPerTarget(t *testing.T) {
	srv := newTestServer(t, `{}`, 200, nil)
	inv := NewInvoker()
	target := targetFor(t, "cached", srv)
	_, err := inv.Invoke(context.Background(), target, &aggregate.Request{})
	require.NoError(t, err)
	c1, err := inv.clientFor(&target)
	require.NoError(t, err)
	c2, err := inv.clientFor(&target)
	require.NoError(t, err)
	assert.Same(t, c1, c2)
}

func TestInvoker_Options(t *testing.T) {
	inv := NewInvoker(WithScheme("https"), WithScheme(""), WithLogger(nil))
	assert.Equal(t, "https", inv.scheme)
}

func TestInvoker_TargetURL(t *testing.T) {
	inv := NewInvoker()
	tlsTarget := &aggregate.Target{Host: "h", Port: 8443, TLS: &config.BackendTLSConfig{Enabled: true}}
	assert.Equal(t, "https://h:8443/", inv.targetURL(tlsTarget, ""))

	plain := &aggregate.Target{Host: "h", Port: 80}
	assert.Equal(t, "http://h:80/api", inv.targetURL(plain, "/api"))

	noPort := &aggregate.Target{Host: "h"}
	assert.Equal(t, "http://h/x", inv.targetURL(noPort, "/x"))
}

func TestInvoker_TransportFor_TLSDisabled(t *testing.T) {
	inv := NewInvoker()
	tr, err := inv.transportFor(nil)
	require.NoError(t, err)
	assert.Nil(t, tr.TLSClientConfig)

	tr2, err := inv.transportFor(&config.BackendTLSConfig{Enabled: false})
	require.NoError(t, err)
	assert.Nil(t, tr2.TLSClientConfig)
}

func TestInvoker_TransportFor_TLSEnabled(t *testing.T) {
	inv := NewInvoker()
	tr, err := inv.transportFor(&config.BackendTLSConfig{
		Enabled:            true,
		Mode:               "SIMPLE",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	require.NotNil(t, tr.TLSClientConfig)
	assert.True(t, tr.TLSClientConfig.InsecureSkipVerify)
}

func TestInvoker_TransportFor_TLSBuildError(t *testing.T) {
	inv := NewInvoker()
	// MUTUAL mode pointing at non-existent cert files triggers a build error.
	_, err := inv.transportFor(&config.BackendTLSConfig{
		Enabled:  true,
		Mode:     "MUTUAL",
		CertFile: "/nonexistent/tls.crt",
		KeyFile:  "/nonexistent/tls.key",
	})
	require.Error(t, err)
}

func TestInvoker_ClientFor_TLSBuildError(t *testing.T) {
	inv := NewInvoker()
	target := &aggregate.Target{
		Name: "bad-tls",
		Host: "h",
		Port: 443,
		TLS: &config.BackendTLSConfig{
			Enabled:  true,
			Mode:     "MUTUAL",
			CertFile: "/nonexistent/tls.crt",
			KeyFile:  "/nonexistent/tls.key",
		},
	}
	_, err := inv.clientFor(target)
	require.Error(t, err)
}

func TestInvoker_Invoke_ClientBuildError(t *testing.T) {
	inv := NewInvoker()
	target := aggregate.Target{
		Name: "bad",
		Host: "h",
		Port: 443,
		TLS: &config.BackendTLSConfig{
			Enabled:  true,
			Mode:     "MUTUAL",
			CertFile: "/nonexistent/tls.crt",
			KeyFile:  "/nonexistent/tls.key",
		},
	}
	resp, err := inv.Invoke(context.Background(), target, &aggregate.Request{})
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "bad", resp.Target)
}

func TestInvoker_Invoke_BuildRequestError(t *testing.T) {
	srv := newTestServer(t, `{}`, 200, nil)
	inv := NewInvoker()
	target := targetFor(t, "a", srv)
	// Invalid method forces http.NewRequestWithContext to fail.
	resp, err := inv.Invoke(context.Background(), target, &aggregate.Request{Method: "BAD\nMETHOD"})
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "a", resp.Target)
}

// U-AD-REST-1: merge mode produces single merged JSON document.
func TestHandler_ServeAggregate_MergeMode(t *testing.T) {
	s1 := newTestServer(t, `{"a":1}`, 200, nil)
	s2 := newTestServer(t, `{"b":2}`, 200, nil)

	invoker := aggregate.InvokerFunc(func(ctx context.Context, target aggregate.Target, req *aggregate.Request) (*aggregate.Response, error) {
		return NewInvoker().Invoke(ctx, target, req)
	})
	h := NewHandler(invoker, nil, nil, nil)

	cfg := &config.AggregateConfig{
		Enabled: true,
		Targets: []config.AggregateTarget{
			targetCfg("a", s1), targetCfg("b", s2),
		},
		Merge: &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	require.NoError(t, h.ServeAggregate(rr, req, cfg))

	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, float64(1), got["a"])
	assert.Equal(t, float64(2), got["b"])
}

// U-AD-REST-2: envelope mode (merge disabled).
func TestHandler_ServeAggregate_EnvelopeMode(t *testing.T) {
	s1 := newTestServer(t, `{"a":1}`, 200, nil)
	s2 := newTestServer(t, "plain", 200, nil)

	h := NewHandler(nil, nil, nil, nil) // default invoker
	cfg := &config.AggregateConfig{
		Enabled: true,
		Targets: []config.AggregateTarget{targetCfg("a", s1), targetCfg("b", s2)},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/data", strings.NewReader(`{"q":1}`))
	require.NoError(t, h.ServeAggregate(rr, req, cfg))

	var envelopes []map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelopes))
	assert.Len(t, envelopes, 2)
}

// U-AD-REST-3: encoding/headers honored — nosniff header set.
func TestHandler_ServeAggregate_HeadersHonored(t *testing.T) {
	s1 := newTestServer(t, `{"a":1}`, 200, nil)
	h := NewHandler(nil, nil, nil, nil)
	cfg := &config.AggregateConfig{
		Enabled: true,
		Targets: []config.AggregateTarget{targetCfg("a", s1)},
		Merge:   &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyDeep},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, h.ServeAggregate(rr, req, cfg))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
}

func TestHandler_ServeAggregate_NoTargets(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	err := h.ServeAggregate(rr, req, &config.AggregateConfig{Enabled: false})
	assert.ErrorIs(t, err, aggregate.ErrNoTargets)
}

func TestHandler_ServeAggregate_FanoutFails(t *testing.T) {
	// Target points to a dead port; FailMode=all → fan-out fails.
	h := NewHandler(nil, nil, nil, nil)
	cfg := &config.AggregateConfig{
		Enabled:  true,
		FailMode: config.FailModeAll,
		Targets: []config.AggregateTarget{
			{Name: "dead", Destination: config.Destination{Host: "127.0.0.1", Port: 1},
				Timeout: config.Duration(50_000_000)},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	err := h.ServeAggregate(rr, req, cfg)
	require.Error(t, err)
}

func TestBuildRequest_BuffersBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/p?x=1", strings.NewReader("payload"))
	req.Header.Set("X-Keep", "v")
	req.Header.Set("Connection", "keep-alive")
	out, err := buildRequest(req)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, out.Method)
	assert.Equal(t, "/p?x=1", out.Path)
	assert.Equal(t, "payload", string(out.Body))
	assert.Contains(t, out.Headers, "X-Keep")
	assert.NotContains(t, out.Headers, "Connection")
}

func TestInvoker_Invoke_JWTDisabled(t *testing.T) {
	var captured http.Request
	srv := newTestServer(t, `{}`, 200, &captured)
	inv := NewInvoker()
	target := targetFor(t, "a", srv)
	target.Auth = &config.BackendAuthConfig{
		Type: "jwt",
		JWT:  &config.BackendJWTAuthConfig{Enabled: false, StaticToken: "tok"},
	}
	_, err := inv.Invoke(context.Background(), target, &aggregate.Request{})
	require.NoError(t, err)
	assert.Empty(t, captured.Header.Get("Authorization"))
}

// errReader always fails, used to exercise the body-read error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, assertErr }

var assertErr = errReaderErr{}

type errReaderErr struct{}

func (errReaderErr) Error() string { return "read failed" }

func TestBuildRequest_BodyReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", errReader{})
	_, err := buildRequest(req)
	require.Error(t, err)
}

func TestBuildRequest_NilBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Body = http.NoBody
	out, err := buildRequest(req)
	require.NoError(t, err)
	assert.NotNil(t, out)
}

func TestCloneHeaders_DropsHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("Host", "x")
	h.Set("Connection", "y")
	h.Set("Content-Length", "10")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("X-Custom", "keep")
	out := cloneHeaders(h)
	assert.NotContains(t, out, "Host")
	assert.NotContains(t, out, "Connection")
	assert.NotContains(t, out, "Content-Length")
	assert.NotContains(t, out, "Transfer-Encoding")
	assert.Contains(t, out, "X-Custom")
}

func targetCfg(name string, srv *httptest.Server) config.AggregateTarget {
	trimmed := strings.TrimPrefix(srv.URL, "http://")
	parts := strings.Split(trimmed, ":")
	port := 0
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			break
		}
		port = port*10 + int(c-'0')
	}
	return config.AggregateTarget{
		Name:        name,
		Destination: config.Destination{Host: parts[0], Port: port},
	}
}

// ensure io import is used (LimitReader exercised through buildRequest body read).
var _ = io.Discard
