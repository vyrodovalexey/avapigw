package era

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// fakeResolver implements BackendResolver.
type fakeResolver struct {
	sb   *backend.ServiceBackend
	path string
	ok   bool
}

func (r *fakeResolver) ResolveBackend(_ string) (*backend.ServiceBackend, string, bool) {
	return r.sb, r.path, r.ok
}

func backendFor(t *testing.T, serverURL string) *backend.ServiceBackend {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	sb, err := backend.NewBackend(config.Backend{
		Name:  "u1",
		Hosts: []config.BackendHost{{Address: u.Hostname(), Port: port}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

func TestNewHTTPLegacyTransport(t *testing.T) {
	t.Parallel()
	tr := NewHTTPLegacyTransport(&fakeResolver{}, 0).(*httpLegacyTransport)
	if tr.maxResponseSize != mcpproxy.DefaultMaxResponseSize {
		t.Fatalf("non-positive size should default, got %d", tr.maxResponseSize)
	}
	tr2 := NewHTTPLegacyTransport(&fakeResolver{}, 123).(*httpLegacyTransport)
	if tr2.maxResponseSize != 123 {
		t.Fatalf("positive size should be kept, got %d", tr2.maxResponseSize)
	}
}

func TestTransportPostRequestHappy(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		w.Header().Set(HeaderMcpSessionID, "sid-42")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	tr := NewHTTPLegacyTransport(&fakeResolver{sb: backendFor(t, srv.URL), path: "/mcp", ok: true}, 0)
	resp, newSID, err := tr.PostRequest(context.Background(), "u1",
		&jsonrpc.Request{JSONRPC: jsonrpc.Version, Method: "tools/list"}, "sess-in")
	if err != nil {
		t.Fatal(err)
	}
	if newSID != "sid-42" || resp == nil {
		t.Fatalf("resp=%v newSID=%q", resp, newSID)
	}
}

func TestTransportPostRequestUnknownUpstream(t *testing.T) {
	t.Parallel()
	tr := NewHTTPLegacyTransport(&fakeResolver{ok: false}, 0)
	_, _, err := tr.PostRequest(context.Background(), "u1", &jsonrpc.Request{}, "")
	if err == nil || !contains(err.Error(), "unknown legacy upstream") {
		t.Fatalf("want unknown upstream error, got %v", err)
	}
}

func TestTransportPostRequest404(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: backendFor(t, srv.URL), path: "/mcp", ok: true}, 0)
	_, _, err := tr.PostRequest(context.Background(), "u1", &jsonrpc.Request{JSONRPC: jsonrpc.Version}, "")
	if err != ErrSessionLost {
		t.Fatalf("want ErrSessionLost, got %v", err)
	}
}

func TestTransportPostRequestNon2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: backendFor(t, srv.URL), path: "/mcp", ok: true}, 0)
	_, _, err := tr.PostRequest(context.Background(), "u1", &jsonrpc.Request{JSONRPC: jsonrpc.Version}, "")
	var ue *mcpproxy.UpstreamError
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.As(err, &ue) || ue.StatusCode != http.StatusBadGateway {
		t.Fatalf("want UpstreamError 502, got %v", err)
	}
}

func TestTransportPostRequestOversized(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 500)))
	}))
	defer srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: backendFor(t, srv.URL), path: "/mcp", ok: true}, 100)
	_, _, err := tr.PostRequest(context.Background(), "u1", &jsonrpc.Request{JSONRPC: jsonrpc.Version}, "")
	if err != mcpproxy.ErrResponseTooLarge {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
}

func TestTransportPostRequestDoError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	sb := backendFor(t, srv.URL)
	srv.Close() // unreachable now
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: sb, path: "/mcp", ok: true}, 0)
	_, _, err := tr.PostRequest(context.Background(), "u1", &jsonrpc.Request{JSONRPC: jsonrpc.Version}, "")
	if err == nil || !contains(err.Error(), "legacy upstream request failed") {
		t.Fatalf("want request failed error, got %v", err)
	}
}

func TestTransportPostNotification(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: backendFor(t, srv.URL), path: "/mcp", ok: true}, 0)
	if err := tr.PostNotification(context.Background(), "u1", &jsonrpc.Request{JSONRPC: jsonrpc.Version, Method: "ping"}, "sid"); err != nil {
		t.Fatal(err)
	}
}

func TestTransportPostNotificationUnknown(t *testing.T) {
	t.Parallel()
	tr := NewHTTPLegacyTransport(&fakeResolver{ok: false}, 0)
	if err := tr.PostNotification(context.Background(), "u1", &jsonrpc.Request{}, ""); err == nil {
		t.Fatal("expected unknown upstream error")
	}
}

func TestTransportPostNotification404(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: backendFor(t, srv.URL), path: "/mcp", ok: true}, 0)
	if err := tr.PostNotification(context.Background(), "u1", &jsonrpc.Request{JSONRPC: jsonrpc.Version}, ""); err != ErrSessionLost {
		t.Fatalf("want ErrSessionLost, got %v", err)
	}
}

func TestTransportPostNotificationDoError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	sb := backendFor(t, srv.URL)
	srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: sb, path: "/mcp", ok: true}, 0)
	if err := tr.PostNotification(context.Background(), "u1", &jsonrpc.Request{JSONRPC: jsonrpc.Version}, ""); err == nil || !contains(err.Error(), "legacy notification failed") {
		t.Fatalf("want notification failed error, got %v", err)
	}
}

func TestTransportOpenServerStreamHappy(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeSSE)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"method\":\"notifications/resources/updated\"}\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: backendFor(t, srv.URL), path: "/mcp", ok: true}, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	received := make(chan mcpproxy.SSEEvent, 1)
	err := tr.OpenServerStream(ctx, "u1", "sid", "last-1", func(ev mcpproxy.SSEEvent) error {
		received <- ev
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	default:
		t.Fatal("no event relayed")
	}
}

func TestTransportOpenServerStreamUnknown(t *testing.T) {
	t.Parallel()
	tr := NewHTTPLegacyTransport(&fakeResolver{ok: false}, 0)
	if err := tr.OpenServerStream(context.Background(), "u1", "sid", "", func(mcpproxy.SSEEvent) error { return nil }); err == nil {
		t.Fatal("expected unknown upstream error")
	}
}

func TestTransportOpenServerStream404(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: backendFor(t, srv.URL), path: "/mcp", ok: true}, 0)
	if err := tr.OpenServerStream(context.Background(), "u1", "sid", "", func(mcpproxy.SSEEvent) error { return nil }); err != ErrSessionLost {
		t.Fatalf("want ErrSessionLost, got %v", err)
	}
}

func TestTransportOpenServerStreamNon2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: backendFor(t, srv.URL), path: "/mcp", ok: true}, 0)
	err := tr.OpenServerStream(context.Background(), "u1", "sid", "", func(mcpproxy.SSEEvent) error { return nil })
	if err == nil || !contains(err.Error(), "legacy SSE status 500") {
		t.Fatalf("want SSE status error, got %v", err)
	}
}

func TestTransportOpenServerStreamDoError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	sb := backendFor(t, srv.URL)
	srv.Close()
	tr := NewHTTPLegacyTransport(&fakeResolver{sb: sb, path: "/mcp", ok: true}, 0)
	if err := tr.OpenServerStream(context.Background(), "u1", "sid", "", func(mcpproxy.SSEEvent) error { return nil }); err == nil || !contains(err.Error(), "open legacy SSE") {
		t.Fatalf("want open SSE error, got %v", err)
	}
}
