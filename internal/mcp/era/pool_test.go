package era

import (
	"context"
	"errors"
	"testing"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func okInitTransport() *fakeTransport {
	return &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
		},
	}
}

func TestNewSessionPoolNilArgs(t *testing.T) {
	t.Parallel()
	if _, err := NewSessionPool(nil, &fakeFactory{}); err == nil {
		t.Fatal("want nil transport error")
	}
	if _, err := NewSessionPool(&fakeTransport{}, nil); err == nil {
		t.Fatal("want nil factory error")
	}
}

func TestNewSessionPoolOptions(t *testing.T) {
	t.Parallel()
	p, err := NewSessionPool(&fakeTransport{}, &fakeFactory{},
		WithPoolLogger(nil), WithPoolLogger(observability.NopLogger()),
		WithPoolMetrics(nil), WithPoolMetrics(mcpmetrics.GetMetrics()))
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("nil pool")
	}
}

func TestAcquireFirstUseInit(t *testing.T) {
	t.Parallel()
	p, _ := NewSessionPool(okInitTransport(), &fakeFactory{})
	sess, err := p.Acquire(context.Background(), "u1")
	if err != nil || sess == nil {
		t.Fatalf("Acquire = %v,%v", sess, err)
	}
	if sess.SessionID() != "sid-1" {
		t.Fatalf("session id = %q", sess.SessionID())
	}
	p.Close()
}

func TestAcquireSharedSession(t *testing.T) {
	t.Parallel()
	tp := okInitTransport()
	p, _ := NewSessionPool(tp, &fakeFactory{})
	s1, _ := p.Acquire(context.Background(), "u1")
	s2, _ := p.Acquire(context.Background(), "u1")
	if s1 != s2 {
		t.Fatal("expected shared session")
	}
	post, _, _ := tp.calls()
	if post != 1 {
		t.Fatalf("expected single init post, got %d", post)
	}
	p.Close()
}

func TestAcquireInitFailureDrops(t *testing.T) {
	t.Parallel()
	failing := true
	tp := &fakeTransport{
		postRequestFn: func(_ context.Context, _ string, _ *jsonrpc.Request, _ string) (*jsonrpc.Response, string, error) {
			if failing {
				return nil, "", errors.New("init boom")
			}
			return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "sid-1", nil
		},
	}
	p, _ := NewSessionPool(tp, &fakeFactory{})
	if _, err := p.Acquire(context.Background(), "u1"); err == nil {
		t.Fatal("expected init error")
	}
	// Session dropped; retry succeeds.
	failing = false
	if _, err := p.Acquire(context.Background(), "u1"); err != nil {
		t.Fatalf("retry after drop failed: %v", err)
	}
	p.Close()
}

func TestGetOrCreateInstallsDispatcher(t *testing.T) {
	t.Parallel()
	handler := func(context.Context, string, *jsonrpc.Request) error { return nil }
	p, _ := NewSessionPool(okInitTransport(), &fakeFactory{handler: handler})
	sess, err := p.Acquire(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Dispatcher() == nil {
		t.Fatal("expected non-nil dispatcher")
	}
	p.Close()
}

func TestAcquireClosedPool(t *testing.T) {
	t.Parallel()
	p, _ := NewSessionPool(okInitTransport(), &fakeFactory{})
	p.Close()
	if _, err := p.Acquire(context.Background(), "u1"); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("want ErrPoolClosed, got %v", err)
	}
}

func TestDropDifferentSession(t *testing.T) {
	t.Parallel()
	p, _ := NewSessionPool(okInitTransport(), &fakeFactory{})
	sess, _ := p.Acquire(context.Background(), "u1")
	// Drop a different (unregistered) session: should not delete the current one.
	other := newSession(&fakeTransport{}, nil)
	p.drop("u1", other)
	p.mu.Lock()
	_, ok := p.sessions["u1"]
	p.mu.Unlock()
	if !ok {
		t.Fatal("current session should remain registered")
	}
	_ = sess
	p.Close()
}

func TestRefreshExistingSession(t *testing.T) {
	t.Parallel()
	tp := okInitTransport()
	p, _ := NewSessionPool(tp, &fakeFactory{})
	_, _ = p.Acquire(context.Background(), "u1")
	if err := p.Refresh(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	post, _, _ := tp.calls()
	if post != 2 {
		t.Fatalf("expected 2 init posts (initial + refresh), got %d", post)
	}
	p.Close()
}

func TestRefreshMissingSession(t *testing.T) {
	t.Parallel()
	p, _ := NewSessionPool(okInitTransport(), &fakeFactory{})
	if err := p.Refresh(context.Background(), "unknown"); err != nil {
		t.Fatalf("missing session refresh should be no-op, got %v", err)
	}
	p.Close()
}

func TestRefreshClosedPool(t *testing.T) {
	t.Parallel()
	p, _ := NewSessionPool(okInitTransport(), &fakeFactory{})
	p.Close()
	if err := p.Refresh(context.Background(), "u1"); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("want ErrPoolClosed, got %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	t.Parallel()
	p, _ := NewSessionPool(okInitTransport(), &fakeFactory{})
	_, _ = p.Acquire(context.Background(), "u1")
	p.Close()
	p.Close() // no-op
}
