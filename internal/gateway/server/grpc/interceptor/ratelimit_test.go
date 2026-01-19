package interceptor

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"github.com/vyrodovalexey/avapigw/internal/ratelimit"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// mockRateLimiter implements RateLimiter for testing
type mockRateLimiter struct {
	allowFunc func(ctx context.Context, key string) (bool, error)
}

func (m *mockRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	if m.allowFunc != nil {
		return m.allowFunc(ctx, key)
	}
	return true, nil
}

// TestUnaryRateLimitInterceptor tests the basic unary rate limit interceptor
func TestUnaryRateLimitInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("allows request when limiter allows", func(t *testing.T) {
		limiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				return true, nil
			},
		}

		interceptor := UnaryRateLimitInterceptor(limiter)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("rejects request when limiter denies", func(t *testing.T) {
		limiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				return false, nil
			},
		}

		interceptor := UnaryRateLimitInterceptor(limiter)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.ResourceExhausted, st.Code())
	})

	t.Run("passes with nil limiter", func(t *testing.T) {
		interceptor := UnaryRateLimitInterceptor(nil)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestUnaryRateLimitInterceptorWithConfig tests the configurable unary rate limit interceptor
func TestUnaryRateLimitInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips rate limiting for configured methods", func(t *testing.T) {
		limiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				return false, nil // Would deny if called
			},
		}

		config := RateLimitConfig{
			Limiter:     limiter,
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := UnaryRateLimitInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("uses custom key function", func(t *testing.T) {
		var receivedKey string
		limiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				receivedKey = key
				return true, nil
			},
		}

		config := RateLimitConfig{
			Limiter: limiter,
			KeyFunc: func(ctx context.Context, method string, md metadata.MD) string {
				return "custom-key"
			},
		}

		interceptor := UnaryRateLimitInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		_, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "custom-key", receivedKey)
	})

	t.Run("allows request on limiter error", func(t *testing.T) {
		limiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				return false, assert.AnError
			},
		}

		config := RateLimitConfig{
			Limiter: limiter,
			Logger:  zap.NewNop(),
		}

		interceptor := UnaryRateLimitInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestStreamRateLimitInterceptor tests the basic stream rate limit interceptor
func TestStreamRateLimitInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("allows stream when limiter allows", func(t *testing.T) {
		limiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				return true, nil
			},
		}

		interceptor := StreamRateLimitInterceptor(limiter)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("rejects stream when limiter denies", func(t *testing.T) {
		limiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				return false, nil
			},
		}

		interceptor := StreamRateLimitInterceptor(limiter)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.ResourceExhausted, st.Code())
	})
}

// TestStreamRateLimitInterceptorWithConfig tests the configurable stream rate limit interceptor
func TestStreamRateLimitInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips rate limiting for configured methods", func(t *testing.T) {
		limiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				return false, nil
			},
		}

		config := RateLimitConfig{
			Limiter:     limiter,
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := StreamRateLimitInterceptorWithConfig(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("allows stream on limiter error", func(t *testing.T) {
		limiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				return false, assert.AnError
			},
		}

		config := RateLimitConfig{
			Limiter: limiter,
			Logger:  zap.NewNop(),
		}

		interceptor := StreamRateLimitInterceptorWithConfig(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})
}

// TestDefaultKeyFunc tests the default key function
func TestDefaultKeyFunc(t *testing.T) {
	t.Parallel()

	t.Run("uses x-forwarded-for header", func(t *testing.T) {
		md := metadata.MD{
			"x-forwarded-for": []string{"192.168.1.1"},
		}

		key := defaultKeyFunc(context.Background(), "/test.Service/Method", md)

		assert.Equal(t, "192.168.1.1", key)
	})

	t.Run("uses x-real-ip header", func(t *testing.T) {
		md := metadata.MD{
			"x-real-ip": []string{"10.0.0.1"},
		}

		key := defaultKeyFunc(context.Background(), "/test.Service/Method", md)

		assert.Equal(t, "10.0.0.1", key)
	})

	t.Run("uses peer address", func(t *testing.T) {
		addr := &net.TCPAddr{IP: net.ParseIP("172.16.0.1"), Port: 12345}
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})

		key := defaultKeyFunc(ctx, "/test.Service/Method", metadata.MD{})

		assert.Equal(t, "172.16.0.1:12345", key)
	})

	t.Run("returns unknown when no source", func(t *testing.T) {
		key := defaultKeyFunc(context.Background(), "/test.Service/Method", metadata.MD{})

		assert.Equal(t, "unknown", key)
	})
}

// TestTokenBucketLimiterWithAdapter tests the token bucket rate limiter via adapter
func TestTokenBucketLimiterWithAdapter(t *testing.T) {
	t.Parallel()

	t.Run("allows requests within rate", func(t *testing.T) {
		// Use the internal ratelimit package with nil store for local rate limiting
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil) // 10 requests/sec, burst of 10
		defer limiter.Close()
		adapter := NewLimiterFromRatelimit(limiter)

		ctx := context.Background()

		// Should allow burst
		for i := 0; i < 10; i++ {
			allowed, err := adapter.Allow(ctx, "test-key")
			assert.NoError(t, err)
			assert.True(t, allowed)
		}
	})

	t.Run("denies requests over limit", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 1, 1, nil) // 1 request/sec, burst of 1
		defer limiter.Close()
		adapter := NewLimiterFromRatelimit(limiter)

		ctx := context.Background()

		// First request should be allowed
		allowed, err := adapter.Allow(ctx, "test-key")
		assert.NoError(t, err)
		assert.True(t, allowed)

		// Second request should be denied
		allowed, err = adapter.Allow(ctx, "test-key")
		assert.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("refills tokens over time", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 100, 1, nil) // 100 requests/sec, burst of 1
		defer limiter.Close()
		adapter := NewLimiterFromRatelimit(limiter)

		ctx := context.Background()

		// Use the token
		allowed, _ := adapter.Allow(ctx, "test-key")
		assert.True(t, allowed)

		// Should be denied immediately
		allowed, _ = adapter.Allow(ctx, "test-key")
		assert.False(t, allowed)

		// Wait for refill
		time.Sleep(20 * time.Millisecond)

		// Should be allowed again
		allowed, _ = adapter.Allow(ctx, "test-key")
		assert.True(t, allowed)
	})

	t.Run("tracks different keys separately", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 1, 1, nil)
		defer limiter.Close()
		adapter := NewLimiterFromRatelimit(limiter)

		ctx := context.Background()

		// Use token for key1
		allowed, _ := adapter.Allow(ctx, "key1")
		assert.True(t, allowed)

		// key1 should be denied
		allowed, _ = adapter.Allow(ctx, "key1")
		assert.False(t, allowed)

		// key2 should still be allowed
		allowed, _ = adapter.Allow(ctx, "key2")
		assert.True(t, allowed)
	})
}

// TestSlidingWindowLimiterWithAdapter tests the sliding window rate limiter via adapter
func TestSlidingWindowLimiterWithAdapter(t *testing.T) {
	t.Parallel()

	t.Run("allows requests within limit", func(t *testing.T) {
		limiter := ratelimit.NewSlidingWindowLimiter(nil, 10, time.Second, nil)
		adapter := NewLimiterFromRatelimit(limiter)

		ctx := context.Background()

		for i := 0; i < 10; i++ {
			allowed, err := adapter.Allow(ctx, "test-key")
			assert.NoError(t, err)
			assert.True(t, allowed)
		}
	})

	t.Run("denies requests over limit", func(t *testing.T) {
		limiter := ratelimit.NewSlidingWindowLimiter(nil, 2, time.Second, nil)
		adapter := NewLimiterFromRatelimit(limiter)

		ctx := context.Background()

		// First two requests should be allowed
		allowed, _ := adapter.Allow(ctx, "test-key")
		assert.True(t, allowed)
		allowed, _ = adapter.Allow(ctx, "test-key")
		assert.True(t, allowed)

		// Third request should be denied
		allowed, _ = adapter.Allow(ctx, "test-key")
		assert.False(t, allowed)
	})

	t.Run("allows requests after window expires", func(t *testing.T) {
		limiter := ratelimit.NewSlidingWindowLimiter(nil, 1, 50*time.Millisecond, nil)
		adapter := NewLimiterFromRatelimit(limiter)

		ctx := context.Background()

		// Use the limit
		allowed, _ := adapter.Allow(ctx, "test-key")
		assert.True(t, allowed)

		// Should be denied
		allowed, _ = adapter.Allow(ctx, "test-key")
		assert.False(t, allowed)

		// Wait for window to expire
		time.Sleep(60 * time.Millisecond)

		// Should be allowed again
		allowed, _ = adapter.Allow(ctx, "test-key")
		assert.True(t, allowed)
	})

	t.Run("tracks different keys separately", func(t *testing.T) {
		limiter := ratelimit.NewSlidingWindowLimiter(nil, 1, time.Second, nil)
		adapter := NewLimiterFromRatelimit(limiter)

		ctx := context.Background()

		// Use limit for key1
		allowed, _ := adapter.Allow(ctx, "key1")
		assert.True(t, allowed)

		// key1 should be denied
		allowed, _ = adapter.Allow(ctx, "key1")
		assert.False(t, allowed)

		// key2 should still be allowed
		allowed, _ = adapter.Allow(ctx, "key2")
		assert.True(t, allowed)
	})
}

// TestMethodRateLimiter tests the method-based rate limiter
func TestMethodRateLimiter(t *testing.T) {
	t.Parallel()

	t.Run("uses default limiter", func(t *testing.T) {
		defaultLimiter := &mockRateLimiter{
			allowFunc: func(ctx context.Context, key string) (bool, error) {
				return true, nil
			},
		}

		limiter := &MethodRateLimiter{
			DefaultLimiter: defaultLimiter,
		}

		allowed, err := limiter.Allow(context.Background(), "test-key")

		assert.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("allows when no default limiter", func(t *testing.T) {
		limiter := &MethodRateLimiter{}

		allowed, err := limiter.Allow(context.Background(), "test-key")

		assert.NoError(t, err)
		assert.True(t, allowed)
	})
}

// TestNoopLimiter tests the noop rate limiter
func TestNoopLimiter(t *testing.T) {
	t.Parallel()

	limiter := &NoopLimiter{}

	allowed, err := limiter.Allow(context.Background(), "any-key")

	assert.NoError(t, err)
	assert.True(t, allowed)
}

// TestRateLimitConfig tests RateLimitConfig struct
func TestRateLimitConfig(t *testing.T) {
	t.Parallel()

	t.Run("default values", func(t *testing.T) {
		config := RateLimitConfig{}

		assert.Nil(t, config.Limiter)
		assert.Nil(t, config.Logger)
		assert.Nil(t, config.KeyFunc)
		assert.Nil(t, config.SkipMethods)
	})

	t.Run("with all fields", func(t *testing.T) {
		limiter := &NoopLimiter{}
		logger := zap.NewNop()
		keyFunc := func(ctx context.Context, method string, md metadata.MD) string {
			return "key"
		}

		config := RateLimitConfig{
			Limiter:     limiter,
			Logger:      logger,
			KeyFunc:     keyFunc,
			SkipMethods: []string{"/test.Service/Method"},
		}

		assert.NotNil(t, config.Limiter)
		assert.NotNil(t, config.Logger)
		assert.NotNil(t, config.KeyFunc)
		assert.Len(t, config.SkipMethods, 1)
	})
}

// TestNewLimiterFromRatelimit tests the adapter creation
func TestNewLimiterFromRatelimit(t *testing.T) {
	t.Parallel()

	t.Run("creates adapter from limiter", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()
		adapter := NewLimiterFromRatelimit(limiter)

		assert.NotNil(t, adapter)

		allowed, err := adapter.Allow(context.Background(), "test")
		assert.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("handles nil limiter", func(t *testing.T) {
		adapter := NewLimiterFromRatelimit(nil)

		assert.NotNil(t, adapter)

		// Should use noop limiter
		allowed, err := adapter.Allow(context.Background(), "test")
		assert.NoError(t, err)
		assert.True(t, allowed)
	})
}

// TestUnaryRateLimitInterceptorWithCore tests the core-based unary rate limit interceptor
func TestUnaryRateLimitInterceptorWithCore(t *testing.T) {
	t.Parallel()

	t.Run("skips rate limiting for configured methods", func(t *testing.T) {
		coreConfig := core.RateLimitCoreConfig{
			BaseConfig: core.BaseConfig{
				SkipPaths: []string{"/test.Service/SkippedMethod"},
			},
		}

		interceptor := UnaryRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("allows request when rate limit not exceeded", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()

		coreConfig := core.RateLimitCoreConfig{
			Limiter: limiter,
		}

		interceptor := UnaryRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("rejects request when rate limit exceeded", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 1, 1, nil)
		defer limiter.Close()

		coreConfig := core.RateLimitCoreConfig{
			Limiter: limiter,
		}

		interceptor := UnaryRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		// First request should succeed
		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)
		assert.NoError(t, err)
		assert.Equal(t, "response", resp)

		// Second request should be rate limited
		resp, err = interceptor(ctx, "request", info, mockUnaryHandler)
		assert.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.ResourceExhausted, st.Code())
	})

	t.Run("handles missing metadata gracefully", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()

		coreConfig := core.RateLimitCoreConfig{
			Limiter: limiter,
		}

		interceptor := UnaryRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background() // No metadata
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("uses nil limiter gracefully", func(t *testing.T) {
		coreConfig := core.RateLimitCoreConfig{
			Limiter: nil, // Will use noop limiter
		}

		interceptor := UnaryRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestStreamRateLimitInterceptorWithCore tests the core-based stream rate limit interceptor
func TestStreamRateLimitInterceptorWithCore(t *testing.T) {
	t.Parallel()

	t.Run("skips rate limiting for configured methods", func(t *testing.T) {
		coreConfig := core.RateLimitCoreConfig{
			BaseConfig: core.BaseConfig{
				SkipPaths: []string{"/test.Service/SkippedMethod"},
			},
		}

		interceptor := StreamRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("allows stream when rate limit not exceeded", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()

		coreConfig := core.RateLimitCoreConfig{
			Limiter: limiter,
		}

		interceptor := StreamRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("rejects stream when rate limit exceeded", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 1, 1, nil)
		defer limiter.Close()

		coreConfig := core.RateLimitCoreConfig{
			Limiter: limiter,
		}

		interceptor := StreamRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		// First request should succeed
		err := interceptor(nil, stream, info, mockStreamHandler)
		assert.NoError(t, err)

		// Second request should be rate limited
		err = interceptor(nil, stream, info, mockStreamHandler)
		assert.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.ResourceExhausted, st.Code())
	})

	t.Run("handles missing metadata gracefully", func(t *testing.T) {
		limiter := ratelimit.NewTokenBucketLimiter(nil, 10, 10, nil)
		defer limiter.Close()

		coreConfig := core.RateLimitCoreConfig{
			Limiter: limiter,
		}

		interceptor := StreamRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background() // No metadata
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("uses nil limiter gracefully", func(t *testing.T) {
		coreConfig := core.RateLimitCoreConfig{
			Limiter: nil, // Will use noop limiter
		}

		interceptor := StreamRateLimitInterceptorWithCore(coreConfig)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})
}
