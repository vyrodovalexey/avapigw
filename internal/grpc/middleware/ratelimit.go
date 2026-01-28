package middleware

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Rate limiter default configuration constants.
const (
	// DefaultGRPCClientTTL is the default TTL for client rate limiter entries.
	DefaultGRPCClientTTL = 10 * time.Minute

	// DefaultGRPCMaxClients is the default maximum number of client entries.
	// This prevents unbounded memory growth from malicious or high-cardinality clients.
	DefaultGRPCMaxClients = 100000

	// MinGRPCCleanupInterval is the minimum interval for cleanup operations.
	MinGRPCCleanupInterval = 10 * time.Second

	// MaxGRPCCleanupInterval is the maximum interval for cleanup operations.
	MaxGRPCCleanupInterval = time.Minute
)

// grpcClientEntry holds a rate limiter and its last access time for TTL-based cleanup.
type grpcClientEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// GRPCRateLimiter provides rate limiting for gRPC requests.
type GRPCRateLimiter struct {
	limiter    *rate.Limiter
	perClient  bool
	clients    map[string]*grpcClientEntry
	mu         sync.RWMutex
	rps        int
	burst      int
	logger     observability.Logger
	clientTTL  time.Duration
	maxClients int
	stopCh     chan struct{}
	stopped    bool
}

// RateLimiterOption is a functional option for configuring the rate limiter.
type RateLimiterOption func(*GRPCRateLimiter)

// WithRateLimiterLogger sets the logger for the rate limiter.
func WithRateLimiterLogger(logger observability.Logger) RateLimiterOption {
	return func(rl *GRPCRateLimiter) {
		rl.logger = logger
	}
}

// WithGRPCClientTTL sets the TTL for client entries.
func WithGRPCClientTTL(ttl time.Duration) RateLimiterOption {
	return func(rl *GRPCRateLimiter) {
		rl.clientTTL = ttl
	}
}

// WithGRPCMaxClients sets the maximum number of client entries.
func WithGRPCMaxClients(maxClients int) RateLimiterOption {
	return func(rl *GRPCRateLimiter) {
		rl.maxClients = maxClients
	}
}

// NewGRPCRateLimiter creates a new gRPC rate limiter.
func NewGRPCRateLimiter(rps, burst int, perClient bool, opts ...RateLimiterOption) *GRPCRateLimiter {
	rl := &GRPCRateLimiter{
		limiter:    rate.NewLimiter(rate.Limit(rps), burst),
		perClient:  perClient,
		clients:    make(map[string]*grpcClientEntry),
		rps:        rps,
		burst:      burst,
		logger:     observability.NopLogger(),
		clientTTL:  DefaultGRPCClientTTL,
		maxClients: DefaultGRPCMaxClients,
		stopCh:     make(chan struct{}),
	}

	for _, opt := range opts {
		opt(rl)
	}

	return rl
}

// Allow checks if a request is allowed.
func (rl *GRPCRateLimiter) Allow(clientAddr string) bool {
	if rl.perClient {
		return rl.allowPerClient(clientAddr)
	}
	return rl.limiter.Allow()
}

// allowPerClient checks rate limit per client.
// Uses a single critical section to avoid race conditions between
// checking existence and updating lastAccess time.
func (rl *GRPCRateLimiter) allowPerClient(clientAddr string) bool {
	now := time.Now()

	rl.mu.Lock()
	entry, exists := rl.clients[clientAddr]
	if !exists {
		// Check if we've hit the max clients limit before adding a new entry
		if len(rl.clients) >= rl.maxClients {
			// Evict oldest entries to make room
			rl.evictOldestLocked()
		}
		entry = &grpcClientEntry{
			limiter:    rate.NewLimiter(rate.Limit(rl.rps), rl.burst),
			lastAccess: now,
		}
		rl.clients[clientAddr] = entry
	} else {
		// Update last access time within the same critical section
		entry.lastAccess = now
	}
	// Get the limiter reference while holding the lock
	limiter := entry.limiter
	rl.mu.Unlock()

	// Allow() is thread-safe on the limiter itself
	return limiter.Allow()
}

// evictOldestLocked evicts the oldest entries to make room for new ones.
// Must be called with the mutex held.
func (rl *GRPCRateLimiter) evictOldestLocked() {
	// First, remove expired entries
	now := time.Now()
	for clientAddr, entry := range rl.clients {
		if now.Sub(entry.lastAccess) > rl.clientTTL {
			delete(rl.clients, clientAddr)
		}
	}

	// If still over capacity, remove oldest entries until we're at 90% capacity
	targetSize := rl.maxClients * 9 / 10
	for len(rl.clients) > targetSize {
		var oldestKey string
		var oldestTime time.Time

		for key, entry := range rl.clients {
			if oldestKey == "" || entry.lastAccess.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.lastAccess
			}
		}

		if oldestKey != "" {
			delete(rl.clients, oldestKey)
		} else {
			break
		}
	}

	rl.logger.Debug("evicted old gRPC rate limiter entries",
		observability.Int("remaining", len(rl.clients)),
		observability.Int("max_clients", rl.maxClients),
	)
}

// CleanupOldClients removes old client limiters to prevent memory leaks.
// It removes entries that haven't been accessed within the TTL period.
func (rl *GRPCRateLimiter) CleanupOldClients() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	expiredClients := make([]string, 0)

	// Find expired entries
	for clientAddr, entry := range rl.clients {
		if now.Sub(entry.lastAccess) > rl.clientTTL {
			expiredClients = append(expiredClients, clientAddr)
		}
	}

	// Remove expired entries
	for _, clientAddr := range expiredClients {
		delete(rl.clients, clientAddr)
	}

	if len(expiredClients) > 0 {
		rl.logger.Debug("cleaned up expired gRPC rate limiter entries",
			observability.Int("removed", len(expiredClients)),
			observability.Int("remaining", len(rl.clients)),
		)
	}
}

// StartAutoCleanup starts automatic cleanup using the rate limiter's internal stop channel.
// This should be called after creating the rate limiter to enable TTL-based cleanup.
func (rl *GRPCRateLimiter) StartAutoCleanup() {
	rl.mu.Lock()
	if rl.stopped {
		rl.mu.Unlock()
		return
	}
	rl.mu.Unlock()

	go func() {
		// Run cleanup every minute or at half the TTL, whichever is smaller
		cleanupInterval := rl.clientTTL / 2
		if cleanupInterval > MaxGRPCCleanupInterval {
			cleanupInterval = MaxGRPCCleanupInterval
		}
		if cleanupInterval < MinGRPCCleanupInterval {
			cleanupInterval = MinGRPCCleanupInterval
		}

		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				rl.CleanupOldClients()
			case <-rl.stopCh:
				return
			}
		}
	}()
}

// Stop stops the rate limiter cleanup goroutine.
func (rl *GRPCRateLimiter) Stop() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if !rl.stopped {
		rl.stopped = true
		close(rl.stopCh)
	}
}

// SetClientTTL sets the TTL for client entries.
func (rl *GRPCRateLimiter) SetClientTTL(ttl time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.clientTTL = ttl
}

// SetMaxClients sets the maximum number of client entries.
func (rl *GRPCRateLimiter) SetMaxClients(maxClients int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxClients = maxClients
}

// ClientCount returns the current number of client entries.
func (rl *GRPCRateLimiter) ClientCount() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return len(rl.clients)
}

// UnaryRateLimitInterceptor returns a unary server interceptor that applies rate limiting.
func UnaryRateLimitInterceptor(limiter *GRPCRateLimiter) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		clientAddr := getClientAddrFromContext(ctx)

		if !limiter.Allow(clientAddr) {
			limiter.logger.Warn("rate limit exceeded",
				observability.String("client_addr", clientAddr),
				observability.String("method", info.FullMethod),
			)
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// StreamRateLimitInterceptor returns a stream server interceptor that applies rate limiting.
func StreamRateLimitInterceptor(limiter *GRPCRateLimiter) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := stream.Context()
		clientAddr := getClientAddrFromContext(ctx)

		if !limiter.Allow(clientAddr) {
			limiter.logger.Warn("rate limit exceeded",
				observability.String("client_addr", clientAddr),
				observability.String("method", info.FullMethod),
			)
			return status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(srv, stream)
	}
}

// getClientAddrFromContext extracts the client address from context.
func getClientAddrFromContext(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return "unknown"
}
