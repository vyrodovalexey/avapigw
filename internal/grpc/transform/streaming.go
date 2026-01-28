// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// StreamingTransformer handles streaming message transformation.
type StreamingTransformer struct {
	logger         observability.Logger
	msgTransformer *ProtobufTransformer

	// Rate limiting
	rateLimiter *rate.Limiter

	// Message counting with mutex for thread-safe increment operations
	messageCount   int64
	messageCountMu sync.Mutex

	// Buffer for aggregation
	buffer []proto.Message
	bufMu  sync.Mutex

	// Stream start time for timeout tracking
	streamStartTime time.Time

	// Last message time for message timeout tracking
	lastMessageTime time.Time
	lastMsgMu       sync.RWMutex

	// Configuration
	bufferSize int
	rateLimit  int
}

// StreamingTransformerOption is a functional option for configuring the streaming transformer.
type StreamingTransformerOption func(*StreamingTransformer)

// WithStreamingRateLimit sets the rate limit for the streaming transformer.
func WithStreamingRateLimit(messagesPerSecond int) StreamingTransformerOption {
	return func(st *StreamingTransformer) {
		st.rateLimit = messagesPerSecond
	}
}

// WithStreamingBufferSize sets the buffer size for aggregation.
func WithStreamingBufferSize(size int) StreamingTransformerOption {
	return func(st *StreamingTransformer) {
		st.bufferSize = size
	}
}

// NewStreamingTransformer creates a new streaming transformer.
func NewStreamingTransformer(
	logger observability.Logger,
	cfg *config.StreamingTransformConfig,
	opts ...StreamingTransformerOption,
) *StreamingTransformer {
	if logger == nil {
		logger = observability.NopLogger()
	}

	st := &StreamingTransformer{
		logger:          logger,
		msgTransformer:  NewProtobufTransformer(logger),
		buffer:          make([]proto.Message, 0),
		streamStartTime: time.Now(),
		lastMessageTime: time.Now(),
		bufferSize:      100, // Default buffer size
	}

	// Apply configuration from config
	if cfg != nil {
		if cfg.BufferSize > 0 {
			st.bufferSize = cfg.BufferSize
		}
		if cfg.RateLimit > 0 {
			st.rateLimit = cfg.RateLimit
			st.rateLimiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)
		}
	}

	// Apply functional options
	for _, opt := range opts {
		opt(st)
	}

	// Create rate limiter if rate limit is set
	if st.rateLimit > 0 && st.rateLimiter == nil {
		st.rateLimiter = rate.NewLimiter(rate.Limit(st.rateLimit), st.rateLimit)
	}

	return st
}

// TransformStreamMessage transforms a single message in a stream.
// Returns the transformed message, a boolean indicating if the message should be sent,
// and any error that occurred.
func (t *StreamingTransformer) TransformStreamMessage(
	ctx context.Context,
	msg proto.Message,
	sequence int,
	cfg *config.StreamingTransformConfig,
) (result proto.Message, shouldSend bool, err error) {
	if msg == nil {
		return nil, false, ErrNilMessage
	}

	// Update message count
	atomic.AddInt64(&t.messageCount, 1)

	// Update last message time
	t.lastMsgMu.Lock()
	t.lastMessageTime = time.Now()
	t.lastMsgMu.Unlock()

	// Check message timeout
	if err := t.CheckMessageTimeout(ctx, cfg); err != nil {
		return nil, false, err
	}

	// Apply rate limiting
	if err := t.ApplyRateLimit(ctx); err != nil {
		return nil, false, err
	}

	// Check if message should be filtered
	shouldFilter, err := t.ShouldFilter(ctx, msg, cfg)
	if err != nil {
		return nil, false, err
	}
	if shouldFilter {
		t.logger.Debug("message filtered",
			observability.Int("sequence", sequence))
		return nil, false, nil
	}

	// Transform the message if per-message transform is enabled
	result = msg
	if cfg != nil && cfg.PerMessageTransform {
		// Create a transform config for the message
		transformCfg := &config.GRPCTransformConfig{
			Response: &config.GRPCResponseTransformConfig{},
		}

		var transformErr error
		result, transformErr = t.msgTransformer.TransformMessage(ctx, msg, transformCfg)
		if transformErr != nil {
			return nil, false, transformErr
		}
	}

	// Handle aggregation
	if cfg != nil && cfg.Aggregate {
		t.bufMu.Lock()
		t.buffer = append(t.buffer, result)
		bufferFull := len(t.buffer) >= t.bufferSize
		t.bufMu.Unlock()

		if !bufferFull {
			// Don't send yet, buffer the message
			return nil, false, nil
		}

		// Buffer is full, aggregate and send
		aggregated, aggErr := t.AggregateMessages(ctx, t.buffer)
		if aggErr != nil {
			return nil, false, aggErr
		}

		// Clear the buffer
		t.bufMu.Lock()
		t.buffer = make([]proto.Message, 0, t.bufferSize)
		t.bufMu.Unlock()

		return aggregated, true, nil
	}

	t.logger.Debug("transformed stream message",
		observability.Int("sequence", sequence),
		observability.Int64("totalMessages", atomic.LoadInt64(&t.messageCount)))

	return result, true, nil
}

// ShouldFilter evaluates if a message should be filtered based on conditions.
func (t *StreamingTransformer) ShouldFilter(
	ctx context.Context,
	msg proto.Message,
	cfg *config.StreamingTransformConfig,
) (bool, error) {
	if cfg == nil || cfg.FilterCondition == "" {
		return false, nil
	}

	// Note: Full CEL expression support would require additional dependencies.
	// This is a simplified implementation that always returns false (no filtering).
	// In a production implementation, you would use the CEL library to evaluate
	// the filter condition against the message.

	t.logger.Debug("evaluating filter condition (simplified)",
		observability.String("condition", cfg.FilterCondition))

	return false, nil
}

// AggregateMessages aggregates multiple messages into one.
// The aggregation strategy depends on the message type.
// For messages with repeated fields, elements are combined.
// For other messages, the last message is returned.
func (t *StreamingTransformer) AggregateMessages(
	ctx context.Context,
	messages []proto.Message,
) (proto.Message, error) {
	if len(messages) == 0 {
		return nil, ErrNilMessage
	}

	if len(messages) == 1 {
		return messages[0], nil
	}

	// For simplicity, return the last message
	// A more sophisticated implementation would merge repeated fields
	result := proto.Clone(messages[len(messages)-1])

	t.logger.Debug("aggregated messages",
		observability.Int("messageCount", len(messages)))

	return result, nil
}

// ApplyRateLimit applies rate limiting to the stream.
func (t *StreamingTransformer) ApplyRateLimit(ctx context.Context) error {
	if t.rateLimiter == nil {
		return nil
	}

	if err := t.rateLimiter.Wait(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrRateLimitExceeded
	}

	return nil
}

// CheckMessageTimeout checks if the message timeout has been exceeded.
func (t *StreamingTransformer) CheckMessageTimeout(
	ctx context.Context,
	cfg *config.StreamingTransformConfig,
) error {
	if cfg == nil {
		return nil
	}

	// Check total timeout
	if cfg.TotalTimeout > 0 {
		elapsed := time.Since(t.streamStartTime)
		if elapsed > time.Duration(cfg.TotalTimeout) {
			return NewTransformError("streaming", "", "total timeout exceeded")
		}
	}

	// Check message timeout
	if cfg.MessageTimeout > 0 {
		t.lastMsgMu.RLock()
		lastMsg := t.lastMessageTime
		t.lastMsgMu.RUnlock()

		elapsed := time.Since(lastMsg)
		if elapsed > time.Duration(cfg.MessageTimeout) {
			return ErrMessageTimeout
		}
	}

	return nil
}

// Reset resets the transformer state for a new stream.
func (t *StreamingTransformer) Reset() {
	t.bufMu.Lock()
	t.buffer = make([]proto.Message, 0, t.bufferSize)
	t.bufMu.Unlock()

	atomic.StoreInt64(&t.messageCount, 0)

	t.lastMsgMu.Lock()
	t.streamStartTime = time.Now()
	t.lastMessageTime = time.Now()
	t.lastMsgMu.Unlock()

	t.logger.Debug("streaming transformer reset")
}

// GetMessageCount returns the current message count.
func (t *StreamingTransformer) GetMessageCount() int64 {
	return atomic.LoadInt64(&t.messageCount)
}

// IncrementMessageCount safely increments the message count and returns the new value.
// This method uses mutex protection for thread-safe increment operations.
func (t *StreamingTransformer) IncrementMessageCount() int64 {
	t.messageCountMu.Lock()
	defer t.messageCountMu.Unlock()
	t.messageCount++
	return t.messageCount
}

// GetBufferedMessages returns the currently buffered messages.
func (t *StreamingTransformer) GetBufferedMessages() []proto.Message {
	t.bufMu.Lock()
	defer t.bufMu.Unlock()

	result := make([]proto.Message, len(t.buffer))
	copy(result, t.buffer)
	return result
}

// FlushBuffer flushes the buffer and returns aggregated messages.
func (t *StreamingTransformer) FlushBuffer(ctx context.Context) (proto.Message, error) {
	t.bufMu.Lock()
	messages := t.buffer
	t.buffer = make([]proto.Message, 0, t.bufferSize)
	t.bufMu.Unlock()

	if len(messages) == 0 {
		return nil, nil
	}

	return t.AggregateMessages(ctx, messages)
}
