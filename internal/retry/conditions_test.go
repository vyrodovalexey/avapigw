package retry

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ============================================================================
// Mock Error Types for Testing
// ============================================================================

// mockNetError implements net.Error interface for testing
type mockNetError struct {
	timeout   bool
	temporary bool
	msg       string
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

// mockURLError creates a url.Error for testing
func mockURLError(timeout, temporary bool) *url.Error {
	return &url.Error{
		Op:  "Get",
		URL: "http://example.com",
		Err: &mockNetError{timeout: timeout, temporary: temporary, msg: "mock url error"},
	}
}

// mockOpError creates a net.OpError for testing
func mockOpError() *net.OpError {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: errors.New("connection failed"),
	}
}

// mockOpErrorWithTimeout creates a net.OpError with a timeout error
func mockOpErrorWithTimeout() *net.OpError {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &mockNetError{timeout: true, msg: "timeout"},
	}
}

// mockOpErrorWithTemporary creates a net.OpError with a temporary error
func mockOpErrorWithTemporary() *net.OpError {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &mockNetError{temporary: true, msg: "temporary"},
	}
}

// ============================================================================
// Test Cases for StatusCodeCondition
// ============================================================================

func TestRetryOnStatusCodes(t *testing.T) {
	tests := []struct {
		name        string
		statusCodes []int
		wantLen     int
	}{
		{
			name:        "single status code",
			statusCodes: []int{500},
			wantLen:     1,
		},
		{
			name:        "multiple status codes",
			statusCodes: []int{500, 502, 503, 504},
			wantLen:     4,
		},
		{
			name:        "empty status codes",
			statusCodes: []int{},
			wantLen:     0,
		},
		{
			name:        "duplicate status codes",
			statusCodes: []int{500, 500, 502},
			wantLen:     2, // duplicates are deduplicated in map
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnStatusCodes(tt.statusCodes...)
			require.NotNil(t, condition)
			assert.Len(t, condition.codes, tt.wantLen)
		})
	}
}

func TestStatusCodeCondition_ShouldRetry(t *testing.T) {
	tests := []struct {
		name        string
		statusCodes []int
		testCode    int
		testErr     error
		want        bool
	}{
		{
			name:        "matching status code",
			statusCodes: []int{500, 502, 503},
			testCode:    500,
			testErr:     nil,
			want:        true,
		},
		{
			name:        "non-matching status code",
			statusCodes: []int{500, 502, 503},
			testCode:    404,
			testErr:     nil,
			want:        false,
		},
		{
			name:        "matching with error",
			statusCodes: []int{500, 502, 503},
			testCode:    502,
			testErr:     errors.New("some error"),
			want:        true,
		},
		{
			name:        "zero status code",
			statusCodes: []int{500, 502, 503},
			testCode:    0,
			testErr:     nil,
			want:        false,
		},
		{
			name:        "empty condition",
			statusCodes: []int{},
			testCode:    500,
			testErr:     nil,
			want:        false,
		},
		{
			name:        "200 OK not retryable",
			statusCodes: []int{500, 502, 503},
			testCode:    200,
			testErr:     nil,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnStatusCodes(tt.statusCodes...)
			result := condition.ShouldRetry(tt.testErr, tt.testCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for Retry5xxCondition
// ============================================================================

func TestRetryOn5xx(t *testing.T) {
	condition := RetryOn5xx()
	require.NotNil(t, condition)
}

func TestRetry5xxCondition_ShouldRetry(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		err        error
		want       bool
	}{
		{
			name:       "500 Internal Server Error",
			statusCode: 500,
			err:        nil,
			want:       true,
		},
		{
			name:       "501 Not Implemented",
			statusCode: 501,
			err:        nil,
			want:       true,
		},
		{
			name:       "502 Bad Gateway",
			statusCode: 502,
			err:        nil,
			want:       true,
		},
		{
			name:       "503 Service Unavailable",
			statusCode: 503,
			err:        nil,
			want:       true,
		},
		{
			name:       "504 Gateway Timeout",
			statusCode: 504,
			err:        nil,
			want:       true,
		},
		{
			name:       "599 upper boundary",
			statusCode: 599,
			err:        nil,
			want:       true,
		},
		{
			name:       "600 not 5xx",
			statusCode: 600,
			err:        nil,
			want:       false,
		},
		{
			name:       "499 not 5xx",
			statusCode: 499,
			err:        nil,
			want:       false,
		},
		{
			name:       "400 Bad Request",
			statusCode: 400,
			err:        nil,
			want:       false,
		},
		{
			name:       "200 OK",
			statusCode: 200,
			err:        nil,
			want:       false,
		},
		{
			name:       "0 status code",
			statusCode: 0,
			err:        nil,
			want:       false,
		},
		{
			name:       "5xx with error",
			statusCode: 503,
			err:        errors.New("service unavailable"),
			want:       true,
		},
	}

	condition := RetryOn5xx()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := condition.ShouldRetry(tt.err, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for RetryableStatusCodes
// ============================================================================

func TestRetryableStatusCodes(t *testing.T) {
	condition := RetryableStatusCodes()
	require.NotNil(t, condition)

	// Verify expected retryable codes
	expectedCodes := []int{408, 429, 500, 502, 503, 504}
	for _, code := range expectedCodes {
		t.Run(fmt.Sprintf("code_%d_is_retryable", code), func(t *testing.T) {
			assert.True(t, condition.ShouldRetry(nil, code), "Expected %d to be retryable", code)
		})
	}

	// Verify non-retryable codes
	nonRetryableCodes := []int{200, 201, 400, 401, 403, 404, 405, 501}
	for _, code := range nonRetryableCodes {
		t.Run(fmt.Sprintf("code_%d_is_not_retryable", code), func(t *testing.T) {
			assert.False(t, condition.ShouldRetry(nil, code), "Expected %d to not be retryable", code)
		})
	}
}

// ============================================================================
// Test Cases for ErrorTypeCondition
// ============================================================================

func TestRetryOnErrors(t *testing.T) {
	err1 := errors.New("error 1")
	err2 := errors.New("error 2")

	tests := []struct {
		name    string
		errors  []error
		wantLen int
	}{
		{
			name:    "single error",
			errors:  []error{err1},
			wantLen: 1,
		},
		{
			name:    "multiple errors",
			errors:  []error{err1, err2},
			wantLen: 2,
		},
		{
			name:    "empty errors",
			errors:  []error{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnErrors(tt.errors...)
			require.NotNil(t, condition)
			assert.Len(t, condition.errors, tt.wantLen)
		})
	}
}

func TestErrorTypeCondition_ShouldRetry(t *testing.T) {
	targetErr := errors.New("target error")
	wrappedErr := fmt.Errorf("wrapped: %w", targetErr)
	otherErr := errors.New("other error")

	tests := []struct {
		name       string
		targetErrs []error
		testErr    error
		statusCode int
		want       bool
	}{
		{
			name:       "nil error",
			targetErrs: []error{targetErr},
			testErr:    nil,
			statusCode: 0,
			want:       false,
		},
		{
			name:       "matching error",
			targetErrs: []error{targetErr},
			testErr:    targetErr,
			statusCode: 0,
			want:       true,
		},
		{
			name:       "wrapped matching error",
			targetErrs: []error{targetErr},
			testErr:    wrappedErr,
			statusCode: 0,
			want:       true,
		},
		{
			name:       "non-matching error",
			targetErrs: []error{targetErr},
			testErr:    otherErr,
			statusCode: 0,
			want:       false,
		},
		{
			name:       "multiple targets - first matches",
			targetErrs: []error{targetErr, otherErr},
			testErr:    targetErr,
			statusCode: 0,
			want:       true,
		},
		{
			name:       "multiple targets - second matches",
			targetErrs: []error{targetErr, otherErr},
			testErr:    otherErr,
			statusCode: 0,
			want:       true,
		},
		{
			name:       "empty targets",
			targetErrs: []error{},
			testErr:    targetErr,
			statusCode: 0,
			want:       false,
		},
		{
			name:       "io.EOF error",
			targetErrs: []error{io.EOF},
			testErr:    io.EOF,
			statusCode: 0,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnErrors(tt.targetErrs...)
			result := condition.ShouldRetry(tt.testErr, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for NetworkErrorCondition
// ============================================================================

func TestRetryOnNetworkErrors(t *testing.T) {
	condition := RetryOnNetworkErrors()
	require.NotNil(t, condition)
}

func TestNetworkErrorCondition_ShouldRetry(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		statusCode int
		want       bool
	}{
		{
			name:       "nil error",
			err:        nil,
			statusCode: 0,
			want:       false,
		},
		{
			name:       "timeout net.Error",
			err:        &mockNetError{timeout: true, temporary: false, msg: "timeout"},
			statusCode: 0,
			want:       true,
		},
		{
			name:       "temporary net.Error",
			err:        &mockNetError{timeout: false, temporary: true, msg: "temporary"},
			statusCode: 0,
			want:       true,
		},
		{
			name:       "timeout and temporary net.Error",
			err:        &mockNetError{timeout: true, temporary: true, msg: "both"},
			statusCode: 0,
			want:       true,
		},
		{
			name:       "non-timeout non-temporary net.Error",
			err:        &mockNetError{timeout: false, temporary: false, msg: "permanent"},
			statusCode: 0,
			want:       false,
		},
		{
			name:       "net.OpError without timeout/temporary",
			err:        mockOpError(),
			statusCode: 0,
			want:       false, // net.OpError implements net.Error, but Timeout() and Temporary() return false
		},
		{
			name:       "net.OpError with timeout",
			err:        mockOpErrorWithTimeout(),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "net.OpError with temporary",
			err:        mockOpErrorWithTemporary(),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "url.Error with timeout",
			err:        mockURLError(true, false),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "url.Error with temporary",
			err:        mockURLError(false, true),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "url.Error non-timeout non-temporary",
			err:        mockURLError(false, false),
			statusCode: 0,
			want:       false,
		},
		{
			name:       "io.EOF",
			err:        io.EOF,
			statusCode: 0,
			want:       true,
		},
		{
			name:       "io.ErrUnexpectedEOF",
			err:        io.ErrUnexpectedEOF,
			statusCode: 0,
			want:       true,
		},
		{
			name:       "wrapped io.EOF",
			err:        fmt.Errorf("wrapped: %w", io.EOF),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "syscall.ECONNRESET",
			err:        syscall.ECONNRESET,
			statusCode: 0,
			want:       false, // syscall.Errno implements net.Error, but Timeout() and Temporary() return false
		},
		{
			name:       "syscall.ECONNREFUSED",
			err:        syscall.ECONNREFUSED,
			statusCode: 0,
			want:       false, // syscall.Errno implements net.Error, but Timeout() and Temporary() return false
		},
		{
			name:       "wrapped syscall.ECONNRESET",
			err:        fmt.Errorf("connection error: %w", syscall.ECONNRESET),
			statusCode: 0,
			want:       false, // syscall.Errno implements net.Error, but Timeout() and Temporary() return false
		},
		{
			name:       "wrapped syscall.ECONNREFUSED",
			err:        fmt.Errorf("connection error: %w", syscall.ECONNREFUSED),
			statusCode: 0,
			want:       false, // syscall.Errno implements net.Error, but Timeout() and Temporary() return false
		},
		{
			name:       "regular error",
			err:        errors.New("some error"),
			statusCode: 0,
			want:       false,
		},
		{
			name:       "wrapped net.OpError",
			err:        fmt.Errorf("wrapped: %w", mockOpError()),
			statusCode: 0,
			want:       false, // net.OpError implements net.Error, but Timeout() and Temporary() return false
		},
	}

	condition := RetryOnNetworkErrors()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := condition.ShouldRetry(tt.err, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for GRPCStatusCondition
// ============================================================================

func TestRetryOnGRPCCodes(t *testing.T) {
	tests := []struct {
		name    string
		codes   []codes.Code
		wantLen int
	}{
		{
			name:    "single code",
			codes:   []codes.Code{codes.Unavailable},
			wantLen: 1,
		},
		{
			name:    "multiple codes",
			codes:   []codes.Code{codes.Unavailable, codes.ResourceExhausted, codes.Aborted},
			wantLen: 3,
		},
		{
			name:    "empty codes",
			codes:   []codes.Code{},
			wantLen: 0,
		},
		{
			name:    "duplicate codes",
			codes:   []codes.Code{codes.Unavailable, codes.Unavailable},
			wantLen: 1, // duplicates are deduplicated in map
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnGRPCCodes(tt.codes...)
			require.NotNil(t, condition)
			assert.Len(t, condition.codes, tt.wantLen)
		})
	}
}

func TestGRPCStatusCondition_ShouldRetry(t *testing.T) {
	tests := []struct {
		name       string
		targetCode []codes.Code
		testErr    error
		statusCode int
		want       bool
	}{
		{
			name:       "nil error",
			targetCode: []codes.Code{codes.Unavailable},
			testErr:    nil,
			statusCode: 0,
			want:       false,
		},
		{
			name:       "matching gRPC code",
			targetCode: []codes.Code{codes.Unavailable},
			testErr:    status.Error(codes.Unavailable, "service unavailable"),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "non-matching gRPC code",
			targetCode: []codes.Code{codes.Unavailable},
			testErr:    status.Error(codes.NotFound, "not found"),
			statusCode: 0,
			want:       false,
		},
		{
			name:       "multiple codes - first matches",
			targetCode: []codes.Code{codes.Unavailable, codes.ResourceExhausted},
			testErr:    status.Error(codes.Unavailable, "unavailable"),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "multiple codes - second matches",
			targetCode: []codes.Code{codes.Unavailable, codes.ResourceExhausted},
			testErr:    status.Error(codes.ResourceExhausted, "exhausted"),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "non-gRPC error",
			targetCode: []codes.Code{codes.Unavailable},
			testErr:    errors.New("regular error"),
			statusCode: 0,
			want:       false,
		},
		{
			name:       "empty codes",
			targetCode: []codes.Code{},
			testErr:    status.Error(codes.Unavailable, "unavailable"),
			statusCode: 0,
			want:       false,
		},
		{
			name:       "DeadlineExceeded",
			targetCode: []codes.Code{codes.DeadlineExceeded},
			testErr:    status.Error(codes.DeadlineExceeded, "deadline exceeded"),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "Aborted",
			targetCode: []codes.Code{codes.Aborted},
			testErr:    status.Error(codes.Aborted, "aborted"),
			statusCode: 0,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnGRPCCodes(tt.targetCode...)
			result := condition.ShouldRetry(tt.testErr, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestRetryableGRPCCodes(t *testing.T) {
	condition := RetryableGRPCCodes()
	require.NotNil(t, condition)

	// Verify expected retryable gRPC codes
	expectedCodes := []codes.Code{
		codes.Unavailable,
		codes.ResourceExhausted,
		codes.Aborted,
		codes.DeadlineExceeded,
	}

	for _, code := range expectedCodes {
		t.Run(fmt.Sprintf("code_%s_is_retryable", code.String()), func(t *testing.T) {
			err := status.Error(code, "test error")
			assert.True(t, condition.ShouldRetry(err, 0), "Expected %s to be retryable", code.String())
		})
	}

	// Verify non-retryable codes
	nonRetryableCodes := []codes.Code{
		codes.OK,
		codes.Canceled,
		codes.Unknown,
		codes.InvalidArgument,
		codes.NotFound,
		codes.AlreadyExists,
		codes.PermissionDenied,
		codes.FailedPrecondition,
		codes.OutOfRange,
		codes.Unimplemented,
		codes.Internal,
		codes.DataLoss,
		codes.Unauthenticated,
	}

	for _, code := range nonRetryableCodes {
		t.Run(fmt.Sprintf("code_%s_is_not_retryable", code.String()), func(t *testing.T) {
			err := status.Error(code, "test error")
			assert.False(t, condition.ShouldRetry(err, 0), "Expected %s to not be retryable", code.String())
		})
	}
}

// ============================================================================
// Test Cases for TimeoutCondition
// ============================================================================

func TestRetryOnTimeout(t *testing.T) {
	condition := RetryOnTimeout()
	require.NotNil(t, condition)
}

func TestTimeoutCondition_ShouldRetry(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		statusCode int
		want       bool
	}{
		{
			name:       "nil error",
			err:        nil,
			statusCode: 0,
			want:       false,
		},
		{
			name:       "net.Error with timeout",
			err:        &mockNetError{timeout: true, temporary: false, msg: "timeout"},
			statusCode: 0,
			want:       true,
		},
		{
			name:       "net.Error without timeout",
			err:        &mockNetError{timeout: false, temporary: true, msg: "temporary"},
			statusCode: 0,
			want:       false,
		},
		{
			name:       "url.Error with timeout",
			err:        mockURLError(true, false),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "url.Error without timeout",
			err:        mockURLError(false, true),
			statusCode: 0,
			want:       false,
		},
		{
			name:       "gRPC DeadlineExceeded",
			err:        status.Error(codes.DeadlineExceeded, "deadline exceeded"),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "gRPC Unavailable (not timeout)",
			err:        status.Error(codes.Unavailable, "unavailable"),
			statusCode: 0,
			want:       false,
		},
		{
			name:       "regular error",
			err:        errors.New("some error"),
			statusCode: 0,
			want:       false,
		},
		{
			name:       "wrapped timeout error",
			err:        fmt.Errorf("wrapped: %w", &mockNetError{timeout: true, msg: "timeout"}),
			statusCode: 0,
			want:       true,
		},
	}

	condition := RetryOnTimeout()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := condition.ShouldRetry(tt.err, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for CompositeCondition
// ============================================================================

func TestRetryOnAny(t *testing.T) {
	cond1 := RetryOn5xx()
	cond2 := RetryOnNetworkErrors()

	tests := []struct {
		name       string
		conditions []RetryCondition
		wantLen    int
	}{
		{
			name:       "single condition",
			conditions: []RetryCondition{cond1},
			wantLen:    1,
		},
		{
			name:       "multiple conditions",
			conditions: []RetryCondition{cond1, cond2},
			wantLen:    2,
		},
		{
			name:       "empty conditions",
			conditions: []RetryCondition{},
			wantLen:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnAny(tt.conditions...)
			require.NotNil(t, condition)
			assert.Len(t, condition.conditions, tt.wantLen)
		})
	}
}

func TestCompositeCondition_ShouldRetry(t *testing.T) {
	tests := []struct {
		name       string
		conditions []RetryCondition
		err        error
		statusCode int
		want       bool
	}{
		{
			name:       "first condition matches",
			conditions: []RetryCondition{RetryOn5xx(), RetryOnNetworkErrors()},
			err:        nil,
			statusCode: 500,
			want:       true,
		},
		{
			name:       "second condition matches",
			conditions: []RetryCondition{RetryOn5xx(), RetryOnNetworkErrors()},
			err:        io.EOF,
			statusCode: 200,
			want:       true,
		},
		{
			name:       "both conditions match",
			conditions: []RetryCondition{RetryOn5xx(), RetryOnStatusCodes(500)},
			err:        nil,
			statusCode: 500,
			want:       true,
		},
		{
			name:       "no condition matches",
			conditions: []RetryCondition{RetryOn5xx(), RetryOnNetworkErrors()},
			err:        errors.New("regular error"),
			statusCode: 400,
			want:       false,
		},
		{
			name:       "empty conditions",
			conditions: []RetryCondition{},
			err:        errors.New("error"),
			statusCode: 500,
			want:       false,
		},
		{
			name:       "single condition matches",
			conditions: []RetryCondition{RetryOn5xx()},
			err:        nil,
			statusCode: 503,
			want:       true,
		},
		{
			name:       "single condition does not match",
			conditions: []RetryCondition{RetryOn5xx()},
			err:        nil,
			statusCode: 400,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnAny(tt.conditions...)
			result := condition.ShouldRetry(tt.err, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for AllCondition
// ============================================================================

func TestRetryOnAll(t *testing.T) {
	cond1 := RetryOn5xx()
	cond2 := AlwaysRetry()

	tests := []struct {
		name       string
		conditions []RetryCondition
		wantLen    int
	}{
		{
			name:       "single condition",
			conditions: []RetryCondition{cond1},
			wantLen:    1,
		},
		{
			name:       "multiple conditions",
			conditions: []RetryCondition{cond1, cond2},
			wantLen:    2,
		},
		{
			name:       "empty conditions",
			conditions: []RetryCondition{},
			wantLen:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnAll(tt.conditions...)
			require.NotNil(t, condition)
			assert.Len(t, condition.conditions, tt.wantLen)
		})
	}
}

func TestAllCondition_ShouldRetry(t *testing.T) {
	tests := []struct {
		name       string
		conditions []RetryCondition
		err        error
		statusCode int
		want       bool
	}{
		{
			name:       "all conditions match",
			conditions: []RetryCondition{RetryOn5xx(), AlwaysRetry()},
			err:        errors.New("error"),
			statusCode: 500,
			want:       true,
		},
		{
			name:       "first condition does not match",
			conditions: []RetryCondition{RetryOn5xx(), AlwaysRetry()},
			err:        errors.New("error"),
			statusCode: 400,
			want:       false,
		},
		{
			name:       "second condition does not match",
			conditions: []RetryCondition{AlwaysRetry(), NeverRetry()},
			err:        errors.New("error"),
			statusCode: 500,
			want:       false,
		},
		{
			name:       "empty conditions",
			conditions: []RetryCondition{},
			err:        errors.New("error"),
			statusCode: 500,
			want:       false,
		},
		{
			name:       "single condition matches",
			conditions: []RetryCondition{RetryOn5xx()},
			err:        nil,
			statusCode: 500,
			want:       true,
		},
		{
			name:       "single condition does not match",
			conditions: []RetryCondition{RetryOn5xx()},
			err:        nil,
			statusCode: 400,
			want:       false,
		},
		{
			name:       "three conditions all match",
			conditions: []RetryCondition{RetryOn5xx(), RetryOnStatusCodes(500, 502, 503), AlwaysRetry()},
			err:        errors.New("error"),
			statusCode: 500,
			want:       true,
		},
		{
			name:       "three conditions one does not match",
			conditions: []RetryCondition{RetryOn5xx(), RetryOnStatusCodes(502, 503), AlwaysRetry()},
			err:        errors.New("error"),
			statusCode: 500,
			want:       false, // 500 is not in [502, 503]
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryOnAll(tt.conditions...)
			result := condition.ShouldRetry(tt.err, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for NeverRetryCondition
// ============================================================================

func TestNeverRetry(t *testing.T) {
	condition := NeverRetry()
	require.NotNil(t, condition)
}

func TestNeverRetryCondition_ShouldRetry(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		statusCode int
		want       bool
	}{
		{
			name:       "nil error",
			err:        nil,
			statusCode: 0,
			want:       false,
		},
		{
			name:       "with error",
			err:        errors.New("error"),
			statusCode: 0,
			want:       false,
		},
		{
			name:       "5xx status code",
			err:        nil,
			statusCode: 500,
			want:       false,
		},
		{
			name:       "error and 5xx status code",
			err:        errors.New("error"),
			statusCode: 503,
			want:       false,
		},
		{
			name:       "network error",
			err:        io.EOF,
			statusCode: 0,
			want:       false,
		},
		{
			name:       "gRPC error",
			err:        status.Error(codes.Unavailable, "unavailable"),
			statusCode: 0,
			want:       false,
		},
	}

	condition := NeverRetry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := condition.ShouldRetry(tt.err, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for AlwaysRetryCondition
// ============================================================================

func TestAlwaysRetry(t *testing.T) {
	condition := AlwaysRetry()
	require.NotNil(t, condition)
}

func TestAlwaysRetryCondition_ShouldRetry(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		statusCode int
		want       bool
	}{
		{
			name:       "nil error and 0 status code",
			err:        nil,
			statusCode: 0,
			want:       false,
		},
		{
			name:       "nil error and 200 status code",
			err:        nil,
			statusCode: 200,
			want:       false,
		},
		{
			name:       "nil error and 399 status code",
			err:        nil,
			statusCode: 399,
			want:       false,
		},
		{
			name:       "nil error and 400 status code",
			err:        nil,
			statusCode: 400,
			want:       true,
		},
		{
			name:       "nil error and 500 status code",
			err:        nil,
			statusCode: 500,
			want:       true,
		},
		{
			name:       "with error and 0 status code",
			err:        errors.New("error"),
			statusCode: 0,
			want:       true,
		},
		{
			name:       "with error and 200 status code",
			err:        errors.New("error"),
			statusCode: 200,
			want:       true,
		},
		{
			name:       "with error and 500 status code",
			err:        errors.New("error"),
			statusCode: 500,
			want:       true,
		},
		{
			name:       "network error",
			err:        io.EOF,
			statusCode: 0,
			want:       true,
		},
		{
			name:       "gRPC error",
			err:        status.Error(codes.Unavailable, "unavailable"),
			statusCode: 0,
			want:       true,
		},
	}

	condition := AlwaysRetry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := condition.ShouldRetry(tt.err, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for IdempotentMethodCondition
// ============================================================================

func TestRetryIfIdempotent(t *testing.T) {
	innerCondition := RetryOn5xx()

	tests := []struct {
		name   string
		method string
	}{
		{name: "GET method", method: "GET"},
		{name: "POST method", method: "POST"},
		{name: "PUT method", method: "PUT"},
		{name: "DELETE method", method: "DELETE"},
		{name: "PATCH method", method: "PATCH"},
		{name: "HEAD method", method: "HEAD"},
		{name: "OPTIONS method", method: "OPTIONS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryIfIdempotent(tt.method, innerCondition)
			require.NotNil(t, condition)
			assert.Equal(t, tt.method, condition.method)
			assert.Equal(t, innerCondition, condition.condition)
		})
	}
}

func TestIdempotentMethodCondition_ShouldRetry(t *testing.T) {
	innerCondition := RetryOn5xx()

	tests := []struct {
		name       string
		method     string
		err        error
		statusCode int
		want       bool
	}{
		// Idempotent methods with retryable condition
		{
			name:       "GET with 500",
			method:     "GET",
			err:        nil,
			statusCode: 500,
			want:       true,
		},
		{
			name:       "HEAD with 500",
			method:     "HEAD",
			err:        nil,
			statusCode: 500,
			want:       true,
		},
		{
			name:       "OPTIONS with 500",
			method:     "OPTIONS",
			err:        nil,
			statusCode: 500,
			want:       true,
		},
		{
			name:       "PUT with 500",
			method:     "PUT",
			err:        nil,
			statusCode: 500,
			want:       true,
		},
		{
			name:       "DELETE with 500",
			method:     "DELETE",
			err:        nil,
			statusCode: 500,
			want:       true,
		},
		// Idempotent methods with non-retryable condition
		{
			name:       "GET with 400",
			method:     "GET",
			err:        nil,
			statusCode: 400,
			want:       false,
		},
		{
			name:       "PUT with 200",
			method:     "PUT",
			err:        nil,
			statusCode: 200,
			want:       false,
		},
		// Non-idempotent methods (should never retry)
		{
			name:       "POST with 500",
			method:     "POST",
			err:        nil,
			statusCode: 500,
			want:       false,
		},
		{
			name:       "PATCH with 500",
			method:     "PATCH",
			err:        nil,
			statusCode: 500,
			want:       false,
		},
		{
			name:       "POST with error",
			method:     "POST",
			err:        errors.New("error"),
			statusCode: 503,
			want:       false,
		},
		// Edge cases
		{
			name:       "lowercase get",
			method:     "get",
			err:        nil,
			statusCode: 500,
			want:       false, // case-sensitive
		},
		{
			name:       "empty method",
			method:     "",
			err:        nil,
			statusCode: 500,
			want:       false,
		},
		{
			name:       "unknown method",
			method:     "UNKNOWN",
			err:        nil,
			statusCode: 500,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := RetryIfIdempotent(tt.method, innerCondition)
			result := condition.ShouldRetry(tt.err, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Test Cases for RetryCondition Interface Compliance
// ============================================================================

func TestRetryConditionInterfaceCompliance(t *testing.T) {
	// Verify all condition types implement the RetryCondition interface
	var _ RetryCondition = &StatusCodeCondition{}
	var _ RetryCondition = &Retry5xxCondition{}
	var _ RetryCondition = &ErrorTypeCondition{}
	var _ RetryCondition = &NetworkErrorCondition{}
	var _ RetryCondition = &GRPCStatusCondition{}
	var _ RetryCondition = &TimeoutCondition{}
	var _ RetryCondition = &CompositeCondition{}
	var _ RetryCondition = &AllCondition{}
	var _ RetryCondition = &NeverRetryCondition{}
	var _ RetryCondition = &AlwaysRetryCondition{}
	var _ RetryCondition = &IdempotentMethodCondition{}
}

// ============================================================================
// Integration Tests - Complex Condition Combinations
// ============================================================================

func TestComplexConditionCombinations(t *testing.T) {
	tests := []struct {
		name       string
		condition  RetryCondition
		err        error
		statusCode int
		want       bool
	}{
		{
			name: "composite with 5xx and network errors - 5xx matches",
			condition: RetryOnAny(
				RetryOn5xx(),
				RetryOnNetworkErrors(),
			),
			err:        nil,
			statusCode: 503,
			want:       true,
		},
		{
			name: "composite with 5xx and network errors - network error matches",
			condition: RetryOnAny(
				RetryOn5xx(),
				RetryOnNetworkErrors(),
			),
			err:        io.EOF,
			statusCode: 200,
			want:       true,
		},
		{
			name: "all with 5xx and always retry - both match",
			condition: RetryOnAll(
				RetryOn5xx(),
				AlwaysRetry(),
			),
			err:        errors.New("error"),
			statusCode: 500,
			want:       true,
		},
		{
			name: "all with 5xx and always retry - only always matches",
			condition: RetryOnAll(
				RetryOn5xx(),
				AlwaysRetry(),
			),
			err:        errors.New("error"),
			statusCode: 400,
			want:       false,
		},
		{
			name: "nested composite conditions",
			condition: RetryOnAny(
				RetryOnAll(
					RetryOn5xx(),
					AlwaysRetry(),
				),
				RetryOnNetworkErrors(),
			),
			err:        io.EOF,
			statusCode: 200,
			want:       true,
		},
		{
			name: "idempotent with composite inner condition",
			condition: RetryIfIdempotent("GET", RetryOnAny(
				RetryOn5xx(),
				RetryOnNetworkErrors(),
			)),
			err:        nil,
			statusCode: 503,
			want:       true,
		},
		{
			name: "idempotent with composite inner condition - non-idempotent method",
			condition: RetryIfIdempotent("POST", RetryOnAny(
				RetryOn5xx(),
				RetryOnNetworkErrors(),
			)),
			err:        nil,
			statusCode: 503,
			want:       false,
		},
		{
			name: "retryable status codes with gRPC codes",
			condition: RetryOnAny(
				RetryableStatusCodes(),
				RetryableGRPCCodes(),
			),
			err:        status.Error(codes.Unavailable, "unavailable"),
			statusCode: 0,
			want:       true,
		},
		{
			name: "timeout with network errors",
			condition: RetryOnAny(
				RetryOnTimeout(),
				RetryOnNetworkErrors(),
			),
			err:        &mockNetError{timeout: true, msg: "timeout"},
			statusCode: 0,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.condition.ShouldRetry(tt.err, tt.statusCode)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

func TestEdgeCases(t *testing.T) {
	t.Run("StatusCodeCondition with negative status code", func(t *testing.T) {
		condition := RetryOnStatusCodes(500, 502, 503)
		result := condition.ShouldRetry(nil, -1)
		assert.False(t, result)
	})

	t.Run("StatusCodeCondition with very large status code", func(t *testing.T) {
		condition := RetryOnStatusCodes(500, 502, 503)
		result := condition.ShouldRetry(nil, 99999)
		assert.False(t, result)
	})

	t.Run("Retry5xxCondition boundary - 499", func(t *testing.T) {
		condition := RetryOn5xx()
		result := condition.ShouldRetry(nil, 499)
		assert.False(t, result)
	})

	t.Run("Retry5xxCondition boundary - 500", func(t *testing.T) {
		condition := RetryOn5xx()
		result := condition.ShouldRetry(nil, 500)
		assert.True(t, result)
	})

	t.Run("Retry5xxCondition boundary - 599", func(t *testing.T) {
		condition := RetryOn5xx()
		result := condition.ShouldRetry(nil, 599)
		assert.True(t, result)
	})

	t.Run("Retry5xxCondition boundary - 600", func(t *testing.T) {
		condition := RetryOn5xx()
		result := condition.ShouldRetry(nil, 600)
		assert.False(t, result)
	})

	t.Run("AlwaysRetryCondition boundary - 399", func(t *testing.T) {
		condition := AlwaysRetry()
		result := condition.ShouldRetry(nil, 399)
		assert.False(t, result)
	})

	t.Run("AlwaysRetryCondition boundary - 400", func(t *testing.T) {
		condition := AlwaysRetry()
		result := condition.ShouldRetry(nil, 400)
		assert.True(t, result)
	})

	t.Run("deeply nested wrapped error", func(t *testing.T) {
		baseErr := io.EOF
		wrapped1 := fmt.Errorf("level 1: %w", baseErr)
		wrapped2 := fmt.Errorf("level 2: %w", wrapped1)
		wrapped3 := fmt.Errorf("level 3: %w", wrapped2)

		condition := RetryOnNetworkErrors()
		result := condition.ShouldRetry(wrapped3, 0)
		assert.True(t, result)
	})

	t.Run("ErrorTypeCondition with nil in target errors", func(t *testing.T) {
		condition := RetryOnErrors(nil, io.EOF)
		result := condition.ShouldRetry(io.EOF, 0)
		assert.True(t, result)
	})
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestConditions_ConcurrentAccess(t *testing.T) {
	conditions := []RetryCondition{
		RetryOnStatusCodes(500, 502, 503),
		RetryOn5xx(),
		RetryableStatusCodes(),
		RetryOnErrors(io.EOF),
		RetryOnNetworkErrors(),
		RetryOnGRPCCodes(codes.Unavailable),
		RetryableGRPCCodes(),
		RetryOnTimeout(),
		RetryOnAny(RetryOn5xx(), RetryOnNetworkErrors()),
		RetryOnAll(RetryOn5xx(), AlwaysRetry()),
		NeverRetry(),
		AlwaysRetry(),
		RetryIfIdempotent("GET", RetryOn5xx()),
	}

	for _, condition := range conditions {
		t.Run(fmt.Sprintf("%T", condition), func(t *testing.T) {
			done := make(chan bool)
			for i := 0; i < 10; i++ {
				go func() {
					for j := 0; j < 100; j++ {
						_ = condition.ShouldRetry(errors.New("error"), 500)
						_ = condition.ShouldRetry(nil, 200)
						_ = condition.ShouldRetry(io.EOF, 0)
					}
					done <- true
				}()
			}

			for i := 0; i < 10; i++ {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("timeout waiting for goroutines")
				}
			}
		})
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkStatusCodeCondition_ShouldRetry(b *testing.B) {
	condition := RetryOnStatusCodes(500, 502, 503, 504)
	err := errors.New("error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		condition.ShouldRetry(err, 500)
	}
}

func BenchmarkRetry5xxCondition_ShouldRetry(b *testing.B) {
	condition := RetryOn5xx()
	err := errors.New("error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		condition.ShouldRetry(err, 500)
	}
}

func BenchmarkNetworkErrorCondition_ShouldRetry(b *testing.B) {
	condition := RetryOnNetworkErrors()
	err := io.EOF

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		condition.ShouldRetry(err, 0)
	}
}

func BenchmarkCompositeCondition_ShouldRetry(b *testing.B) {
	condition := RetryOnAny(
		RetryOn5xx(),
		RetryOnNetworkErrors(),
		RetryableGRPCCodes(),
	)
	err := errors.New("error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		condition.ShouldRetry(err, 500)
	}
}

func BenchmarkAllCondition_ShouldRetry(b *testing.B) {
	condition := RetryOnAll(
		RetryOn5xx(),
		AlwaysRetry(),
	)
	err := errors.New("error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		condition.ShouldRetry(err, 500)
	}
}
