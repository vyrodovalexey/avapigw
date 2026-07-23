package httputil

import (
	"errors"
	"fmt"
	"io"
)

// DefaultMaxResponseBytes is the default upper bound for reading response
// bodies from configured external services (OPA, JWKS, OIDC discovery, IdP
// token endpoints). A misbehaving or compromised endpoint returning a huge
// body must not inflate gateway memory.
const DefaultMaxResponseBytes = 10 * 1024 * 1024 // 10 MiB

// ErrResponseTooLarge indicates that an external service response exceeded
// the configured read limit. Callers should treat it as a hard error (the
// body is truncated, not usable) and surface it via their error metrics.
var ErrResponseTooLarge = errors.New("response body exceeds size limit")

// ReadAllLimited reads r up to limit bytes. When the body is larger than
// limit, it returns ErrResponseTooLarge (wrapped with the limit for
// diagnosability) instead of a silently truncated payload. A non-positive
// limit falls back to DefaultMaxResponseBytes.
func ReadAllLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}

	// Read one byte past the limit to detect (not silently swallow) oversize
	// bodies.
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w (limit %d bytes)", ErrResponseTooLarge, limit)
	}
	return body, nil
}

// ReadAllTruncated reads r up to limit bytes and silently truncates larger
// bodies, appending an ellipsis marker. It is intended for embedding
// external error-response bodies into error strings/logs where truncation
// is acceptable but unbounded reads are not. A non-positive limit falls
// back to DefaultMaxResponseBytes.
func ReadAllTruncated(r io.Reader, limit int64) []byte {
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}

	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(body)) <= limit {
		return body
	}
	return append(body[:limit], []byte("...(truncated)")...)
}
