package middleware

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/transform"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// phase3HijackWriter is a ResponseWriter that also implements http.Hijacker.
// hijackErr controls whether Hijack succeeds or fails. It records header and
// status writes so tests can assert the underlying writer was (not) touched.
type phase3HijackWriter struct {
	header      http.Header
	status      int
	body        bytes.Buffer
	hijackErr   error
	hijackCalls int
}

func newPhase3HijackWriter(hijackErr error) *phase3HijackWriter {
	return &phase3HijackWriter{header: make(http.Header), hijackErr: hijackErr}
}

func (h *phase3HijackWriter) Header() http.Header { return h.header }

func (h *phase3HijackWriter) WriteHeader(code int) { h.status = code }

func (h *phase3HijackWriter) Write(b []byte) (int, error) { return h.body.Write(b) }

func (h *phase3HijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijackCalls++
	if h.hijackErr != nil {
		return nil, nil, h.hijackErr
	}
	// Return a non-nil ReadWriter over a client/server pipe so the value is
	// valid; the test never performs I/O on the connection.
	client, _ := net.Pipe()
	rw := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	return client, rw, nil
}

// flushableWriter is a ResponseWriter that also implements http.Flusher and
// records how many times Flush was invoked.
type flushableWriter struct {
	header     http.Header
	status     int
	body       bytes.Buffer
	flushCalls int
}

func newFlushableWriter() *flushableWriter {
	return &flushableWriter{header: make(http.Header)}
}

func (f *flushableWriter) Header() http.Header  { return f.header }
func (f *flushableWriter) WriteHeader(code int) { f.status = code }
func (f *flushableWriter) Write(b []byte) (int, error) {
	return f.body.Write(b)
}
func (f *flushableWriter) Flush() { f.flushCalls++ }

// failOnWriteWriter fails the test if any of its write methods are called.
// It is used to assert that a code path performs no writes to the client.
type failOnWriteWriter struct {
	t      *testing.T
	header http.Header
}

func newFailOnWriteWriter(t *testing.T) *failOnWriteWriter {
	t.Helper()
	return &failOnWriteWriter{t: t, header: make(http.Header)}
}

func (w *failOnWriteWriter) Header() http.Header { return w.header }

func (w *failOnWriteWriter) WriteHeader(int) {
	w.t.Fatalf("WriteHeader must not be called on the real writer")
}

func (w *failOnWriteWriter) Write([]byte) (int, error) {
	w.t.Fatalf("Write must not be called on the real writer")
	return 0, nil
}

// ---------------------------------------------------------------------------
// T2 — Hijack success + guards, and error path
// ---------------------------------------------------------------------------

func TestTransformResponseRecorder_Hijack_SuccessAndGuards(t *testing.T) {
	t.Parallel()

	underlying := newPhase3HijackWriter(nil)
	trr := &transformResponseRecorder{
		ResponseWriter: underlying,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
	}

	// Act: hijack the connection.
	conn, rw, err := trr.Hijack()

	// Assert: success and hijacked flag set.
	require.NoError(t, err)
	assert.NotNil(t, conn)
	assert.NotNil(t, rw)
	assert.True(t, trr.hijacked, "hijacked must be true after a successful Hijack")
	if conn != nil {
		_ = conn.Close()
	}

	// WriteHeader is a no-op once hijacked: underlying status stays unchanged.
	trr.WriteHeader(http.StatusTeapot)
	assert.Equal(t, 0, underlying.status, "WriteHeader must be a no-op after hijack")

	// Write returns http.ErrHijacked and writes nothing.
	n, writeErr := trr.Write([]byte("data"))
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, writeErr, http.ErrHijacked)
	assert.Zero(t, underlying.body.Len(), "no bytes must reach the underlying writer after hijack")

	// Flush is a no-op after hijack (does not panic, does not touch underlying).
	assert.NotPanics(t, trr.Flush)
}

func TestTransformResponseRecorder_Hijack_ErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		underlying http.ResponseWriter
		wantErr    error
	}{
		{
			name:       "underlying does not implement Hijacker",
			underlying: httptest.NewRecorder(),
			wantErr:    http.ErrNotSupported,
		},
		{
			name:       "underlying Hijacker returns an error",
			underlying: newPhase3HijackWriter(errors.New("boom")),
			wantErr:    nil, // matched by message below
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			trr := &transformResponseRecorder{
				ResponseWriter: tt.underlying,
				statusCode:     http.StatusOK,
				body:           &bytes.Buffer{},
				header:         make(http.Header),
			}

			conn, rw, err := trr.Hijack()

			require.Error(t, err)
			assert.Nil(t, conn)
			assert.Nil(t, rw)
			assert.False(t, trr.hijacked, "hijacked must stay false when Hijack fails")

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// T3 — Flush delegation
// ---------------------------------------------------------------------------

func TestTransformResponseRecorder_Flush_Delegation(t *testing.T) {
	t.Parallel()

	t.Run("buffering mode is a no-op", func(t *testing.T) {
		t.Parallel()

		underlying := newFlushableWriter()
		trr := &transformResponseRecorder{
			ResponseWriter: underlying,
			statusCode:     http.StatusOK,
			body:           &bytes.Buffer{},
			header:         make(http.Header),
			bufferExceeded: false,
		}

		trr.Flush()
		assert.Equal(t, 0, underlying.flushCalls,
			"Flush must not delegate while buffering for transformation")
	})

	t.Run("buffer exceeded delegates to underlying flusher", func(t *testing.T) {
		t.Parallel()

		underlying := newFlushableWriter()
		trr := &transformResponseRecorder{
			ResponseWriter: underlying,
			statusCode:     http.StatusOK,
			body:           &bytes.Buffer{},
			header:         make(http.Header),
			bufferExceeded: true,
		}

		trr.Flush()
		assert.Equal(t, 1, underlying.flushCalls,
			"Flush must delegate exactly once when buffer is exceeded")
	})

	t.Run("hijacked early-returns without delegating", func(t *testing.T) {
		t.Parallel()

		underlying := newFlushableWriter()
		trr := &transformResponseRecorder{
			ResponseWriter: underlying,
			statusCode:     http.StatusOK,
			body:           &bytes.Buffer{},
			header:         make(http.Header),
			bufferExceeded: true, // would delegate if not for hijacked guard
			hijacked:       true,
		}

		trr.Flush()
		assert.Equal(t, 0, underlying.flushCalls,
			"Flush must not touch the underlying writer once hijacked")
	})
}

// ---------------------------------------------------------------------------
// T4 — applyResponseTransform early-return when hijacked
// ---------------------------------------------------------------------------

func TestApplyResponseTransform_HijackedEarlyReturn(t *testing.T) {
	t.Parallel()

	failWriter := newFailOnWriteWriter(t)

	recorder := &transformResponseRecorder{
		ResponseWriter: failWriter,
		statusCode:     http.StatusOK,
		body:           bytes.NewBufferString(`{"name":"test"}`),
		header:         make(http.Header),
		hijacked:       true,
	}

	rt := transform.NewResponseTransformer(observability.NopLogger())
	cfg := &config.ResponseTransformConfig{DenyFields: []string{"name"}}
	metrics := transform.GetTransformMetrics()

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)

	// Act + Assert: must not panic and must not write to the real writer
	// (failWriter fails the test on any write).
	assert.NotPanics(t, func() {
		applyResponseTransform(
			failWriter, req, recorder, rt, cfg, observability.NopLogger(), metrics,
		)
	})
}

// ---------------------------------------------------------------------------
// T5 — copyRecordedHeaders semantics
// ---------------------------------------------------------------------------

func TestCopyRecordedHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		dst               http.Header
		recorded          http.Header
		skipContentLength bool
		want              http.Header
	}{
		{
			name: "replace per key removes stale value with no duplication",
			dst: http.Header{
				"X-Trace": []string{"old-value"},
			},
			recorded: http.Header{
				"X-Trace": []string{"new-value"},
			},
			skipContentLength: false,
			want: http.Header{
				"X-Trace": []string{"new-value"},
			},
		},
		{
			name: "multi-value recorded header preserved in order",
			dst:  http.Header{},
			recorded: http.Header{
				"Set-Cookie": []string{"a=1", "b=2", "c=3"},
			},
			skipContentLength: false,
			want: http.Header{
				"Set-Cookie": []string{"a=1", "b=2", "c=3"},
			},
		},
		{
			name: "skipContentLength true drops Content-Length",
			dst:  http.Header{},
			recorded: http.Header{
				"Content-Length": []string{"1234"},
				"Content-Type":   []string{"application/json"},
			},
			skipContentLength: true,
			want: http.Header{
				"Content-Type": []string{"application/json"},
			},
		},
		{
			name: "skipContentLength false keeps Content-Length",
			dst:  http.Header{},
			recorded: http.Header{
				"Content-Length": []string{"1234"},
				"Content-Type":   []string{"application/json"},
			},
			skipContentLength: false,
			want: http.Header{
				"Content-Length": []string{"1234"},
				"Content-Type":   []string{"application/json"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			copyRecordedHeaders(tt.dst, tt.recorded, tt.skipContentLength)
			assert.Equal(t, tt.want, tt.dst)
		})
	}
}

// TestTransformResponseRecorder_Write_OverflowUsesReplacePerKeyHeaders drives
// the >10MB overflow path in Write() and confirms the overflow flush uses
// replace-per-key headers: a header already set by an outer layer on the real
// writer is replaced (not duplicated) by the recorded value.
func TestTransformResponseRecorder_Write_OverflowUsesReplacePerKeyHeaders(t *testing.T) {
	t.Parallel()

	underlying := newFlushableWriter()
	// Outer layer already set X-Layer on the real writer.
	underlying.Header().Set("X-Layer", "outer")

	trr := &transformResponseRecorder{
		ResponseWriter: underlying,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
	}
	// The recorder captured its own value for the same header key.
	trr.Header().Set("X-Layer", "recorded")

	// Write a chunk that exceeds the buffer limit to trigger the overflow flush.
	bigChunk := bytes.Repeat([]byte("a"), maxTransformBodySize+1)
	n, err := trr.Write(bigChunk)

	require.NoError(t, err)
	assert.Equal(t, len(bigChunk), n)
	assert.True(t, trr.bufferExceeded)

	// The header on the real writer must be exactly the recorded value with no
	// duplication from the outer layer's stale value.
	assert.Equal(t, []string{"recorded"}, underlying.Header().Values("X-Layer"),
		"overflow flush must replace-per-key, not duplicate, headers")
	assert.Equal(t, http.StatusOK, underlying.status)
	assert.Equal(t, len(bigChunk), underlying.body.Len())
}

// ---------------------------------------------------------------------------
// T6 — request metrics table (success / error / passthrough)
// ---------------------------------------------------------------------------

// operationCount reads the gateway_transform_operations_total counter value
// for the given direction/result label pair from the default Prometheus
// gatherer (promauto registers transform metrics on the default registry).
// Reading via the gatherer keeps the test in the middleware package without
// touching the transform package's unexported metric fields.
func operationCount(direction, result string) float64 {
	return counterValue(
		"gateway_transform_operations_total",
		map[string]string{"direction": direction, "result": result},
	)
}

// errorCount reads the gateway_transform_errors_total counter value for the
// given direction/error_type label pair.
func errorCount(direction, errorType string) float64 {
	return counterValue(
		"gateway_transform_errors_total",
		map[string]string{"direction": direction, "error_type": errorType},
	)
}

// counterValue gathers the named counter metric from the default Prometheus
// registry and returns the value of the series matching all provided labels.
// Returns 0 if the series has not been created yet.
func counterValue(name string, labels map[string]string) float64 {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return 0
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, metric := range mf.GetMetric() {
			if labelsMatch(metric.GetLabel(), labels) {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// labelsMatch reports whether every wanted label is present with the expected
// value in the metric's label set.
func labelsMatch(got []*dto.LabelPair, want map[string]string) bool {
	matched := 0
	for _, lp := range got {
		if v, ok := want[lp.GetName()]; ok && v == lp.GetValue() {
			matched++
		}
	}
	return matched == len(want)
}

func TestApplyRequestTransform_MetricsTable(t *testing.T) {
	// Not parallel: asserts deltas on the process-global metrics singleton.
	metrics := transform.GetTransformMetrics()

	tests := []struct {
		name        string
		cfg         *config.RequestTransformConfig
		body        string
		contentType string
		wantResult  string
		// wantResultDelta is the expected increase of the result counter.
		// The success path is counted twice: TransformRequest records
		// "success" internally and recordRequestResult records it again in
		// the middleware. This is existing production behavior, so the test
		// asserts the exact observed delta rather than masking it.
		wantResultDelta float64
		wantErr         bool
		wantErrDelta    bool
	}{
		{
			name:            "success increments result=success",
			cfg:             &config.RequestTransformConfig{RemoveFields: []string{"secret"}},
			body:            `{"name":"test","secret":"x"}`,
			contentType:     "application/json",
			wantResult:      resultSuccess,
			wantResultDelta: 2, // internal + middleware record
			wantErr:         false,
		},
		{
			name:            "template execution error increments result=error and errors_total",
			cfg:             &config.RequestTransformConfig{BodyTemplate: `{{ .request.name.deeper }}`},
			body:            `{"name":"test"}`,
			contentType:     "application/json",
			wantResult:      resultError,
			wantResultDelta: 1,
			wantErr:         true,
			wantErrDelta:    true,
		},
		{
			name:            "non-JSON body increments result=passthrough",
			cfg:             &config.RequestTransformConfig{RemoveFields: []string{"secret"}},
			body:            `plain text not json`,
			contentType:     "text/plain",
			wantResult:      resultPassthrough,
			wantResultDelta: 1,
			wantErr:         false,
		},
		{
			name:            "oversized body increments result=passthrough",
			cfg:             &config.RequestTransformConfig{RemoveFields: []string{"secret"}},
			body:            `{"field":"` + strings.Repeat("x", maxTransformBodySize+1) + `"}`,
			contentType:     "application/json",
			wantResult:      resultPassthrough,
			wantResultDelta: 1,
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := transform.NewRequestTransformer(observability.NopLogger())

			beforeResult := operationCount(directionRequest, tt.wantResult)
			beforeErr := errorCount(directionRequest, errorTypeGeneral)

			req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)

			err := applyRequestTransform(req, rt, tt.cfg, metrics)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			afterResult := operationCount(directionRequest, tt.wantResult)
			assert.Equal(t, beforeResult+tt.wantResultDelta, afterResult,
				"result=%s counter must increment by %v", tt.wantResult, tt.wantResultDelta)

			afterErr := errorCount(directionRequest, errorTypeGeneral)
			if tt.wantErrDelta {
				assert.Equal(t, beforeErr+1, afterErr,
					"errors_total must increment on the error path")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// T7 — response metrics table (success / error / passthrough)
// ---------------------------------------------------------------------------

func TestApplyResponseTransform_MetricsTable(t *testing.T) {
	// Not parallel: asserts deltas on the process-global metrics singleton.
	metrics := transform.GetTransformMetrics()

	tests := []struct {
		name       string
		cfg        *config.ResponseTransformConfig
		body       string
		wantResult string
		// wantResultDelta is the expected increase of the result counter.
		// The success path is counted twice: TransformResponse records
		// "success" internally and applyResponseTransform records it again.
		// This is existing production behavior, asserted as the exact delta.
		wantResultDelta float64
		wantErrDelta    bool
	}{
		{
			name:            "success increments result=success",
			cfg:             &config.ResponseTransformConfig{DenyFields: []string{"secret"}},
			body:            `{"name":"test","secret":"x"}`,
			wantResult:      resultSuccess,
			wantResultDelta: 2, // internal + middleware record
		},
		{
			name:            "non-JSON body increments result=passthrough",
			cfg:             &config.ResponseTransformConfig{DenyFields: []string{"secret"}},
			body:            `this is not json`,
			wantResult:      resultPassthrough,
			wantResultDelta: 1,
		},
		{
			name:            "template execution error increments result=error and errors_total",
			cfg:             &config.ResponseTransformConfig{Template: `{{ .name.deeper }}`},
			body:            `{"name":"test"}`,
			wantResultDelta: 1,
			wantResult:      resultError,
			wantErrDelta:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := transform.NewResponseTransformer(observability.NopLogger())

			recorder := &transformResponseRecorder{
				ResponseWriter: httptest.NewRecorder(),
				statusCode:     http.StatusOK,
				body:           bytes.NewBufferString(tt.body),
				header:         make(http.Header),
			}
			realWriter := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/data", nil)

			beforeResult := operationCount(directionResponse, tt.wantResult)
			beforeErr := errorCount(directionResponse, errorTypeGeneral)

			applyResponseTransform(
				realWriter, req, recorder, rt, tt.cfg, observability.NopLogger(), metrics,
			)

			afterResult := operationCount(directionResponse, tt.wantResult)
			assert.Equal(t, beforeResult+tt.wantResultDelta, afterResult,
				"result=%s counter must increment by %v", tt.wantResult, tt.wantResultDelta)

			if tt.wantErrDelta {
				afterErr := errorCount(directionResponse, errorTypeGeneral)
				assert.Equal(t, beforeErr+1, afterErr,
					"errors_total must increment on the error path")
			}
		})
	}
}
