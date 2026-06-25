package aggregate

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/transform"
)

// Envelope is a single labeled per-target unit used when merging is disabled or
// not applicable (non-JSON bodies). Its JSON shape is
// {"target","status","payload"}.
type Envelope struct {
	// Target is the name of the producing target.
	Target string `json:"target"`

	// Status is the protocol status code.
	Status int `json:"status"`

	// Payload is the raw or JSON-decoded response payload.
	Payload json.RawMessage `json:"payload"`
}

// MergeOutput is the result of combining per-target responses.
type MergeOutput struct {
	// Body is the encoded aggregated body.
	Body []byte

	// ContentType is the content type of Body (always application/json here).
	ContentType string

	// Merged reports whether a true merge occurred (false means labeled
	// envelope fallback).
	Merged bool
}

// contentTypeJSON is the canonical JSON content type emitted by the merger.
const contentTypeJSON = "application/json"

// Merger combines per-target responses into a single aggregated body. It uses
// transform.ResponseMerger for true JSON merging and falls back to a labeled
// envelope for non-JSON payloads.
type Merger struct {
	merger  transform.ResponseMerger
	logger  observability.Logger
	metrics *Metrics
	tracer  Tracer
}

// NewMerger creates a new Merger.
func NewMerger(logger observability.Logger, metrics *Metrics, tracer Tracer) *Merger {
	if logger == nil {
		logger = observability.NopLogger()
	}
	if metrics == nil {
		metrics = NopMetrics()
	}
	if tracer == nil {
		tracer = NopTracer()
	}
	return &Merger{
		merger:  transform.NewResponseMerger(logger),
		logger:  logger,
		metrics: metrics,
		tracer:  tracer,
	}
}

// Combine merges successful responses according to opts. When merge is disabled
// or any payload is non-JSON it produces a labeled envelope array instead.
func (m *Merger) Combine(ctx context.Context, opts *MergeOptions, responses []*Response) (*MergeOutput, error) {
	_, span := m.tracer.Start(ctx, "aggregate.merge")
	defer span.End()

	start := time.Now()
	defer func() { m.metrics.RecordMergeDuration(time.Since(start)) }()

	if !mergeEnabled(opts) {
		return m.envelope(responses)
	}

	// Explicit NDJSON strategy always uses the line merger, regardless of
	// detection or content types (opt-in, predictable).
	if opts.Strategy == config.MergeStrategyNDJSON {
		return m.mergeNDJSON(opts, responses, "explicit")
	}

	docs, ok := decodeJSONDocs(responses)
	if !ok {
		// The deep/shallow/replace path would otherwise fall back to a labeled
		// envelope here (some body is not valid JSON-as-a-whole). Auto-promote
		// to NDJSON only when EVERY successful body is detected NDJSON; this
		// keeps existing JSON merges byte-identical and never promotes
		// valid-JSON-whole bodies.
		if allResponsesNDJSON(responses) {
			return m.mergeNDJSON(opts, responses, "auto")
		}
		m.logger.Debug("aggregate merge falling back to labeled envelope (non-JSON payload)")
		return m.envelope(responses)
	}

	merged, err := m.merger.Merge(docs, opts.Strategy)
	if err != nil {
		span.RecordError(err)
		m.logger.Warn("aggregate merge failed, using labeled envelope", observability.Error(err))
		return m.envelope(responses)
	}

	body, err := json.Marshal(merged)
	if err != nil {
		span.RecordError(err)
		return m.envelope(responses)
	}
	return &MergeOutput{Body: body, ContentType: contentTypeJSON, Merged: true}, nil
}

// mergeNDJSON merges the responses as NDJSON record streams via the line
// merger. mode is "explicit" (strategy: ndjson) or "auto" (promoted from the
// would-be-envelope branch); it is logged for observability with bounded
// cardinality.
func (m *Merger) mergeNDJSON(opts *MergeOptions, responses []*Response, mode string) (*MergeOutput, error) {
	out, err := newLineMerger(opts).Merge(responses)
	if err != nil {
		m.logger.Warn("aggregate ndjson merge failed, using labeled envelope",
			observability.Error(err))
		return m.envelope(responses)
	}
	m.logger.Debug("aggregate merge produced NDJSON stream",
		observability.String("merge_strategy", config.MergeStrategyNDJSON),
		observability.String("merge_mode", mode),
		observability.Int("records", countNDJSONRecords(out.Body)),
	)
	return out, nil
}

// countNDJSONRecords counts the non-empty newline-delimited records in body for
// debug logging only (bounded, cheap).
func countNDJSONRecords(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// envelope builds a labeled-envelope JSON array from the responses.
func (m *Merger) envelope(responses []*Response) (*MergeOutput, error) {
	envelopes := make([]Envelope, 0, len(responses))
	for _, resp := range responses {
		envelopes = append(envelopes, Envelope{
			Target:  resp.Target,
			Status:  resp.StatusCode,
			Payload: rawPayload(resp.Body),
		})
	}
	body, err := json.Marshal(envelopes)
	if err != nil {
		return nil, err
	}
	return &MergeOutput{Body: body, ContentType: contentTypeJSON, Merged: false}, nil
}

// mergeEnabled reports whether merging is requested.
func mergeEnabled(opts *MergeOptions) bool {
	return opts != nil && opts.Enabled
}

// decodeJSONDocs decodes each response body as a JSON object/array. It reports
// false if any body is not valid JSON (triggering the envelope fallback).
func decodeJSONDocs(responses []*Response) ([]interface{}, bool) {
	docs := make([]interface{}, 0, len(responses))
	for _, resp := range responses {
		if !looksLikeJSON(resp) {
			return nil, false
		}
		var doc interface{}
		if err := json.Unmarshal(resp.Body, &doc); err != nil {
			return nil, false
		}
		docs = append(docs, doc)
	}
	return docs, true
}

// looksLikeJSON reports whether a response body is plausibly JSON, by content
// type or by a leading object/array delimiter.
func looksLikeJSON(resp *Response) bool {
	if len(resp.Body) == 0 {
		return false
	}
	if strings.Contains(strings.ToLower(resp.ContentType), "json") {
		return true
	}
	trimmed := strings.TrimSpace(string(resp.Body))
	if trimmed == "" {
		return false
	}
	switch trimmed[0] {
	case '{', '[':
		return true
	default:
		return false
	}
}

// rawPayload returns the body as a json.RawMessage when it is valid JSON,
// otherwise it returns a JSON string-encoded copy so the envelope stays valid
// JSON.
func rawPayload(body []byte) json.RawMessage {
	if json.Valid(body) {
		return json.RawMessage(body)
	}
	encoded, err := json.Marshal(string(body))
	if err != nil {
		return json.RawMessage(`null`)
	}
	return encoded
}
