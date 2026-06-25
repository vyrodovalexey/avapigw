package aggregate

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// contentTypeNDJSON is the canonical NDJSON content type emitted by the line
// merger. It flows verbatim through the REST/GraphQL/gRPC response writers.
const contentTypeNDJSON = "application/stream+json"

// ndjsonContentTypes is the set of media types (lower-cased, without
// parameters) that identify an NDJSON record stream.
var ndjsonContentTypes = map[string]struct{}{
	"application/stream+json": {},
	"application/x-ndjson":    {},
	"application/jsonl":       {},
}

// isNDJSONContentType reports whether ct is one of the recognized NDJSON media
// types. Matching is case-insensitive and ignores any parameters after ';'
// (e.g. "; charset=utf-8").
func isNDJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	media := ct
	if idx := strings.IndexByte(media, ';'); idx >= 0 {
		media = media[:idx]
	}
	media = strings.ToLower(strings.TrimSpace(media))
	_, ok := ndjsonContentTypes[media]
	return ok
}

// looksLikeNDJSON reports whether body is a newline-delimited JSON stream using
// the "valid-per-line but invalid-as-a-whole" heuristic. It returns true iff:
//   - body has at least one non-empty (post-trim) line,
//   - every non-empty line is independently valid JSON, AND
//   - the whole body is NOT valid JSON (so a single JSON object/array body,
//     including one with a trailing newline, returns false).
//
// It is panic-free on arbitrary binary input.
func looksLikeNDJSON(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	if json.Valid(body) {
		return false
	}
	nonEmpty := 0
	for _, line := range bytes.Split(body, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		if !json.Valid(trimmed) {
			return false
		}
		nonEmpty++
	}
	return nonEmpty >= 1
}

// responseIsNDJSON reports whether a successful response carries an NDJSON
// payload, by declared content type or by the body heuristic.
func responseIsNDJSON(resp *Response) bool {
	if resp == nil {
		return false
	}
	return isNDJSONContentType(resp.ContentType) || looksLikeNDJSON(resp.Body)
}

// allResponsesNDJSON reports whether every response in the slice is NDJSON. An
// empty slice returns false (nothing to promote).
func allResponsesNDJSON(responses []*Response) bool {
	if len(responses) == 0 {
		return false
	}
	for _, resp := range responses {
		if !responseIsNDJSON(resp) {
			return false
		}
	}
	return true
}

// ndjsonRecord is a single NDJSON line plus its best-effort decoded form (used
// for sorting and de-duplication). decoded is nil when the line is not a JSON
// object.
type ndjsonRecord struct {
	raw     []byte
	decoded map[string]interface{}
}

// lineMerger merges NDJSON record streams from multiple successful responses
// into a single NDJSON stream, applying optional stable sort, first-wins
// de-duplication and a record limit.
type lineMerger struct {
	// timeField is the sort key; empty disables sorting.
	timeField string

	// keyField is the de-duplication key; empty disables de-duplication.
	keyField string

	// limit caps the emitted record count; 0 means unlimited.
	limit int
}

// newLineMerger constructs a lineMerger from runtime merge options.
func newLineMerger(opts *MergeOptions) *lineMerger {
	return &lineMerger{
		timeField: opts.TimeField,
		keyField:  opts.KeyField,
		limit:     opts.Limit,
	}
}

// Merge combines the NDJSON bodies of the given responses (assumed successful,
// in stable target order) into a single NDJSON MergeOutput. The output content
// type is always application/stream+json with Merged set to true.
func (lm *lineMerger) Merge(responses []*Response) (*MergeOutput, error) {
	records := collectNDJSONRecords(responses)

	if lm.timeField != "" {
		lm.stableSort(records)
	}
	if lm.keyField != "" {
		records = lm.dedupe(records)
	}
	if lm.limit > 0 && len(records) > lm.limit {
		records = records[:lm.limit]
	}

	return &MergeOutput{
		Body:        serializeNDJSON(records),
		ContentType: contentTypeNDJSON,
		Merged:      true,
	}, nil
}

// collectNDJSONRecords splits each response body into NDJSON records, preserving
// cross-target order (responses in slice order, lines in file order). Blank and
// whitespace-only lines are skipped.
func collectNDJSONRecords(responses []*Response) []ndjsonRecord {
	records := make([]ndjsonRecord, 0, len(responses))
	for _, resp := range responses {
		if resp == nil || len(resp.Body) == 0 {
			continue
		}
		for _, line := range bytes.Split(resp.Body, []byte("\n")) {
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) == 0 {
				continue
			}
			raw := make([]byte, len(trimmed))
			copy(raw, trimmed)
			records = append(records, ndjsonRecord{
				raw:     raw,
				decoded: decodeObject(trimmed),
			})
		}
	}
	return records
}

// decodeObject best-effort decodes a line as a JSON object. It returns nil when
// the line is not a JSON object (e.g. a scalar or array), in which case the
// record is treated as lacking any sort/dedupe field.
func decodeObject(line []byte) map[string]interface{} {
	var obj map[string]interface{}
	if err := json.Unmarshal(line, &obj); err != nil {
		return nil
	}
	return obj
}

// stableSort stably sorts records by timeField using the deterministic typing
// rules (numeric, then RFC3339, then string), with present-first / missing-last
// ordering. Records missing the field (or equal) retain their input order.
func (lm *lineMerger) stableSort(records []ndjsonRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		return lm.less(records[i], records[j])
	})
}

// less reports whether record a sorts before record b by timeField (D3 rules).
func (lm *lineMerger) less(a, b ndjsonRecord) bool {
	av, aok := lookupField(a.decoded, lm.timeField)
	bv, bok := lookupField(b.decoded, lm.timeField)
	if !aok || !bok {
		// Present-first / missing-last; both missing => equal (stable).
		return aok && !bok
	}
	return compareValues(av, bv) < 0
}

// dedupe removes duplicate records by keyField, keeping the first occurrence
// (first-wins after sort). Records missing the key are always kept.
func (lm *lineMerger) dedupe(records []ndjsonRecord) []ndjsonRecord {
	seen := make(map[string]struct{}, len(records))
	out := records[:0]
	for _, rec := range records {
		val, ok := lookupField(rec.decoded, lm.keyField)
		if !ok {
			out = append(out, rec)
			continue
		}
		key := scalarString(val)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rec)
	}
	return out
}

// serializeNDJSON joins records as newline-delimited raw lines with a single
// trailing newline. An empty record set yields an empty body.
func serializeNDJSON(records []ndjsonRecord) []byte {
	if len(records) == 0 {
		return []byte{}
	}
	var buf bytes.Buffer
	for _, rec := range records {
		buf.Write(rec.raw)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// lookupField returns the field value and whether it is present in the decoded
// object. A nil object (non-object line) reports the field as absent.
func lookupField(obj map[string]interface{}, field string) (interface{}, bool) {
	if obj == nil {
		return nil, false
	}
	v, ok := obj[field]
	return v, ok
}

// compareValues returns -1, 0 or 1 comparing two field values using the fixed
// D3 typing order: numeric, then RFC3339 timestamp, then canonical string. The
// comparison is total and panic-free for any JSON scalar/compound input.
func compareValues(a, b interface{}) int {
	if an, aok := asNumber(a); aok {
		if bn, bok := asNumber(b); bok {
			return cmpFloat(an, bn)
		}
	}
	as := scalarString(a)
	bs := scalarString(b)
	if at, aok := asTime(as); aok {
		if bt, bok := asTime(bs); bok {
			return cmpTime(at, bt)
		}
	}
	return strings.Compare(as, bs)
}

// asNumber extracts a float64 from a JSON number value (json.Number or float64).
func asNumber(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// asTime parses an RFC3339 timestamp from a string form.
func asTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// scalarString renders a field value as a canonical string for comparison and
// de-duplication. Strings are used verbatim; numbers/bools use their canonical
// form; compound values fall back to their JSON encoding.
func scalarString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return "null"
	default:
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return ""
	}
}

// cmpFloat compares two float64 values.
func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// cmpTime compares two timestamps.
func cmpTime(a, b time.Time) int {
	switch {
	case a.Before(b):
		return -1
	case a.After(b):
		return 1
	default:
		return 0
	}
}
