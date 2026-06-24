package aggregate

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GraphQL response field keys.
const (
	gqlFieldData       = "data"
	gqlFieldErrors     = "errors"
	gqlFieldExtensions = "extensions"
)

// MergeGraphQL combines multiple GraphQL responses: data and extensions are
// deep-merged, errors are concatenated. Non-JSON or malformed responses are
// skipped and surfaced as a synthetic error entry so partial failures remain
// visible to the client.
func (m *Merger) MergeGraphQL(ctx context.Context, responses []*Response) (*MergeOutput, error) {
	_, span := m.tracer.Start(ctx, "aggregate.merge")
	defer span.End()

	start := time.Now()
	defer func() { m.metrics.RecordMergeDuration(time.Since(start)) }()

	dataDocs := make([]interface{}, 0, len(responses))
	extDocs := make([]interface{}, 0, len(responses))
	mergedErrors := make([]interface{}, 0)

	for _, resp := range responses {
		var doc map[string]interface{}
		if err := json.Unmarshal(resp.Body, &doc); err != nil {
			mergedErrors = append(mergedErrors, syntheticError(resp.Target, err.Error()))
			continue
		}
		if d, ok := doc[gqlFieldData]; ok && d != nil {
			dataDocs = append(dataDocs, d)
		}
		if e, ok := doc[gqlFieldExtensions]; ok && e != nil {
			extDocs = append(extDocs, e)
		}
		mergedErrors = appendErrors(mergedErrors, doc[gqlFieldErrors])
	}

	out := buildGraphQLResult(m, dataDocs, extDocs, mergedErrors)
	body, err := json.Marshal(out)
	if err != nil {
		span.RecordError(err)
		m.logger.Warn("graphql aggregate marshal failed", observability.Error(err))
		return nil, err
	}
	return &MergeOutput{Body: body, ContentType: contentTypeJSON, Merged: true}, nil
}

// buildGraphQLResult assembles the merged GraphQL response document.
func buildGraphQLResult(
	m *Merger,
	dataDocs, extDocs, mergedErrors []interface{},
) map[string]interface{} {
	out := make(map[string]interface{}, 3)

	if data := m.deepMergeDocs(dataDocs); data != nil {
		out[gqlFieldData] = data
	}
	if ext := m.deepMergeDocs(extDocs); ext != nil {
		out[gqlFieldExtensions] = ext
	}
	if len(mergedErrors) > 0 {
		out[gqlFieldErrors] = mergedErrors
	}
	return out
}

// deepMergeDocs deep-merges a slice of documents using the shared
// transform.ResponseMerger. It returns nil for an empty input.
func (m *Merger) deepMergeDocs(docs []interface{}) interface{} {
	if len(docs) == 0 {
		return nil
	}
	merged, err := m.merger.Merge(docs, config.MergeStrategyDeep)
	if err != nil {
		m.logger.Warn("graphql deep merge failed", observability.Error(err))
		return docs[0]
	}
	return merged
}

// appendErrors appends a GraphQL errors array (if present) to the accumulator.
func appendErrors(acc []interface{}, raw interface{}) []interface{} {
	arr, ok := raw.([]interface{})
	if !ok {
		return acc
	}
	return append(acc, arr...)
}

// syntheticError builds a GraphQL-shaped error entry for a target that produced
// an unparseable response.
func syntheticError(target, message string) map[string]interface{} {
	return map[string]interface{}{
		"message": message,
		"extensions": map[string]interface{}{
			"target": target,
		},
	}
}
