// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// responseMerger implements the ResponseMerger interface.
type responseMerger struct {
	logger observability.Logger
}

// NewResponseMerger creates a new ResponseMerger instance.
func NewResponseMerger(logger observability.Logger) ResponseMerger {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &responseMerger{
		logger: logger,
	}
}

// Merge merges multiple responses into one using the specified strategy.
func (m *responseMerger) Merge(responses []interface{}, strategy string) (interface{}, error) {
	// Validate strategy first to ensure consistent error handling
	if !isValidMergeStrategy(strategy) {
		return nil, fmt.Errorf("unknown merge strategy: %s", strategy)
	}

	if len(responses) == 0 {
		return nil, nil
	}

	if len(responses) == 1 {
		return responses[0], nil
	}

	switch strategy {
	case config.MergeStrategyDeep, "":
		return m.deepMerge(responses)
	case config.MergeStrategyShallow:
		return m.shallowMerge(responses)
	case config.MergeStrategyReplace:
		return m.replaceMerge(responses)
	default:
		// This should never be reached due to validation above, but kept for safety
		return nil, fmt.Errorf("unknown merge strategy: %s", strategy)
	}
}

// isValidMergeStrategy checks if the given strategy is a valid merge strategy.
func isValidMergeStrategy(strategy string) bool {
	switch strategy {
	case config.MergeStrategyDeep, config.MergeStrategyShallow, config.MergeStrategyReplace, "":
		return true
	default:
		return false
	}
}

// deepMerge performs a deep merge of all responses.
// Nested objects are recursively merged.
func (m *responseMerger) deepMerge(responses []interface{}) (interface{}, error) {
	// Start with the first response
	result := deepCopyValue(responses[0])

	for i := 1; i < len(responses); i++ {
		result = m.mergeTwo(result, responses[i], true)
	}

	m.logger.Debug("deep merged responses",
		observability.Int("count", len(responses)))

	return result, nil
}

// shallowMerge performs a shallow merge of all responses.
// Only top-level fields are merged; nested objects are replaced.
func (m *responseMerger) shallowMerge(responses []interface{}) (interface{}, error) {
	// Start with the first response
	result := deepCopyValue(responses[0])

	for i := 1; i < len(responses); i++ {
		result = m.mergeTwo(result, responses[i], false)
	}

	m.logger.Debug("shallow merged responses",
		observability.Int("count", len(responses)))

	return result, nil
}

// replaceMerge returns the last non-nil response.
func (m *responseMerger) replaceMerge(responses []interface{}) (interface{}, error) {
	// Return the last non-nil response
	for i := len(responses) - 1; i >= 0; i-- {
		if responses[i] != nil {
			m.logger.Debug("replace merge: using response",
				observability.Int("index", i))
			return deepCopyValue(responses[i]), nil
		}
	}
	return nil, nil
}

// mergeTwo merges two values.
func (m *responseMerger) mergeTwo(dst, src interface{}, deep bool) interface{} {
	if src == nil {
		return dst
	}
	if dst == nil {
		return deepCopyValue(src)
	}

	dstMap, dstIsMap := dst.(map[string]interface{})
	srcMap, srcIsMap := src.(map[string]interface{})

	if dstIsMap && srcIsMap {
		return m.mergeMaps(dstMap, srcMap, deep)
	}

	dstArr, dstIsArr := dst.([]interface{})
	srcArr, srcIsArr := src.([]interface{})

	if dstIsArr && srcIsArr {
		return m.mergeArrays(dstArr, srcArr)
	}

	// Different types or primitives - source wins
	return deepCopyValue(src)
}

// mergeMaps merges two maps.
func (m *responseMerger) mergeMaps(dst, src map[string]interface{}, deep bool) map[string]interface{} {
	result := deepCopyMap(dst)

	for key, srcVal := range src {
		dstVal, exists := result[key]

		if !exists {
			result[key] = deepCopyValue(srcVal)
			continue
		}

		if deep {
			// Deep merge nested objects
			dstMap, dstIsMap := dstVal.(map[string]interface{})
			srcMap, srcIsMap := srcVal.(map[string]interface{})

			if dstIsMap && srcIsMap {
				result[key] = m.mergeMaps(dstMap, srcMap, true)
				continue
			}

			// Deep merge arrays
			dstArr, dstIsArr := dstVal.([]interface{})
			srcArr, srcIsArr := srcVal.([]interface{})

			if dstIsArr && srcIsArr {
				result[key] = m.mergeArrays(dstArr, srcArr)
				continue
			}
		}

		// Shallow merge or different types - source wins
		result[key] = deepCopyValue(srcVal)
	}

	return result
}

// mergeArrays merges two arrays by concatenation.
func (m *responseMerger) mergeArrays(dst, src []interface{}) []interface{} {
	result := make([]interface{}, 0, len(dst)+len(src))

	for _, v := range dst {
		result = append(result, deepCopyValue(v))
	}

	for _, v := range src {
		result = append(result, deepCopyValue(v))
	}

	return result
}

// MergeWithConfig merges responses using configuration.
func MergeWithConfig(
	responses []interface{},
	cfg *config.ResponseTransformConfig,
	logger observability.Logger,
) (interface{}, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	merger := NewResponseMerger(logger)
	return merger.Merge(responses, cfg.MergeStrategy)
}
