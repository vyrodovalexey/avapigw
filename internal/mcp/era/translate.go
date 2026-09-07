package era

import (
	"encoding/json"
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// legacyResourceNotFound is the retired legacy resource-not-found error code
// (-32002). The hub never emits it downstream; it is mapped to InvalidParams
// (-32602) when serving a modern client (HUB-410/706).
const legacyResourceNotFound = -32002

// resultTypeField is the modern result discriminator key injected on
// pre-resultType legacy results (HUB-706).
const resultTypeField = "resultType"

// TranslateLegacyResult normalizes a legacy JSON-RPC response into the modern
// result envelope (HUB-706/410):
//
//   - a legacy -32002 (resource-not-found) error is remapped to -32602
//     (InvalidParams), the code the hub is permitted to emit downstream;
//   - a pre-resultType legacy success result has resultType:"complete" injected
//     so modern clients observe the modern discriminator.
//
// The response is normalized in place and also returned for convenience. A nil
// response is returned unchanged. An input_required result (already carrying a
// resultType) is left untouched so the MRTR bridge can process it.
func TranslateLegacyResult(resp *jsonrpc.Response) (*jsonrpc.Response, error) {
	if resp == nil {
		return nil, nil
	}
	if resp.Error != nil {
		translateLegacyError(resp.Error)
		//nolint:nilerr // resp.Error is a JSON-RPC error field, not a Go error return
		return resp, nil
	}
	if len(resp.Result) == 0 {
		return resp, nil
	}
	injected, injErr := injectCompleteResultType(resp.Result)
	if injErr != nil {
		return nil, injErr
	}
	resp.Result = injected
	return resp, nil
}

// translateLegacyError remaps the retired legacy -32002 code to -32602 so the
// hub only emits codes it is permitted to (HUB-410). Other codes are left
// unchanged.
func translateLegacyError(e *jsonrpc.Error) {
	if e.Code == legacyResourceNotFound {
		e.Code = protocol.InvalidParams
	}
}

// injectCompleteResultType injects resultType:"complete" on a legacy result
// that predates the result-type discriminator (HUB-706). A result already
// carrying a resultType (e.g. an input_required result) is returned unchanged
// so downstream MRTR handling is not disturbed. A non-object result is returned
// unchanged.
func injectCompleteResultType(result json.RawMessage) (json.RawMessage, error) {
	obj, ok := decodeJSONObject(result)
	if !ok {
		// Non-object result (array/scalar): no discriminator to inject.
		return result, nil
	}
	if _, present := obj[resultTypeField]; present {
		return result, nil
	}
	raw, err := json.Marshal(protocol.ResultComplete)
	if err != nil {
		return nil, fmt.Errorf("era: encode resultType: %w", err)
	}
	obj[resultTypeField] = raw
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("era: encode translated result: %w", err)
	}
	return out, nil
}

// decodeJSONObject decodes result as a JSON object, reporting ok=false for a
// non-object (array/scalar) or invalid JSON so callers can leave it unchanged.
func decodeJSONObject(result json.RawMessage) (obj map[string]json.RawMessage, ok bool) {
	if err := json.Unmarshal(result, &obj); err != nil {
		return nil, false
	}
	return obj, true
}
