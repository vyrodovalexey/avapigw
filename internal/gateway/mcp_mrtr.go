package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	mcpmrtr "github.com/vyrodovalexey/avapigw/internal/mcp/mrtr"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// serveMRTR brokers an MRTR-eligible request (tools/call, resources/read,
// prompts/get) through the coordinator (HUB-201..209). It de-namespaces the
// call context, forwards the (initial or retry) request upstream, and — when
// the upstream returns input_required — seals the hub envelope and returns the
// enveloped input_required result downstream. Retries are verified before any
// upstream call so untrusted client state never influences routing/authorization
// (HUB-203/204).
func (h *MCPHandler) serveMRTR(
	w http.ResponseWriter, r *http.Request, mr *mcpReq,
	upstreamID string, upstream config.MCPBackend, sb *backend.ServiceBackend,
) {
	// Attach a lazy progress relay so upstream notifications/progress reach the
	// client on the response stream when SSE was requested (HUB-244). It stays
	// inert until the first progress event, so JSON error paths are unaffected.
	r = withProgressRelayContext(r, w)

	cc := h.buildCallContext(r, mr, upstreamID, upstream)

	var (
		upstreamState json.RawMessage
		// round/opStart are derived SERVER-SIDE from the verified envelope so
		// a client cannot forge the MRTR round counter or reset the operation
		// clock (HUB-208). An initial (non-retry) call starts at round 0 with a
		// zero start, which BuildDownstream seals as round 1 / now.
		round   int
		opID    string
		opStart time.Time
	)
	if mcpmrtr.IsRetry(mr.params) {
		state, ok := h.verifyRetry(w, r, mr, cc)
		if !ok {
			return
		}
		upstreamState = state.UpstreamState
		round = state.Round
		opID = state.OperationID
		opStart = state.OperationStart
		// Link this retry span to the operation so all rounds correlate
		// (T-62 / HUB-506).
		annotateOperationSpan(r, state.OperationID)
	}

	resp, ok := h.callMRTRUpstream(w, r, mr, upstreamID, upstream, sb, upstreamState)
	if !ok {
		return
	}

	h.completeMRTR(w, r, mr, cc, upstreamID, resp, mrtrProgress{round: round, opID: opID, opStart: opStart})
}

// mrtrProgress carries the SERVER-SIDE MRTR round accounting across the
// complete/input_required path so client-supplied hints never influence the
// round counter or wall-clock budget (HUB-208).
type mrtrProgress struct {
	// round is the sealed round of the envelope being retried (0 for an
	// initial call); the next sealed round is round+1.
	round int
	// opID links MRTR rounds/spans across the operation.
	opID string
	// opStart is the sealed wall-clock start of the operation (zero for an
	// initial call).
	opStart time.Time
}

// buildCallContext assembles the MRTR call context: de-namespaced name,
// principal, salient params digest source and declared client capabilities
// (HUB-202/206).
func (h *MCPHandler) buildCallContext(
	r *http.Request, mr *mcpReq, upstreamID string, upstream config.MCPBackend,
) mcpmrtr.CallContext {
	principal := ""
	if p := mcpPrincipalFromContext(r); p != nil {
		principal = p.Subject
	}
	return mcpmrtr.CallContext{
		UpstreamID:         upstreamID,
		Method:             mr.method(),
		DenamespacedName:   h.denamespacedName(mr.params, upstream.Name),
		Principal:          principal,
		SalientParams:      salientParams(mr.params),
		ClientCapabilities: declaredClientCaps(mr.params),
	}
}

// verifyRetry verifies the retry envelope and returns the verified state. On
// failure it writes a JSON-RPC error (never silently ignores, HUB-203) and
// returns ok=false.
func (h *MCPHandler) verifyRetry(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, cc mcpmrtr.CallContext,
) (*mcpmrtr.RetryState, bool) {
	token := stringParam(mr.params, mcpmrtr.FieldRequestState)
	state, err := h.coordinator.VerifyRetry(r.Context(), token, cc)
	if err != nil {
		h.metrics.RecordAuthFailure(mr.method(), mcpmetrics.AuthClassRetryState)
		h.logger.Debug("mcp mrtr: retry verification failed",
			observability.String("method", mr.method()), observability.Error(err))
		h.writeJSONRPCError(w, mr.id(), http.StatusBadRequest, protocol.InvalidParams,
			"invalid requestState", nil)
		return nil, false
	}
	return state, true
}

// callMRTRUpstream forwards the (initial or retry) request upstream. On a retry
// it substitutes the upstream's ORIGINAL state verbatim (HUB-202) and forwards
// the client's inputResponses. It applies the per-method/per-tool timeout
// (HUB-243).
func (h *MCPHandler) callMRTRUpstream(
	w http.ResponseWriter, r *http.Request, mr *mcpReq,
	upstreamID string, upstream config.MCPBackend, sb *backend.ServiceBackend,
	upstreamState json.RawMessage,
) (*jsonrpc.Response, bool) {
	method := mr.method()
	version := metaProtocolVersion(mr.params)
	negotiated := negotiatedVersion(upstream, version)

	upstreamReq, err := h.buildMRTRUpstreamRequest(mr, negotiated, upstreamState)
	if err != nil {
		h.metrics.RecordUpstreamFailure(upstreamID, method)
		h.writeJSONRPCError(w, mr.id(), http.StatusBadGateway, protocol.InternalError, err.Error(), nil)
		return nil, false
	}
	upstreamHeaders := h.deriveHeaders(method, mr.params, upstreamID)

	h.metrics.IncInFlight(upstreamID, method)
	defer h.metrics.DecInFlight(upstreamID, method)

	// callContext derives the timeout context from r.Context() so a client
	// disconnect still cancels the upstream call (HUB-241/243).
	callCtx, cancel := h.callContext(r.Context(), upstream, method, mr.params)
	defer cancel()

	// Relay upstream notifications/progress on the response stream when the
	// client requested SSE (HUB-244). The sink is a no-op when the upstream
	// answers with a single JSON body.
	callCtx = h.withProgressRelay(callCtx, r, upstreamID)

	resp, err := h.hub.Call(callCtx, sb, upstream.GetEffectivePath(), upstreamReq, upstreamHeaders)
	if err != nil {
		h.writeUpstreamCallError(w, mr, upstreamID, method, version, err)
		return nil, false
	}
	return resp, true
}

// withProgressRelay attaches a proxy.ProgressSink to ctx that relays upstream
// notifications/progress downstream on the request's response stream, preserving
// progressToken semantics (HUB-244). It is only active when the client is
// willing to receive a stream (Accept: text/event-stream); otherwise the sink
// is omitted and a single-JSON upstream response is returned unchanged.
func (h *MCPHandler) withProgressRelay(
	ctx context.Context, r *http.Request, upstreamID string,
) context.Context {
	relay := progressRelayFromContext(r)
	if relay == nil {
		return ctx
	}
	return mcpproxy.WithProgressSink(ctx, func(raw []byte) {
		if err := relay.writeProgress(raw); err != nil {
			h.logger.Debug("mcp mrtr: progress relay write failed",
				observability.String("upstream", upstreamID), observability.Error(err))
		}
	})
}

// buildMRTRUpstreamRequest builds the upstream request for an MRTR call. For a
// retry it injects the upstream's original requestState verbatim and preserves
// the client's inputResponses; for an initial call it strips any client-supplied
// requestState/inputResponses so untrusted state never reaches the upstream
// (HUB-204).
func (h *MCPHandler) buildMRTRUpstreamRequest(
	mr *mcpReq, negotiated string, upstreamState json.RawMessage,
) (*jsonrpc.Request, error) {
	base, err := h.buildUpstreamRequest(mr, negotiated)
	if err != nil {
		return nil, err
	}
	params := map[string]any{}
	if uerr := json.Unmarshal(base.Params, &params); uerr != nil {
		return nil, uerr
	}
	// Untrusted client fields never pass through unchanged.
	delete(params, mcpmrtr.FieldRequestState)
	if len(upstreamState) > 0 {
		params[mcpmrtr.FieldRequestState] = upstreamState
	} else {
		delete(params, mcpmrtr.FieldInputResponses)
	}
	newParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	base.Params = newParams
	return base, nil
}

// completeMRTR classifies the upstream response: an input_required result is
// enveloped and returned downstream (HUB-202); anything else is written as a
// normal brokered response.
func (h *MCPHandler) completeMRTR(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, cc mcpmrtr.CallContext,
	upstreamID string, resp *jsonrpc.Response, prog mrtrProgress,
) {
	version := metaProtocolVersion(mr.params)
	ins, err := h.coordinator.Inspect(mr.method(), resp)
	if err != nil {
		h.writeJSONRPCError(w, mr.id(), http.StatusBadGateway, protocol.InternalError,
			"invalid upstream result", nil)
		h.recordOutcome(upstreamID, mr.method(), name0(mr.params), version,
			resultTypeUnknown, mcpmetrics.OutcomeError, mr.start)
		return
	}
	if !ins.InputRequired {
		// Terminal (non-input_required) completion: record how many rounds
		// this operation took (HUB-505). The round is the sealed envelope
		// round + 1 for a completed retry, or 1 for a direct completion.
		h.metrics.ObserveMRTRRounds(upstreamID, mr.method(), prog.round+1)
		h.maybeCacheRead(r, mr, resp, upstreamID)
		annotateOutcomeSpan(r, upstreamID, protocol.ResultComplete, mcpmetrics.OutcomeSuccess)
		h.writeMRTRComplete(w, r, mr, resp, upstreamID, version)
		h.auditToolCall(r, mr, upstreamID, auditDecisionFor(resp), protocol.ResultComplete, mrtrLatency(mr))
		return
	}
	annotateOutcomeSpan(r, upstreamID, protocol.ResultInputRequired, mcpmetrics.OutcomeSuccess)
	h.writeInputRequired(w, r, mr, cc, upstreamID, ins, prog)
}

// writeInputRequired seals the hub envelope and writes the enveloped
// input_required result downstream (HUB-202/205/206). A missing-capability
// upstream request is reported as -32021 (HUB-206); round/budget overruns are
// reported as JSON-RPC errors (HUB-208).
func (h *MCPHandler) writeInputRequired(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, cc mcpmrtr.CallContext,
	upstreamID string, ins mcpmrtr.InspectResult, prog mrtrProgress,
) {
	version := metaProtocolVersion(mr.params)
	// The next round is the sealed round + 1; the coordinator enforces the
	// configured MaxRounds and total wall-clock budget SERVER-SIDE (HUB-208).
	nextRound := prog.round + 1

	result, err := h.coordinator.BuildDownstream(
		r.Context(), cc, ins, nextRound, prog.opID, prog.opStart)
	if err != nil {
		h.writeMRTRBuildError(w, mr, err)
		h.recordOutcome(upstreamID, mr.method(), name0(mr.params), version,
			resultTypeUnknown, mcpmetrics.OutcomeError, mr.start)
		return
	}

	resp, err := jsonrpc.NewResponse(mr.id(), result)
	if err != nil {
		h.writeJSONRPCError(w, mr.id(), http.StatusInternalServerError, protocol.InternalError,
			"encode input_required", nil)
		return
	}
	h.writeMRTRResult(w, r, resp)
	h.recordOutcome(upstreamID, mr.method(), name0(mr.params), version,
		protocol.ResultInputRequired, mcpmetrics.OutcomeSuccess, mr.start)
}

// writeMRTRComplete writes a terminal (complete) MRTR result. When a progress
// relay has opened the downstream SSE stream (HUB-244), the rewritten result is
// written as the final event on that stream; otherwise it falls back to the
// normal application/json brokered response.
func (h *MCPHandler) writeMRTRComplete(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, resp *jsonrpc.Response,
	upstreamID, version string,
) {
	relay := progressRelayFromContext(r)
	if relay == nil || !relay.active() {
		h.writeBrokeredResponse(w, mr, resp, upstreamID, version)
		return
	}
	if resp.Error == nil {
		resp.Result = h.rewriteResult(resp.Result, upstreamID)
	}
	_ = h.writeTerminalOnRelay(r, resp)
	outcome := mcpmetrics.OutcomeSuccess
	resultType := protocol.ResultComplete
	if resp.Error != nil {
		outcome = mcpmetrics.OutcomeError
		resultType = resultTypeUnknown
	}
	h.recordOutcome(upstreamID, mr.method(), name0(mr.params), version, resultType, outcome, mr.start)
}

// writeMRTRResult writes an MRTR result honoring content negotiation: SSE when
// the client requested it (HUB-102), else application/json. When a progress
// relay has already opened the downstream SSE stream (HUB-244), the terminal
// result is written as the final event on that same stream rather than
// re-opening a response.
func (h *MCPHandler) writeMRTRResult(w http.ResponseWriter, r *http.Request, resp *jsonrpc.Response) {
	if h.writeTerminalOnRelay(r, resp) {
		return
	}
	if wantsSSE(r) {
		if sw, err := newSSEResponseWriter(w); err == nil {
			body, encErr := jsonrpc.Encode(resp)
			if encErr == nil {
				_ = sw.WriteEvent(eventMessageName, body)
			}
			return
		}
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// writeTerminalOnRelay writes resp as the final SSE event on an already-open
// progress-relay stream, returning true when it did so (HUB-244). When no relay
// is active it returns false and the caller falls back to its normal write.
func (h *MCPHandler) writeTerminalOnRelay(r *http.Request, resp *jsonrpc.Response) bool {
	relay := progressRelayFromContext(r)
	if relay == nil || !relay.active() {
		return false
	}
	body, err := jsonrpc.Encode(resp)
	if err != nil {
		h.logger.Debug("mcp mrtr: encode terminal for relay failed", observability.Error(err))
		return false
	}
	if err := relay.writeTerminal(body); err != nil {
		h.logger.Debug("mcp mrtr: write terminal on relay failed", observability.Error(err))
	}
	return true
}

// writeMRTRBuildError maps an MRTR build failure to the correct JSON-RPC error:
// -32021 for a missing client capability (HUB-206), an invalid-params error for
// round/budget overruns (HUB-208), else an internal error.
func (h *MCPHandler) writeMRTRBuildError(w http.ResponseWriter, mr *mcpReq, err error) {
	var capErr *mcpmrtr.CapabilityError
	if errors.As(err, &capErr) {
		data := map[string]any{"missing": capErr.Missing}
		h.writeJSONRPCError(w, mr.id(), http.StatusBadRequest,
			protocol.MissingRequiredClientCapability,
			"missing required client capability", data)
		return
	}
	if errors.Is(err, mcpmrtr.ErrRoundLimit) || errors.Is(err, mcpmrtr.ErrBudgetExceeded) {
		h.writeJSONRPCError(w, mr.id(), http.StatusBadRequest, protocol.InvalidParams,
			err.Error(), nil)
		return
	}
	h.writeJSONRPCError(w, mr.id(), http.StatusBadGateway, protocol.InternalError,
		"input_required processing failed", nil)
}

// salientParams returns the JSON of the request params that bind the MRTR
// envelope, excluding the client-controlled requestState/inputResponses and the
// _meta object so the digest is stable across rounds (HUB-202/203).
func salientParams(params map[string]any) json.RawMessage {
	salient := make(map[string]any, len(params))
	for k, v := range params {
		switch k {
		case mcpmrtr.FieldRequestState, mcpmrtr.FieldInputResponses, "_meta":
			continue
		default:
			salient[k] = v
		}
	}
	raw, err := json.Marshal(salient)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// declaredClientCaps returns the set of input-request types the downstream
// client declared in its clientCapabilities (HUB-206).
func declaredClientCaps(params map[string]any) map[string]bool {
	caps := map[string]bool{}
	metaObj := extractMeta(params)
	raw, ok := metaObj[protocol.MetaClientCapabilities].(map[string]any)
	if !ok {
		return caps
	}
	for _, name := range []string{mcpmrtr.CapSampling, mcpmrtr.CapElicitation, mcpmrtr.CapRoots} {
		if _, present := raw[name]; present {
			caps[name] = true
		}
	}
	return caps
}

// mrtrLatency returns the elapsed time since the request started, for the audit
// record.
func mrtrLatency(mr *mcpReq) time.Duration {
	return time.Since(mr.start)
}
