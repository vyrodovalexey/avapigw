package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	"github.com/vyrodovalexey/avapigw/internal/mcp/security"
)

// mcpDryRunHeader is the per-request header that enables shadow mode for a
// single request even when the global DryRun flag is off (HUB-507).
const mcpDryRunHeader = "Mcp-Dry-Run"

// dryRunRequested reports whether shadow mode applies to this request: either
// the handler-wide DryRun flag or the per-request Mcp-Dry-Run: true header
// (HUB-507).
func (h *MCPHandler) dryRunRequested(r *http.Request) bool {
	if h.dryRun {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get(mcpDryRunHeader)), "true")
}

// serveDryRun resolves routing/policy/schema for a request WITHOUT invoking the
// upstream and returns a synthetic result describing the resolution (HUB-507).
// Authentication/authorization have already run in ServeHTTP; here we only
// report the routing decision.
func (h *MCPHandler) serveDryRun(
	w http.ResponseWriter, r *http.Request, mr *mcpReq, route *config.MCPRoute,
) {
	name := primitiveName(mr.params)
	upstreamID := h.resolveDryRunUpstream(name, route)

	body := map[string]any{
		"resultType":       protocol.ResultComplete,
		"dryRun":           true,
		"method":           mr.method(),
		"route":            routeName(route),
		"resolvedUpstream": upstreamID,
	}
	if candidates := dryRunCandidates(route); len(candidates) > 0 {
		body["candidateUpstreams"] = candidates
	}
	if name != "" {
		body["primitive"] = name
	}
	raw, err := json.Marshal(body)
	if err != nil {
		h.writeJSONRPCError(w, mr.id(), http.StatusInternalServerError, protocol.InternalError,
			"encode dry-run result", nil)
		return
	}
	resp, err := jsonrpc.NewResponse(mr.id(), raw)
	if err != nil {
		h.writeJSONRPCError(w, mr.id(), http.StatusInternalServerError, protocol.InternalError,
			"encode dry-run response", nil)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
	h.recordOutcome(upstreamID, mr.method(), name0(mr.params), metaProtocolVersion(mr.params),
		protocol.ResultComplete, mcpmetrics.OutcomeSuccess, mr.start)
	h.auditToolCall(r, mr, upstreamID, "dry_run", "dry_run", time.Since(mr.start))
}

// resolveDryRunUpstream resolves the upstream a request WOULD route to without
// calling it: the owning upstream of a namespaced name, else a weighted
// selection over the route's live candidates. It shares the exact selection
// path (pickWeightedUpstream) with real routing so shadow mode reports the
// upstream a real request would actually reach (HUB-507).
func (h *MCPHandler) resolveDryRunUpstream(name string, route *config.MCPRoute) string {
	if name != "" {
		if id, _, ok := h.mapper.Denamespace(name); ok {
			return id
		}
	}
	h.mu.RLock()
	upstreams := h.upstreams
	h.mu.RUnlock()
	if id, _, picked := h.pickWeightedUpstream(route, upstreams); picked {
		return id
	}
	return ""
}

// dryRunCandidates lists the route's weighted upstream candidates (name+weight)
// so shadow mode exposes the full weighted-routing distribution, not just the
// single sampled pick (HUB-507).
func dryRunCandidates(route *config.MCPRoute) []map[string]any {
	if route == nil {
		return nil
	}
	refs := route.UpstreamRefs()
	out := make([]map[string]any, 0, len(refs))
	for _, ref := range refs {
		out = append(out, map[string]any{"name": ref.Name, "weight": ref.Weight})
	}
	return out
}

// auditToolCall emits an audit record for a tools/call (HUB-408). It records
// the principal, upstream, namespaced+de-namespaced tool name, a redacted
// argument digest, the decision, latency and the result classification. It is a
// no-op for non-tools/call methods or when no audit logger is configured.
func (h *MCPHandler) auditToolCall(
	r *http.Request, mr *mcpReq, upstreamID, decision, classification string, latency time.Duration,
) {
	if h.auditLogger == nil || mr.method() != protocol.MethodToolsCall {
		return
	}
	nsName := primitiveName(mr.params)
	deNamespaced := nsName
	if _, original, ok := h.mapper.Denamespace(nsName); ok {
		deNamespaced = original
	}

	event := audit.NewEvent(audit.EventTypeAuthorization, auditActionForDecision(decision),
		auditOutcomeForDecision(decision)).
		WithSubject(h.auditSubject(r)).
		WithResource(&audit.Resource{
			Type:    "mcp_tool",
			Name:    nsName,
			Service: upstreamID,
			Method:  mr.method(),
		}).
		WithDuration(latency).
		WithMetadata("de_namespaced_tool", deNamespaced).
		WithMetadata("argument_digest", security.ArgumentDigest(mr.params)).
		WithMetadata("result_classification", classification)

	h.auditLogger.LogEvent(r.Context(), event)
}

// auditSubject builds the audit subject from the authenticated principal, or a
// system subject when authorization is not configured.
func (h *MCPHandler) auditSubject(r *http.Request) *audit.Subject {
	if p := mcpPrincipalFromContext(r); p != nil {
		return &audit.Subject{ID: p.Subject, Type: "user"}
	}
	return &audit.Subject{ID: "anonymous", Type: "system"}
}

// auditActionForDecision maps a broker decision to an audit action.
func auditActionForDecision(decision string) audit.Action {
	if decision == "deny" {
		return audit.ActionDeny
	}
	return audit.ActionAccess
}

// auditOutcomeForDecision maps a broker decision to an audit outcome.
func auditOutcomeForDecision(decision string) audit.Outcome {
	switch decision {
	case "deny":
		return audit.OutcomeDenied
	case "error":
		return audit.OutcomeError
	default:
		return audit.OutcomeSuccess
	}
}

// routeName returns the matched route name, or "" when unmatched.
func routeName(route *config.MCPRoute) string {
	if route == nil {
		return ""
	}
	return route.Name
}
