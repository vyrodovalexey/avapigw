# Requirements: API Gateway in MCP Hub Mode

**Target protocol revision:** MCP `2026-07-28`
**Interop targets:** `2025-11-25`, `2025-06-18`, `2025-03-26` (legacy / initialization-based era)
**Status:** draft for implementation
**Keywords:** MUST / SHOULD / MAY per RFC 2119 / RFC 8174

---

## 0. Context and role definition

The gateway operates as an **MCP hub**: a single MCP endpoint that fronts N upstream MCP
servers. Toward downstream MCP clients it is an **MCP server** (OAuth 2.1 resource server);
toward upstream MCP servers it is an **MCP client** (OAuth 2.1 client). It is a protocol-aware
reverse proxy, not a transparent L7 proxy.

Three properties of revision `2026-07-28` define the whole design:

1. **The protocol is stateless.** There is no `initialize` handshake, no `Mcp-Session-Id`,
   no session affinity. Every request carries its own protocol version, client capabilities
   and identity in `_meta`.
2. **Server→client requests no longer exist.** Sampling, elicitation and roots are delivered
   as an `InputRequiredResult` that the client answers by *retrying the original request*
   (MRTR). The retry is a new, independent request with a new JSON-RPC id.
3. **Selected body fields are mirrored into HTTP headers** (`Mcp-Method`, `Mcp-Name`,
   `Mcp-Param-*`) explicitly so that intermediaries can route and enforce policy without
   parsing the body — and header/body consistency is a security requirement.

### 0.1 Terminology

| Term | Meaning |
| --- | --- |
| Hub | This gateway, in MCP hub mode |
| Upstream | A configured MCP server behind the hub |
| Downstream | An MCP client connected to the hub |
| Modern era | `2026-07-28`+ (per-request metadata, stateless) |
| Legacy era | `2025-11-25` and earlier (`initialize` handshake, sessions) |
| Namespaced name | Hub-visible primitive name, e.g. `github.search_issues` |

---

## 1. Functional requirements

### 1.1 Endpoint and transport (downstream)

- **HUB-101** The hub MUST expose a single MCP endpoint path accepting HTTP `POST`
  (Streamable HTTP), configurable per listener (default `/mcp`).
- **HUB-102** The hub MUST accept exactly one JSON-RPC *request* or *notification* per POST
  and MUST answer a request with either `application/json` or `text/event-stream`.
- **HUB-103** The hub MUST respond `405 Method Not Allowed` to `GET` and `DELETE` on the MCP
  endpoint (the standalone SSE stream and session termination are removed in this revision),
  unless legacy compatibility mode (§6) is enabled for that listener.
- **HUB-104** The hub MUST ignore any `Mcp-Session-Id` header and MUST NOT mint or echo
  session identifiers in modern mode.
- **HUB-105** The hub MUST ignore `Last-Event-ID`; response streams are not resumable. A
  dropped stream MUST be treated as a lost request, not as something to replay.
- **HUB-106** The hub MUST validate the `Origin` header on all incoming connections and MUST
  respond `403 Forbidden` when a present `Origin` is not on the configured allowlist.
- **HUB-107** The hub MUST send `X-Accel-Buffering: no` on every SSE response it originates.
- **HUB-108** The hub MUST support stdio upstreams (child process, one stream pair) and
  Streamable HTTP upstreams. stdio upstream lifecycle MUST NOT be tied to any downstream
  request, conversation or connection.
- **HUB-109** The hub MUST NOT require or assume that related downstream requests arrive on
  the same TCP connection, the same replica, or in any particular order.

### 1.2 Per-request metadata

- **HUB-121** The hub MUST reject any downstream request whose `params._meta` omits
  `io.modelcontextprotocol/protocolVersion` or `io.modelcontextprotocol/clientCapabilities`
  with JSON-RPC `-32602` and HTTP `400`.
- **HUB-122** The hub MUST verify that `MCP-Protocol-Version` matches
  `_meta["io.modelcontextprotocol/protocolVersion"]` and MUST reject a mismatch with
  `-32020` (`HeaderMismatch`) and HTTP `400`.
- **HUB-123** When the hub does not implement the requested version it MUST return
  `-32022` (`UnsupportedProtocolVersion`) with `data.supported` listing the versions the
  **hub** implements and `data.requested` echoing the client's value. The advertised set MUST
  be the hub's own capability set, independent of upstream eras (the hub translates, §6).
- **HUB-124** For every request forwarded upstream, the hub MUST construct fresh `_meta`:
    - `protocolVersion` = the version negotiated with **that upstream**, not the downstream one;
    - `clientCapabilities` = the downstream client's capabilities, **narrowed** to what the hub
      is able to broker (see HUB-125), never widened;
    - `clientInfo` = the hub's own name/version, optionally with the downstream client's
      identity carried in a vendor-prefixed `_meta` key for audit;
    - `logLevel` propagated verbatim when present.
- **HUB-125** The hub MUST NOT advertise upstream a client capability the downstream client
  did not declare. If the hub itself can satisfy a capability the client lacks (e.g. it can
  answer `roots/list` from configuration), it MAY advertise it and MUST then answer the
  corresponding input request itself without involving the client.
- **HUB-126** The hub MUST include `io.modelcontextprotocol/serverInfo` in the `_meta` of
  every result it returns downstream, identifying the hub (not the upstream). Upstream
  `serverInfo` MAY be preserved under a vendor-prefixed key.
- **HUB-127** The hub MUST propagate `traceparent`, `tracestate` and `baggage` from downstream
  `_meta` into the upstream request `_meta`, creating a child span. It MUST NOT drop or
  rewrite `baggage` entries it does not understand.
- **HUB-128** The hub MUST NOT use self-reported `clientInfo` / `serverInfo` for any
  authorization, routing or rate-limiting decision.

### 1.3 Header mirroring and validation

- **HUB-141** The hub MUST require `Mcp-Method` on all downstream requests and `Mcp-Name` on
  `tools/call`, `resources/read` and `prompts/get`, and MUST reject missing or mismatched
  headers with `-32020` / HTTP `400`.
- **HUB-142** Before comparing header to body, the hub MUST decode the Base64 sentinel form
  `=?base64?<b64>?=` for `Mcp-Name` and `Mcp-Param-*`. Integer parameter values MUST be
  compared numerically, not as strings.
- **HUB-143** The hub MUST re-derive all mirrored headers for the upstream request after any
  body rewrite (notably tool de-namespacing, HUB-162). Forwarding a downstream `Mcp-Name`
  alongside a rewritten body is a header-mismatch defect.
- **HUB-144** The hub MUST mirror `x-mcp-header`-annotated tool parameters into
  `Mcp-Param-{Name}` on upstream calls, applying the spec's encoding rules, and MUST omit the
  header when the value is absent.
- **HUB-145** The hub MUST reject (exclude from `tools/list`) any upstream tool whose
  `x-mcp-header` annotations violate the schema constraints — non-empty, HTTP token syntax, no
  CR/LF, case-insensitively unique, primitive types only (`number` not permitted), statically
  reachable via `properties` chains only — and MUST log the tool name and rejection reason
  while continuing to serve the remaining tools.
- **HUB-146** The hub MUST forward unrecognized `Mcp-Param-*` headers unchanged.
- **HUB-147** When the hub enforces policy (routing, quota, WAF rules) on mirrored headers, it
  MUST first confirm that `MCP-Protocol-Version` names a revision that mandates header/body
  validation, and MUST reject the request otherwise rather than trusting unvalidated headers.
- **HUB-148** Routing and rate-limiting decisions SHOULD be derivable from headers alone
  (`Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`, `MCP-Protocol-Version`, `Authorization`) so that a
  fast path can avoid full body parsing; the hub MUST still validate the body before
  forwarding.

### 1.4 Discovery and capability aggregation

- **HUB-161** The hub MUST implement `server/discover`, returning: `supportedVersions` (the
  hub's own), the **union** of upstream capabilities filtered by policy, the hub's
  `serverInfo`, merged `instructions`, and `ttlMs` / `cacheScope`.
- **HUB-162** The hub MUST maintain a namespacing scheme for tools, prompts, resource
  templates and resource URIs. Default: `<upstream-id><separator><original-name>` with a
  configurable separator restricted to the recommended tool-name alphabet
  (`A-Za-z0-9_.-`); the resulting name MUST be ≤128 characters. On overflow the hub MUST
  apply a deterministic, stable shortening (e.g. truncation + short hash) and MUST keep the
  mapping stable across restarts and replicas.
- **HUB-163** The hub MUST de-namespace `params.name` / `params.uri` when forwarding upstream
  and MUST re-namespace names and resource URIs in every result, including
  `resource_link`, embedded resources and `structuredContent` fields known to carry URIs.
- **HUB-164** `tools/list`, `prompts/list`, `resources/list` and `resources/templates/list`
  MUST return the merged set across upstreams, in a **deterministic order** stable across
  requests and replicas when the underlying set is unchanged.
- **HUB-165** The result set MUST NOT vary per connection. It MAY vary by the authorization
  presented on the request (credentials are per-request input) and by configured
  allow/deny policy.
- **HUB-166** Pagination cursors issued by the hub MUST be opaque, integrity-protected and
  self-contained (encoding per-upstream cursor state), so that any replica can serve the next
  page. The hub MUST NOT expose upstream cursors verbatim. An invalid or expired cursor MUST
  produce an error that instructs the client to restart from the beginning.
- **HUB-167** If an upstream is unavailable, the hub MUST still serve list requests from the
  remaining upstreams (degraded, not failed), MUST mark the degradation in metrics and logs,
  and SHOULD shorten `ttlMs` for degraded responses.
- **HUB-168** The hub MUST detect name collisions across upstreams and MUST resolve them by
  namespacing; it MUST NOT rely on upstream `serverInfo.name` for disambiguation.
- **HUB-169** The hub MUST preserve upstream `inputSchema` / `outputSchema` byte-for-byte
  semantics (including `$schema`, `x-mcp-header`, `$defs`), except for name rewriting.

### 1.5 Caching

- **HUB-181** The hub MUST emit `ttlMs` (≥0) and `cacheScope` on all `resultType: "complete"`
  results for `server/discover`, `tools/list`, `prompts/list`, `resources/list`,
  `resources/templates/list` and `resources/read`.
- **HUB-182** For aggregated results, the hub MUST set `ttlMs` to the minimum of the
  contributing upstream values, clamped to a configured `[min,max]`; and MUST set
  `cacheScope: "private"` if **any** contributing result is `"private"` or if the response was
  filtered by the caller's authorization.
- **HUB-183** As a shared intermediary, the hub MAY cache upstream results keyed by
  (upstream, method, effective params). It MUST NOT reuse a `"private"` cached result across
  authorization contexts (a different access token requires a different cache entry).
- **HUB-184** The hub MUST NOT cache results of requests carrying `inputResponses` or
  `requestState`.
- **HUB-185** The hub MUST invalidate cached entries on receipt of the corresponding
  `list_changed` / `resources/updated` notification from an upstream, and MUST NOT treat
  `ttlMs` as a polling interval; any polling it performs MUST apply jitter and backoff.
- **HUB-186** The hub MUST apply one `cacheScope` consistently across all pages of a paginated
  list response.

### 1.6 Multi Round-Trip Requests (MRTR)

- **HUB-201** The hub MUST relay `InputRequiredResult` (`resultType: "input_required"`)
  downstream for `tools/call`, `resources/read` and `prompts/get`, and MUST NOT emit it for
  any other method.
- **HUB-202** `requestState` is opaque to clients but not routable by itself. The hub MUST
  wrap upstream `requestState` in its own AEAD-protected envelope containing at minimum:
  upstream id, de-namespaced primitive name, a digest of the salient request parameters, the
  authenticated principal, an issue timestamp and a TTL, plus the original upstream state.
  The hub MUST unwrap and verify the envelope on retry and MUST forward the upstream's
  original state verbatim.
- **HUB-203** The hub MUST reject a `requestState` that fails integrity verification, is
  presented by a different principal, has expired, or does not match the retried method and
  parameters — with a JSON-RPC error, never by silently ignoring it.
- **HUB-204** The hub MUST treat `requestState` and `inputResponses` from clients as
  attacker-controlled input and MUST NOT let them influence routing or authorization outside
  the verified envelope.
- **HUB-205** `inputRequests` keys are upstream-assigned and MUST be preserved verbatim in
  both directions; the hub MUST NOT renumber or merge them.
- **HUB-206** If an upstream returns an `inputRequests` entry of a type the downstream client
  did not declare (`sampling`, `elicitation`, `roots`), the hub MUST NOT forward it. It MUST
  either satisfy the request itself (HUB-125) or fail the call with `-32021`
  (`MissingRequiredClientCapability`) listing the missing capabilities.
- **HUB-207** The hub MUST NOT require the retry to land on the same replica: all state needed
  to route and authorize the retry MUST live in the envelope (HUB-202) or in a shared store.
- **HUB-208** The hub MUST support repeated `input_required` rounds for the same logical
  operation and MUST enforce a configurable maximum round count and total wall-clock budget.
- **HUB-209** MRTR envelopes MUST be single-use where the hub holds a legacy upstream request
  open (§6.3); the hub MUST enforce this server-side, not by TTL alone.

### 1.7 Subscriptions and notifications

- **HUB-221** The hub MUST implement `subscriptions/listen`, accepting the filter fields
  `toolsListChanged`, `promptsListChanged`, `resourcesListChanged`, `resourceSubscriptions`,
  and MUST NOT deliver notification types the client did not request.
- **HUB-222** The hub MUST send `notifications/subscriptions/acknowledged` as the first
  message on the stream, carrying the subscription id in
  `_meta["io.modelcontextprotocol/subscriptionId"]` (the JSON-RPC id of the client's
  `subscriptions/listen` request), reflecting only the subset it will honor.
- **HUB-223** The hub MUST fan the subscription out to the upstreams that own the requested
  resource URIs / primitive types, de-namespacing `resourceSubscriptions` URIs, and MUST
  fan the resulting notifications back in, rewriting `subscriptionId` to the downstream value
  and re-namespacing URIs.
- **HUB-224** The hub MUST support multiple concurrent subscriptions per client and MUST
  demultiplex them correctly on stdio (single channel) and HTTP (one stream per subscription).
- **HUB-225** The hub MUST emit SSE keep-alive comment lines on idle subscription streams at a
  configurable interval (default ≤30 s).
- **HUB-226** On graceful shutdown or upstream teardown, the hub MUST answer the original
  `subscriptions/listen` request with a `resultType: "complete"` result carrying the
  subscription id, then close the stream. An abrupt close MUST NOT be preceded by that result.
- **HUB-227** The hub MUST NOT deliver request-scoped notifications (`notifications/progress`,
  `notifications/message`) on a subscription stream; they MUST flow only on the response
  stream of the request they belong to.
- **HUB-228** The hub MUST NOT emit `notifications/message` for a request that did not carry
  `io.modelcontextprotocol/logLevel`, and MUST filter upstream log notifications to the
  requested level.
- **HUB-229** The hub SHOULD coalesce identical `list_changed` notifications from a single
  upstream within a configurable debounce window, and MUST NOT coalesce
  `notifications/resources/updated` for distinct URIs.

### 1.8 Cancellation, timeouts, progress

- **HUB-241** Closure of a downstream SSE response stream MUST be treated as cancellation of
  that request; the hub MUST stop work and MUST NOT emit further messages for it.
- **HUB-242** The hub MUST propagate cancellation upstream: close the upstream SSE stream
  (HTTP) or send `notifications/cancelled` referencing the upstream request id (stdio).
- **HUB-243** The hub MUST enforce per-method and per-tool timeouts and MUST convert an
  upstream timeout into a JSON-RPC error, never into a silent hang. Long-lived
  `subscriptions/listen` streams MUST be exempt from the request timeout.
- **HUB-244** The hub MUST relay `notifications/progress` from upstream on the correct
  response stream, preserving `progressToken` semantics, and MUST convert a single-JSON
  upstream response into either form as needed.

---

## 2. Authorization requirements

- **HUB-301** The hub MUST act as an OAuth 2.1 resource server: publish
  `/.well-known/oauth-protected-resource` (RFC 9728), return `401` with a `WWW-Authenticate`
  challenge containing `resource_metadata` and `scope`, and accept bearer tokens only in the
  `Authorization` header.
- **HUB-302** The hub MUST validate that the presented token's audience is the hub's own
  canonical URI (RFC 8707). It MUST reject tokens minted for an upstream or any other
  resource.
- **HUB-303** The hub MUST NOT forward the downstream client's access token to any upstream.
  Upstream credentials MUST be obtained independently — token exchange (RFC 8693),
  client-credentials (`io.modelcontextprotocol/…` auth extension), or a static/dynamic secret
  from HashiCorp Vault. Token passthrough is a defect, not a configuration option.
- **HUB-304** The hub MUST support per-upstream credential sources: Vault KV-v2, Vault dynamic
  secrets, Kubernetes ServiceAccount token, static secret ref, and OAuth client credentials,
  with automatic renewal and hot rotation without dropping in-flight requests.
- **HUB-305** The hub MUST map tools/prompts/resources to required scopes via configuration
  and MUST return `403` with `WWW-Authenticate: Bearer error="insufficient_scope",
  scope="…", resource_metadata="…"` naming **all** scopes required for the operation in a
  single challenge.
- **HUB-306** The hub MUST account for scope hierarchies when deciding sufficiency and MUST
  filter `tools/list` (and peers) to the primitives the caller's granted scopes permit.
- **HUB-307** The hub MUST NOT rely on `cacheScope` for access control; per-primitive
  authorization MUST be enforced on every request including cache hits.
- **HUB-308** When the hub itself acts as an OAuth client to an upstream, it MUST send the
  `resource` parameter (RFC 8707) with the upstream's canonical URI, MUST validate a present
  `iss` in authorization responses (RFC 9207) against the recorded issuer without URI
  normalization, and MUST key persisted client credentials by issuer, never reusing them
  across authorization servers.
- **HUB-309** The hub SHOULD support `mTLS` to upstreams with certificates issued by Vault PKI.
- **HUB-310** The hub MUST support a deny-by-default policy engine keyed on (principal,
  upstream, primitive, method) and SHOULD support per-tool `annotations`-independent policy
  (annotations are untrusted input).

---

## 3. Security requirements

- **HUB-401** Tool descriptions, titles, `annotations` and `instructions` from upstreams MUST
  be treated as untrusted content. The hub MUST support per-upstream trust levels and MUST be
  able to strip or flag annotations from untrusted upstreams.
- **HUB-402** The hub MUST detect and act on **tool definition drift** (rug-pull): it MUST
  hash each upstream primitive definition, MUST alert on change, and SHOULD support a mode
  requiring re-approval before a changed definition is served downstream.
- **HUB-403** The hub MUST NOT dereference network `$ref` values in schemas by default. If an
  opt-in mode is offered it MUST enforce a host allowlist, reject loopback/link-local/private
  addresses, apply timeouts and size limits, and log every dereferenced URI. Schemas with
  unresolved external `$ref` MUST be rejected, not treated permissively.
- **HUB-404** The hub MUST bound schema validation cost: maximum schema depth, maximum number
  of subschemas, and a per-validation time budget, to prevent composition-keyword DoS.
- **HUB-405** The hub MUST enforce configurable limits on request body size, SSE event size,
  number of content blocks, total response size, concurrent streams per principal, and
  concurrent upstream connections.
- **HUB-406** The hub MUST NOT proxy or fetch icon URIs with credentials. If it rewrites icon
  URIs it MUST reject non-`https:`/non-`data:` schemes, cross-origin redirects, and MUST
  validate content type by magic bytes against an allowlist.
- **HUB-407** The hub MUST sanitize log output: no access tokens, no `requestState` plaintext,
  no tool arguments marked sensitive by policy. It MUST redact `Mcp-Param-*` values flagged as
  sensitive.
- **HUB-408** The hub MUST emit audit records for every `tools/call`, containing principal,
  upstream, namespaced and de-namespaced tool name, argument digest, decision (allow/deny),
  latency, and result classification (`complete` / `input_required` / error / `isError`).
- **HUB-409** The hub MUST NOT emit error codes in `-32020`…`-32099` other than those defined
  by the specification, and MUST NOT reuse retired codes (`-32002`, `-32042`). New hub-specific
  codes MUST be allocated outside `-32768`…`-32000`.
- **HUB-410** The hub MUST map upstream `-32002` (legacy resource-not-found) to `-32602` when
  serving a modern client.

---

## 4. Operability requirements

- **HUB-501** The hub MUST be horizontally scalable with no sticky routing in modern mode.
  Any replica MUST be able to serve any request, including MRTR retries.
- **HUB-502** Upstream configuration MUST be hot-reloadable without dropping in-flight
  requests or subscription streams, via file watch and (in operator mode) CRD reconciliation.
- **HUB-503** The hub MUST expose a Kubernetes CRD (e.g. `MCPUpstream`) covering: transport
  (`stdio` | `streamable-http`), endpoint/command, protocol era and pinned version, credential
  ref, namespace prefix, allow/deny lists for primitives, timeouts, retry and circuit-breaker
  policy, cache TTL clamps, rate limits, and trust level.
- **HUB-504** The hub MUST health-check upstreams with `server/discover` (modern) or a
  configured probe (legacy), with circuit breaking and exponential backoff, and MUST expose
  per-upstream health in a readiness endpoint and in metrics.
- **HUB-505** The hub MUST expose Prometheus metrics with at least the labels
  `upstream`, `mcp_method`, `mcp_name`, `protocol_version`, `result_type`, `outcome`:
  request rate, latency histogram, in-flight requests, SSE streams open, subscription count,
  MRTR rounds per operation, cache hit ratio, upstream failures, schema-rejection count,
  header-mismatch count, auth failures by class.
- **HUB-506** The hub MUST emit OpenTelemetry spans following the GenAI/MCP semantic
  conventions, with one span per downstream request and child spans per upstream call, linked
  across MRTR rounds by the envelope's operation id.
- **HUB-507** The hub MUST support a dry-run / shadow mode that resolves routing, policy and
  schema validation for a request without invoking the upstream.
- **HUB-508** The hub SHOULD expose an admin/inspection API listing resolved upstreams, the
  effective merged primitive catalogue, namespacing map, and current cache state.
- **HUB-509** Graceful shutdown MUST drain: stop accepting new requests, complete in-flight
  requests within a deadline, close subscriptions per HUB-226, terminate stdio children.

---

## 5. Performance requirements (initial targets, to be validated)

- **HUB-601** Header-only routing decision (no body parse): p99 < 1 ms.
- **HUB-602** Proxy overhead for `tools/call` excluding upstream time: p99 < 10 ms,
  p50 < 2 ms.
- **HUB-603** `tools/list` served from cache: p99 < 5 ms for a merged catalogue of ≥1000 tools
  across ≥50 upstreams.
- **HUB-604** ≥10 000 concurrent open subscription streams per replica at ≤4 GiB RSS.
- **HUB-605** Zero allocation of full-body buffers above a configurable threshold; large tool
  results MUST be streamed, not fully buffered, wherever the hub does not rewrite them.

---

## 6. Backward compatibility (dual-era bridging)

This is the hub's primary near-term value: modern clients against a fleet of legacy servers,
and legacy clients against modern servers.

### 6.1 Legacy upstream, modern downstream

- **HUB-701** The hub MUST be able to speak the legacy era to an upstream: perform
  `initialize` / `notifications/initialized`, hold `Mcp-Session-Id`, open the GET SSE stream,
  and honor `Last-Event-ID` resumption where the upstream supports it.
- **HUB-702** The hub MUST own the legacy session lifecycle per upstream (pooled, not per
  downstream client), including re-initialization after session loss, and MUST NOT expose
  session identity downstream.
- **HUB-703** The hub MUST translate legacy `resources/subscribe` / `resources/unsubscribe`
  semantics into its `subscriptions/listen` fan-out.
- **HUB-704** The hub MUST convert legacy server-initiated requests
  (`sampling/createMessage`, `elicitation/create`, `roots/list`) arriving on an upstream SSE
  stream into an `InputRequiredResult` toward the downstream client, keeping the upstream
  request open, and MUST deliver the client's `inputResponses` back as the JSON-RPC response
  to the original upstream request.
- **HUB-705** Because HUB-704 requires held state, the hub MUST either store it in a shared
  backend (e.g. Redis) keyed by the envelope id, or encode a replica routing hint in the
  envelope. It MUST expire held requests on a configurable deadline and MUST return a
  deterministic error to the client when the held request has expired.
- **HUB-706** The hub MUST translate legacy `-32002` and pre-`resultType` results per HUB-410
  and by injecting `resultType: "complete"`.
- **HUB-707** The hub MUST NOT forward `logging/setLevel`, `ping`, or
  `notifications/roots/list_changed` semantics downstream; it MAY use them upstream where the
  legacy upstream requires them.

### 6.2 Modern upstream, legacy downstream (optional listener mode)

- **HUB-711** A listener MAY be configured for legacy compatibility: accept `initialize`,
  mint `Mcp-Session-Id`, serve GET SSE, and translate the session's negotiated capabilities
  into per-request `_meta` for modern upstreams.
- **HUB-712** In this mode the hub MUST convert modern `InputRequiredResult` into a
  server-initiated request on the legacy client's SSE stream, and MUST retry the upstream
  request with the resulting `inputResponses` and `requestState`.
- **HUB-713** Legacy listeners require session affinity. The hub MUST document this and MUST
  expose the affinity key for ingress configuration; modern listeners MUST NOT be affected.

### 6.3 Era detection

- **HUB-721** For HTTP upstreams the hub MUST attempt a modern request first and MUST inspect
  the body of a `400` before falling back: a recognized modern JSON-RPC error means the
  upstream is modern and the hub MUST retry with a supported version rather than falling back.
- **HUB-722** For stdio upstreams the hub MUST probe with `server/discover` and fall back to
  `initialize` on any non-modern error or timeout.
- **HUB-723** The hub MUST cache the era determination per upstream (process for stdio, origin
  for HTTP), MAY persist it across restarts, and MUST re-probe when the cached assumption
  fails.
- **HUB-724** The hub MUST support pinning the era and protocol version per upstream in
  configuration, bypassing probing.

---

## 7. Extensions (opt-in)

- **HUB-801** The hub MUST advertise supported extensions in the `extensions` map of its
  capabilities using prefixed identifiers, and MUST negotiate them independently per upstream.
- **HUB-802** When a downstream client supports an extension the upstream does not, the hub
  MUST either revert to core behavior or return an error — never silently drop extension
  semantics.
- **HUB-803** `io.modelcontextprotocol/tasks` SHOULD be supported: relay task handles,
  `tasks/get` polling and `tasks/update`, with handle namespacing analogous to HUB-162.
  Unsolicited task handles from an upstream MUST NOT be forwarded to a client that has not
  negotiated the extension.
- **HUB-804** `io.modelcontextprotocol/ui` (MCP Apps) MAY be supported; if HTML resources are
  relayed the hub MUST apply the content limits of HUB-405 and MUST NOT rewrite resource
  content beyond URI namespacing.

---

## 8. Out of scope (v1)

- LLM inference, prompt construction, or any model-side decision making.
- Acting as a general HTTP forward proxy for upstream-declared external URLs.
- Serving as the authorization server (it is a resource server and an OAuth client only).
- Persisting tool results beyond the caching model of §1.5.

---

## 9. Acceptance criteria

The implementation is accepted when, against the mock MCP server described in the companion
document, the following hold:

1. **Statelessness.** A randomized test that round-robins every request of a multi-round
   MRTR flow, a paginated list walk, and a subscription re-establish across ≥3 hub replicas
   with no shared session store passes with zero errors.
2. **Header integrity.** For every request forwarded upstream, the recorded `Mcp-Method`,
   `Mcp-Name` and `Mcp-Param-*` values match the forwarded body, including after
   de-namespacing and for Base64-sentinel values.
3. **No token passthrough.** The mock's request journal contains no downstream access token
   on any upstream request, under every configured credential mode.
4. **MRTR correctness.** Tampered, expired, cross-principal and cross-request `requestState`
   are all rejected; valid flows complete within the configured round limit.
5. **Capability discipline.** With a client declaring no `elicitation`, a mock that returns an
   elicitation input request yields `-32021` downstream and no elicitation reaches the client.
6. **Subscription fan-in.** Notifications from ≥10 upstreams arrive with correct downstream
   `subscriptionId`, namespaced URIs, no unrequested types, and correct graceful-closure
   result on shutdown.
7. **Degraded operation.** With 30 % of upstreams failing, `tools/list` still returns the
   remaining catalogue within the latency target and metrics reflect the degradation.
8. **Era bridging.** The same modern client, unchanged, drives a `2025-11-25` mock and a
   `2026-07-28` mock through identical tool, sampling/elicitation and subscription scenarios.
9. **Conformance.** MCP Inspector (CLI mode) passes against the hub endpoint in CI for every
   supported protocol era.