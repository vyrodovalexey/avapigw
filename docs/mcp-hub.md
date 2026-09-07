# MCP Hub Support

## Overview

The AV API Gateway can operate as a **Model Context Protocol (MCP) hub**. In
this mode the gateway is simultaneously:

- an **MCP server** toward downstream MCP clients, and
- an **MCP client** toward one or more upstream MCP servers,

bridging them over **Streamable HTTP** (`POST /mcp`). The hub fans a single
downstream endpoint out to multiple upstreams, aggregates their capabilities
into one namespaced surface, and enforces the gateway's cross-cutting
middleware (authentication, authorization, rate limiting, caching, CORS,
security headers, TLS) on the MCP path.

The target protocol revision is **`2026-07-28`** (the "modern", stateless,
per-request-metadata era) with HTTP-era bridging to legacy MCP servers that
still use the `initialize` handshake and session model.

> **Scope — HTTP/HTTPS transport only:** this iteration implements the
> Streamable HTTP transport (`streamable-http`) for both the downstream
> listener and upstream connections. **stdio upstreams are NOT supported.**

## Table of Contents

- [Overview](#overview)
- [Implemented Scope](#implemented-scope)
- [Deferred / Not Implemented](#deferred--not-implemented)
- [Architecture](#architecture)
- [Configuration Reference](#configuration-reference)
  - [Global MCP Settings (`spec.mcp`)](#global-mcp-settings-specmcp)
  - [MCPRoute](#mcproute)
    - [Weighted Routing (canary / A-B)](#weighted-routing-canary--ab)
  - [MCPBackend](#mcpbackend)
- [Full Configuration Example](#full-configuration-example)
- [Operator / CRD Usage](#operator--crd-usage)
- [Metrics](#metrics)
- [Known Limitations](#known-limitations)
- [Related Documentation](#related-documentation)

## Implemented Scope

The following HUB-### requirement groups from
[`specifications/mcp-hub-req.md`](../specifications/mcp-hub-req.md) are
implemented in this iteration:

| Area | Requirements | Summary |
| --- | --- | --- |
| Transport / endpoint | HUB-101, HUB-106 | `POST /mcp` Streamable HTTP endpoint, **fail-closed** origin allowlist (present Origin not on the list → `403`), request/response size limits |
| Per-request `_meta` | HUB-121..126 | Construction and validation of `io.modelcontextprotocol/*` metadata (protocol version, server/client info); `MCP-Protocol-Version` header is **required** and must match the `_meta` `protocolVersion` (mismatch/absence → `-32020` / `400`) |
| Header mirroring | HUB-141..148 | `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*` mirroring/validation, header-integrity enforcement, de-namespacing rewrite; header↔body comparison is **case-insensitive** with Base64-sentinel decode and numeric compare for integer parameters |
| Discovery & aggregation | HUB-162, HUB-503 | Capability aggregation across upstreams with per-upstream namespacing, allow/deny primitive filtering |
| Weighted routing | HUB-501, HUB-503 | Per-upstream traffic weights (`weightedUpstreams`) for single-upstream selection (canary / A-B); stateless weighted-random pick; aggregation/subscriptions still full fan-out |
| Caching | HUB-182 | `ttlMs` / `cacheScope` aware result caching with TTL clamps; memory or Redis store |
| MRTR | HUB-203, HUB-207, HUB-208, HUB-209 | Multi Round-Trip Requests via an AEAD-protected `requestState` envelope. Round count and wall-clock budget are enforced **server-side** from a sealed envelope; envelope integrity, principal, expiry, and method/param binding are verified; a **cross-replica single-use nonce store** (in-memory bounded default or Redis `SET NX EX`) makes envelopes single-use and replica-portable |
| Capability discipline | HUB-206 | An upstream `inputRequests` entry of a type the downstream client did not advertise is **not forwarded** — the call fails with `-32021` |
| Subscriptions / notifications | HUB-215, HUB-225 | SSE relay of subscriptions and notifications with idle keep-alives |
| Cancellation / timeouts / progress | HUB-243, HUB-244 | Per-method/per-tool timeouts, cancellation propagation, and `notifications/progress` relayed on the correct SSE response stream for `tools/call` |
| Authorization | HUB-301..310 | OAuth 2.1 resource server (RFC 9728 metadata, RFC 8707 audience), **no token passthrough**, per-upstream credentials (incl. Vault), scope mapping, deny-by-default policy mode |
| Security hardening | HUB-401..405 | Trust levels, description/annotation drift detection, schema bounds, request/response/stream limits, audit |
| Observability | HUB-505 | Prometheus (`avapigw_mcp_*`) + OTLP tracing |
| HTTP-era bridging | HUB-701..707, HUB-721..724 | Era auto-detection/pinning, pooled legacy sessions, held server-initiated requests |

## Deferred / Not Implemented

The following are intentionally **not** delivered in this iteration and are
tracked as follow-ups/roadmap. They are documented here so operators do not
configure or rely on them:

- **stdio upstreams** (HUB-108/722) — only `streamable-http` upstream
  transport is supported.
- **Legacy-downstream listener mode** (HUB-711/712/713) — the hub speaks the
  modern era toward downstream clients; it does not expose a legacy-era
  listener.
- **Extensions** — `io.modelcontextprotocol/tasks` (HUB-803) and
  `io.modelcontextprotocol/ui` / MCP Apps (HUB-804) are not implemented.
- **Admin API** (HUB-508) — there is no runtime MCP administration/inspection
  API for resolved upstreams, catalog, namespace map, or cache; configuration
  is static YAML or operator CRDs.
- **`MCPBackend` host:port cross-check** — `MCPBackend` does not yet have an
  admission webhook cross-checking its `host:port` against Backend /
  GRPCBackend / GraphQLBackend (MCPRoute cross-route checking is implemented;
  see [Operator / CRD Usage](#operator--crd-usage)).
- **MCP Inspector CI conformance** — the Inspector-based end-to-end
  conformance suite is not wired into CI.

## Architecture

```
┌──────────────┐    ┌──────────────────────────────────────────┐    ┌─────────────────┐
│  MCP Client  │    │              AV API Gateway (MCP Hub)      │    │  MCP Upstream A │
│              │    │                                            │    │ (streamable-http)│
│  POST /mcp   │───▶│ ┌────────┐ ┌──────────┐ ┌───────────────┐ │───▶│  POST /mcp      │
│  (JSON-RPC)  │    │ │ Router │ │Middleware│ │  Aggregator /  │ │    └─────────────────┘
│              │◀───│ │ (Mcp-  │ │  Chain   │ │  Broker        │ │    ┌─────────────────┐
│  SSE stream  │    │ │ Method,│ │(authn/z, │ │ (namespacing,  │ │───▶│  MCP Upstream B │
│              │    │ │  Name) │ │ RL,cache)│ │  MRTR, cache)  │ │    │ (streamable-http)│
└──────────────┘    │ └────────┘ └──────────┘ └───────────────┘ │    └─────────────────┘
                    └──────────────────────────────────────────┘
```

**Request flow:**

1. **Routing** — the hub matches the request against `mcpRoutes` using the
   mirrored `Mcp-Method` / `Mcp-Name` headers, path, and HTTP headers.
2. **Middleware chain** — the matched route's authentication, authorization,
   rate limiting, CORS, security headers, caching, and header manipulation are
   applied (the same machinery used for HTTP/GraphQL routes).
3. **`_meta` construction / validation** — per-request
   `io.modelcontextprotocol/*` metadata is built/validated.
4. **Aggregation & namespacing** — for discovery methods (`tools/list`,
   `resources/list`, `prompts/list`), capabilities from all `upstreams` are
   merged with each upstream's `namespacePrefix` + separator applied.
5. **Broker** — invocation methods (`tools/call`, `resources/read`,
   `prompts/get`) are de-namespaced and dispatched to the owning upstream over
   Streamable HTTP, with MRTR, cancellation, and progress handled. An
   owner-agnostic (non-namespaced) request is instead sent to a single upstream
   chosen by [weighted selection](#weighted-routing-canary--ab).
6. **Response** — a single JSON result or an SSE stream is relayed downstream.

> **Hot reload:** the discovery aggregator's upstream resolver refreshes on hot
> reload, so new or changed MCPBackends become visible to `server/discover` and
> list aggregation instead of using a stale boot-time snapshot. The aggregated
> MCP list cache key includes the route's upstream set, so routes with
> different upstream sets never cross-serve cached aggregates.

## Configuration Reference

MCP mode is enabled by adding a listener with `protocol: MCP`, a global `mcp`
settings block, and `mcpRoutes` / `mcpBackends`. Field names below are the
canonical YAML keys derived from
[`internal/config/mcp_config.go`](../internal/config/mcp_config.go) and the
JSON Schema `$defs` in
[`pkg/schema/gateway.schema.json`](../pkg/schema/gateway.schema.json).

### Global MCP Settings (`spec.mcp`)

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | string | `/mcp` | Downstream MCP endpoint path (HUB-101). |
| `maxBodySize` | integer (bytes) | `4194304` (4 MiB) | Max downstream request body size (HUB-405). |
| `maxSSEEventSize` | integer (bytes) | `1048576` (1 MiB) | Max size of a single relayed SSE event (HUB-405). |
| `maxResponseSize` | integer (bytes) | `16777216` (16 MiB) | Max total response size (HUB-405). |
| `maxContentBlocks` | integer | `256` | Max content blocks per result (HUB-405). |
| `maxConcurrentStreamsPerPrincipal` | integer | `256` | Max concurrent streams per authenticated principal (HUB-405). |
| `maxConcurrentUpstreamConns` | integer | `512` | Max concurrent upstream connections (HUB-405). |
| `allowedOrigins` | []string | `[]` (all) | Origin allowlist on the downstream endpoint (HUB-106). |
| `namespaceSep` | string | `.` | Namespacing separator; must be a subset of `A-Za-z0-9_.-` (HUB-162). |
| `subscriptionKeepAlive` | duration | ≤30s | Interval between SSE keep-alive lines on idle subscriptions (HUB-225). |
| `mrtrMaxRounds` | integer | — | Max `input_required` rounds per logical operation, enforced server-side from the sealed envelope (HUB-208). |
| `mrtrBudget` | duration | — | Total wall-clock budget for one MRTR operation, enforced server-side from the sealed envelope (HUB-208). |
| `nonceStoreRedis` | object | in-memory | Optional Redis-backed single-use MRTR nonce store for cross-replica portability (HUB-207); see below. When omitted, an in-memory bounded store is used (single-replica). |
| `cacheTTLMin` | duration | — | Lower clamp for aggregated cache TTLs (HUB-182). |
| `cacheTTLMax` | duration | — | Upper clamp for aggregated cache TTLs (HUB-182). |
| `trustPolicy` | string | `strip` | Handling of untrusted-upstream annotations: `strip` or `flag` (HUB-401). |
| `driftRequireReapproval` | bool | `false` | Exclude a drifted tool from discovery until re-approved (HUB-402). |
| `maxSchemaDepth` | integer | `32` | Max tool schema nesting depth (HUB-404). |
| `maxSubschemas` | integer | `2048` | Max subschema nodes per tool schema (HUB-404). |
| `schemaValidationBudget` | duration | — | Max wall-clock time for a single schema validation (HUB-404). |
| `dryRun` | bool | `false` | Shadow mode: resolve routing/policy/schema without invoking upstream (HUB-507). A per-request `Mcp-Dry-Run: true` header also enables it. |
| `healthCheckInterval` | duration | `0` (disabled) | Period between per-upstream MCP health probes. |
| `eraCacheTTL` | duration | `30m` | How long a per-upstream era determination is trusted before re-probe (HUB-723). |
| `legacySessionIdleTimeout` | duration | `5m` | Idle timeout before a pooled legacy session is eligible for teardown (HUB-702). |
| `heldRequestDeadline` | duration | `2m` | Deadline for a held legacy server-initiated request awaiting the client's `inputResponses` (HUB-705). |
| `oauthResourceServer` | object | — | OAuth 2.1 resource-server surface (see below). |
| `sharedKey` | object | — | Shared AEAD key source for the cursor codec and MRTR envelope (see below). |

**`oauthResourceServer`** (HUB-301/302/310):

| Key | Type | Description |
| --- | --- | --- |
| `canonicalURI` | string | Hub's canonical resource identifier; presented tokens MUST carry it in their audience (RFC 8707) and it is published as `resource` in the RFC 9728 metadata. |
| `authorizationServers` | []string | Issuer URLs of trusted authorization servers (RFC 9728 `authorization_servers`). |
| `scopesSupported` | []string | Scopes advertised in the protected-resource metadata (RFC 9728 `scopes_supported`). |
| `oidcProvider` | string | Configured OIDC provider used to validate token signatures/issuers before the audience check. |
| `policyMode` | bool | Enable the deny-by-default policy engine (HUB-310). |

**`sharedKey`** (HUB-166/207) — used so multi-replica deployments verify each
other's cursor tokens and MRTR envelopes. When omitted, a per-process key is
generated (single-replica dev only) and a WARN is logged.

| Key | Type | Description |
| --- | --- | --- |
| `source` | string | `inline`, `vaultKV`, or `vaultTransit`. |
| `value` | string | Base64-encoded 32-byte key when `source: inline`. |
| `vaultMount` | string | Vault mount for the KV or Transit source. |
| `vaultPath` | string | KV secret path (`vaultKV`) or Transit key name (`vaultTransit`). |
| `vaultField` | string | KV field holding the base64 key (`vaultKV`); default `key`. |

**`nonceStoreRedis`** (HUB-207) — a Redis-backed store that makes MRTR
envelope nonces **single-use across replicas**. Each envelope nonce is
consumed with `SET NX EX` (TTL = envelope TTL), so a replayed or
cross-replica-duplicated `requestState` is rejected on second use. When
omitted, the hub uses an in-memory bounded store (correct for a single
replica only). The block reuses the same Redis / Sentinel connection schema
as the route rate limiter (`rateLimit.redis`), including standalone `url`,
`sentinel` (`masterName`, `sentinelAddrs[]`), TLS, Vault-referenced
passwords, timeouts, and `keyPrefix`:

| Key | Type | Description |
| --- | --- | --- |
| `url` | string | Standalone Redis URL (mutually exclusive with `sentinel`). |
| `sentinel` | object | Redis Sentinel connection: `masterName`, `sentinelAddrs[]`, `password` / `passwordVaultPath`, `sentinelPassword` / `sentinelPasswordVaultPath`, `db`. |
| `poolSize` | integer | Connection pool size. |
| `connectTimeout` / `readTimeout` / `writeTimeout` | duration | Connection and per-operation timeouts. |
| `keyPrefix` | string | Key prefix for stored nonces. |
| `tls` | object | TLS to Redis (same schema as `rateLimit.redis.tls`). |

```yaml
mcp:
  # Single-use MRTR nonce store shared across replicas.
  nonceStoreRedis:
    sentinel:
      masterName: mymaster
      sentinelAddrs:
        - redis-sentinel-0.redis.svc:26379
        - redis-sentinel-1.redis.svc:26379
      sentinelPasswordVaultPath: secret/redis-sentinel
    keyPrefix: "mcp:mrtr:nonce:"
```

### MCPRoute

An `mcpRoute` carries routing-specific fields plus the shared cross-cutting
middleware configuration (identical semantics to HTTP/GraphQL routes).

| Key | Type | Description |
| --- | --- | --- |
| `name` | string (required) | Unique route name. |
| `match` | []object | Match conditions (see below). |
| `upstreams` | []string | `mcpBackend` names this route fans out to (legacy, equal weight). Mutually exclusive with `weightedUpstreams`. |
| `weightedUpstreams` | []object | Weighted `mcpBackend` references (`name` + `weight` 0–100) for single-upstream selection (canary / A-B). Mutually exclusive with `upstreams`. See [Weighted Routing](#weighted-routing-canary--ab). |
| `timeout` | duration | Request timeout. |
| `retries` | object | Retry policy. |
| `headers` | object | Header manipulation. |
| `rateLimit` | object | Route-level rate limiting. |
| `cache` | object | Result caching (memory or Redis). |
| `cors` | object | CORS override. |
| `security` | object | Security headers override. |
| `tls` | object | Route-level TLS override (files or Vault PKI). |
| `authentication` | object | Route-level authentication. |
| `authorization` | object | Route-level authorization. |
| `scopeMap` | map[string][]string | Maps a primitive or method to the OAuth scopes required to invoke it (HUB-305/306). |

**`match`** conditions (derivable from mirrored headers alone, HUB-148):

| Key | Type | Description |
| --- | --- | --- |
| `path` | string-match | Matches the HTTP path of the MCP endpoint. |
| `method` | string | Matches the MCP method (mirrored into `Mcp-Method`). |
| `name` | string-match | Matches the MCP primitive name (mirrored into `Mcp-Name`) for `tools/call`, `resources/read`, `prompts/get`. |
| `headers` | []header-match | Matches HTTP headers. |

#### Weighted Routing (canary / A-B)

A route can split single-upstream selection across upstream MCP servers by
weight, exactly as `apiRoutes[].route[].weight` and GRPCRoute weighted
destinations do. This enables canary and A-B rollouts between MCPBackends
(e.g. a stable server and a canary server) without touching downstream
clients.

Use `weightedUpstreams` — a list of `{ name, weight }` entries (weight
`0`–`100`) — **instead of** `upstreams`. The two forms are **mutually
exclusive**: setting both is a validation/admission error. The legacy
`upstreams: [names]` list still works and is treated as equal weight (a single
upstream when only one name is listed).

```yaml
mcpRoutes:
  - name: mcp-canary
    match:
      - path:
          prefix: /mcp
    # 80% of single-upstream traffic to the stable server, 20% to the canary.
    weightedUpstreams:
      - name: mcp-upstream-stable
        weight: 80
      - name: mcp-upstream-canary
        weight: 20
    timeout: 30s
```

**Semantics** (identical to APIRoute weights):

- **All weights `0`** → traffic is spread **uniformly** across the upstreams.
- **Any positive weight** → zero-weight upstreams receive **no traffic** (a
  true 0% canary).
- Selection is a **stateless weighted-random** pick — any gateway replica
  serves any request with no sticky sessions or shared counters (HUB-501), so
  the split holds across a horizontally scaled deployment.

**Scope — weighting applies only to owner-agnostic single-upstream requests:**

- **Aggregation methods** (`tools/list`, `resources/list`, `prompts/list`,
  `server/discover`) and **subscriptions** always **fan out to ALL** upstreams
  regardless of weight — weights never drop an upstream from discovery.
- A **namespaced primitive** (e.g. `tools/call` for a namespaced tool) still
  **pins to its owning upstream**; weighting only applies when the request is
  not owner-pinned.

**Validation** (enforced by config validation, the MCPRoute admission webhook,
and CRD `kubebuilder` min/max markers):

- each weight is in range `0`–`100`;
- when more than one upstream has a positive weight, the weights must sum to
  `100` (mirrors the APIRoute total-weight expectation);
- setting both `upstreams` and `weightedUpstreams` is rejected;
- mixing zero and positive weights emits a warning (the zero-weight upstreams
  get 0% by design);
- an unknown backend reference (a name not present in `mcpBackends`) is an
  error.

**Observability:** the new counter
`avapigw_mcp_upstream_selected_total{route,upstream}` records each weighted
pick, and the selected upstream is reflected in the `upstream` label on MCP
request metrics, audit events, and spans. In [dry-run](#global-mcp-settings-specmcp)
mode the response lists `candidateUpstreams` with their weights alongside the
sampled `resolvedUpstream`.

Weighted upstreams flow end-to-end through the operator (CRD
`weightedUpstreams` → operator JSON apply → gateway config → weighted
selection) and are verified live (80/20 split via the operator) and under
perf load (70/30 split). See [Operator / CRD Usage](#operator--crd-usage).

### MCPBackend

An `mcpBackend` (aliased `MCPUpstream` in the requirements) describes one
upstream MCP server and reuses the shared backend infrastructure (load
balancing, health checks, connection management, TLS/mTLS, per-backend auth).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string (required) | — | Unique upstream name. |
| `hosts` | []object (required, min 1) | — | Upstream host configurations. |
| `transport` | string | `streamable-http` | Only `streamable-http` is supported this iteration. |
| `era` | string | auto-detect | `modern`, `legacy`, or empty (auto-detect). |
| `pinnedVersion` | string | — | Pin a specific protocol version, bypassing probing (HUB-724). |
| `namespacePrefix` | string | `name` | Prefix applied when namespacing this upstream's primitives (HUB-162). |
| `separator` | string | global `namespaceSep` | Per-upstream namespacing separator; subset of `A-Za-z0-9_.-` (HUB-162). |
| `allow` | []string | all | Allow list restricting exposed primitives (HUB-503). |
| `deny` | []string | none | Deny list excluding primitives (HUB-503). |
| `trustLevel` | string | — | `trusted` or `untrusted` (HUB-401). |
| `path` | string | `/mcp` | Upstream MCP endpoint path. |
| `healthCheck` | object | — | Health check configuration. |
| `loadBalancer` | object | — | Load balancer configuration. |
| `tls` | object | — | Upstream TLS, including Vault PKI mTLS (HUB-309). |
| `circuitBreaker` | object | — | Circuit breaking for this upstream (HUB-504). |
| `credential` | object | — | Independent upstream credential source; the downstream client token is **never** forwarded (HUB-303/304). |
| `timeouts` | object | — | Per-method (`perMethod`) / per-tool (`perTool`) / `default` timeouts (HUB-243). |
| `cacheTTLClamp` | object | — | `min` / `max` clamp for this upstream's aggregated cache TTLs (HUB-182). |
| `rateLimit` | object | — | Rate limiting for this upstream. |

## Full Configuration Example

A gateway config with an MCP listener, one `mcpRoute`, and two `mcpBackends`
(aggregation / fan-out across both upstreams):

```yaml
apiVersion: gateway.avapigw.io/v1
kind: Gateway
metadata:
  name: mcp-hub-gateway
spec:
  listeners:
    - name: mcp
      port: 8080
      protocol: MCP

  # Global MCP hub settings.
  mcp:
    path: /mcp
    namespaceSep: "."
    maxBodySize: 4194304        # 4 MiB
    maxSSEEventSize: 1048576    # 1 MiB
    maxResponseSize: 16777216   # 16 MiB
    allowedOrigins:
      - https://client.example.com
    subscriptionKeepAlive: 25s
    mrtrMaxRounds: 6
    mrtrBudget: 2m
    cacheTTLMin: 5s
    cacheTTLMax: 5m
    trustPolicy: strip
    # OAuth 2.1 resource server (no token passthrough to upstreams).
    oauthResourceServer:
      canonicalURI: https://gw.example.com/mcp
      authorizationServers:
        - https://auth.example.com
      scopesSupported:
        - mcp.tools.read
        - mcp.tools.call
      oidcProvider: primary
      policyMode: true
    # Shared AEAD key so all replicas verify each other's MRTR envelopes.
    sharedKey:
      source: vaultKV
      vaultMount: secret
      vaultPath: avapigw/mcp/shared-key
      vaultField: key

  mcpRoutes:
    - name: mcp-aggregate
      match:
        - path:
            prefix: /mcp
      upstreams:
        - mcp-upstream-a
        - mcp-upstream-b
      timeout: 30s
      # Per-primitive/method scope requirements (HUB-305/306).
      scopeMap:
        "tools/call": ["mcp.tools.call"]
        "tools/list": ["mcp.tools.read"]
      cache:
        enabled: true
        type: memory
        ttl: 30s
      rateLimit:
        enabled: true
        requestsPerSecond: 100
        burst: 200

  mcpBackends:
    - name: mcp-upstream-a
      transport: streamable-http
      path: /mcp
      namespacePrefix: a
      trustLevel: untrusted
      hosts:
        - address: mcp-a.svc.cluster.local
          port: 8080
          weight: 1
      loadBalancer:
        algorithm: roundRobin
      healthCheck:
        path: /healthz
        port: 9090
        interval: 10s
        timeout: 5s
      timeouts:
        default: 20s
        perMethod:
          "tools/call": 30s
      # Independent upstream credential (downstream token is never forwarded).
      # Reuses the shared backend auth config (jwt/basic/mtls).
      credential:
        type: jwt
        jwt:
          enabled: true
          tokenSource: oidc
          oidc:
            issuerUrl: https://auth.example.com
            clientId: gw-mcp-a
            clientSecretVaultPath: secret/data/avapigw/mcp/a
            scopes:
              - mcp.upstream

    - name: mcp-upstream-b
      transport: streamable-http
      path: /mcp
      namespacePrefix: b
      trustLevel: untrusted
      hosts:
        - address: mcp-b.svc.cluster.local
          port: 8080
          weight: 1
      loadBalancer:
        algorithm: roundRobin
      healthCheck:
        path: /healthz
        port: 9090
        interval: 10s
        timeout: 5s
      cacheTTLClamp:
        min: 10s
        max: 2m
```

## Operator / CRD Usage

MCP can be configured entirely through the operator using two CRDs in the
`avapigw.io/v1alpha1` API group:

- **`MCPRoute`** (short name `mcpr`) — mirrors `spec.mcpRoutes[]`.
- **`MCPBackend`** (short name `mcpbe`) — mirrors `spec.mcpBackends[]`.

The operator reconciles these resources and streams the resulting
configuration to the gateway over gRPC (operator mode). The bundled operator
`ClusterRole` grants access to `mcproutes` and `mcpbackends` (plus their
`/status` and `/finalizers` subresources), so no additional RBAC is required.

`MCPRoute` is admitted through a dedicated validating webhook
(`vmcproute.avapigw.io` → `/validate-avapigw-io-v1alpha1-mcproute`) that runs
local spec validation, same-kind duplicate detection, and **cross-route
conflict detection** against APIRoute and GraphQLRoute (checked in both
directions). An MCPRoute whose `spec.match[].path` collides at identical
specificity with an existing APIRoute URI or GraphQLRoute path is rejected,
and vice versa; different-specificity combinations coexist and are admitted.
See [Webhook Validation → MCPRoute Conflicts](operator/webhook-validation.md#mcproute-conflicts).

Apply the CRDs (from `helm/avapigw/crds/`) and the resources with `kubectl`:

```bash
kubectl apply -f helm/avapigw/crds/avapigw.io_mcproutes.yaml
kubectl apply -f helm/avapigw/crds/avapigw.io_mcpbackends.yaml
kubectl apply -f test/k8s/crds-mcp-local.yaml -n avapigw-test
```

Example custom resources — two `MCPBackend`s aggregated by one `MCPRoute`,
mirroring [`test/k8s/crds-mcp-local.yaml`](../test/k8s/crds-mcp-local.yaml):

```yaml
---
# MCPBackend 1
apiVersion: avapigw.io/v1alpha1
kind: MCPBackend
metadata:
  name: mcp-backend-1
  namespace: avapigw-test
spec:
  transport: streamable-http
  path: /mcp
  namespacePrefix: mock1
  trustLevel: untrusted
  hosts:
    - address: host.docker.internal
      port: 8821
      weight: 1
  loadBalancer:
    algorithm: roundRobin
  healthCheck:
    path: /healthz
    port: 9095
    interval: 10s
    timeout: 5s
    healthyThreshold: 2
    unhealthyThreshold: 3

---
# MCPBackend 2 (proves aggregation / fan-out)
apiVersion: avapigw.io/v1alpha1
kind: MCPBackend
metadata:
  name: mcp-backend-2
  namespace: avapigw-test
spec:
  transport: streamable-http
  path: /mcp
  namespacePrefix: mock2
  trustLevel: untrusted
  hosts:
    - address: host.docker.internal
      port: 8822
      weight: 1
  loadBalancer:
    algorithm: roundRobin
  healthCheck:
    path: /healthz
    port: 9096
    interval: 10s
    timeout: 5s
    healthyThreshold: 2
    unhealthyThreshold: 3

---
# MCPRoute - aggregates both backends and carries route-level options
apiVersion: avapigw.io/v1alpha1
kind: MCPRoute
metadata:
  name: mcp-aggregate
  namespace: avapigw-test
spec:
  match:
    - path:
        prefix: /mcp
  upstreams:
    - mcp-backend-1
    - mcp-backend-2
  timeout: 30s
  headers:
    request:
      set:
        X-Gateway: avapigw
    response:
      add:
        X-Processed-By: avapigw-mcp
  cache:
    enabled: true
    type: redis
    ttl: 30s
    redis:
      sentinel:
        masterName: mymaster
        sentinelAddrs:
          - host.docker.internal:26379
          - host.docker.internal:26380
          - host.docker.internal:26381
        password: password
      keyPrefix: "k8s:mcp:"
  rateLimit:
    enabled: true
    requestsPerSecond: 100
    burst: 200
    perClient: false
    store: redis
    redis:
      sentinel:
        masterName: mymaster
        sentinelAddrs:
          - host.docker.internal:26379
          - host.docker.internal:26380
          - host.docker.internal:26381
        password: password
      keyPrefix: "k8s:mcprl:"
      failOpen: true
```

For a canary / A-B split, replace the `upstreams` list with
`weightedUpstreams`. The operator ships the field to the gateway (CRD
`weightedUpstreams` → operator JSON apply → gateway config → weighted
selection), so the split is applied by the data plane on the next reload:

```yaml
apiVersion: avapigw.io/v1alpha1
kind: MCPRoute
metadata:
  name: mcp-canary
  namespace: avapigw-test
spec:
  match:
    - path:
        prefix: /mcp
  # 80% stable / 20% canary single-upstream selection.
  weightedUpstreams:
    - name: mcp-backend-1
      weight: 80
    - name: mcp-backend-2
      weight: 20
  timeout: 30s
```

The admission webhook (`vmcproute.avapigw.io`) applies the same weighted-route
validation as the config loader (range `0`–`100`, sum `100`, `upstreams` /
`weightedUpstreams` mutual exclusivity, unknown-backend rejection). See
[Weighted Routing](#weighted-routing-canary--ab).

## Metrics

The hub emits Prometheus metrics under the `avapigw_mcp_*` namespace/subsystem
(verified against
[`internal/mcp/metrics/metrics.go`](../internal/mcp/metrics/metrics.go)).

**Common label set** for the per-request series
(`requests_total`, `request_duration_seconds`): `upstream`, `mcp_method`,
`mcp_name`, `protocol_version`, `result_type`, `outcome`.

| Metric | Type | Labels |
| --- | --- | --- |
| `avapigw_mcp_requests_total` | counter | `upstream`, `mcp_method`, `mcp_name`, `protocol_version`, `result_type`, `outcome` |
| `avapigw_mcp_request_duration_seconds` | histogram | (same as above) |
| `avapigw_mcp_requests_in_flight` | gauge | `upstream`, `mcp_method` |
| `avapigw_mcp_upstream_selected_total` | counter | `route`, `upstream` (weighted single-upstream pick) |
| `avapigw_mcp_upstream_failures_total` | counter | `upstream`, `mcp_method` |
| `avapigw_mcp_header_mismatch_total` | counter | `mcp_method` |
| `avapigw_mcp_schema_rejection_total` | counter | `mcp_method` |
| `avapigw_mcp_auth_failures_total` | counter | `mcp_method`, `class` |
| `avapigw_mcp_sse_streams_open` | gauge | `upstream` |
| `avapigw_mcp_subscriptions_open` | gauge | `upstream` |
| `avapigw_mcp_mrtr_rounds_total` | counter | `upstream`, `mcp_method` |
| `avapigw_mcp_mrtr_rounds_per_operation` | histogram | `upstream`, `mcp_method` |
| `avapigw_mcp_cache_hits_total` | counter | `upstream`, `mcp_method` |
| `avapigw_mcp_cache_misses_total` | counter | `upstream`, `mcp_method` |
| `avapigw_mcp_drift_detected_total` | counter | `upstream`, `mcp_name` |
| `avapigw_mcp_upstream_healthy` | gauge | `upstream` (1 healthy, 0 degraded) |
| `avapigw_mcp_era_determination_total` | counter | `upstream`, `era` |
| `avapigw_mcp_legacy_sessions_open` | gauge | `upstream` |
| `avapigw_mcp_legacy_session_reinits_total` | counter | `upstream` |
| `avapigw_mcp_held_requests_open` | gauge | `upstream` |
| `avapigw_mcp_held_request_expired_total` | counter | `upstream` |

The `class` label on `avapigw_mcp_auth_failures_total` is bounded to:
`no_token`, `invalid_token`, `audience_mismatch`, `insufficient_scope`,
`policy_denied`, `invalid_retry_state`. The `outcome` label is `success` or
`error`; `era` is `modern` or `legacy`.

## Known Limitations

- **stdio upstreams are not supported** — only `streamable-http` upstreams.
- **Reference `mcp-mock-server` `_meta` mismatch (mock limitation, not a
  gateway defect):** the Phase 1 reference
  `ghcr.io/vyrodovalexey/mcp-mock-server` only accepts **bare** `_meta` keys,
  whereas the gateway is spec-correct and emits vendored
  `io.modelcontextprotocol/*` `_meta` keys (per revision `2026-07-28`). As a
  result, an end-to-end `tools/call` against that mock fails at the terminal
  handshake and the hub returns **HTTP 502**. Discovery/aggregation and the
  cross-cutting middleware path (routing, rate limit, cache, header
  manipulation) still exercise correctly against the mock; only the terminal
  `tools/call` round-trip is affected. This is a limitation of the mock, not
  of the gateway.
- See [Deferred / Not Implemented](#deferred--not-implemented) for features
  that are out of scope this iteration.

## Related Documentation

- [Configuration Reference](configuration-reference.md)
- [CRD Reference](crd-reference.md)
- [Metrics Reference](metrics.md)
- [Aggregate (Fan-out) Mirroring Guide](aggregate-mirroring.md)
- [Vault PKI Integration Guide](vault-pki-integration.md)
- [Performance Testing Guide](performance-testing.md)
- [MCP Hub Requirements](../specifications/mcp-hub-req.md)
</content>
</invoke>
