# Aggregate (Fan-out) Mirroring

## Overview

Aggregate (fan-out) mirroring fans a **single client request out to multiple
backends in parallel**, collects every backend response, and returns a **single
aggregated response** to the client. It is fully wired for **unary** traffic:
REST, GraphQL (POST/unary), and gRPC unary. gRPC streaming and WebSocket (WS)
aggregate are documented follow-ups (see
[Per-Protocol Support](#per-protocol-support) for the exact status).

Aggregate mirroring is **additive and distinct** from the existing
single-destination `mirror` configuration. The two solve different problems:

| Aspect | `mirror` (single-destination) | `aggregate` (fan-out) |
|---|---|---|
| Destinations | One shadow destination | One or more targets (>= 1) |
| Timing | Asynchronous, fire-and-forget | Synchronous, part of the request path |
| Response | Discarded (shadow only) | Aggregated and returned to the client |
| Client impact | None (best-effort copy) | Client waits for the aggregate result |
| Typical use | Shadow testing, traffic copy | Scatter/gather, response composition |

The single-destination `mirror` config (`{ destination, percentage }`) is
unchanged and continues to work exactly as before. You may use both on the same
route.

## Per-Protocol Support

Aggregate fan-out is wired into the data plane for **unary** protocols today.
Streaming protocols are a documented follow-up. The current support matrix is:

| Protocol | Status | Behavior |
|---|---|---|
| **REST unary** | Supported | Parallel fan-out; JSON merge (`deep`/`shallow`/`replace`) when feasible, else labeled envelope. |
| **GraphQL (POST/unary)** | Supported | `data` is deep-merged across targets; `errors[]` are concatenated; `extensions` is deep-merged. |
| **gRPC unary** | Supported | Parallel fan-out via the connection pool; descriptor-based JSON merge when feasible, else labeled-envelope / last-wins. Per-target mTLS and OIDC/basic/JWT auth are honored. Emits `gateway_aggregate_*` metrics and spans. |
| **gRPC streaming** | **Not supported yet** | A streaming method with `aggregate.enabled=true` returns gRPC status `Unimplemented` ("gRPC streaming aggregate not supported"). Documented follow-up. |
| **WebSocket (WS/WSS)** | **Not wired yet** | Framed-interleave primitives exist in the engine (`StreamMux`, `Frame`, `FrameSink`), but WebSocket aggregate is not yet wired into the gateway entrypoint. Documented follow-up. |

Until the streaming data plane is wired, the framed-interleave behavior and
`perMessageMerge` described under
[Streaming and WebSocket Semantics](#streaming-and-websocket-semantics) describe
the **engine-level** primitives and intended semantics; they are not yet active
on the gRPC streaming or WebSocket data paths.

## Table of Contents

- [Per-Protocol Support](#per-protocol-support)
- [How It Works](#how-it-works)
- [Merging Responses](#merging-responses)
- [Labeled Envelope](#labeled-envelope)
- [Streaming and WebSocket Semantics](#streaming-and-websocket-semantics)
- [Redis Spool](#redis-spool)
- [Configuration Reference](#configuration-reference)
- [Per-Protocol Examples](#per-protocol-examples)
- [Observability](#observability)
- [Failure Modes and Edge Cases](#failure-modes-and-edge-cases)

## How It Works

1. **Parallel fan-out.** The engine invokes every configured target
   concurrently. Concurrency is bounded by `maxParallel` (default `8`); the
   bound is clamped to the number of targets.
2. **Per-target context and timeout.** Each target runs under its own
   `context.WithTimeout`, using the target `timeout` (default `30s`). A slow or
   hung target cannot block the others; its deadline fires independently.
3. **Retry with exponential backoff.** Transient failures (transport errors and
   `5xx`-style status codes) are retried up to the per-target `retries` count
   using exponential backoff. Permanent failures are not retried.
4. **Result collection under FailMode.** Responses are collected in stable
   target order. The configured `failMode` decides whether the aggregate
   request as a whole succeeds:

   | `failMode` | Success threshold |
   |---|---|
   | `all` (default) | Every target must succeed. |
   | `any` | At least one target must succeed. |
   | `quorum` | A quorum must succeed: `quorumCount` when set, otherwise a simple majority (`len(targets)/2 + 1`). |

5. **Cancellation.** When the client disconnects or the parent context is
   canceled, all in-flight target invocations are canceled and the engine tears
   down cleanly with no goroutine leaks.

If the success threshold is not met, the aggregate fails; partial per-target
errors are always recorded in metrics and (where the protocol allows) surfaced
in the response.

## Merging Responses

Merging is **optional**. When `merge.enabled` is `true` and all successful
responses are JSON objects or arrays, the engine merges them into a single JSON
document using the shared response merger.

| Strategy | Behavior |
|---|---|
| `deep` (default) | Recursively merge nested objects; later targets overlay earlier ones. |
| `shallow` | Merge only top-level keys. |
| `replace` | Last non-nil value wins. |

Arrays are **concatenated** across targets under all strategies.

Merging applies to unary JSON traffic: **REST**, **GraphQL** (POST/unary), and
**gRPC unary** when the message is JSON-mappable.

GraphQL responses are merged with GraphQL-aware semantics:

- `data` is deep-merged across targets.
- `errors` arrays are concatenated.
- `extensions` is deep-merged.
- A target whose body cannot be parsed contributes a synthetic entry to
  `errors[]` (carrying `extensions.target`) so partial failures remain visible.

If `merge.enabled` is `false`, or any successful body is non-JSON, or the merge
fails, the engine falls back to the **labeled envelope** (no error is raised).

## Labeled Envelope

When merging is disabled or not applicable, the aggregated body is a JSON array
of labeled envelopes, one per successful target:

```json
[
  { "target": "backend-a", "status": 200, "payload": { "id": 1 } },
  { "target": "backend-b", "status": 200, "payload": { "id": 2 } }
]
```

Each envelope carries:

- `target` - the configured target `name`.
- `status` - the protocol status code (HTTP status, gRPC code, etc.).
- `payload` - the raw response body when it is valid JSON, otherwise the body
  encoded as a JSON string so the envelope stays valid JSON.

The aggregated content type is always `application/json`.

## Streaming and WebSocket Semantics

> **Status.** The semantics in this section describe the **engine-level**
> streaming primitives and the intended design. They are **not yet wired** into
> the gateway data plane: a gRPC streaming method with aggregate enabled returns
> `Unimplemented` ("gRPC streaming aggregate not supported"), and WebSocket
> aggregate is not yet injected at the gateway entrypoint. Both are documented
> follow-ups. See [Per-Protocol Support](#per-protocol-support).

Streaming traffic cannot be merged into one document, so the default behavior is
**framed labeled interleave (passthrough)**. Each upstream message is wrapped in
a labeled frame and forwarded to the client as it arrives, interleaved across
all targets:

```json
{ "target": "backend-a", "status": 200, "payload": { "event": "tick", "n": 1 } }
```

A `Frame` has the same JSON shape as the unary envelope:
`{ "target", "status", "payload" }`.

Key properties:

- **Backpressure.** Each frame write blocks the producing goroutine until the
  client transport accepts it.
- **Independent streams.** One target's stream error does not abort the others;
  the configured `failMode` still governs the overall outcome.
- **Clean teardown.** A client disconnect cancels every upstream stream with no
  goroutine leaks.

Set `perMessageMerge: true` to opt in to per-message JSON merge for streaming
traffic where a correlation key is present. When it is not enabled (the
default), streaming traffic is passed through as labeled framed interleave.

This applies to **WebSocket** and **gRPC server/bidirectional streaming**.
GraphQL subscriptions (which run over WebSocket) use the same streaming path.

## Redis Spool

For large response bodies or a high target fan-out, partial responses can be
**spooled off-heap to Redis** instead of being held in memory. Spooling is
**optional** and defaults to in-memory buffering.

- Enable with `spool.enabled: true` and `spool.backend: redis`.
- Only bodies at or above `spool.thresholdBytes` (default `1048576` = 1 MiB)
  are written off-heap; smaller bodies stay in memory.
- Spool keys are namespaced (`avapigw:aggregate:spool:`), hashed, and given a
  TTL (`spool.ttl`, default `5m`, with jitter to avoid synchronized expiry).
  Keys are deleted when the aggregation completes.
- **Standalone and Sentinel** Redis are both supported via `spool.redisRef`.
  `address` and `sentinel` are mutually exclusive.
- The Redis password may be supplied inline (`password`) or resolved from Vault
  (`passwordVaultPath`, format `mount/path`).

**Memory fallback.** When spooling is disabled, the body is below the threshold,
or Redis is unavailable, the engine falls back to in-memory buffering and the
request still succeeds. Spool write/read failures are counted in metrics and
logged, but never fail the aggregate request.

## Configuration Reference

The aggregate block attaches to a route under `aggregate` (file mode) or
`spec.aggregate` (operator/CRD mode). The field names are identical in both
modes.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable aggregate fan-out for the route. |
| `targets[]` | list | - | Fan-out backends (>= 1 required). |
| `targets[].name` | string | - | Unique, stable label (metrics/tracing/envelope). Required. |
| `targets[].destination.host` | string | - | Backend host. Required. |
| `targets[].destination.port` | int | - | Backend port (1-65535). Required. |
| `targets[].timeout` | duration | `30s` | Per-target request timeout. |
| `targets[].retries` | int | `0` | Max retries for transient errors (0-10). |
| `targets[].tls` | object | - | Per-target TLS (including mTLS). |
| `targets[].authentication` | object | - | Per-target backend auth (basic/JWT/OIDC/mTLS; Vault refs supported). |
| `merge.enabled` | bool | `false` | Enable response merging (else labeled envelope). |
| `merge.strategy` | enum | `deep` | `deep` \| `shallow` \| `replace`. |
| `spool.enabled` | bool | `false` | Enable off-heap spooling. |
| `spool.backend` | enum | `memory` | `memory` \| `redis`. |
| `spool.thresholdBytes` | int | `1048576` | Spool only bodies >= this size. |
| `spool.ttl` | duration | `5m` | Lifetime of spooled entries. |
| `spool.redisRef.address` | string | - | Standalone Redis `host:port` (mutually exclusive with `sentinel`). |
| `spool.redisRef.db` | int | `0` | Redis database number (0-15). |
| `spool.redisRef.password` | string | - | Redis password (prefer `passwordVaultPath`). |
| `spool.redisRef.passwordVaultPath` | string | - | Vault path resolving the Redis password (`mount/path`). |
| `spool.redisRef.sentinel` | object | - | Redis Sentinel connection (mutually exclusive with `address`). |
| `failMode` | enum | `all` | `all` \| `any` \| `quorum`. |
| `quorumCount` | int | `0` | Explicit quorum threshold (0 = simple majority). |
| `maxParallel` | int | `8` | Bound on concurrent target invocations (1-1024). |
| `perMessageMerge` | bool | `false` | Per-message JSON merge for streaming traffic. |

### Sentinel sub-fields

`spool.redisRef.sentinel` uses the standard Redis Sentinel fields:
`masterName`, `sentinelAddrs[]`, `sentinelPassword`, `password`, `db`,
`passwordVaultPath`, `sentinelPasswordVaultPath`.

### Environment variable overrides

Two values honor environment overrides (ENV takes priority over file/flag):

| Variable | Overrides |
|---|---|
| `AVAPIGW_AGGREGATE_MAX_PARALLEL` | `maxParallel` |
| `AVAPIGW_AGGREGATE_SPOOL_THRESHOLD_BYTES` | `spool.thresholdBytes` |

## Per-Protocol Examples

Each example is shown in both **file mode** (gateway YAML config) and
**operator mode** (CRD). The CRDs use the `avapigw.io/v1alpha1` API group.

### REST (merge)

File mode:

```yaml
routes:
  - name: rest-aggregate
    match:
      - uri:
          prefix: /api/aggregate
    aggregate:
      enabled: true
      failMode: all
      maxParallel: 8
      merge:
        enabled: true
        strategy: deep
      targets:
        - name: backend-a
          destination:
            host: backend-a.default.svc.cluster.local
            port: 8080
          timeout: 30s
          retries: 1
        - name: backend-b
          destination:
            host: backend-b.default.svc.cluster.local
            port: 8080
```

Operator mode:

```yaml
apiVersion: avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: rest-aggregate
spec:
  match:
    - uri:
        prefix: /api/aggregate
  aggregate:
    enabled: true
    failMode: all
    maxParallel: 8
    merge:
      enabled: true
      strategy: deep
    targets:
      - name: backend-a
        destination:
          host: backend-a.default.svc.cluster.local
          port: 8080
        timeout: 30s
        retries: 1
      - name: backend-b
        destination:
          host: backend-b.default.svc.cluster.local
          port: 8080
```

### WebSocket (framed interleave, optional per-message merge)

> **Status.** WebSocket aggregate is **not yet wired** into the gateway data
> plane (the framed-interleave primitives exist in the engine but are not
> injected at the gateway entrypoint). The example below documents the intended
> configuration shape for the upcoming follow-up. See
> [Per-Protocol Support](#per-protocol-support).

File mode:

```yaml
routes:
  - name: ws-aggregate
    match:
      - uri:
          prefix: /ws/aggregate
    aggregate:
      enabled: true
      failMode: any
      perMessageMerge: false   # default: labeled framed interleave (passthrough)
      targets:
        - name: stream-a
          destination:
            host: stream-a.default.svc.cluster.local
            port: 9090
        - name: stream-b
          destination:
            host: stream-b.default.svc.cluster.local
            port: 9090
```

Operator mode:

```yaml
apiVersion: avapigw.io/v1alpha1
kind: APIRoute
metadata:
  name: ws-aggregate
spec:
  match:
    - uri:
        prefix: /ws/aggregate
  aggregate:
    enabled: true
    failMode: any
    perMessageMerge: false
    targets:
      - name: stream-a
        destination:
          host: stream-a.default.svc.cluster.local
          port: 9090
      - name: stream-b
        destination:
          host: stream-b.default.svc.cluster.local
          port: 9090
```

### GraphQL (data merge + errors concat)

File mode:

```yaml
graphqlRoutes:
  - name: graphql-aggregate
    match:
      - uri:
          prefix: /graphql
    aggregate:
      enabled: true
      failMode: all
      merge:
        enabled: true
        strategy: deep   # data is deep-merged; errors are concatenated
      targets:
        - name: graphql-a
          destination:
            host: graphql-a.default.svc.cluster.local
            port: 8080
        - name: graphql-b
          destination:
            host: graphql-b.default.svc.cluster.local
            port: 8080
```

Operator mode:

```yaml
apiVersion: avapigw.io/v1alpha1
kind: GraphQLRoute
metadata:
  name: graphql-aggregate
spec:
  match:
    - uri:
        prefix: /graphql
  aggregate:
    enabled: true
    failMode: all
    merge:
      enabled: true
      strategy: deep
    targets:
      - name: graphql-a
        destination:
          host: graphql-a.default.svc.cluster.local
          port: 8080
      - name: graphql-b
        destination:
          host: graphql-b.default.svc.cluster.local
          port: 8080
```

### gRPC unary (per-target mTLS + OIDC, Redis spool)

> **Note.** Aggregate fan-out is supported for gRPC **unary** methods only. The
> matched unary request is fanned out to every target in parallel over the
> connection pool (honoring per-target mTLS and OIDC/basic/JWT auth) and the
> responses are merged (descriptor-based JSON merge when feasible, else
> labeled-envelope / last-wins). If a **streaming** method is matched with
> `aggregate.enabled=true`, the call is rejected with gRPC status `Unimplemented`
> ("gRPC streaming aggregate not supported") - see the gRPC streaming example
> below.

File mode:

```yaml
grpcRoutes:
  - name: grpc-aggregate
    match:
      - service: example.UserService
    aggregate:
      enabled: true
      failMode: quorum
      quorumCount: 2
      maxParallel: 16
      targets:
        - name: grpc-a
          destination:
            host: grpc-a.default.svc.cluster.local
            port: 9000
          tls:
            enabled: true
            mode: MUTUAL
            caFile: /etc/certs/ca.pem
            certFile: /etc/certs/client.pem
            keyFile: /etc/certs/client-key.pem
        - name: grpc-b
          destination:
            host: grpc-b.default.svc.cluster.local
            port: 9000
          authentication:
            type: jwt
            jwt:
              enabled: true
              tokenSource: oidc
              oidc:
                issuerUrl: https://keycloak.example.com/realms/avapigw
                clientId: avapigw
                clientSecretVaultPath: secret/avapigw/oidc
      spool:
        enabled: true
        backend: redis
        thresholdBytes: 1048576
        ttl: 5m
        redisRef:
          address: redis.default.svc.cluster.local:6379
          db: 0
          passwordVaultPath: secret/avapigw/redis
```

Operator mode:

```yaml
apiVersion: avapigw.io/v1alpha1
kind: GRPCRoute
metadata:
  name: grpc-aggregate
spec:
  match:
    - service: example.UserService
  aggregate:
    enabled: true
    failMode: quorum
    quorumCount: 2
    maxParallel: 16
    targets:
      - name: grpc-a
        destination:
          host: grpc-a.default.svc.cluster.local
          port: 9000
        tls:
          enabled: true
          mode: MUTUAL
          caFile: /etc/certs/ca.pem
          certFile: /etc/certs/client.pem
          keyFile: /etc/certs/client-key.pem
      - name: grpc-b
        destination:
          host: grpc-b.default.svc.cluster.local
          port: 9000
        authentication:
          type: jwt
          jwt:
            enabled: true
            tokenSource: oidc
            oidc:
              issuerUrl: https://keycloak.example.com/realms/avapigw
              clientId: avapigw
              clientSecretVaultPath: secret/avapigw/oidc
    spool:
      enabled: true
      backend: redis
      thresholdBytes: 1048576
      ttl: 5m
      redisRef:
        address: redis.default.svc.cluster.local:6379
        db: 0
        passwordVaultPath: secret/avapigw/redis
```

### gRPC streaming (framed interleave, Redis Sentinel spool)

> **Status.** gRPC streaming aggregate is **not supported yet**. A streaming
> method matched with `aggregate.enabled=true` returns gRPC status
> `Unimplemented` ("gRPC streaming aggregate not supported"). The
> framed-interleave / Redis-spool configuration below documents the intended
> shape for the upcoming follow-up; it is not yet active on the streaming data
> path. See [Per-Protocol Support](#per-protocol-support).

File mode:

```yaml
grpcRoutes:
  - name: grpc-stream-aggregate
    match:
      - service: example.EventService
    aggregate:
      enabled: true
      failMode: any
      perMessageMerge: false
      targets:
        - name: events-a
          destination:
            host: events-a.default.svc.cluster.local
            port: 9000
        - name: events-b
          destination:
            host: events-b.default.svc.cluster.local
            port: 9000
      spool:
        enabled: true
        backend: redis
        thresholdBytes: 2097152
        redisRef:
          sentinel:
            masterName: mymaster
            sentinelAddrs:
              - sentinel-0.default.svc.cluster.local:26379
              - sentinel-1.default.svc.cluster.local:26379
            passwordVaultPath: secret/avapigw/redis
```

Operator mode:

```yaml
apiVersion: avapigw.io/v1alpha1
kind: GRPCRoute
metadata:
  name: grpc-stream-aggregate
spec:
  match:
    - service: example.EventService
  aggregate:
    enabled: true
    failMode: any
    perMessageMerge: false
    targets:
      - name: events-a
        destination:
          host: events-a.default.svc.cluster.local
          port: 9000
      - name: events-b
        destination:
          host: events-b.default.svc.cluster.local
          port: 9000
    spool:
      enabled: true
      backend: redis
      thresholdBytes: 2097152
      redisRef:
        sentinel:
          masterName: mymaster
          sentinelAddrs:
            - sentinel-0.default.svc.cluster.local:26379
            - sentinel-1.default.svc.cluster.local:26379
          passwordVaultPath: secret/avapigw/redis
```

## Observability

### Metrics

The engine exposes the following Prometheus metrics (namespace `gateway`,
subsystem `aggregate`). Label cardinality is intentionally bounded to the
aggregate-level `result` label and the operator-controlled `target` name label.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `gateway_aggregate_requests_total` | counter | - | Total aggregate fan-out requests. |
| `gateway_aggregate_targets_total` | counter | - | Total target invocations across all aggregate requests. |
| `gateway_aggregate_target_errors_total` | counter | `target` | Failed target invocations, by target. |
| `gateway_aggregate_results_total` | counter | `result` | Aggregate results by outcome (`success` / `failure`). |
| `gateway_aggregate_duration_seconds` | histogram | - | End-to-end fan-out duration. |
| `gateway_aggregate_merge_duration_seconds` | histogram | - | Response merge duration. |
| `gateway_aggregate_spool_bytes` | histogram | - | Size in bytes of responses spooled off-heap. |
| `gateway_aggregate_spool_errors_total` | counter | - | Total spool errors (write/read/cleanup). |

### Tracing

OpenTelemetry spans are emitted for each stage and nest under the fan-out span:

| Span | Scope |
|---|---|
| `aggregate.fanout` | The overall fan-out for one request. |
| `aggregate.target` | A single target invocation (child of `aggregate.fanout`). |
| `aggregate.merge` | The merge (or GraphQL merge) step. |

### Grafana dashboard

The bundled gateway dashboard (`monitoring/grafana/gateway-dashboard.json`)
includes an **"Aggregate (Fan-out) Mirroring"** row that visualizes the
aggregate request rate, per-target invocations and errors, fan-out and merge
duration percentiles, results breakdown, and spool bytes/errors.

## Failure Modes and Edge Cases

| Case | Behavior |
|---|---|
| **Empty targets** | Rejected by config and operator webhook validation (>= 1 target required); the engine returns `ErrNoTargets`. |
| **Partial failure** | The outcome follows `failMode` (`all` / `any` / `quorum`). Per-target errors are counted in `gateway_aggregate_target_errors_total` and surfaced where the protocol allows (e.g. GraphQL `errors[]`). |
| **Target timeout** | Each target has its own `context.WithTimeout`; a timed-out target is marked failed while the others continue. |
| **Transient error** | Retried with exponential backoff up to `retries`; permanent errors are not retried. |
| **Huge bodies / many targets** | Bodies at or above `spool.thresholdBytes` spool to Redis (when enabled); concurrency is bounded by `maxParallel`. |
| **Non-JSON body** | The engine falls back to the labeled envelope; no merge is attempted and no error is raised. |
| **Merge conflict** (type mismatch) | Deterministic, source-wins behavior per the configured strategy. |
| **Redis outage** | The engine degrades to the in-memory fallback; the request still succeeds and the spool error is counted. |
| **Per-target mTLS / OIDC** | Each target carries its own `tls` and `authentication`; sensitive values may reference Vault. |
| **gRPC streaming with aggregate enabled** | Not supported yet: the call is rejected with gRPC status `Unimplemented` ("gRPC streaming aggregate not supported"). Documented follow-up. |
| **WebSocket with aggregate enabled** | Not wired yet: the framed-interleave primitives exist in the engine but are not injected at the gateway entrypoint. Documented follow-up. |

## See Also

- [CRD Reference](crd-reference.md)
- [Configuration Reference](configuration-reference.md)
- [GraphQL Gateway](graphql.md)
- [Vault PKI Integration](vault-pki-integration.md)
