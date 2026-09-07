#!/usr/bin/env python3
"""phaseL-vmsnap.py - snapshot a curated set of avapigw gateway metrics from
VictoriaMetrics into a JSON file, scoped to the perf gateway instance
(job="avapigw-gateway"). Usage: phaseL-vmsnap.py <VM_URL> <out.json>
"""
import sys, json, urllib.request, urllib.parse

vm, out = sys.argv[1], sys.argv[2]
J = '{job="avapigw-gateway"}'
queries = {
    # canonical HTTP/route traffic
    "route_requests_total": f"sum(gateway_route_requests_total{J})",
    "route_req_by_code": f"sum by (status_code) (gateway_route_requests_total{J})",
    "route_p50": f"histogram_quantile(0.50, sum(rate(gateway_route_request_duration_seconds_bucket{J}[1m])) by (le))",
    "route_p95": f"histogram_quantile(0.95, sum(rate(gateway_route_request_duration_seconds_bucket{J}[1m])) by (le))",
    "route_p99": f"histogram_quantile(0.99, sum(rate(gateway_route_request_duration_seconds_bucket{J}[1m])) by (le))",
    "backend_requests_total": f"sum(gateway_backend_requests_total{J})",
    # auth
    "auth_successes": f"sum(gateway_route_auth_successes_total{J})",
    "auth_failures": f"sum(gateway_route_auth_failures_total{J})",
    # cache (redis sentinel)
    "cache_hits": f"sum(gateway_route_cache_hits_total{J})",
    "cache_misses": f"sum(gateway_route_cache_misses_total{J})",
    # rate limiting (redis sentinel)
    "route_ratelimit_hits": f"sum(gateway_route_ratelimit_hits_total{J})",
    "redis_rl_allowed": f"sum(gateway_middleware_redis_rate_limit_allowed_total{J})",
    "redis_rl_denied": f"sum(gateway_middleware_redis_rate_limit_denied_total{J})",
    # transform / encoding / cors
    "transform_count": f"sum(gateway_transform_operations_total{J})",
    "encoding_count": f"sum(gateway_encoding_encode_total{J})",
    "cors_count": f"sum(gateway_middleware_cors_requests_total{J})",
    # openapi validation
    "openapi_validation_requests": f"sum(gateway_openapi_validation_requests_total{J})",
    "openapi_validation_errors": f"sum(gateway_openapi_validation_errors_total{J})",
    # grpc streaming
    "grpc_stream_count": f"sum(gateway_grpc_stream_duration_seconds_count{J})",
    "grpc_stream_active": f"sum(gateway_grpc_stream_active{J})",
    "grpc_stream_msgs_sent": f"sum(gateway_grpc_stream_messages_sent_total{J})",
    # websocket
    "ws_connections": f"sum(gateway_ws_connections_total{J})",
    "ws_connections_active": f"sum(gateway_ws_connections_active{J})",
    # tls
    "tls_handshake_count": f"sum(gateway_tls_handshake_duration_seconds_count{J})",
    # graphql
    "graphql_requests": f"sum(avapigw_graphql_requests_total{J})",
    # MCP (scenarios 7/8)
    "mcp_requests_total": f"sum(avapigw_mcp_requests_total{J})",
    "mcp_requests_by_outcome": f"sum by (outcome) (avapigw_mcp_requests_total{J})",
    "mcp_in_flight": f"sum(avapigw_mcp_in_flight{J})",
    "mcp_upstream_failures": f"sum(avapigw_mcp_upstream_failures_total{J})",
    "mcp_auth_failures": f"sum(avapigw_mcp_auth_failures_total{J})",
    "mcp_duration_count": f"sum(avapigw_mcp_request_duration_seconds_count{J})",
    "up": 'up{job="avapigw-gateway"}',
}
res = {}
for k, q in queries.items():
    try:
        u = vm + "/api/v1/query?query=" + urllib.parse.quote(q)
        d = json.load(urllib.request.urlopen(u, timeout=10))
        r = d.get("data", {}).get("result", [])
        if not r:
            res[k] = None
        elif len(r) == 1 and "sum by" not in q and "by (" not in q:
            res[k] = float(r[0]["value"][1])
        else:
            # multi-series: keep label->value map
            m = {}
            for x in r:
                lbl = x["metric"]
                key = lbl.get("status_code") or lbl.get("outcome") or lbl.get("instance") or json.dumps(lbl)
                m[key] = float(x["value"][1])
            res[k] = m
    except Exception as e:
        res[k] = f"ERR:{e}"
json.dump(res, open(out, "w"), indent=2)
print(json.dumps({k: res[k] for k in ("route_requests_total", "mcp_requests_total", "up") if k in res}))
