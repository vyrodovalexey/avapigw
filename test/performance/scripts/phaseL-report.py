#!/usr/bin/env python3
"""phaseL-report.py <results_dir>

Parse all Phase L scenario outputs (hey .txt, ghz .json, k6 ws .json) + VM
metric snapshots, emit a machine-readable summary.json, a markdown report, and
charts:
  - latency_vs_rps.png       (p50/p95/p99 latency vs achieved RPS per scenario)
  - response_codes_vs_rps.png(2xx/4xx/5xx stacked vs RPS per sub-scenario)
  - mcp_metrics.png          (MCP requests/failures + rate-limit denials)
"""
import sys, os, re, json, glob

RD = sys.argv[1]
CHARTS = os.path.join(RD, "charts")
os.makedirs(CHARTS, exist_ok=True)

SCEN_ORDER = [
    ("s1-grpc", "1. gRPC & streaming (mTLS + OIDC)"),
    ("s2-grpc-tls", "2. TLS gRPC & streaming (mTLS + OIDC)"),
    ("s3-http", "3. HTTP & WS (auth/RL/transform/encoding/cache/CORS/OpenAPI)"),
    ("s4-https", "4. HTTPS & WSS (same feature stack over TLS)"),
    ("s5-graphql", "5. GraphQL & WS (auth/RL/transform/CORS)"),
    ("s6-graphql-tls", "6. TLS GraphQL & WSS"),
    ("s7-mcp", "7. MCP (OIDC + sentinel rate limit)"),
    ("s8-mcp-tls", "8. TLS MCP (OIDC + sentinel rate limit)"),
]


def parse_hey(p):
    t = open(p).read()

    def num(rx):
        m = re.search(rx, t)
        return float(m.group(1)) if m else None
    rps = num(r'Requests/sec:\s+([\d.]+)')
    p50 = num(r'\n\s+50%%?\s+in\s+([\d.]+)\s+secs')
    p95 = num(r'\n\s+95%%?\s+in\s+([\d.]+)\s+secs')
    p99 = num(r'\n\s+99%%?\s+in\s+([\d.]+)\s+secs')
    avg = num(r'Average:\s+([\d.]+)\s+secs')
    codes = {}
    for m in re.finditer(r'\[(\d{3})\]\s+(\d+)\s+responses', t):
        codes[m.group(1)] = int(m.group(2))
    total = sum(codes.values())
    err = sum(v for k, v in codes.items() if k[0] in "45")
    return {
        "tool": "hey", "rps": round(rps) if rps else None,
        "avg_ms": round(avg * 1000, 2) if avg else None,
        "p50_ms": round(p50 * 1000, 2) if p50 else None,
        "p95_ms": round(p95 * 1000, 2) if p95 else None,
        "p99_ms": round(p99 * 1000, 2) if p99 else None,
        "codes": codes, "total": total,
        "error_rate_pct": round(100 * err / total, 3) if total else None,
    }


def parse_ghz(p):
    d = json.load(open(p))
    dist = d.get("latencyDistribution") or []

    def pct(x):
        for e in dist:
            if e.get("percentage") == x:
                return round(e["latency"] / 1e6, 2)
        return None
    status = d.get("statusCodeDistribution", {}) or {}
    total = d.get("count") or sum(status.values())
    ok = status.get("OK", 0)
    err = total - ok
    return {
        "tool": "ghz", "rps": round(d.get("rps") or 0), "count": total,
        "avg_ms": round((d.get("average") or 0) / 1e6, 2),
        "p50_ms": pct(50), "p95_ms": pct(95), "p99_ms": pct(99),
        "status": status,
        "error_rate_pct": round(100 * err / total, 3) if total else None,
    }


def load_vm(scen):
    b = f"{RD}/{scen}/vm_{scen}_before.json"
    a = f"{RD}/{scen}/vm_{scen}_after.json"
    if not (os.path.exists(b) and os.path.exists(a)):
        return None
    B, A = json.load(open(b)), json.load(open(a))
    out = {}
    for k in A:
        bx, ax = B.get(k), A.get(k)
        # Treat an absent/None "before" as 0 so first-appearance counters
        # (e.g. avapigw_mcp_* which did not exist before the first MCP run)
        # still produce a meaningful delta.
        bnum = bx if isinstance(bx, (int, float)) else 0
        if isinstance(ax, (int, float)):
            out[k] = {"before": bx, "after": ax, "delta": round(ax - bnum, 2)}
        else:
            out[k] = {"before": bx, "after": ax}
    return out


summary = {}
for scen, title in SCEN_ORDER:
    d = os.path.join(RD, scen)
    if not os.path.isdir(d):
        continue
    sub = {}
    for f in sorted(glob.glob(os.path.join(d, "*.txt"))):
        name = os.path.splitext(os.path.basename(f))[0]
        if name.endswith("_elapsed"):
            continue
        try:
            sub[name] = parse_hey(f)
        except Exception:
            pass
    for f in sorted(glob.glob(os.path.join(d, "*.json"))):
        name = os.path.splitext(os.path.basename(f))[0]
        if name.startswith("vm_") or name == "summary":
            continue
        try:
            j = json.load(open(f))
            if "rps" in j and "latencyDistribution" in j:
                sub[name] = parse_ghz(f)
            elif "msgs_per_sec_recv" in j:
                sub[name] = {"tool": "k6-ws", **j}
        except Exception:
            pass
    el = os.path.join(d, f"{scen}_elapsed.txt")
    elapsed = None
    if os.path.exists(el):
        m = re.search(r'(\d+)', open(el).read())
        elapsed = int(m.group(1)) if m else None
    summary[scen] = {
        "title": title, "elapsed_seconds": elapsed,
        "scenarios": sub, "vm_metrics": load_vm(scen),
    }

json.dump(summary, open(os.path.join(RD, "summary.json"), "w"), indent=2)
print("wrote", os.path.join(RD, "summary.json"))

# ---------------------------------------------------------------- charts
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# Chart 1: latency (p50/p95/p99) vs RPS per sub-scenario (grouped by scenario)
labels, p50s, p95s, p99s, rpss = [], [], [], [], []
for scen, title in SCEN_ORDER:
    if scen not in summary:
        continue
    for name, r in summary[scen]["scenarios"].items():
        if r.get("tool") == "k6-ws":
            continue
        if r.get("p99_ms") is None:
            continue
        labels.append(f"{scen.split('-')[0]}/{name}")
        p50s.append(r.get("p50_ms") or 0)
        p95s.append(r.get("p95_ms") or 0)
        p99s.append(r.get("p99_ms") or 0)
        rpss.append(r.get("rps") or 0)

if labels:
    x = np.arange(len(labels))
    fig, ax1 = plt.subplots(figsize=(max(14, len(labels) * 0.5), 7))
    w = 0.25
    ax1.bar(x - w, p50s, w, label="p50 ms", color="#4c9f70")
    ax1.bar(x, p95s, w, label="p95 ms", color="#f0a202")
    ax1.bar(x + w, p99s, w, label="p99 ms", color="#d1495b")
    ax1.set_ylabel("latency (ms)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=75, ha="right", fontsize=7)
    ax1.set_title("Phase L: latency percentiles per sub-scenario (bars) vs achieved RPS (line)")
    ax2 = ax1.twinx()
    ax2.plot(x, rpss, "o-", color="#1b1b3a", label="RPS")
    ax2.set_ylabel("achieved RPS")
    ax1.legend(loc="upper left")
    ax2.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(os.path.join(CHARTS, "latency_vs_rps.png"), dpi=130)
    plt.close(fig)
    print("wrote latency_vs_rps.png")

# Chart 2: response codes (2xx/4xx/5xx) vs RPS per sub-scenario
labels2, c2xx, c4xx, c5xx, rps2 = [], [], [], [], []
for scen, title in SCEN_ORDER:
    if scen not in summary:
        continue
    for name, r in summary[scen]["scenarios"].items():
        codes = r.get("codes") or {}
        status = r.get("status") or {}
        if codes:
            two = sum(v for k, v in codes.items() if k[0] == "2")
            four = sum(v for k, v in codes.items() if k[0] == "4")
            five = sum(v for k, v in codes.items() if k[0] == "5")
        elif status:
            two = status.get("OK", 0)
            four = 0
            five = sum(v for k, v in status.items() if k != "OK")
        else:
            continue
        labels2.append(f"{scen.split('-')[0]}/{name}")
        c2xx.append(two)
        c4xx.append(four)
        c5xx.append(five)
        rps2.append(r.get("rps") or 0)

if labels2:
    x = np.arange(len(labels2))
    fig, ax1 = plt.subplots(figsize=(max(14, len(labels2) * 0.5), 7))
    ax1.bar(x, c2xx, label="2xx/OK", color="#2a9d8f")
    ax1.bar(x, c4xx, bottom=c2xx, label="4xx (incl. deliberate 429)", color="#e9c46a")
    ax1.bar(x, np.array(c4xx) + np.array(c2xx), color="none")
    ax1.bar(x, c5xx, bottom=np.array(c2xx) + np.array(c4xx),
            label="5xx (MCP=expected mock 502)", color="#e76f51")
    ax1.set_ylabel("responses (count)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels2, rotation=75, ha="right", fontsize=7)
    ax1.set_title("Phase L: response codes per sub-scenario (stacked) vs achieved RPS (line)")
    ax2 = ax1.twinx()
    ax2.plot(x, rps2, "o-", color="#1b1b3a", label="RPS")
    ax2.set_ylabel("achieved RPS")
    ax1.legend(loc="upper left")
    ax2.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(os.path.join(CHARTS, "response_codes_vs_rps.png"), dpi=130)
    plt.close(fig)
    print("wrote response_codes_vs_rps.png")

# Chart 3: MCP metrics
mcp = {}
for scen in ("s7-mcp", "s8-mcp-tls"):
    if scen in summary and summary[scen].get("vm_metrics"):
        vm = summary[scen]["vm_metrics"]
        mcp[scen] = {
            "mcp_requests": (vm.get("mcp_requests_total") or {}).get("delta"),
            "mcp_upstream_failures": (vm.get("mcp_upstream_failures") or {}).get("delta"),
            "redis_rl_denied": (vm.get("redis_rl_denied") or {}).get("delta"),
        }
if mcp:
    scens = list(mcp.keys())
    x = np.arange(len(scens))
    w = 0.27
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(x - w, [mcp[s]["mcp_requests"] or 0 for s in scens], w, label="avapigw_mcp_requests_total Δ", color="#264653")
    ax.bar(x, [mcp[s]["mcp_upstream_failures"] or 0 for s in scens], w, label="avapigw_mcp_upstream_failures_total Δ", color="#e76f51")
    ax.bar(x + w, [mcp[s]["redis_rl_denied"] or 0 for s in scens], w, label="redis sentinel rate-limit denied Δ", color="#e9c46a")
    ax.set_xticks(x)
    ax.set_xticklabels(scens)
    ax.set_ylabel("counter delta during 180s run")
    ax.set_title("Phase L: MCP gateway metrics (VictoriaMetrics deltas)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(CHARTS, "mcp_metrics.png"), dpi=130)
    plt.close(fig)
    print("wrote mcp_metrics.png")
