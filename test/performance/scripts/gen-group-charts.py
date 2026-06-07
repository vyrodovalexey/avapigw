#!/usr/bin/env python3
"""Generate per-group performance charts: latency vs RPS and response codes vs RPS.
Reads MASTER-SUMMARY.json produced by the perf agent run."""
import json, os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RD = sys.argv[1] if len(sys.argv) > 1 else "test/performance/.yandextank/run-20260607"
master = json.load(open(os.path.join(RD, "MASTER-SUMMARY.json")))
CHARTS = os.path.join(RD, "charts")
os.makedirs(CHARTS, exist_ok=True)

def norm(scn):
    """Return list of (name, rps, p50, p95, p99, ok, err) from a group summary."""
    rows = []
    for name, m in scn.items():
        if "rps" in m and m.get("rps") is not None and ("p50_ms" in m or "p50" in m):
            rps = m.get("rps")
            p50 = m.get("p50_ms", m.get("p50"))
            p95 = m.get("p95_ms", m.get("p95"))
            p99 = m.get("p99_ms", m.get("p99"))
            codes = m.get("codes", {})
            ok = codes.get("200", 0)
            tot = sum(codes.values()) or 1
            err = 100.0 * (tot - ok) / tot
            rows.append((name, rps, p50 or 0, p95 or 0, p99 or 0, ok, err))
        elif "count" in m and "status" in m:  # grpc
            rps = m.get("rps")
            ok = m.get("status", {}).get("OK", 0)
            tot = m.get("count", 1)
            err = 100.0 * (tot - ok) / tot
            rows.append((name, rps, m.get("p50") or 0, m.get("p95") or 0, m.get("p99") or 0, ok, err))
    return rows

for g, scn in master.items():
    rows = norm(scn)
    if not rows:
        continue
    rows.sort(key=lambda r: r[1])
    names = [r[0] for r in rows]
    rps = [r[1] for r in rows]
    p50 = [r[2] for r in rows]; p95 = [r[3] for r in rows]; p99 = [r[4] for r in rows]
    err = [r[6] for r in rows]
    x = np.arange(len(names))

    fig, axes = plt.subplots(1, 3, figsize=(20, 6))
    fig.suptitle(f"{g} — Performance (180s/scenario, k8s operator mode)", fontsize=14, weight="bold")

    # 1) Latency percentiles vs scenario (with RPS annotated)
    ax = axes[0]
    w = 0.25
    ax.bar(x - w, p50, w, label="p50", color="#4caf50")
    ax.bar(x, p95, w, label="p95", color="#ff9800")
    ax.bar(x + w, p99, w, label="p99", color="#f44336")
    ax.set_xticks(x); ax.set_xticklabels(names, rotation=40, ha="right", fontsize=8)
    ax.set_ylabel("Latency (ms)"); ax.set_title("Latency percentiles by scenario"); ax.legend()
    ax.grid(axis="y", alpha=0.3)

    # 2) Latency vs RPS scatter
    ax = axes[1]
    sc = ax.scatter(rps, p99, c=err, cmap="RdYlGn_r", s=120, edgecolors="k", vmin=0, vmax=25)
    for i, n in enumerate(names):
        ax.annotate(n, (rps[i], p99[i]), fontsize=7, xytext=(4, 4), textcoords="offset points")
    ax.set_xlabel("Throughput (RPS / streams-s)"); ax.set_ylabel("p99 latency (ms)")
    ax.set_title("p99 Latency vs Throughput (color = error %)")
    ax.grid(alpha=0.3)
    plt.colorbar(sc, ax=ax, label="error %")

    # 3) Response success vs RPS
    ax = axes[2]
    ok_pct = [100 - e for e in err]
    bars = ax.bar(x, ok_pct, color=["#4caf50" if e < 1 else "#ff9800" if e < 10 else "#f44336" for e in err])
    for i, b in enumerate(bars):
        ax.text(b.get_x() + b.get_width()/2, min(ok_pct[i], 98), f"{rps[i]:.0f}rps", ha="center", va="top", fontsize=7, rotation=90)
    ax.set_xticks(x); ax.set_xticklabels(names, rotation=40, ha="right", fontsize=8)
    ax.set_ylabel("Success (2xx/OK) %"); ax.set_ylim(0, 105); ax.set_title("Success rate by scenario (label=RPS)")
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    out = os.path.join(CHARTS, f"{g}.png")
    plt.savefig(out, dpi=130); plt.close()
    print("wrote", out)

# Cross-group throughput overview
fig, ax = plt.subplots(figsize=(14, 7))
for g, scn in master.items():
    rows = norm(scn)
    if not rows: continue
    rps = [r[1] for r in rows]; p99 = [r[4] for r in rows]
    ax.scatter(rps, p99, s=90, alpha=0.75, label=g, edgecolors="k")
ax.set_xlabel("Throughput (RPS / streams-s)"); ax.set_ylabel("p99 latency (ms)")
ax.set_title("All groups: p99 latency vs throughput (180s scenarios)")
ax.legend(); ax.grid(alpha=0.3)
plt.tight_layout()
out = os.path.join(CHARTS, "all-groups-overview.png")
plt.savefig(out, dpi=130); plt.close()
print("wrote", out)
