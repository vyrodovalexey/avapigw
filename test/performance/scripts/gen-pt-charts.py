#!/usr/bin/env python3
"""Generate PT-01..06 charts from a pt-suite output dir.

Produces, under <dir>/charts/:
  - PT-NN_latency.png        : p50/p95/p99 per scenario (latency vs scenario)
  - PT-NN_codes.png          : 2xx / 4xx(429) / 5xx per scenario (answers vs load)
  - overview_throughput.png  : summed RPS per group
  - overview_aggregate.png   : aggregate fan-out Δ per group (mirroring)
Usage: gen-pt-charts.py <pt-suite-dir>
"""
import json, os, sys, glob, re
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

d = sys.argv[1]
cdir = os.path.join(d, "charts")
os.makedirs(cdir, exist_ok=True)

def load(p):
    try: return json.load(open(p))
    except Exception: return {}

def hey_pcts(txt):
    if not os.path.exists(txt): return (None, None, None)
    t = open(txt).read()
    def pct(p):
        m = re.search(rf'\n\s+{p}%+\s+in\s+([\d.]+)\s+secs', t)
        return round(float(m.group(1))*1000, 2) if m else None
    return pct(50), pct(95), pct(99)

GRPC = {"01", "02"}
DESC = {"01":"PT-01 gRPC+stream","02":"PT-02 TLS gRPC+stream+mirror",
        "03":"PT-03 HTTP+WS","04":"PT-04 HTTPS+WSS+mirror",
        "05":"PT-05 GraphQL+WS","06":"PT-06 TLS GraphQL+WSS+mirror"}

group_rps = {}
group_agg = {}

for pt in ["01","02","03","04","05","06"]:
    s = load(os.path.join(d, f"PT-{pt}", "summary.json"))
    if not s: continue
    names, p50s, p95s, p99s = [], [], [], []
    c2, c4, c5 = [], [], []
    cnames = []
    rps_sum = 0
    for name, v in sorted(s.items()):
        if not isinstance(v, dict): continue
        if pt in GRPC:
            if "rps" not in v: continue
            rps_sum += v.get("rps", 0) or 0
            names.append(name)
            p50s.append(v.get("p50") or 0); p95s.append(v.get("p95") or 0); p99s.append(v.get("p99") or 0)
            st = v.get("status", {}) or {}
            ok = st.get("OK", 0)
            rl = st.get("ResourceExhausted", 0)
            err = sum(x for k,x in st.items() if k not in ("OK","ResourceExhausted") and isinstance(x,int))
            cnames.append(name); c2.append(ok); c4.append(rl); c5.append(err)
        else:
            if v.get("rps") is None: continue
            rps_sum += v.get("rps", 0) or 0
            p50, p95, p99 = v.get("p50_ms"), v.get("p95_ms"), v.get("p99_ms")
            if p50 is None:
                p50, p95, p99 = hey_pcts(os.path.join(d, f"PT-{pt}", name + ".txt"))
            names.append(name)
            p50s.append(p50 or 0); p95s.append(p95 or 0); p99s.append(p99 or 0)
            codes = v.get("codes", {}) or {}
            ok = sum(n for c,n in codes.items() if c.startswith("2"))
            rl = codes.get("429", 0)
            c5v = sum(n for c,n in codes.items() if c.startswith("5"))
            cnames.append(name); c2.append(ok); c4.append(rl); c5.append(c5v)
    group_rps[pt] = round(rps_sum)
    vb = load(os.path.join(d, f"vm_PT-{pt}_before.json"))
    va = load(os.path.join(d, f"vm_PT-{pt}_after.json"))
    try:
        group_agg[pt] = (va.get("aggregate_requests_total") or 0) - (vb.get("aggregate_requests_total") or 0)
    except Exception:
        group_agg[pt] = 0

    # latency chart
    if names:
        x = np.arange(len(names)); w = 0.25
        fig, ax = plt.subplots(figsize=(max(7, len(names)*1.1), 4.5))
        ax.bar(x - w, p50s, w, label="p50", color="#4C9F70")
        ax.bar(x, p95s, w, label="p95", color="#E1A140")
        ax.bar(x + w, p99s, w, label="p99", color="#C0504D")
        ax.set_title(f"{DESC[pt]} — latency per scenario (ms)")
        ax.set_ylabel("latency (ms)"); ax.set_xticks(x); ax.set_xticklabels(names, rotation=30, ha="right")
        ax.legend(); ax.grid(axis="y", alpha=0.3)
        fig.tight_layout(); fig.savefig(os.path.join(cdir, f"PT-{pt}_latency.png"), dpi=130); plt.close(fig)

    # codes chart
    if cnames:
        x = np.arange(len(cnames))
        fig, ax = plt.subplots(figsize=(max(7, len(cnames)*1.1), 4.5))
        ax.bar(x, c2, label="2xx/OK", color="#4C9F70")
        ax.bar(x, c4, bottom=c2, label="429/ratelimit", color="#E1A140")
        bottom2 = [a+b for a,b in zip(c2,c4)]
        ax.bar(x, c5, bottom=bottom2, label="5xx/err", color="#C0504D")
        ax.set_title(f"{DESC[pt]} — responses per scenario")
        ax.set_ylabel("responses"); ax.set_xticks(x); ax.set_xticklabels(cnames, rotation=30, ha="right")
        ax.legend(); ax.grid(axis="y", alpha=0.3)
        fig.tight_layout(); fig.savefig(os.path.join(cdir, f"PT-{pt}_codes.png"), dpi=130); plt.close(fig)

# overview throughput
if group_rps:
    pts = sorted(group_rps); vals = [group_rps[p] for p in pts]
    fig, ax = plt.subplots(figsize=(8,4.5))
    ax.bar([f"PT-{p}" for p in pts], vals, color="#3B6EA5")
    for i,v in enumerate(vals): ax.text(i, v, str(v), ha="center", va="bottom")
    ax.set_title("Throughput per group — summed RPS across concurrent scenarios")
    ax.set_ylabel("RPS (sum)"); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(os.path.join(cdir, "overview_throughput.png"), dpi=130); plt.close(fig)

# overview aggregate mirroring
if group_agg:
    pts = sorted(group_agg); vals = [group_agg[p] for p in pts]
    fig, ax = plt.subplots(figsize=(8,4.5))
    colors = ["#C0504D" if v==0 else "#4C9F70" for v in vals]
    ax.bar([f"PT-{p}" for p in pts], vals, color=colors)
    for i,v in enumerate(vals): ax.text(i, v, str(int(v)), ha="center", va="bottom")
    ax.set_title("Aggregate fan-out (mirroring) Δ requests per group")
    ax.set_ylabel("gateway_aggregate_requests_total Δ"); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(os.path.join(cdir, "overview_aggregate.png"), dpi=130); plt.close(fig)

print("charts written to", cdir)
print("\n".join(sorted(os.path.basename(p) for p in glob.glob(os.path.join(cdir, "*.png")))))
