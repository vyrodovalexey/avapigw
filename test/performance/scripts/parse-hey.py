#!/usr/bin/env python3
"""Parse hey .txt outputs in a directory into summary.json. Handles hey's '50%%' format."""
import json, os, sys, glob, re
od = sys.argv[1]
out = {}
def parse_hey(p):
    t = open(p).read()
    def num(rx):
        m = re.search(rx, t); return float(m.group(1)) if m else None
    # hey prints "  50%% in 0.0154 secs"
    def pct(p):
        m = re.search(r'\n\s+%d%%+\s+in\s+([\d.]+)\s+secs' % p, t)
        return round(float(m.group(1))*1000, 2) if m else None
    codes = {}
    for m in re.finditer(r'\[(\d{3})\]\s+(\d+)\s+responses', t):
        codes[m.group(1)] = int(m.group(2))
    return {"rps": round(num(r'Requests/sec:\s+([\d.]+)') or 0),
            "avg_ms": round((num(r'Average:\s+([\d.]+)\s+secs') or 0)*1000, 2),
            "p50_ms": pct(50), "p95_ms": pct(95), "p99_ms": pct(99),
            "codes": codes}
for f in sorted(glob.glob(os.path.join(od, "*.txt"))):
    out[os.path.splitext(os.path.basename(f))[0]] = parse_hey(f)
for f in sorted(glob.glob(os.path.join(od, "ws*.json"))):
    name = os.path.splitext(os.path.basename(f))[0]
    try: out[name] = json.load(open(f))
    except Exception: pass
json.dump(out, open(os.path.join(od, "summary.json"), "w"), indent=2)
for k, v in out.items():
    if 'rps' in v:
        print(f"  {k}: rps={v['rps']} p50={v.get('p50_ms')} p95={v.get('p95_ms')} p99={v.get('p99_ms')} codes={v.get('codes')}")
    else:
        print(f"  {k}: sessions={v.get('sessions')} recv={v.get('messages_received')} errs={v.get('connection_errors')}")
