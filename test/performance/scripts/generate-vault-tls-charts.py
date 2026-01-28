#!/usr/bin/env python3
"""
generate-vault-tls-charts.py - Vault PKI TLS Performance Chart Generator

Generates specialized charts for Vault PKI TLS performance tests:
- Latency vs RPS comparison (Vault vs file-based)
- Response code distribution vs RPS
- Certificate renewal impact analysis (latency over time)
- Multi-route SNI performance comparison

Usage:
    ./generate-vault-tls-charts.py <results-dir> [options]
    ./generate-vault-tls-charts.py --compare <vault-dir> <baseline-dir>
    ./generate-vault-tls-charts.py --renewal <renewal-results-dir>

Options:
    --output=<dir>      Output directory for charts (default: results-dir/charts)
    --format=<fmt>      Output format: png, svg, both (default: png)
    --compare           Compare Vault vs file-based TLS results
    --renewal           Generate certificate renewal analysis charts
    --all               Generate all chart types

Examples:
    ./generate-vault-tls-charts.py results/vault-tls-handshake_20260127/
    ./generate-vault-tls-charts.py --compare results/vault-tls/ results/file-tls/
    ./generate-vault-tls-charts.py --renewal results/vault-cert-renewal_20260127/
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    from matplotlib.ticker import FuncFormatter
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not installed. Install with: pip install matplotlib")

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


def parse_phout(phout_file: str) -> Dict[str, List]:
    """Parse Yandex Tank phout.txt file."""
    data = {
        'timestamps': [],
        'latencies': [],
        'connect_times': [],
        'send_times': [],
        'proto_codes': [],
        'net_codes': [],
        'sizes': [],
    }

    with open(phout_file, 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 12:
                try:
                    data['timestamps'].append(float(parts[0]))
                    data['latencies'].append(float(parts[3]) / 1000)  # us to ms
                    data['connect_times'].append(float(parts[4]) / 1000)
                    data['send_times'].append(float(parts[5]) / 1000)
                    data['proto_codes'].append(int(parts[11]))
                    data['net_codes'].append(int(parts[10]))
                    if len(parts) > 9:
                        data['sizes'].append(int(parts[9]))
                except (ValueError, IndexError):
                    continue

    return data


def calculate_percentiles(values: List[float], percentiles: List[int] = None) -> Dict[str, float]:
    """Calculate percentiles from a list of values."""
    if percentiles is None:
        percentiles = [50, 90, 95, 99]

    if not values:
        return {f'p{p}': 0 for p in percentiles}

    if HAS_NUMPY:
        return {f'p{p}': float(np.percentile(values, p)) for p in percentiles}

    sorted_values = sorted(values)
    n = len(sorted_values)
    result = {}
    for p in percentiles:
        idx = int(n * p / 100)
        result[f'p{p}'] = sorted_values[min(idx, n - 1)]
    return result


def calculate_rps_over_time(timestamps: List[float], bucket_size: int = 1) -> Tuple[List[float], List[float]]:
    """Calculate RPS over time with given bucket size in seconds."""
    if not timestamps:
        return [], []

    min_ts = min(timestamps)
    buckets = {}
    for ts in timestamps:
        bucket = int((ts - min_ts) / bucket_size)
        buckets[bucket] = buckets.get(bucket, 0) + 1

    times = []
    rps = []
    for bucket in sorted(buckets.keys()):
        times.append(bucket * bucket_size)
        rps.append(buckets[bucket] / bucket_size)

    return times, rps


def calculate_latency_over_time(timestamps: List[float], latencies: List[float],
                                 bucket_size: int = 5) -> Dict[str, Tuple[List[float], List[float]]]:
    """Calculate latency percentiles over time."""
    if not timestamps or not latencies:
        return {}

    min_ts = min(timestamps)
    buckets = {}
    for ts, lat in zip(timestamps, latencies):
        bucket = int((ts - min_ts) / bucket_size)
        if bucket not in buckets:
            buckets[bucket] = []
        buckets[bucket].append(lat)

    result = {'p50': ([], []), 'p95': ([], []), 'p99': ([], []), 'avg': ([], [])}

    for bucket in sorted(buckets.keys()):
        t = bucket * bucket_size
        vals = buckets[bucket]
        percs = calculate_percentiles(vals, [50, 95, 99])

        result['p50'][0].append(t)
        result['p50'][1].append(percs['p50'])
        result['p95'][0].append(t)
        result['p95'][1].append(percs['p95'])
        result['p99'][0].append(t)
        result['p99'][1].append(percs['p99'])
        result['avg'][0].append(t)
        result['avg'][1].append(sum(vals) / len(vals))

    return result


def calculate_error_rate_over_time(timestamps: List[float], proto_codes: List[float],
                                    bucket_size: int = 5) -> Dict[str, Tuple[List[float], List[float]]]:
    """Calculate error rates over time."""
    if not timestamps or not proto_codes:
        return {}

    min_ts = min(timestamps)
    buckets = {}
    for ts, code in zip(timestamps, proto_codes):
        bucket = int((ts - min_ts) / bucket_size)
        if bucket not in buckets:
            buckets[bucket] = {'total': 0, '2xx': 0, '4xx': 0, '5xx': 0}
        buckets[bucket]['total'] += 1
        if 200 <= code < 300:
            buckets[bucket]['2xx'] += 1
        elif 400 <= code < 500:
            buckets[bucket]['4xx'] += 1
        elif 500 <= code < 600:
            buckets[bucket]['5xx'] += 1

    result = {'2xx': ([], []), '4xx': ([], []), '5xx': ([], [])}

    for bucket in sorted(buckets.keys()):
        t = bucket * bucket_size
        total = buckets[bucket]['total']
        if total > 0:
            for code_class in ['2xx', '4xx', '5xx']:
                result[code_class][0].append(t)
                result[code_class][1].append(buckets[bucket][code_class] / total * 100)

    return result


def find_phout_file(results_dir: str) -> Optional[str]:
    """Find phout file in results directory."""
    results_path = Path(results_dir)
    phout_files = list(results_path.glob('**/phout*.log')) + list(results_path.glob('**/phout*.txt'))
    if phout_files:
        return str(phout_files[0])
    return None


def generate_latency_vs_rps_chart(data: Dict, output_file: str,
                                   title: str = "Latency vs RPS - Vault TLS"):
    """Generate latency depends on RPS chart."""
    if not HAS_MATPLOTLIB:
        return

    timestamps = data.get('timestamps', [])
    latencies = data.get('latencies', [])
    if not timestamps or not latencies:
        return

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10), sharex=True)

    # Calculate RPS and latency over time
    times, rps = calculate_rps_over_time(timestamps, bucket_size=5)
    lat_over_time = calculate_latency_over_time(timestamps, latencies, bucket_size=5)

    # Top: RPS over time
    ax1.plot(times, rps, color='#3498db', linewidth=1.5, label='RPS')
    ax1.fill_between(times, rps, alpha=0.2, color='#3498db')
    ax1.set_ylabel('Requests/Second', fontsize=12)
    ax1.set_title(title, fontsize=14, fontweight='bold')
    ax1.grid(True, alpha=0.3)
    ax1.legend(loc='upper left')

    # Bottom: Latency percentiles over time
    colors = {'p50': '#2ecc71', 'p95': '#f39c12', 'p99': '#e74c3c', 'avg': '#9b59b6'}
    for label, (t, v) in lat_over_time.items():
        ax2.plot(t, v, color=colors.get(label, '#333'), linewidth=1.5, label=label, alpha=0.8)

    ax2.set_xlabel('Time (seconds)', fontsize=12)
    ax2.set_ylabel('Latency (ms)', fontsize=12)
    ax2.grid(True, alpha=0.3)
    ax2.legend(loc='upper left')

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def generate_response_codes_vs_rps_chart(data: Dict, output_file: str,
                                          title: str = "Response Codes vs RPS - Vault TLS"):
    """Generate response code distribution depends on RPS chart."""
    if not HAS_MATPLOTLIB:
        return

    timestamps = data.get('timestamps', [])
    proto_codes = data.get('proto_codes', [])
    if not timestamps or not proto_codes:
        return

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10), sharex=True)

    # Top: RPS over time
    times, rps = calculate_rps_over_time(timestamps, bucket_size=5)
    ax1.plot(times, rps, color='#3498db', linewidth=1.5, label='RPS')
    ax1.fill_between(times, rps, alpha=0.2, color='#3498db')
    ax1.set_ylabel('Requests/Second', fontsize=12)
    ax1.set_title(title, fontsize=14, fontweight='bold')
    ax1.grid(True, alpha=0.3)
    ax1.legend(loc='upper left')

    # Bottom: Error rates over time
    error_rates = calculate_error_rate_over_time(timestamps, proto_codes, bucket_size=5)
    colors = {'2xx': '#2ecc71', '4xx': '#f39c12', '5xx': '#e74c3c'}

    for code_class, (t, v) in error_rates.items():
        ax2.plot(t, v, color=colors.get(code_class, '#333'), linewidth=1.5,
                 label=f'{code_class} %', alpha=0.8)

    ax2.set_xlabel('Time (seconds)', fontsize=12)
    ax2.set_ylabel('Response Rate (%)', fontsize=12)
    ax2.set_ylim(-5, 105)
    ax2.grid(True, alpha=0.3)
    ax2.legend(loc='upper right')

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def generate_renewal_analysis_chart(data: Dict, output_file: str,
                                     title: str = "Certificate Renewal Impact Analysis"):
    """Generate certificate renewal analysis chart showing latency stability."""
    if not HAS_MATPLOTLIB:
        return

    timestamps = data.get('timestamps', [])
    latencies = data.get('latencies', [])
    proto_codes = data.get('proto_codes', [])
    if not timestamps or not latencies:
        return

    fig = plt.figure(figsize=(16, 14))
    gs = gridspec.GridSpec(3, 2, hspace=0.35, wspace=0.3)

    # 1. Latency over time with renewal markers (top, full width)
    ax1 = fig.add_subplot(gs[0, :])
    lat_over_time = calculate_latency_over_time(timestamps, latencies, bucket_size=2)

    colors = {'p50': '#2ecc71', 'p95': '#f39c12', 'p99': '#e74c3c', 'avg': '#9b59b6'}
    for label, (t, v) in lat_over_time.items():
        ax1.plot(t, v, color=colors.get(label, '#333'), linewidth=1.5, label=label, alpha=0.8)

    # Add renewal markers (every ~60s for TTL=2m, renewBefore=1m)
    if timestamps:
        test_duration = max(timestamps) - min(timestamps)
        renewal_interval = 60  # seconds (TTL - renewBefore)
        renewal_time = renewal_interval
        while renewal_time < test_duration:
            ax1.axvline(x=renewal_time, color='blue', linestyle='--', alpha=0.4, linewidth=1)
            ax1.annotate(f'Renewal\n~{int(renewal_time)}s', xy=(renewal_time, ax1.get_ylim()[1] * 0.85),
                        fontsize=8, color='blue', ha='center', alpha=0.7)
            renewal_time += renewal_interval

    ax1.set_xlabel('Time (seconds)', fontsize=11)
    ax1.set_ylabel('Latency (ms)', fontsize=11)
    ax1.set_title('Latency Over Time (with cert renewal markers)', fontsize=12, fontweight='bold')
    ax1.grid(True, alpha=0.3)
    ax1.legend(loc='upper right')

    # 2. RPS stability (middle left)
    ax2 = fig.add_subplot(gs[1, 0])
    times, rps = calculate_rps_over_time(timestamps, bucket_size=2)
    ax2.plot(times, rps, color='#3498db', linewidth=1.5)
    ax2.fill_between(times, rps, alpha=0.2, color='#3498db')
    avg_rps = sum(rps) / len(rps) if rps else 0
    ax2.axhline(y=avg_rps, color='red', linestyle='--', alpha=0.7, label=f'Avg: {avg_rps:.0f}')
    ax2.set_xlabel('Time (seconds)')
    ax2.set_ylabel('RPS')
    ax2.set_title('Throughput Stability During Renewals')
    ax2.grid(True, alpha=0.3)
    ax2.legend()

    # 3. Error rate over time (middle right)
    ax3 = fig.add_subplot(gs[1, 1])
    error_rates = calculate_error_rate_over_time(timestamps, proto_codes, bucket_size=2)
    err_colors = {'2xx': '#2ecc71', '4xx': '#f39c12', '5xx': '#e74c3c'}
    for code_class, (t, v) in error_rates.items():
        ax3.plot(t, v, color=err_colors.get(code_class, '#333'), linewidth=1.5,
                 label=f'{code_class} %')
    ax3.set_xlabel('Time (seconds)')
    ax3.set_ylabel('Response Rate (%)')
    ax3.set_title('Response Code Rates During Renewals')
    ax3.set_ylim(-5, 105)
    ax3.grid(True, alpha=0.3)
    ax3.legend()

    # 4. Latency distribution (bottom left)
    ax4 = fig.add_subplot(gs[2, 0])
    percentiles = calculate_percentiles(latencies, [50, 90, 95, 99])
    p_labels = list(percentiles.keys())
    p_values = list(percentiles.values())
    bar_colors = ['#2ecc71', '#f1c40f', '#e67e22', '#e74c3c']
    bars = ax4.bar(p_labels, p_values, color=bar_colors)
    for bar, val in zip(bars, p_values):
        ax4.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                 f'{val:.2f}', ha='center', va='bottom', fontsize=9)
    ax4.set_xlabel('Percentile')
    ax4.set_ylabel('Latency (ms)')
    ax4.set_title('Overall Latency Percentiles')

    # 5. Summary metrics (bottom right)
    ax5 = fig.add_subplot(gs[2, 1])
    ax5.axis('off')

    total = len(latencies)
    avg_lat = sum(latencies) / total if total else 0
    errors = sum(1 for c in proto_codes if c >= 400 or c == 0)
    error_rate = (errors / total * 100) if total else 0
    net_errors = sum(1 for c in data.get('net_codes', []) if c != 0)

    # Estimate renewal count
    test_duration = max(timestamps) - min(timestamps) if timestamps else 0
    est_renewals = int(test_duration / 60)  # ~1 renewal per minute

    summary_text = f"""
    Renewal Impact Summary
    =======================

    Test Duration:     {test_duration:.0f}s
    Est. Renewals:     ~{est_renewals}
    Total Requests:    {total:,}

    Latency:
      Average:         {avg_lat:.2f} ms
      P50:             {percentiles['p50']:.2f} ms
      P95:             {percentiles['p95']:.2f} ms
      P99:             {percentiles['p99']:.2f} ms

    Avg RPS:           {avg_rps:.0f}
    Error Rate:        {error_rate:.3f}%
    Net Errors:        {net_errors}

    Verdict: {'PASS - No impact' if error_rate < 0.1 and percentiles['p99'] < 100 else 'INVESTIGATE'}
    """

    ax5.text(0.05, 0.95, summary_text, transform=ax5.transAxes, fontsize=10,
             verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

    fig.suptitle(title, fontsize=16, fontweight='bold', y=0.98)
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def generate_comparison_chart(vault_data: Dict, baseline_data: Dict, output_file: str,
                               title: str = "Vault TLS vs File-Based TLS Comparison"):
    """Generate comparison chart between Vault and file-based TLS."""
    if not HAS_MATPLOTLIB:
        return

    fig = plt.figure(figsize=(16, 14))
    gs = gridspec.GridSpec(3, 2, hspace=0.35, wspace=0.3)

    vault_lat = vault_data.get('latencies', [])
    base_lat = baseline_data.get('latencies', [])

    # 1. Latency distribution comparison (top left)
    ax1 = fig.add_subplot(gs[0, 0])
    if vault_lat and base_lat:
        max_lat = max(max(vault_lat), max(base_lat))
        bins = 50
        ax1.hist(vault_lat, bins=bins, alpha=0.5, label='Vault TLS', color='#3498db', density=True)
        ax1.hist(base_lat, bins=bins, alpha=0.5, label='File TLS', color='#e74c3c', density=True)
        ax1.set_xlabel('Latency (ms)')
        ax1.set_ylabel('Density')
        ax1.set_title('Latency Distribution')
        ax1.legend()
        if max_lat > 10:
            ax1.set_xscale('log')

    # 2. Percentile comparison (top right)
    ax2 = fig.add_subplot(gs[0, 1])
    if vault_lat and base_lat:
        percentiles = [50, 90, 95, 99]
        v_percs = calculate_percentiles(vault_lat, percentiles)
        b_percs = calculate_percentiles(base_lat, percentiles)

        x = range(len(percentiles))
        width = 0.35
        ax2.bar([i - width / 2 for i in x], [v_percs[f'p{p}'] for p in percentiles],
                width, label='Vault TLS', color='#3498db')
        ax2.bar([i + width / 2 for i in x], [b_percs[f'p{p}'] for p in percentiles],
                width, label='File TLS', color='#e74c3c')

        ax2.set_xlabel('Percentile')
        ax2.set_ylabel('Latency (ms)')
        ax2.set_title('Latency Percentile Comparison')
        ax2.set_xticks(x)
        ax2.set_xticklabels([f'p{p}' for p in percentiles])
        ax2.legend()

        # Add value labels
        for i, p in enumerate(percentiles):
            ax2.text(i - width / 2, v_percs[f'p{p}'] + 0.5, f'{v_percs[f"p{p}"]:.1f}',
                     ha='center', fontsize=8)
            ax2.text(i + width / 2, b_percs[f'p{p}'] + 0.5, f'{b_percs[f"p{p}"]:.1f}',
                     ha='center', fontsize=8)

    # 3. RPS comparison (middle, full width)
    ax3 = fig.add_subplot(gs[1, :])
    v_times, v_rps = calculate_rps_over_time(vault_data.get('timestamps', []), bucket_size=5)
    b_times, b_rps = calculate_rps_over_time(baseline_data.get('timestamps', []), bucket_size=5)

    if v_times:
        ax3.plot(v_times, v_rps, color='#3498db', linewidth=1.5, label='Vault TLS', alpha=0.8)
    if b_times:
        ax3.plot(b_times, b_rps, color='#e74c3c', linewidth=1.5, label='File TLS', alpha=0.8)

    ax3.set_xlabel('Time (seconds)')
    ax3.set_ylabel('Requests/Second')
    ax3.set_title('Throughput Over Time')
    ax3.grid(True, alpha=0.3)
    ax3.legend()

    # 4. Latency over time comparison (bottom left)
    ax4 = fig.add_subplot(gs[2, 0])
    v_lat_time = calculate_latency_over_time(vault_data.get('timestamps', []),
                                              vault_data.get('latencies', []), bucket_size=5)
    b_lat_time = calculate_latency_over_time(baseline_data.get('timestamps', []),
                                              baseline_data.get('latencies', []), bucket_size=5)

    if 'p95' in v_lat_time:
        ax4.plot(v_lat_time['p95'][0], v_lat_time['p95'][1], color='#3498db',
                 linewidth=1.5, label='Vault P95', alpha=0.8)
    if 'p95' in b_lat_time:
        ax4.plot(b_lat_time['p95'][0], b_lat_time['p95'][1], color='#e74c3c',
                 linewidth=1.5, label='File P95', alpha=0.8)

    ax4.set_xlabel('Time (seconds)')
    ax4.set_ylabel('P95 Latency (ms)')
    ax4.set_title('P95 Latency Over Time')
    ax4.grid(True, alpha=0.3)
    ax4.legend()

    # 5. Summary table (bottom right)
    ax5 = fig.add_subplot(gs[2, 1])
    ax5.axis('off')

    if vault_lat and base_lat:
        v_percs = calculate_percentiles(vault_lat)
        b_percs = calculate_percentiles(base_lat)
        v_avg_rps = sum(v_rps) / len(v_rps) if v_rps else 0
        b_avg_rps = sum(b_rps) / len(b_rps) if b_rps else 0

        v_errors = sum(1 for c in vault_data.get('proto_codes', []) if c >= 400 or c == 0)
        b_errors = sum(1 for c in baseline_data.get('proto_codes', []) if c >= 400 or c == 0)
        v_err_rate = (v_errors / len(vault_lat) * 100) if vault_lat else 0
        b_err_rate = (b_errors / len(base_lat) * 100) if base_lat else 0

        table_data = [
            ['Metric', 'Vault TLS', 'File TLS', 'Diff %'],
            ['Total Reqs', f'{len(vault_lat):,}', f'{len(base_lat):,}', ''],
            ['Avg RPS', f'{v_avg_rps:.0f}', f'{b_avg_rps:.0f}',
             f'{((v_avg_rps - b_avg_rps) / max(b_avg_rps, 1) * 100):+.1f}%'],
            ['Avg Lat (ms)', f'{sum(vault_lat) / len(vault_lat):.2f}',
             f'{sum(base_lat) / len(base_lat):.2f}',
             f'{((sum(vault_lat) / len(vault_lat) - sum(base_lat) / len(base_lat)) / max(sum(base_lat) / len(base_lat), 0.001) * 100):+.1f}%'],
            ['P50 (ms)', f'{v_percs["p50"]:.2f}', f'{b_percs["p50"]:.2f}',
             f'{((v_percs["p50"] - b_percs["p50"]) / max(b_percs["p50"], 0.001) * 100):+.1f}%'],
            ['P95 (ms)', f'{v_percs["p95"]:.2f}', f'{b_percs["p95"]:.2f}',
             f'{((v_percs["p95"] - b_percs["p95"]) / max(b_percs["p95"], 0.001) * 100):+.1f}%'],
            ['P99 (ms)', f'{v_percs["p99"]:.2f}', f'{b_percs["p99"]:.2f}',
             f'{((v_percs["p99"] - b_percs["p99"]) / max(b_percs["p99"], 0.001) * 100):+.1f}%'],
            ['Error Rate', f'{v_err_rate:.3f}%', f'{b_err_rate:.3f}%', ''],
        ]

        table = ax5.table(cellText=table_data, loc='center', cellLoc='center')
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1.2, 1.5)

        for i in range(4):
            table[(0, i)].set_facecolor('#3498db')
            table[(0, i)].set_text_props(color='white', weight='bold')

    ax5.set_title('Performance Comparison Summary', pad=20)

    fig.suptitle(title, fontsize=16, fontweight='bold', y=0.98)
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def generate_vault_tls_dashboard(data: Dict, output_file: str,
                                  title: str = "Vault PKI TLS Performance Dashboard"):
    """Generate comprehensive dashboard for a single Vault TLS test."""
    if not HAS_MATPLOTLIB:
        return

    latencies = data.get('latencies', [])
    timestamps = data.get('timestamps', [])
    proto_codes = data.get('proto_codes', [])

    if not latencies:
        print(f"Skipping {output_file}: no latency data")
        return

    fig = plt.figure(figsize=(18, 14))
    gs = gridspec.GridSpec(3, 3, hspace=0.35, wspace=0.3)

    percentiles = calculate_percentiles(latencies)
    times, rps = calculate_rps_over_time(timestamps, bucket_size=5)

    # 1. Latency vs RPS (top, spans 2 cols)
    ax1 = fig.add_subplot(gs[0, :2])
    lat_over_time = calculate_latency_over_time(timestamps, latencies, bucket_size=5)

    ax1_twin = ax1.twinx()
    ax1_twin.plot(times, rps, color='#3498db', linewidth=1, alpha=0.3, label='RPS')
    ax1_twin.fill_between(times, rps, alpha=0.1, color='#3498db')
    ax1_twin.set_ylabel('RPS', color='#3498db')

    colors = {'p50': '#2ecc71', 'p95': '#f39c12', 'p99': '#e74c3c'}
    for label in ['p50', 'p95', 'p99']:
        if label in lat_over_time:
            t, v = lat_over_time[label]
            ax1.plot(t, v, color=colors[label], linewidth=1.5, label=label)

    ax1.set_xlabel('Time (seconds)')
    ax1.set_ylabel('Latency (ms)')
    ax1.set_title('Latency Percentiles vs RPS Over Time')
    ax1.grid(True, alpha=0.3)
    ax1.legend(loc='upper left')

    # 2. Key metrics (top right)
    ax2 = fig.add_subplot(gs[0, 2])
    ax2.axis('off')

    total = len(latencies)
    avg_lat = sum(latencies) / total
    avg_rps_val = sum(rps) / len(rps) if rps else 0
    max_rps_val = max(rps) if rps else 0
    errors = sum(1 for c in proto_codes if c >= 400 or c == 0)
    error_rate = (errors / total * 100) if total else 0

    metrics_text = f"""
    Vault TLS Metrics
    ==================

    Total Requests: {total:,}
    Avg RPS:        {avg_rps_val:.0f}
    Max RPS:        {max_rps_val:.0f}

    Latency:
      Average: {avg_lat:.2f} ms
      P50:     {percentiles['p50']:.2f} ms
      P95:     {percentiles['p95']:.2f} ms
      P99:     {percentiles['p99']:.2f} ms

    Error Rate: {error_rate:.3f}%
    """

    ax2.text(0.05, 0.95, metrics_text, transform=ax2.transAxes, fontsize=10,
             verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

    # 3. Response codes vs RPS (middle, full width)
    ax3 = fig.add_subplot(gs[1, :])
    error_rates = calculate_error_rate_over_time(timestamps, proto_codes, bucket_size=5)

    ax3_twin = ax3.twinx()
    ax3_twin.plot(times, rps, color='#3498db', linewidth=1, alpha=0.3, label='RPS')
    ax3_twin.set_ylabel('RPS', color='#3498db')

    err_colors = {'2xx': '#2ecc71', '4xx': '#f39c12', '5xx': '#e74c3c'}
    for code_class, (t, v) in error_rates.items():
        ax3.plot(t, v, color=err_colors.get(code_class, '#333'), linewidth=1.5,
                 label=f'{code_class} %')

    ax3.set_xlabel('Time (seconds)')
    ax3.set_ylabel('Response Rate (%)')
    ax3.set_title('Response Code Distribution vs RPS')
    ax3.set_ylim(-5, 105)
    ax3.grid(True, alpha=0.3)
    ax3.legend(loc='center right')

    # 4. Latency histogram (bottom left)
    ax4 = fig.add_subplot(gs[2, 0])
    ax4.hist(latencies, bins=50, edgecolor='black', alpha=0.7, color='#3498db')
    ax4.set_xlabel('Latency (ms)')
    ax4.set_ylabel('Count')
    ax4.set_title('Latency Distribution')
    if max(latencies) > 10:
        ax4.set_xscale('log')

    # 5. Percentile bars (bottom middle)
    ax5 = fig.add_subplot(gs[2, 1])
    p_labels = ['p50', 'p90', 'p95', 'p99']
    p_values = [percentiles.get(p, 0) for p in p_labels]
    bar_colors = ['#2ecc71', '#f1c40f', '#e67e22', '#e74c3c']
    bars = ax5.bar(p_labels, p_values, color=bar_colors)
    for bar, val in zip(bars, p_values):
        ax5.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                 f'{val:.1f}', ha='center', va='bottom', fontsize=9)
    ax5.set_xlabel('Percentile')
    ax5.set_ylabel('Latency (ms)')
    ax5.set_title('Latency Percentiles')

    # 6. Response code pie (bottom right)
    ax6 = fig.add_subplot(gs[2, 2])
    code_counts = {}
    for code in proto_codes:
        code_counts[code] = code_counts.get(code, 0) + 1

    categories = {
        '2xx': sum(v for k, v in code_counts.items() if 200 <= k < 300),
        '4xx': sum(v for k, v in code_counts.items() if 400 <= k < 500),
        '5xx': sum(v for k, v in code_counts.items() if 500 <= k < 600),
    }
    categories = {k: v for k, v in categories.items() if v > 0}

    if categories:
        pie_colors = {'2xx': '#2ecc71', '4xx': '#f39c12', '5xx': '#e74c3c'}
        ax6.pie(categories.values(), labels=categories.keys(), autopct='%1.1f%%',
                colors=[pie_colors.get(k, '#95a5a6') for k in categories.keys()], startangle=90)
    ax6.set_title('Response Codes')

    fig.suptitle(title, fontsize=16, fontweight='bold', y=0.98)
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Generate Vault PKI TLS performance charts')
    parser.add_argument('results_dir', nargs='?', help='Results directory')
    parser.add_argument('--compare', nargs=2, metavar=('VAULT_DIR', 'BASELINE_DIR'),
                        help='Compare Vault vs file-based TLS results')
    parser.add_argument('--renewal', action='store_true',
                        help='Generate certificate renewal analysis charts')
    parser.add_argument('--output', '-o', help='Output directory')
    parser.add_argument('--format', '-f', choices=['png', 'svg', 'both'],
                        default='png', help='Output format')
    parser.add_argument('--all', '-a', action='store_true', help='Generate all charts')

    args = parser.parse_args()

    if not HAS_MATPLOTLIB:
        print("Error: matplotlib is required for chart generation")
        print("Install with: pip install matplotlib")
        sys.exit(1)

    # Handle comparison mode
    if args.compare:
        vault_dir, baseline_dir = args.compare

        vault_file = find_phout_file(vault_dir)
        baseline_file = find_phout_file(baseline_dir)

        if not vault_file or not baseline_file:
            print(f"Error: Could not find phout files in {vault_dir} or {baseline_dir}")
            sys.exit(1)

        vault_data = parse_phout(vault_file)
        baseline_data = parse_phout(baseline_file)

        output_dir = Path(args.output) if args.output else Path(vault_dir) / 'charts'
        output_dir.mkdir(parents=True, exist_ok=True)

        formats = ['png', 'svg'] if args.format == 'both' else [args.format]
        for fmt in formats:
            generate_comparison_chart(vault_data, baseline_data,
                                      output_dir / f'vault_vs_file_comparison.{fmt}')
        return

    # Single results mode
    if not args.results_dir:
        parser.print_help()
        sys.exit(1)

    phout_file = find_phout_file(args.results_dir)
    if not phout_file:
        print(f"Error: No phout file found in {args.results_dir}")
        sys.exit(1)

    print(f"Found results file: {phout_file}")
    data = parse_phout(phout_file)

    output_dir = Path(args.output) if args.output else Path(args.results_dir) / 'charts'
    output_dir.mkdir(parents=True, exist_ok=True)

    formats = ['png', 'svg'] if args.format == 'both' else [args.format]

    for fmt in formats:
        # Always generate the dashboard
        generate_vault_tls_dashboard(data, output_dir / f'vault_tls_dashboard.{fmt}')

        # Latency vs RPS
        generate_latency_vs_rps_chart(data, output_dir / f'latency_vs_rps.{fmt}')

        # Response codes vs RPS
        generate_response_codes_vs_rps_chart(data, output_dir / f'response_codes_vs_rps.{fmt}')

        # Renewal analysis (if requested or --all)
        if args.renewal or args.all:
            generate_renewal_analysis_chart(data, output_dir / f'renewal_analysis.{fmt}')

    print(f"\nCharts saved to: {output_dir}")


if __name__ == '__main__':
    main()
