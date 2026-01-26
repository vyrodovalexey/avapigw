#!/usr/bin/env python3
"""
generate-charts.py - Comprehensive Performance Test Chart Generator

Supports:
- Yandex Tank phout.txt results (HTTP tests)
- ghz JSON results (gRPC tests)
- k6 JSON results (WebSocket tests)

Usage:
    ./generate-charts.py <results-dir> [options]
    ./generate-charts.py --compare <dir1> <dir2> [options]
    ./generate-charts.py --summary <results-base-dir> [options]

Options:
    --output=<dir>      Output directory for charts (default: results-dir/charts)
    --format=<fmt>      Output format: png, svg, both (default: png)
    --compare           Compare two test runs
    --summary           Generate summary report across all test types
    --all               Generate all chart types
    --latency           Generate latency distribution chart
    --rps               Generate RPS over time chart
    --errors            Generate error rate chart
    --dashboard         Generate summary dashboard

Examples:
    ./generate-charts.py results/http-throughput_20240101_120000/
    ./generate-charts.py --compare results/run1/ results/run2/
    ./generate-charts.py --summary results/ --format=svg
    ./generate-charts.py results/latest/ --format=svg --all
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Try to import matplotlib, provide helpful error if not available
try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
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
                    data['latencies'].append(float(parts[3]) / 1000)  # Convert to ms
                    data['connect_times'].append(float(parts[4]) / 1000)
                    data['proto_codes'].append(int(parts[11]))
                    data['net_codes'].append(int(parts[10]))
                    if len(parts) > 9:
                        data['sizes'].append(int(parts[9]))
                except (ValueError, IndexError):
                    continue
    
    return data


def parse_ghz_json(json_file: str) -> Dict[str, Any]:
    """Parse ghz JSON results file (gRPC tests)."""
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    # Convert to common format
    result = {
        'type': 'grpc',
        'count': data.get('count', 0),
        'rps': data.get('rps', 0),
        'average': data.get('average', 0) / 1000000,  # ns to ms
        'fastest': data.get('fastest', 0) / 1000000,
        'slowest': data.get('slowest', 0) / 1000000,
        'latency_distribution': {},
        'status_codes': data.get('statusCodeDistribution', {}),
        'errors': data.get('errorDistribution', {}),
    }
    
    # Parse latency distribution
    for item in data.get('latencyDistribution', []):
        p = item.get('percentage', 0)
        latency = item.get('latency', 0) / 1000000  # ns to ms
        result['latency_distribution'][f'p{p}'] = latency
    
    return result


def parse_k6_json(json_file: str) -> Dict[str, Any]:
    """Parse k6 JSON results file (WebSocket tests)."""
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    metrics = data.get('metrics', {})
    
    # Find the relevant metrics (different tests use different metric names)
    latency_metric = None
    for name in ['ws_message_latency', 'wss_message_latency', 'ws_auth_message_latency', 
                 'ws_connection_time', 'wss_tls_handshake_time']:
        if name in metrics:
            latency_metric = metrics[name]
            break
    
    success_metric = None
    for name in ['ws_message_success', 'wss_message_success', 'ws_auth_message_success',
                 'ws_connection_success']:
        if name in metrics:
            success_metric = metrics[name]
            break
    
    sent_metric = None
    for name in ['ws_messages_sent', 'wss_messages_sent', 'ws_auth_messages_sent',
                 'ws_total_connections']:
        if name in metrics:
            sent_metric = metrics[name]
            break
    
    result = {
        'type': 'websocket',
        'count': sent_metric['values']['count'] if sent_metric else 0,
        'duration': data.get('state', {}).get('testRunDurationMs', 0) / 1000,
        'latency_distribution': {},
        'success_rate': success_metric['values']['rate'] if success_metric else 0,
    }
    
    if latency_metric and 'values' in latency_metric:
        values = latency_metric['values']
        result['average'] = values.get('avg', 0)
        result['min'] = values.get('min', 0)
        result['max'] = values.get('max', 0)
        result['latency_distribution'] = {
            'p50': values.get('p(50)', 0),
            'p90': values.get('p(90)', 0),
            'p95': values.get('p(95)', 0),
            'p99': values.get('p(99)', 0),
        }
    
    # Calculate RPS/messages per second
    if result['duration'] > 0:
        result['rps'] = result['count'] / result['duration']
    else:
        result['rps'] = 0
    
    return result


def calculate_percentiles(values: List[float], percentiles: List[int] = None) -> Dict[str, float]:
    """Calculate percentiles from a list of values."""
    if percentiles is None:
        percentiles = [50, 90, 95, 99]
    
    if not values:
        return {f'p{p}': 0 for p in percentiles}
    
    if HAS_NUMPY:
        return {f'p{p}': np.percentile(values, p) for p in percentiles}
    
    # Simple percentile calculation without numpy
    sorted_values = sorted(values)
    n = len(sorted_values)
    result = {}
    for p in percentiles:
        idx = int(n * p / 100)
        result[f'p{p}'] = sorted_values[min(idx, n-1)]
    return result


def calculate_rps_over_time(timestamps: List[float], bucket_size: int = 1) -> Tuple[List[float], List[float]]:
    """Calculate RPS over time with given bucket size in seconds."""
    if not timestamps:
        return [], []
    
    min_ts = min(timestamps)
    max_ts = max(timestamps)
    
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


def generate_latency_histogram(data: Dict, output_file: str, title: str = "Latency Distribution"):
    """Generate latency distribution histogram."""
    if not HAS_MATPLOTLIB:
        print(f"Skipping {output_file}: matplotlib not available")
        return
    
    latencies = data.get('latencies', [])
    if not latencies:
        print(f"Skipping {output_file}: no latency data")
        return
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Create histogram with dynamic bins based on data range
    max_lat = max(latencies)
    min_lat = min(latencies)
    
    # Create bins that make sense for the data range
    if max_lat <= 10:
        bins = [i * 0.5 for i in range(int(max_lat * 2) + 3)]
    elif max_lat <= 100:
        bins = [0, 1, 2, 5, 10, 20, 50, 100, max_lat + 1]
    elif max_lat <= 1000:
        bins = [0, 10, 25, 50, 100, 200, 500, 1000, max_lat + 1]
    else:
        bins = [0, 10, 25, 50, 100, 200, 500, 1000, 2000, 5000, max_lat + 1]
    
    # Filter bins to only include those less than max + 1
    bins = sorted(set([b for b in bins if b <= max_lat + 1]))
    if len(bins) < 2:
        bins = [min_lat, max_lat + 0.1]
    
    counts, edges, patches = ax.hist(latencies, bins=bins, edgecolor='black', alpha=0.7)
    
    # Color code by latency
    colors = ['#2ecc71', '#27ae60', '#f1c40f', '#e67e22', '#e74c3c', '#c0392b', '#8e44ad', '#9b59b6', '#34495e', '#2c3e50']
    for patch, color in zip(patches, colors[:len(patches)]):
        patch.set_facecolor(color)
    
    # Add percentile lines
    percentiles = calculate_percentiles(latencies)
    for label, value in percentiles.items():
        ax.axvline(x=value, color='red', linestyle='--', alpha=0.7)
        ax.annotate(f'{label}: {value:.1f}ms', xy=(value, ax.get_ylim()[1] * 0.9),
                   rotation=90, fontsize=8, color='red')
    
    ax.set_xlabel('Latency (ms)')
    ax.set_ylabel('Request Count')
    ax.set_title(title)
    if max_lat > 10:
        ax.set_xscale('log')
    
    # Add statistics text
    stats_text = f"Total: {len(latencies):,}\n"
    stats_text += f"Avg: {sum(latencies)/len(latencies):.2f}ms\n"
    stats_text += f"Min: {min(latencies):.2f}ms\n"
    stats_text += f"Max: {max(latencies):.2f}ms"
    ax.text(0.98, 0.98, stats_text, transform=ax.transAxes, fontsize=9,
            verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    plt.close()
    print(f"Generated: {output_file}")


def generate_rps_chart(data: Dict, output_file: str, title: str = "Requests Per Second Over Time"):
    """Generate RPS over time chart."""
    if not HAS_MATPLOTLIB:
        print(f"Skipping {output_file}: matplotlib not available")
        return
    
    times, rps = calculate_rps_over_time(data.get('timestamps', []))
    
    if not times:
        print(f"Skipping {output_file}: no timestamp data")
        return
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    ax.plot(times, rps, color='#3498db', linewidth=1.5)
    ax.fill_between(times, rps, alpha=0.3, color='#3498db')
    
    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('Requests/Second')
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    
    # Add statistics
    avg_rps = sum(rps) / len(rps) if rps else 0
    max_rps = max(rps) if rps else 0
    
    stats_text = f"Avg RPS: {avg_rps:.1f}\nMax RPS: {max_rps:.1f}"
    ax.text(0.98, 0.98, stats_text, transform=ax.transAxes, fontsize=10,
            verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    plt.close()
    print(f"Generated: {output_file}")


def generate_error_chart(data: Dict, output_file: str, title: str = "Response Code Distribution"):
    """Generate error rate chart."""
    if not HAS_MATPLOTLIB:
        print(f"Skipping {output_file}: matplotlib not available")
        return
    
    proto_codes = data.get('proto_codes', [])
    if not proto_codes:
        print(f"Skipping {output_file}: no response code data")
        return
    
    # Count response codes
    code_counts = {}
    for code in proto_codes:
        code_counts[code] = code_counts.get(code, 0) + 1
    
    # Group by category
    categories = {
        '2xx': sum(v for k, v in code_counts.items() if 200 <= k < 300),
        '3xx': sum(v for k, v in code_counts.items() if 300 <= k < 400),
        '4xx': sum(v for k, v in code_counts.items() if 400 <= k < 500),
        '5xx': sum(v for k, v in code_counts.items() if 500 <= k < 600),
        'Other': sum(v for k, v in code_counts.items() if k < 200 or k >= 600),
    }
    
    # Remove zero categories
    categories = {k: v for k, v in categories.items() if v > 0}
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Pie chart
    colors = {'2xx': '#2ecc71', '3xx': '#3498db', '4xx': '#f39c12', '5xx': '#e74c3c', 'Other': '#95a5a6'}
    pie_colors = [colors.get(k, '#95a5a6') for k in categories.keys()]
    
    ax1.pie(categories.values(), labels=categories.keys(), autopct='%1.1f%%',
            colors=pie_colors, startangle=90)
    ax1.set_title('Response Code Distribution')
    
    # Bar chart of specific codes
    top_codes = sorted(code_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    codes = [str(c[0]) for c in top_codes]
    counts = [c[1] for c in top_codes]
    
    bar_colors = []
    for code in [c[0] for c in top_codes]:
        if 200 <= code < 300:
            bar_colors.append('#2ecc71')
        elif 300 <= code < 400:
            bar_colors.append('#3498db')
        elif 400 <= code < 500:
            bar_colors.append('#f39c12')
        elif 500 <= code < 600:
            bar_colors.append('#e74c3c')
        else:
            bar_colors.append('#95a5a6')
    
    ax2.bar(codes, counts, color=bar_colors)
    ax2.set_xlabel('Response Code')
    ax2.set_ylabel('Count')
    ax2.set_title('Top Response Codes')
    ax2.tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    plt.close()
    print(f"Generated: {output_file}")


def generate_grpc_chart(data: Dict, output_file: str, title: str = "gRPC Performance Results"):
    """Generate chart for gRPC test results."""
    if not HAS_MATPLOTLIB:
        print(f"Skipping {output_file}: matplotlib not available")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # 1. Latency percentiles bar chart
    ax = axes[0, 0]
    latency_dist = data.get('latency_distribution', {})
    if latency_dist:
        labels = list(latency_dist.keys())
        values = list(latency_dist.values())
        colors = ['#2ecc71', '#f1c40f', '#e67e22', '#e74c3c'][:len(labels)]
        ax.bar(labels, values, color=colors)
        ax.set_xlabel('Percentile')
        ax.set_ylabel('Latency (ms)')
        ax.set_title('Latency Percentiles')
        for i, v in enumerate(values):
            ax.text(i, v + 0.5, f'{v:.2f}', ha='center', fontsize=9)
    else:
        ax.text(0.5, 0.5, 'No latency data', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Latency Percentiles')
    
    # 2. Key metrics
    ax = axes[0, 1]
    ax.axis('off')
    
    metrics_text = f"""
    gRPC Test Results
    ==================
    
    Total Requests: {data.get('count', 0):,}
    Requests/sec:   {data.get('rps', 0):.2f}
    
    Latency:
      Average:      {data.get('average', 0):.2f} ms
      Fastest:      {data.get('fastest', 0):.2f} ms
      Slowest:      {data.get('slowest', 0):.2f} ms
    """
    
    ax.text(0.1, 0.9, metrics_text, transform=ax.transAxes, fontsize=11,
            verticalalignment='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    ax.set_title('Key Metrics')
    
    # 3. Status code distribution
    ax = axes[1, 0]
    status_codes = data.get('status_codes', {})
    if status_codes:
        codes = list(status_codes.keys())
        counts = list(status_codes.values())
        colors = ['#2ecc71' if c == 'OK' else '#e74c3c' for c in codes]
        ax.bar(codes, counts, color=colors)
        ax.set_xlabel('Status Code')
        ax.set_ylabel('Count')
        ax.set_title('Status Code Distribution')
    else:
        ax.text(0.5, 0.5, 'No status code data', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Status Code Distribution')
    
    # 4. Error distribution
    ax = axes[1, 1]
    errors = data.get('errors', {})
    if errors:
        error_types = list(errors.keys())
        error_counts = list(errors.values())
        ax.barh(error_types, error_counts, color='#e74c3c')
        ax.set_xlabel('Count')
        ax.set_title('Error Distribution')
    else:
        ax.text(0.5, 0.5, 'No errors', ha='center', va='center', transform=ax.transAxes,
                fontsize=14, color='#2ecc71')
        ax.set_title('Error Distribution')
    
    fig.suptitle(title, fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def generate_websocket_chart(data: Dict, output_file: str, title: str = "WebSocket Performance Results"):
    """Generate chart for WebSocket test results."""
    if not HAS_MATPLOTLIB:
        print(f"Skipping {output_file}: matplotlib not available")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # 1. Latency percentiles
    ax = axes[0, 0]
    latency_dist = data.get('latency_distribution', {})
    if latency_dist:
        labels = list(latency_dist.keys())
        values = list(latency_dist.values())
        colors = ['#2ecc71', '#f1c40f', '#e67e22', '#e74c3c'][:len(labels)]
        ax.bar(labels, values, color=colors)
        ax.set_xlabel('Percentile')
        ax.set_ylabel('Latency (ms)')
        ax.set_title('Message Latency Percentiles')
        for i, v in enumerate(values):
            ax.text(i, v + 0.5, f'{v:.2f}', ha='center', fontsize=9)
    else:
        ax.text(0.5, 0.5, 'No latency data', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Message Latency Percentiles')
    
    # 2. Key metrics
    ax = axes[0, 1]
    ax.axis('off')
    
    metrics_text = f"""
    WebSocket Test Results
    =======================
    
    Total Messages: {data.get('count', 0):,}
    Messages/sec:   {data.get('rps', 0):.2f}
    Duration:       {data.get('duration', 0):.1f} s
    Success Rate:   {data.get('success_rate', 0) * 100:.2f}%
    
    Latency:
      Average:      {data.get('average', 0):.2f} ms
      Min:          {data.get('min', 0):.2f} ms
      Max:          {data.get('max', 0):.2f} ms
    """
    
    ax.text(0.1, 0.9, metrics_text, transform=ax.transAxes, fontsize=11,
            verticalalignment='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    ax.set_title('Key Metrics')
    
    # 3. Success rate gauge
    ax = axes[1, 0]
    success_rate = data.get('success_rate', 0)
    
    # Create a simple gauge
    theta = [0, success_rate * 180, 180]
    colors_gauge = ['#2ecc71', '#e74c3c']
    ax.pie([success_rate, 1 - success_rate], colors=colors_gauge, startangle=90,
           counterclock=False, wedgeprops=dict(width=0.3))
    ax.text(0, 0, f'{success_rate * 100:.1f}%', ha='center', va='center', fontsize=20, fontweight='bold')
    ax.set_title('Success Rate')
    
    # 4. Throughput summary
    ax = axes[1, 1]
    ax.axis('off')
    
    throughput_text = f"""
    Throughput Analysis
    ===================
    
    Target: 2000+ msg/s
    Achieved: {data.get('rps', 0):.2f} msg/s
    
    Status: {'PASS' if data.get('rps', 0) >= 2000 else 'BELOW TARGET'}
    """
    
    color = '#2ecc71' if data.get('rps', 0) >= 2000 else '#e74c3c'
    ax.text(0.1, 0.9, throughput_text, transform=ax.transAxes, fontsize=11,
            verticalalignment='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor=color, alpha=0.3))
    ax.set_title('Throughput Analysis')
    
    fig.suptitle(title, fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def generate_comparison_chart(data1: Dict, data2: Dict, output_file: str, 
                             label1: str = "Run 1", label2: str = "Run 2"):
    """Generate comparison chart between two test runs."""
    if not HAS_MATPLOTLIB:
        print(f"Skipping {output_file}: matplotlib not available")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # Latency comparison
    ax = axes[0, 0]
    latencies1 = data1.get('latencies', [])
    latencies2 = data2.get('latencies', [])
    
    if latencies1 and latencies2:
        ax.hist(latencies1, bins=50, alpha=0.5, label=label1, color='#3498db')
        ax.hist(latencies2, bins=50, alpha=0.5, label=label2, color='#e74c3c')
        ax.set_xlabel('Latency (ms)')
        ax.set_ylabel('Count')
        ax.set_title('Latency Distribution Comparison')
        ax.legend()
        if max(max(latencies1), max(latencies2)) > 10:
            ax.set_xscale('log')
    
    # RPS comparison
    ax = axes[0, 1]
    times1, rps1 = calculate_rps_over_time(data1.get('timestamps', []))
    times2, rps2 = calculate_rps_over_time(data2.get('timestamps', []))
    
    if times1 and times2:
        ax.plot(times1, rps1, label=label1, color='#3498db', alpha=0.7)
        ax.plot(times2, rps2, label=label2, color='#e74c3c', alpha=0.7)
        ax.set_xlabel('Time (seconds)')
        ax.set_ylabel('RPS')
        ax.set_title('RPS Over Time Comparison')
        ax.legend()
        ax.grid(True, alpha=0.3)
    
    # Percentile comparison
    ax = axes[1, 0]
    if latencies1 and latencies2:
        percentiles = [50, 90, 95, 99]
        p1 = calculate_percentiles(latencies1, percentiles)
        p2 = calculate_percentiles(latencies2, percentiles)
        
        x = range(len(percentiles))
        width = 0.35
        
        ax.bar([i - width/2 for i in x], [p1[f'p{p}'] for p in percentiles],
               width, label=label1, color='#3498db')
        ax.bar([i + width/2 for i in x], [p2[f'p{p}'] for p in percentiles],
               width, label=label2, color='#e74c3c')
        
        ax.set_xlabel('Percentile')
        ax.set_ylabel('Latency (ms)')
        ax.set_title('Latency Percentile Comparison')
        ax.set_xticks(x)
        ax.set_xticklabels([f'p{p}' for p in percentiles])
        ax.legend()
    
    # Summary statistics
    ax = axes[1, 1]
    ax.axis('off')
    
    if latencies1 and latencies2:
        p1 = calculate_percentiles(latencies1)
        p2 = calculate_percentiles(latencies2)
        
        stats = [
            ['Metric', label1, label2, 'Diff'],
            ['Total Requests', f'{len(latencies1):,}', f'{len(latencies2):,}',
             f'{((len(latencies2) - len(latencies1)) / max(len(latencies1), 1) * 100):+.1f}%'],
            ['Avg Latency (ms)', f'{sum(latencies1)/len(latencies1):.2f}',
             f'{sum(latencies2)/len(latencies2):.2f}',
             f'{((sum(latencies2)/len(latencies2) - sum(latencies1)/len(latencies1)) / max(sum(latencies1)/len(latencies1), 0.001) * 100):+.1f}%'],
            ['P95 Latency (ms)', f'{p1["p95"]:.2f}', f'{p2["p95"]:.2f}',
             f'{((p2["p95"] - p1["p95"]) / max(p1["p95"], 0.001) * 100):+.1f}%'],
            ['P99 Latency (ms)', f'{p1["p99"]:.2f}', f'{p2["p99"]:.2f}',
             f'{((p2["p99"] - p1["p99"]) / max(p1["p99"], 0.001) * 100):+.1f}%'],
            ['Avg RPS', f'{sum(rps1)/len(rps1):.1f}' if rps1 else 'N/A',
             f'{sum(rps2)/len(rps2):.1f}' if rps2 else 'N/A', ''],
        ]
        
        table = ax.table(cellText=stats, loc='center', cellLoc='center')
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1.2, 1.5)
        
        # Color header row
        for i in range(4):
            table[(0, i)].set_facecolor('#3498db')
            table[(0, i)].set_text_props(color='white', weight='bold')
    
    ax.set_title('Summary Comparison', pad=20)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    plt.close()
    print(f"Generated: {output_file}")


def generate_summary_dashboard(data: Dict, output_file: str, title: str = "Performance Test Summary"):
    """Generate a summary dashboard with all key metrics."""
    if not HAS_MATPLOTLIB:
        print(f"Skipping {output_file}: matplotlib not available")
        return
    
    fig = plt.figure(figsize=(16, 12))
    
    # Create grid
    gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
    
    latencies = data.get('latencies', [])
    if not latencies:
        print(f"Skipping {output_file}: no latency data")
        return
    
    times, rps = calculate_rps_over_time(data.get('timestamps', []))
    percentiles = calculate_percentiles(latencies)
    
    # 1. Latency histogram (top left, spans 2 columns)
    ax1 = fig.add_subplot(gs[0, :2])
    ax1.hist(latencies, bins=50, edgecolor='black', alpha=0.7, color='#3498db')
    ax1.set_xlabel('Latency (ms)')
    ax1.set_ylabel('Count')
    ax1.set_title('Latency Distribution')
    if max(latencies) > 10:
        ax1.set_xscale('log')
    
    # 2. Key metrics (top right)
    ax2 = fig.add_subplot(gs[0, 2])
    ax2.axis('off')
    
    total = len(latencies)
    avg_lat = sum(latencies) / total if total else 0
    avg_rps_val = sum(rps) / len(rps) if rps else 0
    max_rps_val = max(rps) if rps else 0
    
    # Count errors
    proto_codes = data.get('proto_codes', [])
    errors = sum(1 for c in proto_codes if c >= 400 or c == 0)
    error_rate = (errors / total * 100) if total else 0
    
    metrics_text = f"""
    Total Requests: {total:,}
    
    Avg Latency: {avg_lat:.2f} ms
    P50 Latency: {percentiles['p50']:.2f} ms
    P95 Latency: {percentiles['p95']:.2f} ms
    P99 Latency: {percentiles['p99']:.2f} ms
    
    Avg RPS: {avg_rps_val:.1f}
    Max RPS: {max_rps_val:.1f}
    
    Error Rate: {error_rate:.2f}%
    """
    
    ax2.text(0.1, 0.9, metrics_text, transform=ax2.transAxes, fontsize=11,
             verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    ax2.set_title('Key Metrics')
    
    # 3. RPS over time (middle, spans all columns)
    ax3 = fig.add_subplot(gs[1, :])
    if times and rps:
        ax3.plot(times, rps, color='#2ecc71', linewidth=1.5)
        ax3.fill_between(times, rps, alpha=0.3, color='#2ecc71')
        ax3.axhline(y=avg_rps_val, color='red', linestyle='--', alpha=0.7, label=f'Avg: {avg_rps_val:.1f}')
        ax3.axhline(y=2000, color='blue', linestyle=':', alpha=0.7, label='Target: 2000')
        ax3.legend()
    ax3.set_xlabel('Time (seconds)')
    ax3.set_ylabel('Requests/Second')
    ax3.set_title('Throughput Over Time')
    ax3.grid(True, alpha=0.3)
    
    # 4. Response code distribution (bottom left)
    ax4 = fig.add_subplot(gs[2, 0])
    code_counts = {}
    for code in proto_codes:
        code_counts[code] = code_counts.get(code, 0) + 1
    
    categories = {
        '2xx': sum(v for k, v in code_counts.items() if 200 <= k < 300),
        '3xx': sum(v for k, v in code_counts.items() if 300 <= k < 400),
        '4xx': sum(v for k, v in code_counts.items() if 400 <= k < 500),
        '5xx': sum(v for k, v in code_counts.items() if 500 <= k < 600),
    }
    categories = {k: v for k, v in categories.items() if v > 0}
    
    if categories:
        colors = {'2xx': '#2ecc71', '3xx': '#3498db', '4xx': '#f39c12', '5xx': '#e74c3c'}
        pie_colors = [colors.get(k, '#95a5a6') for k in categories.keys()]
        ax4.pie(categories.values(), labels=categories.keys(), autopct='%1.1f%%',
                colors=pie_colors, startangle=90)
    ax4.set_title('Response Codes')
    
    # 5. Percentile bars (bottom middle)
    ax5 = fig.add_subplot(gs[2, 1])
    p_labels = ['p50', 'p90', 'p95', 'p99']
    p_values = [percentiles[p] for p in p_labels]
    colors = ['#2ecc71', '#f1c40f', '#e67e22', '#e74c3c']
    
    bars = ax5.bar(p_labels, p_values, color=colors)
    ax5.set_xlabel('Percentile')
    ax5.set_ylabel('Latency (ms)')
    ax5.set_title('Latency Percentiles')
    
    # Add value labels on bars
    for bar, val in zip(bars, p_values):
        ax5.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f'{val:.1f}', ha='center', va='bottom', fontsize=9)
    
    # 6. Latency over time (bottom right)
    ax6 = fig.add_subplot(gs[2, 2])
    
    # Calculate rolling average latency
    bucket_size = max(1, len(latencies) // 100)
    rolling_lat = []
    rolling_times = []
    
    for i in range(0, len(latencies), bucket_size):
        bucket = latencies[i:i+bucket_size]
        if bucket:
            rolling_lat.append(sum(bucket) / len(bucket))
            rolling_times.append(i / len(latencies) * (times[-1] if times else 1))
    
    if rolling_times and rolling_lat:
        ax6.plot(rolling_times, rolling_lat, color='#9b59b6', linewidth=1.5)
    ax6.set_xlabel('Time (seconds)')
    ax6.set_ylabel('Avg Latency (ms)')
    ax6.set_title('Latency Over Time')
    ax6.grid(True, alpha=0.3)
    
    # Main title
    fig.suptitle(title, fontsize=14, fontweight='bold', y=0.98)
    
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def generate_cross_test_summary(results_dir: str, output_file: str):
    """Generate a summary report comparing all test types."""
    if not HAS_MATPLOTLIB:
        print(f"Skipping {output_file}: matplotlib not available")
        return
    
    results_path = Path(results_dir)
    
    # Find all result directories
    test_results = {
        'http': [],
        'grpc': [],
        'websocket': [],
    }
    
    for subdir in results_path.iterdir():
        if not subdir.is_dir():
            continue
        
        name = subdir.name.lower()
        if 'http' in name:
            test_results['http'].append(subdir)
        elif 'grpc' in name:
            test_results['grpc'].append(subdir)
        elif 'websocket' in name or 'ws' in name:
            test_results['websocket'].append(subdir)
    
    # Parse results
    summary_data = []
    
    for test_type, dirs in test_results.items():
        for result_dir in dirs:
            result_file, file_type = find_results_file(str(result_dir))
            if not result_file:
                continue
            
            try:
                if file_type == 'phout':
                    data = parse_phout(result_file)
                    if data['latencies']:
                        percentiles = calculate_percentiles(data['latencies'])
                        times, rps = calculate_rps_over_time(data['timestamps'])
                        summary_data.append({
                            'name': result_dir.name,
                            'type': 'HTTP',
                            'count': len(data['latencies']),
                            'rps': sum(rps) / len(rps) if rps else 0,
                            'avg_latency': sum(data['latencies']) / len(data['latencies']),
                            'p95_latency': percentiles['p95'],
                            'p99_latency': percentiles['p99'],
                        })
                elif file_type == 'json':
                    with open(result_file, 'r') as f:
                        raw_data = json.load(f)
                    
                    if 'count' in raw_data and 'rps' in raw_data:
                        # ghz format
                        data = parse_ghz_json(result_file)
                        summary_data.append({
                            'name': result_dir.name,
                            'type': 'gRPC',
                            'count': data['count'],
                            'rps': data['rps'],
                            'avg_latency': data['average'],
                            'p95_latency': data['latency_distribution'].get('p95', 0),
                            'p99_latency': data['latency_distribution'].get('p99', 0),
                        })
                    elif 'metrics' in raw_data:
                        # k6 format
                        data = parse_k6_json(result_file)
                        summary_data.append({
                            'name': result_dir.name,
                            'type': 'WebSocket',
                            'count': data['count'],
                            'rps': data['rps'],
                            'avg_latency': data.get('average', 0),
                            'p95_latency': data['latency_distribution'].get('p95', 0),
                            'p99_latency': data['latency_distribution'].get('p99', 0),
                        })
            except Exception as e:
                print(f"Error parsing {result_dir}: {e}")
                continue
    
    if not summary_data:
        print("No test results found to summarize")
        return
    
    # Generate summary chart
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    # 1. RPS comparison
    ax = axes[0, 0]
    names = [d['name'][:30] for d in summary_data]
    rps_values = [d['rps'] for d in summary_data]
    colors = ['#3498db' if d['type'] == 'HTTP' else '#2ecc71' if d['type'] == 'gRPC' else '#9b59b6' 
              for d in summary_data]
    
    bars = ax.barh(names, rps_values, color=colors)
    ax.axvline(x=2000, color='red', linestyle='--', alpha=0.7, label='Target: 2000 RPS')
    ax.set_xlabel('Requests/Second')
    ax.set_title('Throughput Comparison')
    ax.legend()
    
    # 2. Latency comparison
    ax = axes[0, 1]
    x = range(len(summary_data))
    width = 0.25
    
    ax.bar([i - width for i in x], [d['avg_latency'] for d in summary_data], width, label='Avg', color='#3498db')
    ax.bar([i for i in x], [d['p95_latency'] for d in summary_data], width, label='P95', color='#f39c12')
    ax.bar([i + width for i in x], [d['p99_latency'] for d in summary_data], width, label='P99', color='#e74c3c')
    
    ax.set_xlabel('Test')
    ax.set_ylabel('Latency (ms)')
    ax.set_title('Latency Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels([d['name'][:15] for d in summary_data], rotation=45, ha='right')
    ax.legend()
    
    # 3. Test type distribution
    ax = axes[1, 0]
    type_counts = {}
    for d in summary_data:
        type_counts[d['type']] = type_counts.get(d['type'], 0) + 1
    
    colors = {'HTTP': '#3498db', 'gRPC': '#2ecc71', 'WebSocket': '#9b59b6'}
    ax.pie(type_counts.values(), labels=type_counts.keys(), autopct='%1.1f%%',
           colors=[colors.get(t, '#95a5a6') for t in type_counts.keys()], startangle=90)
    ax.set_title('Test Type Distribution')
    
    # 4. Summary table
    ax = axes[1, 1]
    ax.axis('off')
    
    table_data = [['Test', 'Type', 'Count', 'RPS', 'Avg (ms)', 'P95 (ms)']]
    for d in summary_data[:10]:  # Limit to 10 rows
        table_data.append([
            d['name'][:20],
            d['type'],
            f"{d['count']:,}",
            f"{d['rps']:.1f}",
            f"{d['avg_latency']:.2f}",
            f"{d['p95_latency']:.2f}",
        ])
    
    table = ax.table(cellText=table_data, loc='center', cellLoc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.2, 1.5)
    
    # Color header row
    for i in range(6):
        table[(0, i)].set_facecolor('#3498db')
        table[(0, i)].set_text_props(color='white', weight='bold')
    
    ax.set_title('Test Summary', pad=20)
    
    fig.suptitle('Cross-Test Performance Summary', fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def find_results_file(results_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Find the results file in the given directory."""
    results_dir = Path(results_dir)
    
    # Check for phout.txt (Yandex Tank)
    phout_files = list(results_dir.glob('**/phout*.log')) + list(results_dir.glob('**/phout*.txt'))
    if phout_files:
        return str(phout_files[0]), 'phout'
    
    # Check for JSON results (ghz or k6)
    json_files = list(results_dir.glob('**/*results*.json'))
    if json_files:
        return str(json_files[0]), 'json'
    
    return None, None


def main():
    parser = argparse.ArgumentParser(description='Generate performance test charts')
    parser.add_argument('results_dir', nargs='?', help='Results directory')
    parser.add_argument('--compare', nargs=2, metavar=('DIR1', 'DIR2'),
                       help='Compare two test runs')
    parser.add_argument('--summary', action='store_true',
                       help='Generate cross-test summary report')
    parser.add_argument('--output', '-o', help='Output directory')
    parser.add_argument('--format', '-f', choices=['png', 'svg', 'both'],
                       default='png', help='Output format')
    parser.add_argument('--all', '-a', action='store_true', help='Generate all charts')
    parser.add_argument('--latency', action='store_true', help='Generate latency chart')
    parser.add_argument('--rps', action='store_true', help='Generate RPS chart')
    parser.add_argument('--errors', action='store_true', help='Generate error chart')
    parser.add_argument('--dashboard', action='store_true', help='Generate summary dashboard')
    
    args = parser.parse_args()
    
    if not HAS_MATPLOTLIB:
        print("Error: matplotlib is required for chart generation")
        print("Install with: pip install matplotlib")
        sys.exit(1)
    
    # Handle summary mode
    if args.summary:
        if not args.results_dir:
            print("Error: results directory required for summary mode")
            sys.exit(1)
        
        output_dir = Path(args.output) if args.output else Path(args.results_dir) / 'charts'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        formats = ['png', 'svg'] if args.format == 'both' else [args.format]
        for fmt in formats:
            generate_cross_test_summary(args.results_dir, output_dir / f'cross_test_summary.{fmt}')
        return
    
    # Handle comparison mode
    if args.compare:
        dir1, dir2 = args.compare
        
        file1, type1 = find_results_file(dir1)
        file2, type2 = find_results_file(dir2)
        
        if not file1 or not file2:
            print(f"Error: Could not find results files in {dir1} or {dir2}")
            sys.exit(1)
        
        if type1 != 'phout' or type2 != 'phout':
            print("Error: Comparison only supported for Yandex Tank (phout) results")
            sys.exit(1)
        
        data1 = parse_phout(file1)
        data2 = parse_phout(file2)
        
        output_dir = Path(args.output) if args.output else Path(dir1) / 'charts'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        formats = ['png', 'svg'] if args.format == 'both' else [args.format]
        for fmt in formats:
            generate_comparison_chart(data1, data2, output_dir / f'comparison.{fmt}',
                                     label1=Path(dir1).name, label2=Path(dir2).name)
        return
    
    # Single results mode
    if not args.results_dir:
        parser.print_help()
        sys.exit(1)
    
    results_file, results_type = find_results_file(args.results_dir)
    
    if not results_file:
        print(f"Error: No results file found in {args.results_dir}")
        sys.exit(1)
    
    print(f"Found results file: {results_file} (type: {results_type})")
    
    # Determine output directory
    output_dir = Path(args.output) if args.output else Path(args.results_dir) / 'charts'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Determine which charts to generate
    generate_all = args.all or not (args.latency or args.rps or args.errors or args.dashboard)
    
    formats = ['png', 'svg'] if args.format == 'both' else [args.format]
    
    # Parse results based on type
    if results_type == 'phout':
        data = parse_phout(results_file)
        
        for fmt in formats:
            if generate_all or args.latency:
                generate_latency_histogram(data, output_dir / f'latency_distribution.{fmt}')
            
            if generate_all or args.rps:
                generate_rps_chart(data, output_dir / f'rps_over_time.{fmt}')
            
            if generate_all or args.errors:
                generate_error_chart(data, output_dir / f'response_codes.{fmt}')
            
            if generate_all or args.dashboard:
                generate_summary_dashboard(data, output_dir / f'summary_dashboard.{fmt}')
    
    elif results_type == 'json':
        with open(results_file, 'r') as f:
            raw_data = json.load(f)
        
        # Detect format (ghz vs k6)
        if 'count' in raw_data and 'rps' in raw_data:
            # ghz format (gRPC)
            data = parse_ghz_json(results_file)
            for fmt in formats:
                generate_grpc_chart(data, output_dir / f'grpc_results.{fmt}')
        elif 'metrics' in raw_data:
            # k6 format (WebSocket)
            data = parse_k6_json(results_file)
            for fmt in formats:
                generate_websocket_chart(data, output_dir / f'websocket_results.{fmt}')
        else:
            print("Warning: Unknown JSON format")
    
    print(f"\nCharts saved to: {output_dir}")


if __name__ == '__main__':
    main()
