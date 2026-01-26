#!/usr/bin/env python3
"""
Generate charts for gRPC performance test results (ghz JSON format)
"""

import json
import os
import sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("Error: matplotlib and numpy are required")
    sys.exit(1)


def load_ghz_results(json_file):
    """Load ghz JSON results file."""
    with open(json_file, 'r') as f:
        return json.load(f)


def generate_latency_chart(data, output_file, title):
    """Generate latency distribution chart from ghz results."""
    latency_dist = data.get('latencyDistribution', [])
    if not latency_dist:
        print(f"No latency distribution data for {title}")
        return
    
    percentiles = [d['percentage'] for d in latency_dist]
    latencies = [d['latency'] / 1e6 for d in latency_dist]  # Convert ns to ms
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    colors = ['#2ecc71', '#27ae60', '#f1c40f', '#e67e22', '#e74c3c', '#c0392b', '#8e44ad']
    bars = ax.bar([f'p{p}' for p in percentiles], latencies, color=colors[:len(percentiles)])
    
    ax.set_xlabel('Percentile')
    ax.set_ylabel('Latency (ms)')
    ax.set_title(title)
    ax.grid(True, alpha=0.3, axis='y')
    
    # Add value labels on bars
    for bar, val in zip(bars, latencies):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f'{val:.2f}', ha='center', va='bottom', fontsize=9)
    
    # Add summary stats
    avg = data.get('average', 0) / 1e6
    fastest = data.get('fastest', 0) / 1e6
    slowest = data.get('slowest', 0) / 1e6
    
    stats_text = f"Avg: {avg:.2f}ms\nMin: {fastest:.2f}ms\nMax: {slowest:.2f}ms"
    ax.text(0.98, 0.98, stats_text, transform=ax.transAxes, fontsize=10,
            verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    plt.close()
    print(f"Generated: {output_file}")


def generate_summary_chart(data, output_file, title):
    """Generate summary dashboard for ghz results."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # 1. Latency percentiles (top left)
    ax = axes[0, 0]
    latency_dist = data.get('latencyDistribution', [])
    if latency_dist:
        percentiles = [d['percentage'] for d in latency_dist]
        latencies = [d['latency'] / 1e6 for d in latency_dist]
        colors = ['#2ecc71', '#27ae60', '#f1c40f', '#e67e22', '#e74c3c', '#c0392b', '#8e44ad']
        ax.bar([f'p{p}' for p in percentiles], latencies, color=colors[:len(percentiles)])
        ax.set_xlabel('Percentile')
        ax.set_ylabel('Latency (ms)')
        ax.set_title('Latency Percentiles')
        ax.grid(True, alpha=0.3, axis='y')
    
    # 2. Status code distribution (top right)
    ax = axes[0, 1]
    status_dist = data.get('statusCodeDistribution', {})
    if status_dist:
        codes = list(status_dist.keys())
        counts = list(status_dist.values())
        colors = ['#2ecc71' if c == 'OK' else '#e74c3c' for c in codes]
        ax.pie(counts, labels=codes, autopct='%1.1f%%', colors=colors, startangle=90)
        ax.set_title('Status Code Distribution')
    
    # 3. Key metrics (bottom left)
    ax = axes[1, 0]
    ax.axis('off')
    
    count = data.get('count', 0)
    rps = data.get('rps', 0)
    avg = data.get('average', 0) / 1e6
    fastest = data.get('fastest', 0) / 1e6
    slowest = data.get('slowest', 0) / 1e6
    
    # Get percentile values
    p50 = p90 = p95 = p99 = 0
    for d in latency_dist:
        if d['percentage'] == 50:
            p50 = d['latency'] / 1e6
        elif d['percentage'] == 90:
            p90 = d['latency'] / 1e6
        elif d['percentage'] == 95:
            p95 = d['latency'] / 1e6
        elif d['percentage'] == 99:
            p99 = d['latency'] / 1e6
    
    metrics_text = f"""
    Total Requests: {count:,}
    RPS: {rps:.2f}
    
    Latency (ms):
      Average: {avg:.2f}
      Min: {fastest:.2f}
      Max: {slowest:.2f}
      P50: {p50:.2f}
      P90: {p90:.2f}
      P95: {p95:.2f}
      P99: {p99:.2f}
    """
    
    ax.text(0.1, 0.9, metrics_text, transform=ax.transAxes, fontsize=12,
            verticalalignment='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    ax.set_title('Key Metrics')
    
    # 4. Error distribution (bottom right)
    ax = axes[1, 1]
    error_dist = data.get('errorDistribution', {})
    if error_dist:
        errors = list(error_dist.keys())
        counts = list(error_dist.values())
        # Truncate long error messages
        errors = [e[:50] + '...' if len(e) > 50 else e for e in errors]
        ax.barh(errors, counts, color='#e74c3c')
        ax.set_xlabel('Count')
        ax.set_title('Error Distribution')
    else:
        ax.text(0.5, 0.5, 'No Errors', transform=ax.transAxes, fontsize=14,
                ha='center', va='center')
        ax.set_title('Error Distribution')
        ax.axis('off')
    
    fig.suptitle(title, fontsize=14, fontweight='bold', y=0.98)
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Generated: {output_file}")


def main():
    # Get the script's directory and navigate to results
    script_dir = Path(__file__).parent.parent
    results_dir = script_dir / 'results'
    charts_dir = results_dir / 'charts'
    charts_dir.mkdir(parents=True, exist_ok=True)
    
    # Process each gRPC result file
    grpc_files = [
        ('grpc-unary-results.json', 'gRPC Unary Test'),
        ('grpc-server-streaming-results.json', 'gRPC Server Streaming Test'),
        ('grpc-bidi-streaming-results.json', 'gRPC Bidirectional Streaming Test'),
    ]
    
    for filename, title in grpc_files:
        filepath = results_dir / filename
        if filepath.exists():
            print(f"\nProcessing {filename}...")
            data = load_ghz_results(filepath)
            
            # Generate latency chart
            latency_file = charts_dir / f'{filename.replace("-results.json", "-latency.png")}'
            generate_latency_chart(data, latency_file, f'{title} - Latency Distribution')
            
            # Generate summary chart
            summary_file = charts_dir / f'{filename.replace("-results.json", "-summary.png")}'
            generate_summary_chart(data, summary_file, f'{title} - Summary')
        else:
            print(f"File not found: {filepath}")
    
    print(f"\nCharts saved to: {charts_dir}")


if __name__ == '__main__':
    main()
