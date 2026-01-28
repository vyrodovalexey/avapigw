#!/usr/bin/env python3
"""
Generate performance charts for new features tests.

This script analyzes phout.txt files from Yandex Tank and generates
visualizations for max sessions, backend rate limiting, and capacity-aware
load balancer performance tests.

Usage:
    python generate-new-features-charts.py <results_dir> [--output <output_dir>]
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    import numpy as np
except ImportError:
    print("Error: matplotlib and numpy are required.")
    print("Install with: pip install matplotlib numpy")
    sys.exit(1)


def parse_phout(phout_path):
    """Parse phout.txt file and return structured data."""
    data = {
        'timestamps': [],
        'latencies': [],
        'connect_times': [],
        'http_codes': [],
        'net_codes': [],
        'sizes': [],
    }
    
    with open(phout_path, 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 12:
                continue
            
            try:
                timestamp = float(parts[0])
                interval_real = int(parts[2]) / 1000  # Convert to ms
                connect_time = int(parts[3]) / 1000
                http_code = int(parts[11])
                net_code = int(parts[10])
                size_in = int(parts[9])
                
                data['timestamps'].append(timestamp)
                data['latencies'].append(interval_real)
                data['connect_times'].append(connect_time)
                data['http_codes'].append(http_code)
                data['net_codes'].append(net_code)
                data['sizes'].append(size_in)
            except (ValueError, IndexError):
                continue
    
    return data


def calculate_percentiles(values, percentiles=[50, 90, 95, 99]):
    """Calculate percentiles for a list of values."""
    if not values:
        return {p: 0 for p in percentiles}
    
    sorted_values = sorted(values)
    result = {}
    for p in percentiles:
        idx = int(len(sorted_values) * p / 100)
        result[p] = sorted_values[min(idx, len(sorted_values) - 1)]
    return result


def calculate_rps_over_time(timestamps, window_size=1):
    """Calculate RPS over time with given window size in seconds."""
    if not timestamps:
        return [], []
    
    min_ts = int(min(timestamps))
    max_ts = int(max(timestamps))
    
    rps_times = []
    rps_values = []
    
    for ts in range(min_ts, max_ts + 1, window_size):
        count = sum(1 for t in timestamps if ts <= t < ts + window_size)
        rps_times.append(datetime.fromtimestamp(ts))
        rps_values.append(count / window_size)
    
    return rps_times, rps_values


def calculate_latency_over_time(timestamps, latencies, window_size=5):
    """Calculate average latency over time with given window size."""
    if not timestamps or not latencies:
        return [], [], [], []
    
    min_ts = int(min(timestamps))
    max_ts = int(max(timestamps))
    
    times = []
    avg_latencies = []
    p95_latencies = []
    p99_latencies = []
    
    for ts in range(min_ts, max_ts + 1, window_size):
        window_latencies = [
            lat for t, lat in zip(timestamps, latencies)
            if ts <= t < ts + window_size
        ]
        
        if window_latencies:
            times.append(datetime.fromtimestamp(ts))
            avg_latencies.append(np.mean(window_latencies))
            percentiles = calculate_percentiles(window_latencies, [95, 99])
            p95_latencies.append(percentiles[95])
            p99_latencies.append(percentiles[99])
    
    return times, avg_latencies, p95_latencies, p99_latencies


def calculate_error_rate_over_time(timestamps, http_codes, net_codes, window_size=5):
    """Calculate error rate over time."""
    if not timestamps:
        return [], []
    
    min_ts = int(min(timestamps))
    max_ts = int(max(timestamps))
    
    times = []
    error_rates = []
    
    for ts in range(min_ts, max_ts + 1, window_size):
        window_codes = [
            (http, net) for t, http, net in zip(timestamps, http_codes, net_codes)
            if ts <= t < ts + window_size
        ]
        
        if window_codes:
            errors = sum(1 for http, net in window_codes if http >= 400 or net != 0)
            times.append(datetime.fromtimestamp(ts))
            error_rates.append(errors / len(window_codes) * 100)
    
    return times, error_rates


def calculate_http_code_distribution(http_codes):
    """Calculate HTTP code distribution."""
    distribution = defaultdict(int)
    for code in http_codes:
        if code < 200:
            distribution['1xx'] += 1
        elif code < 300:
            distribution['2xx'] += 1
        elif code < 400:
            distribution['3xx'] += 1
        elif code < 500:
            distribution['4xx'] += 1
        else:
            distribution['5xx'] += 1
    return dict(distribution)


def generate_summary_chart(data, output_path, test_name):
    """Generate a summary chart with multiple subplots."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(f'Performance Test Results: {test_name}', fontsize=14, fontweight='bold')
    
    # 1. RPS over time
    ax1 = axes[0, 0]
    rps_times, rps_values = calculate_rps_over_time(data['timestamps'])
    if rps_times:
        ax1.plot(rps_times, rps_values, 'b-', linewidth=1)
        ax1.fill_between(rps_times, rps_values, alpha=0.3)
        ax1.set_xlabel('Time')
        ax1.set_ylabel('Requests per Second')
        ax1.set_title('Throughput Over Time')
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax1.grid(True, alpha=0.3)
    
    # 2. Latency over time
    ax2 = axes[0, 1]
    times, avg_lat, p95_lat, p99_lat = calculate_latency_over_time(
        data['timestamps'], data['latencies']
    )
    if times:
        ax2.plot(times, avg_lat, 'g-', label='Average', linewidth=1)
        ax2.plot(times, p95_lat, 'orange', label='P95', linewidth=1)
        ax2.plot(times, p99_lat, 'r-', label='P99', linewidth=1)
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Latency (ms)')
        ax2.set_title('Latency Over Time')
        ax2.legend(loc='upper right')
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax2.grid(True, alpha=0.3)
    
    # 3. Error rate over time
    ax3 = axes[1, 0]
    err_times, err_rates = calculate_error_rate_over_time(
        data['timestamps'], data['http_codes'], data['net_codes']
    )
    if err_times:
        ax3.plot(err_times, err_rates, 'r-', linewidth=1)
        ax3.fill_between(err_times, err_rates, alpha=0.3, color='red')
        ax3.set_xlabel('Time')
        ax3.set_ylabel('Error Rate (%)')
        ax3.set_title('Error Rate Over Time')
        ax3.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax3.grid(True, alpha=0.3)
        ax3.set_ylim(bottom=0)
    
    # 4. HTTP code distribution
    ax4 = axes[1, 1]
    distribution = calculate_http_code_distribution(data['http_codes'])
    if distribution:
        colors = {'1xx': 'gray', '2xx': 'green', '3xx': 'blue', '4xx': 'orange', '5xx': 'red'}
        labels = list(distribution.keys())
        values = list(distribution.values())
        bar_colors = [colors.get(l, 'gray') for l in labels]
        ax4.bar(labels, values, color=bar_colors)
        ax4.set_xlabel('HTTP Status Code')
        ax4.set_ylabel('Count')
        ax4.set_title('HTTP Response Code Distribution')
        
        # Add percentage labels
        total = sum(values)
        for i, (label, value) in enumerate(zip(labels, values)):
            pct = value / total * 100
            ax4.text(i, value + total * 0.01, f'{pct:.1f}%', ha='center', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"Generated: {output_path}")


def generate_latency_histogram(data, output_path, test_name):
    """Generate latency distribution histogram."""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    latencies = data['latencies']
    if not latencies:
        return
    
    # Create histogram with log scale for x-axis
    bins = np.logspace(np.log10(max(0.1, min(latencies))), 
                       np.log10(max(latencies)), 50)
    ax.hist(latencies, bins=bins, edgecolor='black', alpha=0.7)
    ax.set_xscale('log')
    
    # Add percentile lines
    percentiles = calculate_percentiles(latencies, [50, 90, 95, 99])
    colors = {50: 'green', 90: 'blue', 95: 'orange', 99: 'red'}
    for p, value in percentiles.items():
        ax.axvline(x=value, color=colors[p], linestyle='--', 
                   label=f'P{p}: {value:.1f}ms')
    
    ax.set_xlabel('Latency (ms)')
    ax.set_ylabel('Count')
    ax.set_title(f'Latency Distribution: {test_name}')
    ax.legend(loc='upper right')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"Generated: {output_path}")


def generate_max_sessions_chart(data, output_path):
    """Generate chart specific to max sessions test."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Max Sessions Performance Analysis', fontsize=14, fontweight='bold')
    
    # 1. RPS vs 503 errors (session limit reached)
    ax1 = axes[0, 0]
    rps_times, rps_values = calculate_rps_over_time(data['timestamps'])
    
    # Calculate 503 rate over time
    times_503 = []
    rate_503 = []
    min_ts = int(min(data['timestamps']))
    max_ts = int(max(data['timestamps']))
    
    for ts in range(min_ts, max_ts + 1, 5):
        window_codes = [
            code for t, code in zip(data['timestamps'], data['http_codes'])
            if ts <= t < ts + 5
        ]
        if window_codes:
            times_503.append(datetime.fromtimestamp(ts))
            rate_503.append(sum(1 for c in window_codes if c == 503) / len(window_codes) * 100)
    
    if rps_times:
        ax1_twin = ax1.twinx()
        ax1.plot(rps_times, rps_values, 'b-', label='RPS', linewidth=1)
        ax1_twin.plot(times_503, rate_503, 'r-', label='503 Rate', linewidth=1)
        ax1.set_xlabel('Time')
        ax1.set_ylabel('RPS', color='blue')
        ax1_twin.set_ylabel('503 Error Rate (%)', color='red')
        ax1.set_title('RPS vs Session Limit Errors')
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax1.grid(True, alpha=0.3)
    
    # 2. Latency impact of queuing
    ax2 = axes[0, 1]
    times, avg_lat, p95_lat, p99_lat = calculate_latency_over_time(
        data['timestamps'], data['latencies']
    )
    if times:
        ax2.plot(times, avg_lat, 'g-', label='Average', linewidth=1)
        ax2.plot(times, p95_lat, 'orange', label='P95', linewidth=1)
        ax2.plot(times, p99_lat, 'r-', label='P99', linewidth=1)
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Latency (ms)')
        ax2.set_title('Latency Impact (Queue Wait Time)')
        ax2.legend(loc='upper right')
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax2.grid(True, alpha=0.3)
    
    # 3. Success rate over time
    ax3 = axes[1, 0]
    success_times = []
    success_rates = []
    
    for ts in range(min_ts, max_ts + 1, 5):
        window_codes = [
            code for t, code in zip(data['timestamps'], data['http_codes'])
            if ts <= t < ts + 5
        ]
        if window_codes:
            success_times.append(datetime.fromtimestamp(ts))
            success_rates.append(sum(1 for c in window_codes if 200 <= c < 300) / len(window_codes) * 100)
    
    if success_times:
        ax3.plot(success_times, success_rates, 'g-', linewidth=1)
        ax3.fill_between(success_times, success_rates, alpha=0.3, color='green')
        ax3.set_xlabel('Time')
        ax3.set_ylabel('Success Rate (%)')
        ax3.set_title('Request Success Rate')
        ax3.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax3.grid(True, alpha=0.3)
        ax3.set_ylim(0, 105)
    
    # 4. Response code breakdown
    ax4 = axes[1, 1]
    distribution = calculate_http_code_distribution(data['http_codes'])
    if distribution:
        colors = {'1xx': 'gray', '2xx': 'green', '3xx': 'blue', '4xx': 'orange', '5xx': 'red'}
        labels = list(distribution.keys())
        values = list(distribution.values())
        bar_colors = [colors.get(l, 'gray') for l in labels]
        ax4.bar(labels, values, color=bar_colors)
        ax4.set_xlabel('HTTP Status Code')
        ax4.set_ylabel('Count')
        ax4.set_title('Response Code Distribution')
        
        total = sum(values)
        for i, (label, value) in enumerate(zip(labels, values)):
            pct = value / total * 100
            ax4.text(i, value + total * 0.01, f'{pct:.1f}%', ha='center', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"Generated: {output_path}")


def generate_rate_limit_chart(data, output_path):
    """Generate chart specific to backend rate limit test."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Backend Rate Limit Performance Analysis', fontsize=14, fontweight='bold')
    
    min_ts = int(min(data['timestamps']))
    max_ts = int(max(data['timestamps']))
    
    # 1. RPS vs 429 errors (rate limited)
    ax1 = axes[0, 0]
    rps_times, rps_values = calculate_rps_over_time(data['timestamps'])
    
    times_429 = []
    rate_429 = []
    
    for ts in range(min_ts, max_ts + 1, 5):
        window_codes = [
            code for t, code in zip(data['timestamps'], data['http_codes'])
            if ts <= t < ts + 5
        ]
        if window_codes:
            times_429.append(datetime.fromtimestamp(ts))
            rate_429.append(sum(1 for c in window_codes if c == 429) / len(window_codes) * 100)
    
    if rps_times:
        ax1_twin = ax1.twinx()
        ax1.plot(rps_times, rps_values, 'b-', label='RPS', linewidth=1)
        ax1_twin.plot(times_429, rate_429, 'r-', label='429 Rate', linewidth=1)
        ax1.set_xlabel('Time')
        ax1.set_ylabel('RPS', color='blue')
        ax1_twin.set_ylabel('429 Error Rate (%)', color='red')
        ax1.set_title('RPS vs Rate Limit Errors')
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax1.grid(True, alpha=0.3)
    
    # 2. Effective throughput (successful requests only)
    ax2 = axes[0, 1]
    success_times = []
    success_rps = []
    
    for ts in range(min_ts, max_ts + 1, 1):
        window_codes = [
            code for t, code in zip(data['timestamps'], data['http_codes'])
            if ts <= t < ts + 1
        ]
        if window_codes:
            success_times.append(datetime.fromtimestamp(ts))
            success_rps.append(sum(1 for c in window_codes if 200 <= c < 300))
    
    if success_times:
        ax2.plot(success_times, success_rps, 'g-', linewidth=1)
        ax2.fill_between(success_times, success_rps, alpha=0.3, color='green')
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Successful RPS')
        ax2.set_title('Effective Throughput (Successful Requests)')
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax2.grid(True, alpha=0.3)
    
    # 3. Latency for successful vs rate-limited requests
    ax3 = axes[1, 0]
    success_latencies = [lat for lat, code in zip(data['latencies'], data['http_codes']) if 200 <= code < 300]
    limited_latencies = [lat for lat, code in zip(data['latencies'], data['http_codes']) if code == 429]
    
    if success_latencies or limited_latencies:
        box_data = []
        labels = []
        if success_latencies:
            box_data.append(success_latencies)
            labels.append('Successful')
        if limited_latencies:
            box_data.append(limited_latencies)
            labels.append('Rate Limited')
        
        bp = ax3.boxplot(box_data, labels=labels, patch_artist=True)
        colors = ['green', 'red']
        for patch, color in zip(bp['boxes'], colors[:len(box_data)]):
            patch.set_facecolor(color)
            patch.set_alpha(0.5)
        ax3.set_ylabel('Latency (ms)')
        ax3.set_title('Latency Comparison')
        ax3.grid(True, alpha=0.3)
    
    # 4. Response code breakdown
    ax4 = axes[1, 1]
    distribution = calculate_http_code_distribution(data['http_codes'])
    if distribution:
        colors = {'1xx': 'gray', '2xx': 'green', '3xx': 'blue', '4xx': 'orange', '5xx': 'red'}
        labels = list(distribution.keys())
        values = list(distribution.values())
        bar_colors = [colors.get(l, 'gray') for l in labels]
        ax4.bar(labels, values, color=bar_colors)
        ax4.set_xlabel('HTTP Status Code')
        ax4.set_ylabel('Count')
        ax4.set_title('Response Code Distribution')
        
        total = sum(values)
        for i, (label, value) in enumerate(zip(labels, values)):
            pct = value / total * 100
            ax4.text(i, value + total * 0.01, f'{pct:.1f}%', ha='center', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"Generated: {output_path}")


def generate_capacity_lb_chart(data, output_path):
    """Generate chart specific to capacity-aware load balancer test."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Capacity-Aware Load Balancer Performance Analysis', fontsize=14, fontweight='bold')
    
    min_ts = int(min(data['timestamps']))
    max_ts = int(max(data['timestamps']))
    
    # 1. RPS vs capacity errors
    ax1 = axes[0, 0]
    rps_times, rps_values = calculate_rps_over_time(data['timestamps'])
    
    times_503 = []
    rate_503 = []
    
    for ts in range(min_ts, max_ts + 1, 5):
        window_codes = [
            code for t, code in zip(data['timestamps'], data['http_codes'])
            if ts <= t < ts + 5
        ]
        if window_codes:
            times_503.append(datetime.fromtimestamp(ts))
            rate_503.append(sum(1 for c in window_codes if c == 503) / len(window_codes) * 100)
    
    if rps_times:
        ax1_twin = ax1.twinx()
        ax1.plot(rps_times, rps_values, 'b-', label='RPS', linewidth=1)
        ax1_twin.plot(times_503, rate_503, 'r-', label='503 Rate', linewidth=1)
        ax1.set_xlabel('Time')
        ax1.set_ylabel('RPS', color='blue')
        ax1_twin.set_ylabel('Capacity Error Rate (%)', color='red')
        ax1.set_title('RPS vs Capacity Errors')
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax1.grid(True, alpha=0.3)
    
    # 2. Latency percentiles over time
    ax2 = axes[0, 1]
    times, avg_lat, p95_lat, p99_lat = calculate_latency_over_time(
        data['timestamps'], data['latencies']
    )
    if times:
        ax2.plot(times, avg_lat, 'g-', label='Average', linewidth=1)
        ax2.plot(times, p95_lat, 'orange', label='P95', linewidth=1)
        ax2.plot(times, p99_lat, 'r-', label='P99', linewidth=1)
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Latency (ms)')
        ax2.set_title('Latency Over Time')
        ax2.legend(loc='upper right')
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax2.grid(True, alpha=0.3)
    
    # 3. Success rate over time
    ax3 = axes[1, 0]
    success_times = []
    success_rates = []
    
    for ts in range(min_ts, max_ts + 1, 5):
        window_codes = [
            code for t, code in zip(data['timestamps'], data['http_codes'])
            if ts <= t < ts + 5
        ]
        if window_codes:
            success_times.append(datetime.fromtimestamp(ts))
            success_rates.append(sum(1 for c in window_codes if 200 <= c < 300) / len(window_codes) * 100)
    
    if success_times:
        ax3.plot(success_times, success_rates, 'g-', linewidth=1)
        ax3.fill_between(success_times, success_rates, alpha=0.3, color='green')
        ax3.set_xlabel('Time')
        ax3.set_ylabel('Success Rate (%)')
        ax3.set_title('Request Success Rate')
        ax3.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax3.grid(True, alpha=0.3)
        ax3.set_ylim(0, 105)
    
    # 4. Response code breakdown
    ax4 = axes[1, 1]
    distribution = calculate_http_code_distribution(data['http_codes'])
    if distribution:
        colors = {'1xx': 'gray', '2xx': 'green', '3xx': 'blue', '4xx': 'orange', '5xx': 'red'}
        labels = list(distribution.keys())
        values = list(distribution.values())
        bar_colors = [colors.get(l, 'gray') for l in labels]
        ax4.bar(labels, values, color=bar_colors)
        ax4.set_xlabel('HTTP Status Code')
        ax4.set_ylabel('Count')
        ax4.set_title('Response Code Distribution')
        
        total = sum(values)
        for i, (label, value) in enumerate(zip(labels, values)):
            pct = value / total * 100
            ax4.text(i, value + total * 0.01, f'{pct:.1f}%', ha='center', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"Generated: {output_path}")


def generate_comparison_chart(results_dirs, output_path):
    """Generate comparison chart for multiple test runs."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Performance Comparison', fontsize=14, fontweight='bold')
    
    test_names = []
    avg_latencies = []
    p95_latencies = []
    p99_latencies = []
    error_rates = []
    throughputs = []
    
    for results_dir in results_dirs:
        phout_path = Path(results_dir) / 'phout.txt'
        if not phout_path.exists():
            continue
        
        data = parse_phout(phout_path)
        if not data['timestamps']:
            continue
        
        test_name = Path(results_dir).name
        test_names.append(test_name[:20])  # Truncate long names
        
        avg_latencies.append(np.mean(data['latencies']))
        percentiles = calculate_percentiles(data['latencies'], [95, 99])
        p95_latencies.append(percentiles[95])
        p99_latencies.append(percentiles[99])
        
        errors = sum(1 for c in data['http_codes'] if c >= 400)
        error_rates.append(errors / len(data['http_codes']) * 100)
        
        duration = max(data['timestamps']) - min(data['timestamps'])
        throughputs.append(len(data['timestamps']) / max(duration, 1))
    
    if not test_names:
        print("No valid results found for comparison")
        return
    
    x = np.arange(len(test_names))
    width = 0.25
    
    # 1. Latency comparison
    ax1 = axes[0, 0]
    ax1.bar(x - width, avg_latencies, width, label='Average', color='green')
    ax1.bar(x, p95_latencies, width, label='P95', color='orange')
    ax1.bar(x + width, p99_latencies, width, label='P99', color='red')
    ax1.set_xlabel('Test')
    ax1.set_ylabel('Latency (ms)')
    ax1.set_title('Latency Comparison')
    ax1.set_xticks(x)
    ax1.set_xticklabels(test_names, rotation=45, ha='right')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # 2. Error rate comparison
    ax2 = axes[0, 1]
    colors = ['green' if r < 1 else 'orange' if r < 5 else 'red' for r in error_rates]
    ax2.bar(test_names, error_rates, color=colors)
    ax2.set_xlabel('Test')
    ax2.set_ylabel('Error Rate (%)')
    ax2.set_title('Error Rate Comparison')
    ax2.set_xticklabels(test_names, rotation=45, ha='right')
    ax2.grid(True, alpha=0.3)
    
    # 3. Throughput comparison
    ax3 = axes[1, 0]
    ax3.bar(test_names, throughputs, color='blue')
    ax3.set_xlabel('Test')
    ax3.set_ylabel('Throughput (RPS)')
    ax3.set_title('Throughput Comparison')
    ax3.set_xticklabels(test_names, rotation=45, ha='right')
    ax3.grid(True, alpha=0.3)
    
    # 4. Summary table
    ax4 = axes[1, 1]
    ax4.axis('off')
    
    table_data = []
    for i, name in enumerate(test_names):
        table_data.append([
            name,
            f'{avg_latencies[i]:.1f}',
            f'{p95_latencies[i]:.1f}',
            f'{error_rates[i]:.2f}%',
            f'{throughputs[i]:.0f}'
        ])
    
    table = ax4.table(
        cellText=table_data,
        colLabels=['Test', 'Avg Lat', 'P95 Lat', 'Error Rate', 'RPS'],
        loc='center',
        cellLoc='center'
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.5)
    ax4.set_title('Summary', pad=20)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"Generated: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Generate performance charts')
    parser.add_argument('results_dir', help='Results directory containing phout.txt')
    parser.add_argument('--output', '-o', help='Output directory for charts')
    parser.add_argument('--test-type', '-t', 
                        choices=['max-sessions', 'backend-ratelimit', 'capacity-lb', 'generic'],
                        default='generic',
                        help='Type of test for specialized charts')
    parser.add_argument('--compare', '-c', nargs='+', 
                        help='Additional results directories for comparison')
    
    args = parser.parse_args()
    
    results_dir = Path(args.results_dir)
    output_dir = Path(args.output) if args.output else results_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    
    phout_path = results_dir / 'phout.txt'
    if not phout_path.exists():
        # Try to find phout.txt in subdirectories
        phout_files = list(results_dir.rglob('phout.txt'))
        if phout_files:
            phout_path = phout_files[0]
        else:
            print(f"Error: phout.txt not found in {results_dir}")
            sys.exit(1)
    
    print(f"Parsing: {phout_path}")
    data = parse_phout(phout_path)
    
    if not data['timestamps']:
        print("Error: No data found in phout.txt")
        sys.exit(1)
    
    print(f"Parsed {len(data['timestamps'])} requests")
    
    test_name = results_dir.name
    
    # Generate summary chart
    generate_summary_chart(data, output_dir / 'summary.png', test_name)
    
    # Generate latency histogram
    generate_latency_histogram(data, output_dir / 'latency_histogram.png', test_name)
    
    # Generate test-specific charts
    if args.test_type == 'max-sessions' or 'max-sessions' in test_name.lower():
        generate_max_sessions_chart(data, output_dir / 'max_sessions_analysis.png')
    elif args.test_type == 'backend-ratelimit' or 'ratelimit' in test_name.lower():
        generate_rate_limit_chart(data, output_dir / 'rate_limit_analysis.png')
    elif args.test_type == 'capacity-lb' or 'capacity' in test_name.lower():
        generate_capacity_lb_chart(data, output_dir / 'capacity_lb_analysis.png')
    
    # Generate comparison chart if multiple directories provided
    if args.compare:
        all_dirs = [str(results_dir)] + args.compare
        generate_comparison_chart(all_dirs, output_dir / 'comparison.png')
    
    print(f"\nCharts generated in: {output_dir}")


if __name__ == '__main__':
    main()
