#!/usr/bin/env python3
"""
Generate performance test charts from K8s comprehensive test results.
Creates visualizations for RPS, latency, and response codes.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
except ImportError:
    print("Installing required packages...")
    import subprocess

    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "matplotlib", "numpy"]
    )
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np


def load_summary(results_dir):
    """Load the summary.json file."""
    summary_path = Path(results_dir) / "summary.json"
    if not summary_path.exists():
        print(f"Error: {summary_path} not found")
        sys.exit(1)

    with open(summary_path) as f:
        return json.load(f)


def load_hey_results(results_dir, test_name):
    """Parse hey output file for detailed metrics."""
    result_file = Path(results_dir) / f"{test_name}.txt"
    if not result_file.exists():
        return None

    metrics = {
        "rps": 0,
        "avg_latency": 0,
        "p50_latency": 0,
        "p90_latency": 0,
        "p99_latency": 0,
        "status_2xx": 0,
        "status_4xx": 0,
        "status_5xx": 0,
        "total_requests": 0,
    }

    with open(result_file) as f:
        content = f.read()

        # Parse RPS
        for line in content.split("\n"):
            if "Requests/sec:" in line:
                try:
                    metrics["rps"] = float(line.split(":")[1].strip())
                except:
                    pass
            elif "Average:" in line and metrics["avg_latency"] == 0:
                try:
                    metrics["avg_latency"] = (
                        float(line.split()[1]) * 1000
                    )  # Convert to ms
                except:
                    pass
            elif "50%" in line and "in" not in line:
                try:
                    metrics["p50_latency"] = float(line.split()[1]) * 1000
                except:
                    pass
            elif "90%" in line and "in" not in line:
                try:
                    metrics["p90_latency"] = float(line.split()[1]) * 1000
                except:
                    pass
            elif "99%" in line and "in" not in line:
                try:
                    metrics["p99_latency"] = float(line.split()[1]) * 1000
                except:
                    pass
            elif "[200]" in line:
                try:
                    metrics["status_2xx"] = int(line.split()[0])
                except:
                    pass
            elif "[4" in line and "]" in line:
                try:
                    metrics["status_4xx"] += int(line.split()[0])
                except:
                    pass
            elif "[5" in line and "]" in line:
                try:
                    metrics["status_5xx"] += int(line.split()[0])
                except:
                    pass

    metrics["total_requests"] = (
        metrics["status_2xx"] + metrics["status_4xx"] + metrics["status_5xx"]
    )
    return metrics


def load_ghz_results(results_dir, test_name):
    """Parse ghz JSON output for gRPC metrics."""
    result_file = Path(results_dir) / f"{test_name}.json"
    if not result_file.exists():
        return None

    with open(result_file) as f:
        data = json.load(f)

    return {
        "rps": data.get("rps", 0),
        "avg_latency": data.get("average", 0) / 1_000_000,  # ns to ms
        "p50_latency": data.get("latencyDistribution", [{}])[4].get("latency", 0)
        / 1_000_000
        if len(data.get("latencyDistribution", [])) > 4
        else 0,
        "p90_latency": data.get("latencyDistribution", [{}])[8].get("latency", 0)
        / 1_000_000
        if len(data.get("latencyDistribution", [])) > 8
        else 0,
        "p99_latency": data.get("latencyDistribution", [{}])[9].get("latency", 0)
        / 1_000_000
        if len(data.get("latencyDistribution", [])) > 9
        else 0,
        "total_requests": data.get("count", 0),
        "status_ok": data.get("statusCodeDistribution", {}).get("OK", 0),
        "errors": data.get("errorDistribution", {}),
    }


def load_k6_results(results_dir, test_name):
    """Parse k6 JSON summary for WebSocket/GraphQL metrics."""
    result_file = Path(results_dir) / f"{test_name}.json"
    if not result_file.exists():
        return None

    with open(result_file) as f:
        data = json.load(f)

    metrics = data.get("metrics", {})

    return {
        "iterations": metrics.get("iterations", {}).get("values", {}).get("count", 0),
        "vus": metrics.get("vus", {}).get("values", {}).get("value", 0),
        "http_reqs": metrics.get("http_reqs", {}).get("values", {}).get("count", 0),
        "http_req_duration_avg": metrics.get("http_req_duration", {})
        .get("values", {})
        .get("avg", 0),
        "http_req_duration_p95": metrics.get("http_req_duration", {})
        .get("values", {})
        .get("p(95)", 0),
        "errors": metrics.get("errors", {}).get("values", {}).get("rate", 0),
    }


def create_rps_chart(summary, results_dir, output_dir):
    """Create RPS comparison chart."""
    tests = summary["tests"]

    # Filter tests with numeric RPS
    rps_data = []
    for test in tests:
        if test["rps"] != "N/A" and test["rps"] != "0":
            try:
                rps_data.append(
                    {
                        "name": test["name"],
                        "rps": float(test["rps"]),
                        "result": test["result"],
                    }
                )
            except:
                pass

    if not rps_data:
        print("No RPS data available for chart")
        return

    # Sort by RPS
    rps_data.sort(key=lambda x: x["rps"], reverse=True)

    # Create chart
    fig, ax = plt.subplots(figsize=(14, 8))

    names = [d["name"] for d in rps_data]
    rps_values = [d["rps"] for d in rps_data]
    colors = ["#2ecc71" if d["result"] == "PASS" else "#e74c3c" for d in rps_data]

    bars = ax.barh(names, rps_values, color=colors)

    # Add value labels
    for bar, rps in zip(bars, rps_values):
        ax.text(
            bar.get_width() + 50,
            bar.get_y() + bar.get_height() / 2,
            f"{rps:.0f}",
            va="center",
            fontsize=9,
        )

    ax.set_xlabel("Requests per Second (RPS)", fontsize=12)
    ax.set_title(
        "K8s Performance Test: RPS by Test Scenario", fontsize=14, fontweight="bold"
    )
    ax.set_xlim(0, max(rps_values) * 1.15)

    # Add legend
    pass_patch = mpatches.Patch(color="#2ecc71", label="PASS")
    fail_patch = mpatches.Patch(color="#e74c3c", label="FAIL")
    ax.legend(handles=[pass_patch, fail_patch], loc="lower right")

    plt.tight_layout()
    plt.savefig(output_dir / "rps_comparison.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Created: {output_dir / 'rps_comparison.png'}")


def create_latency_chart(summary, results_dir, output_dir):
    """Create latency comparison chart for HTTP tests."""
    http_tests = [
        t for t in summary["tests"] if t["name"].startswith(("http-", "https-"))
    ]

    latency_data = []
    for test in http_tests:
        metrics = load_hey_results(results_dir, test["name"])
        if metrics and metrics["avg_latency"] > 0:
            latency_data.append(
                {
                    "name": test["name"],
                    "avg": metrics["avg_latency"],
                    "p50": metrics["p50_latency"],
                    "p90": metrics["p90_latency"],
                    "p99": metrics["p99_latency"],
                }
            )

    if not latency_data:
        print("No latency data available for chart")
        return

    # Sort by avg latency
    latency_data.sort(key=lambda x: x["avg"])

    fig, ax = plt.subplots(figsize=(14, 8))

    names = [d["name"] for d in latency_data]
    x = np.arange(len(names))
    width = 0.2

    avg_vals = [d["avg"] for d in latency_data]
    p50_vals = [d["p50"] for d in latency_data]
    p90_vals = [d["p90"] for d in latency_data]
    p99_vals = [d["p99"] for d in latency_data]

    ax.barh(x - 1.5 * width, avg_vals, width, label="Avg", color="#3498db")
    ax.barh(x - 0.5 * width, p50_vals, width, label="P50", color="#2ecc71")
    ax.barh(x + 0.5 * width, p90_vals, width, label="P90", color="#f39c12")
    ax.barh(x + 1.5 * width, p99_vals, width, label="P99", color="#e74c3c")

    ax.set_yticks(x)
    ax.set_yticklabels(names)
    ax.set_xlabel("Latency (ms)", fontsize=12)
    ax.set_title(
        "K8s Performance Test: Latency Distribution by Test Scenario",
        fontsize=14,
        fontweight="bold",
    )
    ax.legend(loc="lower right")

    plt.tight_layout()
    plt.savefig(output_dir / "latency_comparison.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Created: {output_dir / 'latency_comparison.png'}")


def create_grpc_chart(summary, results_dir, output_dir):
    """Create gRPC performance chart."""
    grpc_tests = [t for t in summary["tests"] if "grpc" in t["name"].lower()]

    grpc_data = []
    for test in grpc_tests:
        metrics = load_ghz_results(results_dir, test["name"])
        if metrics and metrics["rps"] > 0:
            grpc_data.append(
                {
                    "name": test["name"],
                    "rps": metrics["rps"],
                    "avg_latency": metrics["avg_latency"],
                    "total": metrics["total_requests"],
                }
            )

    if not grpc_data:
        print("No gRPC data available for chart")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    names = [d["name"] for d in grpc_data]
    rps_vals = [d["rps"] for d in grpc_data]
    latency_vals = [d["avg_latency"] for d in grpc_data]

    # RPS chart
    bars1 = ax1.barh(names, rps_vals, color="#3498db")
    ax1.set_xlabel("Requests per Second (RPS)", fontsize=12)
    ax1.set_title("gRPC RPS", fontsize=12, fontweight="bold")
    for bar, rps in zip(bars1, rps_vals):
        ax1.text(
            bar.get_width() + 20,
            bar.get_y() + bar.get_height() / 2,
            f"{rps:.0f}",
            va="center",
            fontsize=9,
        )

    # Latency chart
    bars2 = ax2.barh(names, latency_vals, color="#e74c3c")
    ax2.set_xlabel("Average Latency (ms)", fontsize=12)
    ax2.set_title("gRPC Latency", fontsize=12, fontweight="bold")
    for bar, lat in zip(bars2, latency_vals):
        ax2.text(
            bar.get_width() + 0.2,
            bar.get_y() + bar.get_height() / 2,
            f"{lat:.2f}ms",
            va="center",
            fontsize=9,
        )

    plt.suptitle(
        "K8s Performance Test: gRPC Performance", fontsize=14, fontweight="bold"
    )
    plt.tight_layout()
    plt.savefig(output_dir / "grpc_performance.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Created: {output_dir / 'grpc_performance.png'}")


def create_test_category_chart(summary, output_dir):
    """Create test category summary chart."""
    categories = {
        "gRPC": {"pass": 0, "fail": 0, "skip": 0},
        "HTTP": {"pass": 0, "fail": 0, "skip": 0},
        "HTTPS": {"pass": 0, "fail": 0, "skip": 0},
        "GraphQL": {"pass": 0, "fail": 0, "skip": 0},
        "WebSocket": {"pass": 0, "fail": 0, "skip": 0},
    }

    for test in summary["tests"]:
        name = test["name"].lower()
        result = test["result"].lower()

        if "grpc" in name:
            cat = "gRPC"
        elif "graphql" in name:
            cat = "GraphQL"
        elif "websocket" in name:
            cat = "WebSocket"
        elif "https" in name:
            cat = "HTTPS"
        elif "http" in name:
            cat = "HTTP"
        else:
            continue

        categories[cat][result] += 1

    fig, ax = plt.subplots(figsize=(10, 6))

    cat_names = list(categories.keys())
    pass_vals = [categories[c]["pass"] for c in cat_names]
    fail_vals = [categories[c]["fail"] for c in cat_names]
    skip_vals = [categories[c]["skip"] for c in cat_names]

    x = np.arange(len(cat_names))
    width = 0.25

    ax.bar(x - width, pass_vals, width, label="PASS", color="#2ecc71")
    ax.bar(x, fail_vals, width, label="FAIL", color="#e74c3c")
    ax.bar(x + width, skip_vals, width, label="SKIP", color="#f39c12")

    ax.set_xticks(x)
    ax.set_xticklabels(cat_names)
    ax.set_ylabel("Number of Tests", fontsize=12)
    ax.set_title(
        "K8s Performance Test: Results by Category", fontsize=14, fontweight="bold"
    )
    ax.legend()

    # Add value labels
    for i, (p, f, s) in enumerate(zip(pass_vals, fail_vals, skip_vals)):
        if p > 0:
            ax.text(i - width, p + 0.1, str(p), ha="center", fontsize=10)
        if f > 0:
            ax.text(i, f + 0.1, str(f), ha="center", fontsize=10)
        if s > 0:
            ax.text(i + width, s + 0.1, str(s), ha="center", fontsize=10)

    plt.tight_layout()
    plt.savefig(output_dir / "category_summary.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Created: {output_dir / 'category_summary.png'}")


def create_summary_dashboard(summary, output_dir):
    """Create a summary dashboard with key metrics."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # Test results pie chart
    ax1 = axes[0, 0]
    results = {
        "PASS": summary["passed"],
        "FAIL": summary["failed"],
        "SKIP": summary["skipped"],
    }
    colors = ["#2ecc71", "#e74c3c", "#f39c12"]
    non_zero = [(k, v) for k, v in results.items() if v > 0]
    if non_zero:
        ax1.pie(
            [v for k, v in non_zero],
            labels=[k for k, v in non_zero],
            colors=[colors[["PASS", "FAIL", "SKIP"].index(k)] for k, v in non_zero],
            autopct="%1.1f%%",
            startangle=90,
        )
    ax1.set_title("Test Results Distribution", fontsize=12, fontweight="bold")

    # Top 10 RPS tests
    ax2 = axes[0, 1]
    rps_tests = [
        (t["name"], float(t["rps"]))
        for t in summary["tests"]
        if t["rps"] not in ["N/A", "0"]
    ]
    rps_tests.sort(key=lambda x: x[1], reverse=True)
    top_10 = rps_tests[:10]
    if top_10:
        names = [t[0][:20] + "..." if len(t[0]) > 20 else t[0] for t in top_10]
        values = [t[1] for t in top_10]
        ax2.barh(names, values, color="#3498db")
        ax2.set_xlabel("RPS")
        ax2.set_title("Top 10 Tests by RPS", fontsize=12, fontweight="bold")
        ax2.invert_yaxis()

    # Test duration distribution
    ax3 = axes[1, 0]
    durations = [t["duration"] for t in summary["tests"] if t["duration"] > 0]
    if durations:
        ax3.hist(durations, bins=20, color="#9b59b6", edgecolor="white")
        ax3.set_xlabel("Duration (seconds)")
        ax3.set_ylabel("Number of Tests")
        ax3.set_title("Test Duration Distribution", fontsize=12, fontweight="bold")

    # Summary text
    ax4 = axes[1, 1]
    ax4.axis("off")
    summary_text = f"""
    K8s Performance Test Summary
    ============================
    
    Timestamp: {summary["timestamp"]}
    Namespace: {summary["namespace"]}
    Gateway: {summary["gateway"]}
    
    Duration per test: {summary["duration_per_test"]}s
    Target RPS: {summary["target_rps"]}
    
    Results:
    - Passed: {summary["passed"]}
    - Failed: {summary["failed"]}
    - Skipped: {summary["skipped"]}
    - Total: {len(summary["tests"])}
    
    Success Rate: {summary["passed"] / len(summary["tests"]) * 100:.1f}%
    """
    ax4.text(
        0.1,
        0.9,
        summary_text,
        transform=ax4.transAxes,
        fontsize=11,
        verticalalignment="top",
        fontfamily="monospace",
        bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5),
    )

    plt.suptitle(
        "K8s Comprehensive Performance Test Dashboard", fontsize=16, fontweight="bold"
    )
    plt.tight_layout()
    plt.savefig(output_dir / "dashboard.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Created: {output_dir / 'dashboard.png'}")


def main():
    if len(sys.argv) < 2:
        # Find the latest results directory
        yandextank_dir = Path(__file__).parent.parent / ".yandextank"
        results_dirs = sorted(yandextank_dir.glob("k8s-comprehensive-*"), reverse=True)
        if not results_dirs:
            print("Usage: python generate-k8s-perftest-charts.py <results_dir>")
            print("No k8s-comprehensive-* directories found")
            sys.exit(1)
        results_dir = results_dirs[0]
        print(f"Using latest results: {results_dir}")
    else:
        results_dir = Path(sys.argv[1])

    if not results_dir.exists():
        print(f"Error: {results_dir} does not exist")
        sys.exit(1)

    # Create charts directory
    charts_dir = results_dir / "charts"
    charts_dir.mkdir(exist_ok=True)

    # Load summary
    summary = load_summary(results_dir)
    print(
        f"Loaded summary: {summary['passed']} passed, {summary['failed']} failed, {summary['skipped']} skipped"
    )

    # Generate charts
    print("\nGenerating charts...")
    create_summary_dashboard(summary, charts_dir)
    create_rps_chart(summary, results_dir, charts_dir)
    create_latency_chart(summary, results_dir, charts_dir)
    create_grpc_chart(summary, results_dir, charts_dir)
    create_test_category_chart(summary, charts_dir)

    print(f"\nAll charts saved to: {charts_dir}")


if __name__ == "__main__":
    main()
