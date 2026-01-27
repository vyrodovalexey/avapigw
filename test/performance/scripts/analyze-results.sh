#!/bin/bash
# analyze-results.sh - Analyze Yandex Tank test results
# Usage: ./analyze-results.sh <results-dir> [options]
#
# Options:
#   --summary         - Show brief summary only
#   --detailed        - Show detailed analysis
#   --export=<format> - Export results (json, csv)
#   --compare=<dir>   - Compare with another test run

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(dirname "$SCRIPT_DIR")"

# Arguments
RESULTS_DIR="${1:-}"
SUMMARY_ONLY=false
DETAILED=false
EXPORT_FORMAT=""
COMPARE_DIR=""

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --summary)
            SUMMARY_ONLY=true
            shift
            ;;
        --detailed)
            DETAILED=true
            shift
            ;;
        --export=*)
            EXPORT_FORMAT="${1#*=}"
            shift
            ;;
        --compare=*)
            COMPARE_DIR="${1#*=}"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if results directory exists
check_results_dir() {
    if [ -z "$RESULTS_DIR" ]; then
        # Find latest results
        RESULTS_DIR=$(ls -td "$PERF_DIR/results"/*/ 2>/dev/null | head -1)
        if [ -z "$RESULTS_DIR" ]; then
            log_error "No results directory specified and no results found"
            exit 1
        fi
        log_info "Using latest results: $RESULTS_DIR"
    fi
    
    if [ ! -d "$RESULTS_DIR" ]; then
        log_error "Results directory not found: $RESULTS_DIR"
        exit 1
    fi
}

# Parse phout.txt file
parse_phout() {
    local phout_file="$RESULTS_DIR/phout.txt"
    
    if [ ! -f "$phout_file" ]; then
        # Search for phout_*.log files (Yandex Tank naming convention)
        phout_file=$(find "$RESULTS_DIR" -name "phout_*.log" -o -name "phout*.log" -o -name "phout*.txt" 2>/dev/null | head -1)
        if [ -z "$phout_file" ] || [ ! -f "$phout_file" ]; then
            log_warn "phout file not found in $RESULTS_DIR"
            return 1
        fi
    fi
    
    log_info "Parsing $phout_file..."
    
    # phout.txt format:
    # timestamp tag interval_real connect_time send_time latency receive_time interval_event size_out size_in net_code proto_code
    
    # Calculate statistics using awk
    awk '
    BEGIN {
        total = 0
        errors = 0
        sum_latency = 0
        min_latency = 999999999
        max_latency = 0
        sum_connect = 0
        http_2xx = 0
        http_3xx = 0
        http_4xx = 0
        http_5xx = 0
        net_errors = 0
    }
    {
        total++
        latency = $4 / 1000  # Convert to ms
        connect = $5 / 1000
        proto_code = $12
        net_code = $11
        
        sum_latency += latency
        sum_connect += connect
        
        if (latency < min_latency) min_latency = latency
        if (latency > max_latency) max_latency = latency
        
        # Store for percentile calculation
        latencies[total] = latency
        
        # Count HTTP codes
        if (proto_code >= 200 && proto_code < 300) http_2xx++
        else if (proto_code >= 300 && proto_code < 400) http_3xx++
        else if (proto_code >= 400 && proto_code < 500) http_4xx++
        else if (proto_code >= 500) http_5xx++
        
        # Count network errors
        if (net_code != 0) net_errors++
        
        # Count errors
        if (proto_code >= 400 || net_code != 0) errors++
    }
    END {
        if (total == 0) {
            print "No data found"
            exit 1
        }
        
        avg_latency = sum_latency / total
        avg_connect = sum_connect / total
        error_rate = (errors / total) * 100
        
        # Sort latencies for percentiles
        n = asort(latencies)
        p50 = latencies[int(n * 0.50)]
        p90 = latencies[int(n * 0.90)]
        p95 = latencies[int(n * 0.95)]
        p99 = latencies[int(n * 0.99)]
        
        printf "TOTAL_REQUESTS=%d\n", total
        printf "ERRORS=%d\n", errors
        printf "ERROR_RATE=%.2f\n", error_rate
        printf "AVG_LATENCY=%.2f\n", avg_latency
        printf "MIN_LATENCY=%.2f\n", min_latency
        printf "MAX_LATENCY=%.2f\n", max_latency
        printf "P50_LATENCY=%.2f\n", p50
        printf "P90_LATENCY=%.2f\n", p90
        printf "P95_LATENCY=%.2f\n", p95
        printf "P99_LATENCY=%.2f\n", p99
        printf "AVG_CONNECT=%.2f\n", avg_connect
        printf "HTTP_2XX=%d\n", http_2xx
        printf "HTTP_3XX=%d\n", http_3xx
        printf "HTTP_4XX=%d\n", http_4xx
        printf "HTTP_5XX=%d\n", http_5xx
        printf "NET_ERRORS=%d\n", net_errors
    }
    ' "$phout_file"
}

# Display summary
display_summary() {
    local stats=$(parse_phout)
    
    if [ -z "$stats" ]; then
        log_error "Failed to parse results"
        return 1
    fi
    
    # Parse stats into variables
    eval "$stats"
    
    echo ""
    echo "============================================"
    echo -e "${CYAN}  Performance Test Results Summary${NC}"
    echo "============================================"
    echo ""
    echo -e "${BLUE}Request Statistics:${NC}"
    printf "  Total Requests:    %'d\n" "$TOTAL_REQUESTS"
    printf "  Successful:        %'d (%.1f%%)\n" "$HTTP_2XX" "$(echo "scale=1; $HTTP_2XX * 100 / $TOTAL_REQUESTS" | bc)"
    printf "  Errors:            %'d (%.2f%%)\n" "$ERRORS" "$ERROR_RATE"
    echo ""
    echo -e "${BLUE}Response Codes:${NC}"
    printf "  2xx (Success):     %'d\n" "$HTTP_2XX"
    printf "  3xx (Redirect):    %'d\n" "$HTTP_3XX"
    printf "  4xx (Client Err):  %'d\n" "$HTTP_4XX"
    printf "  5xx (Server Err):  %'d\n" "$HTTP_5XX"
    printf "  Network Errors:    %'d\n" "$NET_ERRORS"
    echo ""
    echo -e "${BLUE}Latency (ms):${NC}"
    printf "  Average:           %.2f ms\n" "$AVG_LATENCY"
    printf "  Minimum:           %.2f ms\n" "$MIN_LATENCY"
    printf "  Maximum:           %.2f ms\n" "$MAX_LATENCY"
    printf "  P50 (Median):      %.2f ms\n" "$P50_LATENCY"
    printf "  P90:               %.2f ms\n" "$P90_LATENCY"
    printf "  P95:               %.2f ms\n" "$P95_LATENCY"
    printf "  P99:               %.2f ms\n" "$P99_LATENCY"
    echo ""
    echo -e "${BLUE}Connection:${NC}"
    printf "  Avg Connect Time:  %.2f ms\n" "$AVG_CONNECT"
    echo ""
    
    # Determine overall status
    if (( $(echo "$ERROR_RATE < 1" | bc -l) )) && (( $(echo "$P95_LATENCY < 500" | bc -l) )); then
        echo -e "${GREEN}Status: PASSED${NC} - Error rate < 1% and P95 latency < 500ms"
    elif (( $(echo "$ERROR_RATE < 5" | bc -l) )) && (( $(echo "$P95_LATENCY < 1000" | bc -l) )); then
        echo -e "${YELLOW}Status: WARNING${NC} - Performance is acceptable but could be improved"
    else
        echo -e "${RED}Status: FAILED${NC} - Error rate >= 5% or P95 latency >= 1000ms"
    fi
    
    echo "============================================"
}

# Display detailed analysis
display_detailed() {
    display_summary
    
    echo ""
    echo "============================================"
    echo -e "${CYAN}  Detailed Analysis${NC}"
    echo "============================================"
    
    # Calculate RPS over time
    local phout_file="$RESULTS_DIR/phout.txt"
    
    if [ -f "$phout_file" ]; then
        echo ""
        echo -e "${BLUE}Throughput Over Time (RPS):${NC}"
        
        awk '
        {
            timestamp = int($1)
            requests[timestamp]++
        }
        END {
            n = asorti(requests, sorted)
            
            # Show first 10 and last 10 seconds
            print "  First 10 seconds:"
            for (i = 1; i <= 10 && i <= n; i++) {
                printf "    %s: %d RPS\n", sorted[i], requests[sorted[i]]
            }
            
            if (n > 20) {
                print "  ..."
                print "  Last 10 seconds:"
                for (i = n - 9; i <= n; i++) {
                    printf "    %s: %d RPS\n", sorted[i], requests[sorted[i]]
                }
            }
            
            # Calculate average RPS
            total = 0
            for (ts in requests) total += requests[ts]
            avg_rps = total / n
            printf "\n  Average RPS: %.2f\n", avg_rps
            
            # Find peak RPS
            max_rps = 0
            for (ts in requests) {
                if (requests[ts] > max_rps) max_rps = requests[ts]
            }
            printf "  Peak RPS: %d\n", max_rps
        }
        ' "$phout_file"
    fi
    
    # Show latency distribution
    echo ""
    echo -e "${BLUE}Latency Distribution:${NC}"
    
    awk '
    {
        latency = $4 / 1000  # Convert to ms
        
        if (latency < 10) bucket["0-10ms"]++
        else if (latency < 50) bucket["10-50ms"]++
        else if (latency < 100) bucket["50-100ms"]++
        else if (latency < 200) bucket["100-200ms"]++
        else if (latency < 500) bucket["200-500ms"]++
        else if (latency < 1000) bucket["500ms-1s"]++
        else bucket[">1s"]++
        
        total++
    }
    END {
        buckets[1] = "0-10ms"
        buckets[2] = "10-50ms"
        buckets[3] = "50-100ms"
        buckets[4] = "100-200ms"
        buckets[5] = "200-500ms"
        buckets[6] = "500ms-1s"
        buckets[7] = ">1s"
        
        for (i = 1; i <= 7; i++) {
            b = buckets[i]
            count = bucket[b] + 0
            pct = (count / total) * 100
            bar = ""
            for (j = 0; j < pct / 2; j++) bar = bar "#"
            printf "  %-12s %6d (%5.1f%%) %s\n", b, count, pct, bar
        }
    }
    ' "$phout_file"
    
    echo "============================================"
}

# Export results
export_results() {
    local format=$1
    local stats=$(parse_phout)
    
    if [ -z "$stats" ]; then
        log_error "Failed to parse results for export"
        return 1
    fi
    
    eval "$stats"
    
    local output_file="$RESULTS_DIR/results.$format"
    
    case $format in
        json)
            cat > "$output_file" << EOF
{
  "summary": {
    "total_requests": $TOTAL_REQUESTS,
    "errors": $ERRORS,
    "error_rate": $ERROR_RATE
  },
  "response_codes": {
    "2xx": $HTTP_2XX,
    "3xx": $HTTP_3XX,
    "4xx": $HTTP_4XX,
    "5xx": $HTTP_5XX,
    "network_errors": $NET_ERRORS
  },
  "latency_ms": {
    "average": $AVG_LATENCY,
    "minimum": $MIN_LATENCY,
    "maximum": $MAX_LATENCY,
    "p50": $P50_LATENCY,
    "p90": $P90_LATENCY,
    "p95": $P95_LATENCY,
    "p99": $P99_LATENCY
  },
  "connection": {
    "avg_connect_time_ms": $AVG_CONNECT
  }
}
EOF
            ;;
        csv)
            cat > "$output_file" << EOF
metric,value
total_requests,$TOTAL_REQUESTS
errors,$ERRORS
error_rate,$ERROR_RATE
http_2xx,$HTTP_2XX
http_3xx,$HTTP_3XX
http_4xx,$HTTP_4XX
http_5xx,$HTTP_5XX
network_errors,$NET_ERRORS
avg_latency_ms,$AVG_LATENCY
min_latency_ms,$MIN_LATENCY
max_latency_ms,$MAX_LATENCY
p50_latency_ms,$P50_LATENCY
p90_latency_ms,$P90_LATENCY
p95_latency_ms,$P95_LATENCY
p99_latency_ms,$P99_LATENCY
avg_connect_time_ms,$AVG_CONNECT
EOF
            ;;
        *)
            log_error "Unknown export format: $format"
            return 1
            ;;
    esac
    
    log_success "Results exported to: $output_file"
}

# Compare two test runs
compare_results() {
    local dir1="$RESULTS_DIR"
    local dir2="$COMPARE_DIR"
    
    if [ ! -d "$dir2" ]; then
        log_error "Comparison directory not found: $dir2"
        return 1
    fi
    
    log_info "Comparing results..."
    
    # Parse both results
    local stats1=$(RESULTS_DIR="$dir1" parse_phout)
    local stats2=$(RESULTS_DIR="$dir2" parse_phout)
    
    # Create temporary files for comparison
    echo "$stats1" > /tmp/stats1.txt
    echo "$stats2" > /tmp/stats2.txt
    
    source /tmp/stats1.txt
    local total1=$TOTAL_REQUESTS
    local errors1=$ERRORS
    local avg_lat1=$AVG_LATENCY
    local p95_lat1=$P95_LATENCY
    
    source /tmp/stats2.txt
    local total2=$TOTAL_REQUESTS
    local errors2=$ERRORS
    local avg_lat2=$AVG_LATENCY
    local p95_lat2=$P95_LATENCY
    
    echo ""
    echo "============================================"
    echo -e "${CYAN}  Results Comparison${NC}"
    echo "============================================"
    echo ""
    printf "%-20s %15s %15s %10s\n" "Metric" "Run 1" "Run 2" "Change"
    echo "------------------------------------------------------------"
    
    # Compare metrics
    local diff_total=$(echo "scale=1; ($total2 - $total1) * 100 / $total1" | bc)
    printf "%-20s %15d %15d %+9.1f%%\n" "Total Requests" "$total1" "$total2" "$diff_total"
    
    local diff_errors=$(echo "scale=1; ($errors2 - $errors1) * 100 / ($errors1 + 1)" | bc)
    printf "%-20s %15d %15d %+9.1f%%\n" "Errors" "$errors1" "$errors2" "$diff_errors"
    
    local diff_avg=$(echo "scale=1; ($avg_lat2 - $avg_lat1) * 100 / $avg_lat1" | bc)
    printf "%-20s %12.2f ms %12.2f ms %+9.1f%%\n" "Avg Latency" "$avg_lat1" "$avg_lat2" "$diff_avg"
    
    local diff_p95=$(echo "scale=1; ($p95_lat2 - $p95_lat1) * 100 / $p95_lat1" | bc)
    printf "%-20s %12.2f ms %12.2f ms %+9.1f%%\n" "P95 Latency" "$p95_lat1" "$p95_lat2" "$diff_p95"
    
    echo "============================================"
    
    # Cleanup
    rm -f /tmp/stats1.txt /tmp/stats2.txt
}

# Show help
show_help() {
    cat << EOF
Yandex Tank Results Analyzer

Usage: $0 <results-dir> [options]

Options:
  --summary         Show brief summary only
  --detailed        Show detailed analysis
  --export=<format> Export results (json, csv)
  --compare=<dir>   Compare with another test run

Examples:
  $0 results/http-throughput_20240101_120000/
  $0 results/http-throughput_20240101_120000/ --detailed
  $0 results/run1/ --compare=results/run2/
  $0 --export=json

EOF
}

# Main
main() {
    if [ "$1" = "help" ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_help
        exit 0
    fi
    
    check_results_dir
    
    if [ -n "$EXPORT_FORMAT" ]; then
        export_results "$EXPORT_FORMAT"
    fi
    
    if [ -n "$COMPARE_DIR" ]; then
        compare_results
    elif [ "$DETAILED" = true ]; then
        display_detailed
    else
        display_summary
    fi
}

main "$@"
