#!/bin/bash
# start-gateway.sh - Start the gateway for performance testing
# Usage: ./start-gateway.sh [options]
#
# Options:
#   --config=<file>   - Gateway config file (default: gateway-perftest.yaml)
#   --build           - Force rebuild before starting
#   --foreground      - Run in foreground (don't daemonize)
#   --log-level=<lvl> - Log level (debug, info, warn, error)
#   --stop            - Stop running gateway

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$(dirname "$PERF_DIR")")"

# Default values
CONFIG_FILE="$PERF_DIR/configs/gateway-perftest.yaml"
FORCE_BUILD=false
FOREGROUND=false
LOG_LEVEL="warn"
STOP_GATEWAY=false
PID_FILE="$PERF_DIR/results/.gateway.pid"
LOG_FILE="$PERF_DIR/results/gateway.log"

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --config=*)
            CONFIG_FILE="${1#*=}"
            shift
            ;;
        --build)
            FORCE_BUILD=true
            shift
            ;;
        --foreground)
            FOREGROUND=true
            shift
            ;;
        --log-level=*)
            LOG_LEVEL="${1#*=}"
            shift
            ;;
        --stop)
            STOP_GATEWAY=true
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

# Stop gateway
stop_gateway() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping gateway (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            
            # Wait for process to stop
            local count=0
            while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
                sleep 1
                ((count++))
            done
            
            if kill -0 "$pid" 2>/dev/null; then
                log_warn "Gateway didn't stop gracefully, forcing..."
                kill -9 "$pid" 2>/dev/null || true
            fi
            
            rm -f "$PID_FILE"
            log_success "Gateway stopped"
        else
            log_info "Gateway process not running"
            rm -f "$PID_FILE"
        fi
    else
        log_info "No PID file found"
        
        # Try to find and kill any running gateway
        local pids=$(pgrep -f "gateway.*gateway-perftest" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            log_info "Found gateway processes: $pids"
            echo "$pids" | xargs kill 2>/dev/null || true
            log_success "Gateway processes stopped"
        fi
    fi
}

# Check if gateway is running
is_gateway_running() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Build gateway
build_gateway() {
    log_info "Building gateway..."
    cd "$PROJECT_ROOT"
    make build
    log_success "Gateway built successfully"
}

# Start gateway
start_gateway() {
    # Create results directory if needed
    mkdir -p "$PERF_DIR/results"
    
    # Check if already running
    if is_gateway_running; then
        log_warn "Gateway is already running"
        return 0
    fi
    
    # Check config file
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Config file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Build if needed
    if [ "$FORCE_BUILD" = true ] || [ ! -f "$PROJECT_ROOT/bin/gateway" ]; then
        build_gateway
    fi
    
    cd "$PROJECT_ROOT"
    
    log_info "Starting gateway..."
    log_info "Config: $CONFIG_FILE"
    log_info "Log level: $LOG_LEVEL"
    
    if [ "$FOREGROUND" = true ]; then
        log_info "Running in foreground (Ctrl+C to stop)"
        ./bin/gateway -config "$CONFIG_FILE" -log-level "$LOG_LEVEL"
    else
        # Start in background
        nohup ./bin/gateway -config "$CONFIG_FILE" -log-level "$LOG_LEVEL" > "$LOG_FILE" 2>&1 &
        local pid=$!
        echo $pid > "$PID_FILE"
        
        log_info "Gateway started with PID: $pid"
        log_info "Log file: $LOG_FILE"
        
        # Wait for gateway to be ready
        log_info "Waiting for gateway to be ready..."
        local count=0
        while ! curl -s -o /dev/null http://127.0.0.1:8080/health 2>/dev/null && [ $count -lt 30 ]; do
            sleep 1
            ((count++))
            
            # Check if process is still running
            if ! kill -0 "$pid" 2>/dev/null; then
                log_error "Gateway process died unexpectedly"
                log_error "Check log file: $LOG_FILE"
                cat "$LOG_FILE"
                exit 1
            fi
        done
        
        if curl -s -o /dev/null http://127.0.0.1:8080/health 2>/dev/null; then
            log_success "Gateway is ready and accepting connections"
            
            # Show endpoints
            echo ""
            log_info "Gateway endpoints:"
            echo "  HTTP:    http://127.0.0.1:8080"
            echo "  gRPC:    127.0.0.1:9000"
            echo "  Metrics: http://127.0.0.1:9090/metrics"
            echo "  Health:  http://127.0.0.1:8080/health"
        else
            log_error "Gateway failed to start within 30 seconds"
            log_error "Check log file: $LOG_FILE"
            exit 1
        fi
    fi
}

# Show status
show_status() {
    echo ""
    log_info "Gateway Status"
    echo "============================================"
    
    if is_gateway_running; then
        local pid=$(cat "$PID_FILE")
        echo "Status: Running (PID: $pid)"
        
        # Check health
        local health=$(curl -s http://127.0.0.1:8080/health 2>/dev/null || echo "unavailable")
        echo "Health: $health"
        
        # Show resource usage
        if command -v ps &> /dev/null; then
            echo ""
            echo "Resource Usage:"
            ps -p "$pid" -o pid,ppid,%cpu,%mem,rss,vsz,etime,command 2>/dev/null || true
        fi
    else
        echo "Status: Not running"
    fi
    
    echo "============================================"
}

# Main
main() {
    if [ "$STOP_GATEWAY" = true ]; then
        stop_gateway
        exit 0
    fi
    
    start_gateway
    show_status
}

main
