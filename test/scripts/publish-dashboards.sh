#!/usr/bin/env bash
#
# publish-dashboards.sh - Publish Grafana dashboards from monitoring/grafana/ to a Grafana instance
#
# Usage:
#   ./publish-dashboards.sh [options]
#
# Options:
#   --grafana-url=<url>       Grafana URL (default: http://127.0.0.1:3000)
#   --grafana-user=<user>     Grafana username (default: admin)
#   --grafana-password=<pass> Grafana password (default: admin)
#   --dashboard-dir=<dir>     Dashboard directory (default: monitoring/grafana)
#   --folder=<name>           Target folder name (default: avapigw)
#   --verify                  Only verify dashboards, don't publish
#   --dry-run                 Show what would be done without making changes
#   --help                    Show this help message
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
GRAFANA_URL="http://127.0.0.1:3000"
GRAFANA_USER="admin"
GRAFANA_PASSWORD="admin"
DASHBOARD_DIR="monitoring/grafana"
FOLDER_NAME="avapigw"
VERIFY_ONLY=false
DRY_RUN=false

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show help
show_help() {
    sed -n '3,17p' "$0" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --grafana-url=*)
                GRAFANA_URL="${1#*=}"
                shift
                ;;
            --grafana-user=*)
                GRAFANA_USER="${1#*=}"
                shift
                ;;
            --grafana-password=*)
                GRAFANA_PASSWORD="${1#*=}"
                shift
                ;;
            --dashboard-dir=*)
                DASHBOARD_DIR="${1#*=}"
                shift
                ;;
            --folder=*)
                FOLDER_NAME="${1#*=}"
                shift
                ;;
            --verify)
                VERIFY_ONLY=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                ;;
        esac
    done
}

# Check if required tools are available
check_dependencies() {
    local missing=()
    
    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing+=("jq")
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
}

# Check Grafana connectivity
check_grafana() {
    log_info "Checking Grafana connectivity at ${GRAFANA_URL}..."
    
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        "${GRAFANA_URL}/api/health" 2>/dev/null || echo "000")
    
    if [[ "$response" != "200" ]]; then
        log_error "Cannot connect to Grafana at ${GRAFANA_URL} (HTTP ${response})"
        log_error "Make sure Grafana is running and credentials are correct"
        exit 1
    fi
    
    log_success "Grafana is accessible"
}

# Get or create folder
# Returns folder ID via stdout, logs to stderr
get_or_create_folder() {
    local folder_name="$1"
    local folder_id
    
    log_info "Getting or creating folder '${folder_name}'..." >&2
    
    # Try to get existing folder
    local folders_response
    folders_response=$(curl -s \
        -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        "${GRAFANA_URL}/api/folders" 2>/dev/null)
    
    folder_id=$(echo "$folders_response" | jq -r ".[] | select(.title == \"${folder_name}\") | .id" 2>/dev/null || echo "")
    
    if [[ -n "$folder_id" && "$folder_id" != "null" ]]; then
        log_info "Found existing folder '${folder_name}' with ID ${folder_id}" >&2
        echo "$folder_id"
        return
    fi
    
    # Create new folder
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would create folder '${folder_name}'" >&2
        echo "0"
        return
    fi
    
    local create_response
    create_response=$(curl -s \
        -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -H "Content-Type: application/json" \
        -X POST \
        -d "{\"title\": \"${folder_name}\"}" \
        "${GRAFANA_URL}/api/folders" 2>/dev/null)
    
    folder_id=$(echo "$create_response" | jq -r '.id' 2>/dev/null || echo "")
    
    if [[ -z "$folder_id" || "$folder_id" == "null" ]]; then
        log_error "Failed to create folder '${folder_name}'" >&2
        log_error "Response: ${create_response}" >&2
        exit 1
    fi
    
    log_success "Created folder '${folder_name}' with ID ${folder_id}" >&2
    echo "$folder_id"
}

# Publish a single dashboard
publish_dashboard() {
    local dashboard_file="$1"
    local folder_id="$2"
    local filename
    filename=$(basename "$dashboard_file")
    
    log_info "Processing dashboard: ${filename}"
    
    # Validate JSON
    if ! jq empty "$dashboard_file" 2>/dev/null; then
        log_error "Invalid JSON in ${filename}"
        return 1
    fi
    
    # Ensure folder_id is a valid number
    if [[ -z "$folder_id" || "$folder_id" == "null" ]]; then
        folder_id="0"
    fi
    
    # Get dashboard UID and title
    local uid title
    uid=$(jq -r '.uid // empty' "$dashboard_file")
    title=$(jq -r '.title // empty' "$dashboard_file")
    
    if [[ -z "$uid" ]]; then
        log_warning "Dashboard ${filename} has no UID, skipping"
        return 1
    fi
    
    if [[ -z "$title" ]]; then
        log_warning "Dashboard ${filename} has no title, skipping"
        return 1
    fi
    
    log_info "  UID: ${uid}"
    log_info "  Title: ${title}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would publish dashboard '${title}' (${uid})"
        return 0
    fi
    
    # Prepare the import payload using a temp file to avoid command line length issues
    local temp_file
    temp_file=$(mktemp)
    trap "rm -f '$temp_file'" RETURN
    
    # Build the payload JSON
    jq --argjson folderId "$folder_id" \
        '{
            dashboard: (. | .id = null),
            folderId: $folderId,
            overwrite: true,
            message: "Published by publish-dashboards.sh"
        }' "$dashboard_file" > "$temp_file"
    
    if [[ ! -s "$temp_file" ]]; then
        log_error "Failed to prepare payload for '${title}'"
        return 1
    fi
    
    # Import dashboard
    local response http_code
    response=$(curl -s -w "\n%{http_code}" \
        -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -H "Content-Type: application/json" \
        -X POST \
        -d "@${temp_file}" \
        "${GRAFANA_URL}/api/dashboards/db" 2>/dev/null)
    
    http_code=$(echo "$response" | tail -n1)
    response=$(echo "$response" | sed '$d')
    
    if [[ "$http_code" != "200" ]]; then
        log_error "Failed to publish dashboard '${title}' (HTTP ${http_code})"
        log_error "Response: ${response}"
        return 1
    fi
    
    local status
    status=$(echo "$response" | jq -r '.status // empty')
    
    if [[ "$status" == "success" ]]; then
        log_success "Published dashboard '${title}' (${uid})"
        return 0
    else
        log_error "Failed to publish dashboard '${title}'"
        log_error "Response: ${response}"
        return 1
    fi
}

# Verify a single dashboard
verify_dashboard() {
    local dashboard_file="$1"
    local filename
    filename=$(basename "$dashboard_file")
    
    # Validate JSON
    if ! jq empty "$dashboard_file" 2>/dev/null; then
        log_error "Invalid JSON in ${filename}"
        return 1
    fi
    
    # Get dashboard UID
    local uid title
    uid=$(jq -r '.uid // empty' "$dashboard_file")
    title=$(jq -r '.title // empty' "$dashboard_file")
    
    if [[ -z "$uid" ]]; then
        log_warning "Dashboard ${filename} has no UID, skipping verification"
        return 1
    fi
    
    log_info "Verifying dashboard: ${title} (${uid})"
    
    # Check if dashboard exists in Grafana
    local response http_code
    response=$(curl -s -w "\n%{http_code}" \
        -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        "${GRAFANA_URL}/api/dashboards/uid/${uid}" 2>/dev/null)
    
    http_code=$(echo "$response" | tail -n1)
    response=$(echo "$response" | sed '$d')
    
    if [[ "$http_code" == "200" ]]; then
        local remote_title
        remote_title=$(echo "$response" | jq -r '.dashboard.title // empty')
        log_success "Dashboard '${title}' (${uid}) exists in Grafana as '${remote_title}'"
        return 0
    elif [[ "$http_code" == "404" ]]; then
        log_warning "Dashboard '${title}' (${uid}) not found in Grafana"
        return 1
    else
        log_error "Failed to verify dashboard '${title}' (HTTP ${http_code})"
        return 1
    fi
}

# Main function
main() {
    parse_args "$@"
    check_dependencies
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Resolve dashboard directory
    local dashboard_path="${DASHBOARD_DIR}"
    if [[ ! -d "$dashboard_path" ]]; then
        log_error "Dashboard directory not found: ${dashboard_path}"
        exit 1
    fi
    
    # Find all JSON files
    local dashboard_files=()
    while IFS= read -r -d '' file; do
        # Skip .gitkeep and other non-dashboard files
        if [[ "$(basename "$file")" == ".gitkeep" ]]; then
            continue
        fi
        dashboard_files+=("$file")
    done < <(find "$dashboard_path" -maxdepth 1 -name "*.json" -type f -print0 | sort -z)
    
    if [[ ${#dashboard_files[@]} -eq 0 ]]; then
        log_warning "No dashboard files found in ${dashboard_path}"
        exit 0
    fi
    
    log_info "Found ${#dashboard_files[@]} dashboard(s) in ${dashboard_path}"
    
    # Check Grafana connectivity
    check_grafana
    
    local success_count=0
    local fail_count=0
    
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        # Verify mode
        log_info "Running in verify mode..."
        echo ""
        
        for dashboard_file in "${dashboard_files[@]}"; do
            if verify_dashboard "$dashboard_file"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        done
    else
        # Publish mode
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "Running in dry-run mode..."
        else
            log_info "Publishing dashboards..."
        fi
        echo ""
        
        # Get or create folder
        local folder_id
        folder_id=$(get_or_create_folder "$FOLDER_NAME")
        echo ""
        
        for dashboard_file in "${dashboard_files[@]}"; do
            if publish_dashboard "$dashboard_file" "$folder_id"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
            echo ""
        done
    fi
    
    # Print summary
    echo ""
    echo "========================================"
    log_info "Summary:"
    log_success "  Successful: ${success_count}"
    if [[ $fail_count -gt 0 ]]; then
        log_error "  Failed: ${fail_count}"
    else
        log_info "  Failed: ${fail_count}"
    fi
    echo "========================================"
    
    if [[ $fail_count -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
