#!/bin/bash
# generate-ammo.sh - Generate ammo files for Yandex Tank
# Usage: ./generate-ammo.sh [type] [options]
#
# Types:
#   get       - Generate GET request ammo (URI-style)
#   post      - Generate POST request ammo (request-style)
#   mixed     - Generate mixed workload ammo
#   custom    - Generate custom ammo from template
#
# Options:
#   --count=<n>       - Number of requests to generate (default: 100)
#   --output=<file>   - Output file path
#   --base-url=<url>  - Base URL for requests

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AMMO_DIR="$(dirname "$SCRIPT_DIR")/ammo"

# Default values
AMMO_TYPE="${1:-get}"
COUNT=100
OUTPUT_FILE=""
BASE_URL="http://localhost:8080"

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --count=*)
            COUNT="${1#*=}"
            shift
            ;;
        --output=*)
            OUTPUT_FILE="${1#*=}"
            shift
            ;;
        --base-url=*)
            BASE_URL="${1#*=}"
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

# Generate GET ammo (URI-style)
generate_get_ammo() {
    local output="${OUTPUT_FILE:-$AMMO_DIR/http-get-generated.txt}"
    
    log_info "Generating GET ammo file: $output"
    
    cat > "$output" << 'EOF'
[Host: localhost]
[User-Agent: YandexTank/Perftest]
[Accept: application/json]
[Connection: keep-alive]
EOF
    
    # Add URIs
    local endpoints=(
        "/health"
        "/api/v1/simple"
        "/api/v1/items"
        "/api/v1/users"
        "/api/v1/orders"
        "/backend/health"
    )
    
    for ((i=1; i<=COUNT; i++)); do
        # Rotate through endpoints
        local idx=$((i % ${#endpoints[@]}))
        local endpoint="${endpoints[$idx]}"
        
        # Add some variety with IDs
        if [[ "$endpoint" == "/api/v1/items" ]] && ((i % 3 == 0)); then
            endpoint="/api/v1/items/$((RANDOM % 100 + 1))"
        elif [[ "$endpoint" == "/api/v1/users" ]] && ((i % 4 == 0)); then
            endpoint="/api/v1/users/$((RANDOM % 50 + 1))"
        fi
        
        echo "$endpoint" >> "$output"
    done
    
    log_success "Generated $COUNT GET requests in $output"
}

# Generate POST ammo (request-style)
generate_post_ammo() {
    local output="${OUTPUT_FILE:-$AMMO_DIR/http-post-generated.txt}"
    
    log_info "Generating POST ammo file: $output"
    
    > "$output"  # Clear file
    
    for ((i=1; i<=COUNT; i++)); do
        local endpoint
        local body
        
        case $((i % 4)) in
            0)
                endpoint="/api/v1/items"
                body=$(cat << EOF
{"name":"Item $i","description":"Generated test item $i","price":$((RANDOM % 1000 + 1)).99,"quantity":$((RANDOM % 100 + 1)),"category":"generated"}
EOF
)
                ;;
            1)
                endpoint="/api/v1/users"
                body=$(cat << EOF
{"username":"user_$i","email":"user$i@example.com","firstName":"User","lastName":"$i","role":"user","active":true}
EOF
)
                ;;
            2)
                endpoint="/api/v1/echo"
                body=$(cat << EOF
{"message":"Echo test $i","timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","sequence":$i}
EOF
)
                ;;
            3)
                endpoint="/api/v1/orders"
                body=$(cat << EOF
{"userId":$((RANDOM % 100 + 1)),"items":[{"itemId":$((RANDOM % 50 + 1)),"quantity":$((RANDOM % 5 + 1))}],"total":$((RANDOM % 500 + 50)).99}
EOF
)
                ;;
        esac
        
        local body_length=${#body}
        local header_length=120  # Approximate header length
        local total_length=$((body_length + header_length))
        
        cat >> "$output" << EOF
$total_length $endpoint
Host: localhost
User-Agent: YandexTank/Perftest
Accept: application/json
Content-Type: application/json
Connection: keep-alive

$body
EOF
    done
    
    log_success "Generated $COUNT POST requests in $output"
}

# Generate mixed ammo
generate_mixed_ammo() {
    local output="${OUTPUT_FILE:-$AMMO_DIR/mixed-generated.txt}"
    
    log_info "Generating mixed ammo file: $output"
    
    # Start with GET headers
    cat > "$output" << 'EOF'
[Host: localhost]
[User-Agent: YandexTank/Perftest]
[Accept: application/json]
[Connection: keep-alive]
EOF
    
    # Add GET requests (70% of traffic)
    local get_count=$((COUNT * 70 / 100))
    local endpoints=(
        "/health"
        "/api/v1/simple"
        "/api/v1/items"
        "/api/v1/items/1"
        "/api/v1/items/2"
        "/api/v1/users"
        "/api/v1/users/1"
        "/api/v1/orders"
    )
    
    for ((i=1; i<=get_count; i++)); do
        local idx=$((RANDOM % ${#endpoints[@]}))
        echo "${endpoints[$idx]}" >> "$output"
    done
    
    # Add POST requests (30% of traffic)
    local post_count=$((COUNT * 30 / 100))
    
    for ((i=1; i<=post_count; i++)); do
        local body
        local endpoint
        
        case $((i % 3)) in
            0)
                endpoint="/api/v1/items"
                body='{"name":"Mixed Item","price":99.99,"quantity":1}'
                ;;
            1)
                endpoint="/api/v1/echo"
                body='{"message":"Mixed test"}'
                ;;
            2)
                endpoint="/api/v1/orders"
                body='{"userId":1,"items":[{"itemId":1,"quantity":1}]}'
                ;;
        esac
        
        local body_length=${#body}
        local total_length=$((body_length + 120))
        
        cat >> "$output" << EOF
$total_length $endpoint
Host: localhost
User-Agent: YandexTank/Perftest
Accept: application/json
Content-Type: application/json
Connection: keep-alive

$body
EOF
    done
    
    log_success "Generated $COUNT mixed requests in $output"
}

# Generate custom ammo from template
generate_custom_ammo() {
    local template_file="${1:-}"
    local output="${OUTPUT_FILE:-$AMMO_DIR/custom-generated.txt}"
    
    if [ -z "$template_file" ] || [ ! -f "$template_file" ]; then
        echo -e "${RED}Error: Template file required for custom ammo${NC}"
        echo "Usage: $0 custom --template=<file>"
        exit 1
    fi
    
    log_info "Generating custom ammo from template: $template_file"
    
    # Read template and replicate
    > "$output"
    
    for ((i=1; i<=COUNT; i++)); do
        # Replace placeholders in template
        sed -e "s/{{INDEX}}/$i/g" \
            -e "s/{{RANDOM}}/$RANDOM/g" \
            -e "s/{{TIMESTAMP}}/$(date -u +%Y-%m-%dT%H:%M:%SZ)/g" \
            "$template_file" >> "$output"
    done
    
    log_success "Generated $COUNT custom requests in $output"
}

# Show help
show_help() {
    cat << EOF
Ammo Generator for Yandex Tank

Usage: $0 [type] [options]

Types:
  get       Generate GET request ammo (URI-style)
  post      Generate POST request ammo (request-style)
  mixed     Generate mixed workload ammo
  custom    Generate custom ammo from template

Options:
  --count=<n>       Number of requests to generate (default: 100)
  --output=<file>   Output file path
  --base-url=<url>  Base URL for requests

Examples:
  $0 get --count=1000
  $0 post --count=500 --output=custom-post.txt
  $0 mixed --count=2000

EOF
}

# Main
main() {
    case $AMMO_TYPE in
        get)
            generate_get_ammo
            ;;
        post)
            generate_post_ammo
            ;;
        mixed)
            generate_mixed_ammo
            ;;
        custom)
            generate_custom_ammo "$2"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown ammo type: $AMMO_TYPE${NC}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
