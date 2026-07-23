#!/usr/bin/env bash
#
# publish-dashboards.sh - Publish Grafana dashboards from monitoring/grafana/
#
# DEPRECATED WRAPPER: the canonical implementation lives in
#   test/monitoring/scripts/publish-dashboards.sh
# This thin delegator exists only for backward compatibility of documented
# invocations; the two copies previously diverged (review finding L7).
#
# Usage:
#   ./publish-dashboards.sh [options]
#
# Options (translated to the canonical script's environment variables):
#   --grafana-url=<url>       Grafana URL (default: http://127.0.0.1:3000)
#   --grafana-user=<user>     Grafana username (default: admin)
#   --grafana-password=<pass> Grafana password (default: admin)
#   --dashboard-dir=<dir>     Dashboard directory (default: monitoring/grafana)
#   --folder=<name>           Target folder name (default: avapigw)
#   --help                    Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CANONICAL="${PROJECT_ROOT}/test/monitoring/scripts/publish-dashboards.sh"

GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin}"
DASHBOARD_DIR="${DASHBOARD_DIR:-monitoring/grafana}"
FOLDER_NAME="${FOLDER_NAME:-avapigw}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --grafana-url=*)      GRAFANA_URL="${1#*=}"; shift ;;
        --grafana-user=*)     GRAFANA_USER="${1#*=}"; shift ;;
        --grafana-password=*) GRAFANA_PASSWORD="${1#*=}"; shift ;;
        --dashboard-dir=*)    DASHBOARD_DIR="${1#*=}"; shift ;;
        --folder=*)           FOLDER_NAME="${1#*=}"; shift ;;
        --help)
            sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "[WARN] Ignoring unsupported option: $1 (see --help)" >&2
            shift
            ;;
    esac
done

if [[ ! -x "${CANONICAL}" ]]; then
    echo "[ERROR] Canonical script not found or not executable: ${CANONICAL}" >&2
    exit 1
fi

exec env \
    GRAFANA_URL="${GRAFANA_URL}" \
    GRAFANA_USER="${GRAFANA_USER}" \
    GRAFANA_PASSWORD="${GRAFANA_PASSWORD}" \
    DASHBOARD_DIR="${DASHBOARD_DIR}" \
    FOLDER_NAME="${FOLDER_NAME}" \
    "${CANONICAL}"
