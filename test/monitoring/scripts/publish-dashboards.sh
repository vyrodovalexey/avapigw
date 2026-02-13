#!/usr/bin/env bash
# publish-dashboards.sh — Publish Grafana dashboards via the Grafana HTTP API
# and validate that each dashboard is importable and has no errors.
#
# Usage:
#   ./publish-dashboards.sh [GRAFANA_URL] [GRAFANA_USER] [GRAFANA_PASSWORD]
#
# Environment variables (override arguments):
#   GRAFANA_URL       — Grafana base URL        (default: http://127.0.0.1:3000)
#   GRAFANA_USER      — Grafana admin user       (default: admin)
#   GRAFANA_PASSWORD  — Grafana admin password    (default: admin)
#   DASHBOARD_DIR     — Path to dashboard JSONs   (default: monitoring/grafana)
#   DATASOURCE_UID    — VictoriaMetrics datasource UID (default: victoriametrics)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GRAFANA_URL="${GRAFANA_URL:-${1:-http://127.0.0.1:3000}}"
GRAFANA_USER="${GRAFANA_USER:-${2:-admin}}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-${3:-admin}}"
DASHBOARD_DIR="${DASHBOARD_DIR:-monitoring/grafana}"
DATASOURCE_UID="${DATASOURCE_UID:-victoriametrics}"

GRAFANA_AUTH="${GRAFANA_USER}:${GRAFANA_PASSWORD}"
FAILED=0
PASSED=0
TOTAL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "==> $*"; }
ok()   { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; FAILED=$((FAILED + 1)); }

# ---------------------------------------------------------------------------
# Wait for Grafana to be ready
# ---------------------------------------------------------------------------
wait_for_grafana() {
  log "Waiting for Grafana at ${GRAFANA_URL}..."
  for i in $(seq 1 30); do
    if curl -sf -u "${GRAFANA_AUTH}" "${GRAFANA_URL}/api/health" \
         -o /dev/null 2>/dev/null; then
      ok "Grafana is ready"
      return 0
    fi
    echo "  Attempt ${i}/30: waiting..."
    sleep 2
  done
  fail "Grafana did not become ready within 60 seconds"
  return 1
}

# ---------------------------------------------------------------------------
# Create VictoriaMetrics datasource (idempotent)
# ---------------------------------------------------------------------------
create_datasource() {
  log "Creating VictoriaMetrics datasource..."

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${GRAFANA_AUTH}" \
    -X POST "${GRAFANA_URL}/api/datasources" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"VictoriaMetrics\",
      \"type\": \"prometheus\",
      \"uid\": \"${DATASOURCE_UID}\",
      \"access\": \"proxy\",
      \"url\": \"http://victoriametrics:8428\",
      \"isDefault\": true,
      \"jsonData\": {
        \"timeInterval\": \"15s\",
        \"httpMethod\": \"POST\"
      }
    }")

  case "${http_code}" in
    200) ok "Datasource 'VictoriaMetrics' created" ;;
    409) ok "Datasource 'VictoriaMetrics' already exists" ;;
    *)   fail "Datasource 'VictoriaMetrics' creation returned HTTP ${http_code}" ;;
  esac
}

# ---------------------------------------------------------------------------
# Create Tempo datasource stub (for dashboard reference validation)
# ---------------------------------------------------------------------------
create_tempo_datasource() {
  log "Creating Tempo datasource stub..."

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${GRAFANA_AUTH}" \
    -X POST "${GRAFANA_URL}/api/datasources" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Tempo",
      "type": "tempo",
      "uid": "tempo",
      "access": "proxy",
      "url": "http://localhost:3200",
      "isDefault": false
    }')

  case "${http_code}" in
    200) ok "Datasource 'Tempo' created (stub)" ;;
    409) ok "Datasource 'Tempo' already exists" ;;
    *)   fail "Datasource 'Tempo' creation returned HTTP ${http_code}" ;;
  esac
}

# ---------------------------------------------------------------------------
# Publish a single dashboard
# ---------------------------------------------------------------------------
publish_dashboard() {
  local file="$1"
  local name
  name=$(basename "${file}" .json)

  TOTAL=$((TOTAL + 1))

  # Validate JSON syntax first
  if ! jq empty "${file}" 2>/dev/null; then
    fail "${name}: invalid JSON"
    return 1
  fi

  # Wrap the dashboard JSON in the import payload
  local payload
  payload=$(jq -c '{
    dashboard: .,
    overwrite: true,
    folderId: 0
  }' "${file}")

  # POST to Grafana
  local response http_code body
  response=$(curl -s -w "\n%{http_code}" \
    -u "${GRAFANA_AUTH}" \
    -X POST "${GRAFANA_URL}/api/dashboards/db" \
    -H "Content-Type: application/json" \
    -d "${payload}")

  http_code=$(echo "${response}" | tail -1)
  body=$(echo "${response}" | sed '$d')

  if [ "${http_code}" = "200" ]; then
    local uid slug
    uid=$(echo "${body}" | jq -r '.uid // "unknown"')
    slug=$(echo "${body}" | jq -r '.slug // "unknown"')
    ok "${name}: published (uid=${uid}, slug=${slug})"
    PASSED=$((PASSED + 1))
    return 0
  fi

  local message
  message=$(echo "${body}" | jq -r '.message // "unknown error"')
  fail "${name}: HTTP ${http_code} — ${message}"
  return 1
}

# ---------------------------------------------------------------------------
# Verify dashboard is accessible via API
# ---------------------------------------------------------------------------
verify_dashboard() {
  local file="$1"
  local name
  name=$(basename "${file}" .json)

  local uid
  uid=$(jq -r '.uid // empty' "${file}")
  if [ -z "${uid}" ]; then
    fail "${name}: no uid field in dashboard JSON"
    return 1
  fi

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${GRAFANA_AUTH}" \
    "${GRAFANA_URL}/api/dashboards/uid/${uid}")

  if [ "${http_code}" = "200" ]; then
    ok "${name}: verified accessible (uid=${uid})"
    return 0
  fi

  fail "${name}: GET by uid returned HTTP ${http_code}"
  return 1
}

# ---------------------------------------------------------------------------
# Validate dashboard panels have valid datasource references
# ---------------------------------------------------------------------------
validate_panels() {
  local file="$1"
  local name
  name=$(basename "${file}" .json)

  # Extract all datasource UIDs referenced in panels
  local ds_uids
  ds_uids=$(jq -r '
    [.. | .datasource? // empty | .uid? // empty]
    | map(select(. != "" and . != "-- Grafana --" and . != "-- Mixed --"))
    | unique[]
  ' "${file}" 2>/dev/null)

  if [ -z "${ds_uids}" ]; then
    ok "${name}: no external datasource references"
    return 0
  fi

  local all_ok=true
  for ds_uid in ${ds_uids}; do
    local ds_code
    ds_code=$(curl -s -o /dev/null -w "%{http_code}" \
      -u "${GRAFANA_AUTH}" \
      "${GRAFANA_URL}/api/datasources/uid/${ds_uid}")

    if [ "${ds_code}" = "200" ]; then
      ok "${name}: datasource '${ds_uid}' exists"
    else
      fail "${name}: datasource '${ds_uid}' not found (HTTP ${ds_code})"
      all_ok=false
    fi
  done

  ${all_ok}
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  log "Grafana Dashboard Test Suite"
  log "  URL:           ${GRAFANA_URL}"
  log "  Dashboard dir: ${DASHBOARD_DIR}"
  echo ""

  wait_for_grafana || exit 1
  create_datasource
  create_tempo_datasource
  echo ""

  # Publish all dashboards
  log "Publishing dashboards..."
  for file in "${DASHBOARD_DIR}"/*.json; do
    [ -f "${file}" ] || continue
    publish_dashboard "${file}" || true
  done
  echo ""

  # Verify all dashboards are accessible
  log "Verifying dashboards are accessible..."
  for file in "${DASHBOARD_DIR}"/*.json; do
    [ -f "${file}" ] || continue
    verify_dashboard "${file}" || true
  done
  echo ""

  # Validate datasource references in panels
  log "Validating panel datasource references..."
  for file in "${DASHBOARD_DIR}"/*.json; do
    [ -f "${file}" ] || continue
    validate_panels "${file}" || true
  done
  echo ""

  # Summary
  log "Results: ${PASSED} published, ${FAILED} failed, ${TOTAL} total"

  if [ "${FAILED}" -gt 0 ]; then
    fail "Dashboard tests FAILED"
    exit 1
  fi

  ok "All dashboard tests PASSED"
  exit 0
}

main "$@"
