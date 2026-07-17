#!/bin/bash
# start-pt-docker.sh - start/stop the PT gateway + graphql-mock as containers on
# the avapigw-test compose network (codifies the ad-hoc docker commands of the
# 20260715 PT run; see perftest-report_pt-local-docker_20260715_071500.md
# "Deployment topology" for WHY the gateway must run inside the compose network:
# the Sentinel-announced Redis master is a docker-bridge IP unreachable from a
# macOS host).
#
#   start-pt-docker.sh start   # run avapigw-pt-gqlmock + avapigw-pt
#   start-pt-docker.sh stop    # remove both containers
#
# NOTE (20260716 cycle): the container-level sysctls used on 20260715
# (ip_local_port_range/tcp_tw_reuse) default OFF so a run verifies the pooled
# REST transport (internal/proxy/proxy.go) — PT-03/04 pass clean without them.
# The GRAPHQL forwarder still dial-storms per request (no pooled-transport fix
# there yet), so PT-05/06 need PT_SYSCTLS=1 to avoid ephemeral-port exhaustion
# (56k TIME_WAIT observed) until the GraphQL proxy transport is pooled too.
set -eu
cd "$(dirname "$0")/../../.." || exit 1
ROOT="$(pwd)"
NET="${PT_NET:-avapigw-test_default}"
IMG="${PT_IMG:-alpine:3.22}"
ARCH="$(uname -m)"          # arm64 on Apple silicon
BIN="$ROOT/bin/gateway-linux-${ARCH/x86_64/amd64}"
MOCKBIN="$ROOT/bin/graphql-mock-linux-${ARCH/x86_64/amd64}"
CFG="/perf/configs/gateway-pt-docker.yaml"

start() {
  [ -x "$BIN" ] || { echo "missing $BIN (build: GOOS=linux GOARCH=$ARCH make ...)"; exit 1; }
  [ -x "$MOCKBIN" ] || { echo "missing $MOCKBIN"; exit 1; }
  docker rm -f avapigw-pt avapigw-pt-gqlmock >/dev/null 2>&1 || true

  echo "==> starting avapigw-pt-gqlmock (graphql mock :8901/:8902, compose network only)"
  docker run -d --name avapigw-pt-gqlmock --network "$NET" \
    -v "$MOCKBIN":/app/graphql-mock:ro \
    "$IMG" /app/graphql-mock -port 8901 -port2 8902

  set -- 
  if [ "${PT_SYSCTLS:-0}" = "1" ]; then
    echo "==> PT_SYSCTLS=1: widening ephemeral ports + tw_reuse (GraphQL dial-storm mitigation)"
    set -- --sysctl "net.ipv4.ip_local_port_range=1024 65535" --sysctl net.ipv4.tcp_tw_reuse=1
  fi
  echo "==> starting avapigw-pt (gateway, ports 8080/8443/9000/9443/9090 published)"
  docker run -d --name avapigw-pt --network "$NET" "$@" \
    -p 8080:8080 -p 8443:8443 -p 9000:9000 -p 9443:9443 -p 9090:9090 \
    -v "$ROOT/test/performance":/perf:ro \
    -v "$ROOT/test/docker-compose/certs":/certs:ro \
    -v "$BIN":/app/gateway:ro \
    -e VAULT_ADDR=http://vault:8200 -e VAULT_TOKEN=myroot \
    "$IMG" /app/gateway -config "$CFG"

  echo "==> waiting for gateway health"
  for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
      echo "gateway healthy"; docker ps --format '{{.Names}}\t{{.Status}}' | grep avapigw-pt; return 0
    fi
    sleep 1
  done
  echo "gateway did not become healthy; logs:"; docker logs avapigw-pt | tail -30; exit 1
}

stop() {
  docker rm -f avapigw-pt avapigw-pt-gqlmock 2>/dev/null || true
  echo "PT containers removed"
}

case "${1:-start}" in
  start) start ;;
  stop)  stop ;;
  *) echo "usage: $0 start|stop"; exit 1 ;;
esac
