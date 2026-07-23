#!/usr/bin/env bash
# k8s-load-images.sh - Load locally built docker images into the local
# Kubernetes cluster's container runtime.
#
# Supports:
#   - kind clusters                  -> kind load docker-image
#   - minikube                       -> minikube image load
#   - Docker Desktop (classic)       -> no-op (shares the docker daemon)
#   - Docker Desktop (kind-based,    -> streams `docker save` through a
#     node "desktop-control-plane")     helper pod into the node containerd
#     and other unmanaged kind-style     (ctr -n k8s.io images import -)
#     nodes
#
# Usage:
#   ./k8s-load-images.sh IMAGE [IMAGE...]
#
# Environment:
#   KUBE_CONTEXT  - kubectl context to use (default: current-context)
#   LOADER_NS     - namespace for the helper pod (default: kube-system)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1" >&2; }

[ $# -ge 1 ] || { err "usage: $0 IMAGE [IMAGE...]"; exit 1; }

KUBE_CONTEXT="${KUBE_CONTEXT:-$(kubectl config current-context)}"
LOADER_NS="${LOADER_NS:-kube-system}"
KCTL=(kubectl --context "${KUBE_CONTEXT}")

log "kubectl context: ${KUBE_CONTEXT}"

# ---------------------------------------------------------------------------
# Strategy detection
# ---------------------------------------------------------------------------
if [[ "${KUBE_CONTEXT}" == kind-* ]] && command -v kind &>/dev/null; then
    CLUSTER="${KUBE_CONTEXT#kind-}"
    log "kind cluster '${CLUSTER}' detected -> kind load docker-image"
    for img in "$@"; do
        kind load docker-image "${img}" --name "${CLUSTER}"
        ok "loaded ${img}"
    done
    exit 0
fi

if [[ "${KUBE_CONTEXT}" == "minikube" ]] && command -v minikube &>/dev/null; then
    log "minikube detected -> minikube image load"
    for img in "$@"; do
        minikube image load "${img}"
        ok "loaded ${img}"
    done
    exit 0
fi

NODE=$("${KCTL[@]}" get nodes -o jsonpath='{.items[0].metadata.name}')
RUNTIME=$("${KCTL[@]}" get node "${NODE}" -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}')
log "node: ${NODE} runtime: ${RUNTIME}"

# Classic Docker Desktop (docker-desktop node, docker:// runtime) shares the
# host docker daemon image store - nothing to do.
if [[ "${NODE}" == "docker-desktop" && "${RUNTIME}" == docker://* ]]; then
    ok "classic Docker Desktop shares the docker daemon image store - no load needed"
    exit 0
fi

# ---------------------------------------------------------------------------
# Generic containerd node (Docker Desktop kind-based "desktop-control-plane",
# unmanaged kind, k3d-style nodes): stream docker save through a helper pod
# that mounts the node's containerd socket and the node's static ctr binary.
# ---------------------------------------------------------------------------
POD="avapigw-image-loader"
log "containerd node -> streaming import via helper pod ${LOADER_NS}/${POD}"

"${KCTL[@]}" -n "${LOADER_NS}" delete pod "${POD}" --ignore-not-found --wait=true >/dev/null 2>&1 || true

"${KCTL[@]}" -n "${LOADER_NS}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  labels:
    app.kubernetes.io/name: avapigw-image-loader
spec:
  nodeName: ${NODE}
  restartPolicy: Never
  tolerations:
    - operator: Exists
  containers:
    - name: loader
      image: busybox:1.36
      command: ["sleep", "600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: containerd-sock
          mountPath: /run/containerd/containerd.sock
        - name: ctr-bin
          mountPath: /usr/local/bin/ctr
  volumes:
    - name: containerd-sock
      hostPath:
        path: /run/containerd/containerd.sock
        type: Socket
    - name: ctr-bin
      hostPath:
        path: /usr/local/bin/ctr
        type: File
EOF

"${KCTL[@]}" -n "${LOADER_NS}" wait --for=condition=Ready "pod/${POD}" --timeout=120s >/dev/null

trap '"${KCTL[@]}" -n "${LOADER_NS}" delete pod "${POD}" --ignore-not-found --wait=false >/dev/null 2>&1 || true' EXIT

for img in "$@"; do
    log "importing ${img} into node containerd (k8s.io namespace)..."
    docker save "${img}" | "${KCTL[@]}" -n "${LOADER_NS}" exec -i "${POD}" -- \
        ctr -n k8s.io images import - >/dev/null
    ok "loaded ${img}"
done

ok "all images loaded"
