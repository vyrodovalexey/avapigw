//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Live-cluster E2E helpers (AGG-17 / E-1..E-6)
// =============================================================================
//
// These helpers drive the *deployed* operator-mode gateway + operator in the
// local Kubernetes namespace (default `avapigw-test` on docker-desktop). They
// are intentionally env-driven (no hardcoded cluster assumptions beyond sane
// defaults) and shell out to `kubectl` because the deployment lifecycle is
// owned by the DevOps DO-04 subtask, not the test process.
//
// Gating: the whole live suite is skipped unless the live cluster is reachable
// and the deployed aggregate CRD is present. This keeps `make test-e2e` green
// in environments where the cluster is not provisioned.
//
// Reaching the gateway: the gateway Service exposes only TLS listeners
// (https/8443, grpcs/9443) plus metrics/9090. On docker-desktop NodePorts are
// not always routable from the host, so we use `kubectl port-forward` (the same
// approach the existing e2e/integration suites rely on for in-cluster access).

const (
	// envLiveNamespace selects the namespace under test.
	envLiveNamespace = "AVAPIGW_E2E_NAMESPACE"
	// defaultLiveNamespace is the operator-mode namespace per the DO-04 deploy.
	defaultLiveNamespace = "avapigw-test"

	// envAggregateRoute selects the deployed aggregate APIRoute name.
	envAggregateRoute = "AVAPIGW_E2E_AGGREGATE_ROUTE"
	// defaultAggregateRoute is the aggregate route applied by crds-do04-aggregate.yaml.
	defaultAggregateRoute = "do04-aggregate-route"

	// envAggregatePath selects the client-facing aggregate route prefix.
	envAggregatePath = "AVAPIGW_E2E_AGGREGATE_PATH"
	// defaultAggregatePath matches the deployed aggregate route prefix.
	defaultAggregatePath = "/api/v1/aggregate"

	// envVMURL selects the VictoriaMetrics base URL.
	envVMURL = "AVAPIGW_E2E_VM_URL"
	// defaultVMURL is the local VictoriaMetrics endpoint scraping the gateway.
	defaultVMURL = "http://localhost:8428"

	// envGatewayService selects the gateway Service name.
	envGatewayService = "AVAPIGW_E2E_GATEWAY_SVC"
	// defaultGatewayService is the deployed gateway Service.
	defaultGatewayService = "avapigw"

	// liveCtxTimeout bounds every kubectl invocation; hanging kubectl calls
	// otherwise stall CI. (Cross-cutting practice: timeouts everywhere.)
	liveCtxTimeout = 30 * time.Second
)

// liveNamespace returns the namespace under test (ENV override, no hardcode).
func liveNamespace() string {
	if v := os.Getenv(envLiveNamespace); v != "" {
		return v
	}
	return defaultLiveNamespace
}

// liveAggregateRoute returns the deployed aggregate APIRoute name.
func liveAggregateRoute() string {
	if v := os.Getenv(envAggregateRoute); v != "" {
		return v
	}
	return defaultAggregateRoute
}

// liveAggregatePath returns the client-facing aggregate route prefix.
func liveAggregatePath() string {
	if v := os.Getenv(envAggregatePath); v != "" {
		return v
	}
	return defaultAggregatePath
}

// liveVMURL returns the VictoriaMetrics base URL.
func liveVMURL() string {
	if v := os.Getenv(envVMURL); v != "" {
		return v
	}
	return defaultVMURL
}

// liveGatewayService returns the gateway Service name.
func liveGatewayService() string {
	if v := os.Getenv(envGatewayService); v != "" {
		return v
	}
	return defaultGatewayService
}

// kubectlAvailable reports whether the kubectl binary is on PATH.
func kubectlAvailable() bool {
	_, err := exec.LookPath("kubectl")
	return err == nil
}

// kubectl runs kubectl with a bounded context and returns combined output.
// stdin, when non-empty, is piped to the command (used for `apply -f -`).
func kubectl(ctx context.Context, stdin string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, liveCtxTimeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, "kubectl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// liveClusterReachable reports whether the deployed aggregate route exists in
// the target namespace. It is the single gate for the entire live suite.
func liveClusterReachable(ctx context.Context) bool {
	if !kubectlAvailable() {
		return false
	}
	out, err := kubectl(ctx, "", "get", "apiroute", liveAggregateRoute(),
		"-n", liveNamespace(), "-o", "jsonpath={.metadata.name}")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == liveAggregateRoute()
}

// skipUnlessLive skips the test unless the live operator-mode deployment with
// the aggregate CRD is reachable.
func skipUnlessLive(t *testing.T, ctx context.Context) {
	t.Helper()
	if os.Getenv("AVAPIGW_E2E_LIVE") == "0" {
		t.Skip("AVAPIGW_E2E_LIVE=0: live-cluster aggregate e2e explicitly disabled")
	}
	if !liveClusterReachable(ctx) {
		t.Skipf("live operator-mode deployment not reachable "+
			"(kubectl get apiroute/%s -n %s failed); skipping live aggregate e2e. "+
			"Set up via DevOps DO-04 (crds-do04-aggregate.yaml).",
			liveAggregateRoute(), liveNamespace())
	}
}

// portForward starts `kubectl port-forward svc/<svc> <local>:<remote>` against
// the gateway Service and waits until the local port accepts connections. It
// returns a stop func that tears the forwarder down. Resource isolation: each
// caller picks its own local port so parallel tests do not collide.
func portForward(ctx context.Context, t *testing.T, svc string, local, remote int) (stop func()) {
	t.Helper()

	cctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cctx, "kubectl", "port-forward",
		"-n", liveNamespace(),
		fmt.Sprintf("svc/%s", svc),
		fmt.Sprintf("%d:%d", local, remote),
	)
	// Capture diagnostics so a CI failure can be reconstructed.
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("failed to start port-forward svc/%s %d:%d: %v", svc, local, remote, err)
	}

	stop = func() {
		cancel()
		_ = cmd.Wait()
	}

	// Wait for the local listener to be ready (bounded).
	addr := fmt.Sprintf("127.0.0.1:%d", local)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Logf("port-forward ready: svc/%s %d->%d", svc, local, remote)
			return stop
		}
		time.Sleep(250 * time.Millisecond)
	}
	stop()
	t.Fatalf("port-forward to svc/%s %d:%d did not become ready", svc, local, remote)
	return func() {}
}

// tlsHTTPClient returns an HTTP client that trusts the gateway's self-signed
// TLS (the gateway exposes only TLS listeners in the deployed config).
func tlsHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // e2e against self-signed gateway cert
		},
	}
}
