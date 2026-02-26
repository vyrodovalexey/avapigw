package backend

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/vyrodovalexey/avapigw/internal/config"
	backendmetrics "github.com/vyrodovalexey/avapigw/internal/metrics/backend"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// HealthStatusFunc is called when a host's health status changes.
// Parameters: backendName, hostAddress (host:port), healthy.
type HealthStatusFunc func(backendName, hostAddress string, healthy bool)

// Health check default configuration constants.
const (
	// DefaultHealthCheckTimeout is the default timeout for health check requests.
	DefaultHealthCheckTimeout = 5 * time.Second

	// DefaultHealthCheckInterval is the default interval between health checks.
	DefaultHealthCheckInterval = 10 * time.Second

	// DefaultHealthyThreshold is the default number of consecutive successes
	// required to mark a host as healthy.
	DefaultHealthyThreshold = 2

	// DefaultUnhealthyThreshold is the default number of consecutive failures
	// required to mark a host as unhealthy.
	DefaultUnhealthyThreshold = 3
)

// HealthChecker performs periodic health checks on backend hosts.
type HealthChecker struct {
	hosts              []*Host
	config             config.HealthCheck
	client             *http.Client
	logger             observability.Logger
	stopCh             chan struct{}
	stoppedCh          chan struct{}
	running            bool
	mu                 sync.Mutex
	healthyThreshold   int
	unhealthyThreshold int
	healthyCounts      map[*Host]int
	unhealthyCounts    map[*Host]int
	backendName        string
	onStatusChange     HealthStatusFunc
	useTLS             bool
	useGRPC            bool
	grpcService        string
	grpcConns          map[string]*grpc.ClientConn
	grpcMu             sync.Mutex
	grpcCreds          credentials.TransportCredentials
}

// HealthCheckOption is a functional option for configuring the health checker.
type HealthCheckOption func(*HealthChecker)

// WithHealthCheckLogger sets the logger for the health checker.
func WithHealthCheckLogger(logger observability.Logger) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.logger = logger
	}
}

// WithHealthCheckClient sets the HTTP client for the health checker.
func WithHealthCheckClient(client *http.Client) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.client = client
	}
}

// WithBackendName sets the backend name for the health checker.
func WithBackendName(name string) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.backendName = name
	}
}

// WithHealthStatusCallback sets a callback for health status changes.
func WithHealthStatusCallback(fn HealthStatusFunc) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.onStatusChange = fn
	}
}

// WithHealthCheckTLS enables HTTPS for health check requests.
func WithHealthCheckTLS(useTLS bool) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.useTLS = useTLS
	}
}

// WithGRPCHealthCheck enables native gRPC health checking.
func WithGRPCHealthCheck(service string) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.useGRPC = true
		hc.grpcService = service
	}
}

// WithGRPCTransportCredentials sets TLS credentials
// for gRPC health checks.
func WithGRPCTransportCredentials(
	creds credentials.TransportCredentials,
) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.grpcCreds = creds
	}
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(hosts []*Host, cfg config.HealthCheck, opts ...HealthCheckOption) *HealthChecker {
	timeout := cfg.Timeout.Duration()
	if timeout == 0 {
		timeout = DefaultHealthCheckTimeout
	}

	hc := &HealthChecker{
		hosts:  hosts,
		config: cfg,
		client: &http.Client{
			Timeout: timeout,
		},
		logger:             observability.NopLogger(),
		stopCh:             make(chan struct{}),
		stoppedCh:          make(chan struct{}),
		healthyThreshold:   cfg.HealthyThreshold,
		unhealthyThreshold: cfg.UnhealthyThreshold,
		healthyCounts:      make(map[*Host]int),
		unhealthyCounts:    make(map[*Host]int),
		grpcConns:          make(map[string]*grpc.ClientConn),
	}

	// Apply UseGRPC from config
	if cfg.UseGRPC {
		hc.useGRPC = true
		hc.grpcService = cfg.GRPCService
	}

	if hc.healthyThreshold == 0 {
		hc.healthyThreshold = DefaultHealthyThreshold
	}
	if hc.unhealthyThreshold == 0 {
		hc.unhealthyThreshold = DefaultUnhealthyThreshold
	}

	for _, opt := range opts {
		opt(hc)
	}

	return hc
}

// Start starts the health checker.
func (hc *HealthChecker) Start(ctx context.Context) {
	hc.mu.Lock()
	if hc.running {
		hc.mu.Unlock()
		return
	}
	hc.running = true
	hc.mu.Unlock()

	go hc.run(ctx)
}

// Stop stops the health checker.
func (hc *HealthChecker) Stop() {
	hc.mu.Lock()
	if !hc.running {
		hc.mu.Unlock()
		return
	}
	hc.running = false
	hc.mu.Unlock()

	close(hc.stopCh)
	<-hc.stoppedCh
	hc.closeAllGRPCConns()
}

// run is the main health check loop.
func (hc *HealthChecker) run(ctx context.Context) {
	defer close(hc.stoppedCh)

	interval := hc.config.Interval.Duration()
	if interval == 0 {
		interval = DefaultHealthCheckInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run initial health check
	hc.checkAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-hc.stopCh:
			return
		case <-ticker.C:
			hc.checkAll(ctx)
		}
	}
}

// checkAll checks all hosts.
func (hc *HealthChecker) checkAll(ctx context.Context) {
	var wg sync.WaitGroup

	for _, host := range hc.hosts {
		wg.Add(1)
		go func(h *Host) {
			defer wg.Done()
			hc.checkHost(ctx, h)
		}(host)
	}

	wg.Wait()
}

// checkHost checks a single host.
func (hc *HealthChecker) checkHost(ctx context.Context, host *Host) {
	// Check if context is already canceled before making the request
	select {
	case <-ctx.Done():
		return
	default:
		// Context is still valid, proceed with health check
	}

	if hc.useGRPC {
		hc.checkHostGRPC(ctx, host)
		return
	}

	hc.checkHostHTTP(ctx, host)
}

// checkHostHTTP performs an HTTP health check on a single host.
func (hc *HealthChecker) checkHostHTTP(
	ctx context.Context, host *Host,
) {
	var url string
	if hc.config.Port > 0 {
		// Use override port (e.g. monitoring port for gRPC
		// backends). Health check port always uses plain HTTP.
		addr := net.JoinHostPort(
			host.Address, strconv.Itoa(hc.config.Port),
		)
		url = "http://" + addr + hc.config.Path
	} else {
		url = host.URLWithScheme(hc.useTLS) + hc.config.Path
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, url, http.NoBody,
	)
	if err != nil {
		hc.recordFailure(host, err)
		return
	}

	checkStart := time.Now()
	resp, err := hc.client.Do(req)
	checkDuration := time.Since(checkStart)

	bm := backendmetrics.GetBackendMetrics()

	if err != nil {
		hc.recordFailure(host, err)
		bm.RecordHealthCheck(
			hc.backendName, "failure", checkDuration,
		)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusOK &&
		resp.StatusCode < http.StatusMultipleChoices {
		hc.recordSuccess(host)
		bm.RecordHealthCheck(
			hc.backendName, "success", checkDuration,
		)
	} else {
		hc.recordFailure(host, nil)
		bm.RecordHealthCheck(
			hc.backendName, "failure", checkDuration,
		)
	}
}

// checkHostGRPC performs a native gRPC health check on a host.
func (hc *HealthChecker) checkHostGRPC(
	ctx context.Context, host *Host,
) {
	addr := net.JoinHostPort(
		host.Address, strconv.Itoa(host.Port),
	)

	conn, err := hc.getGRPCConn(addr)
	if err != nil {
		hc.recordFailure(host, err)
		backendmetrics.GetBackendMetrics().RecordHealthCheck(
			hc.backendName, "failure", 0,
		)
		return
	}

	client := healthpb.NewHealthClient(conn)

	timeout := hc.config.Timeout.Duration()
	if timeout == 0 {
		timeout = DefaultHealthCheckTimeout
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	checkStart := time.Now()
	resp, err := client.Check(
		checkCtx,
		&healthpb.HealthCheckRequest{
			Service: hc.grpcService,
		},
	)
	checkDuration := time.Since(checkStart)

	bm := backendmetrics.GetBackendMetrics()

	if err != nil {
		hc.recordFailure(host, err)
		bm.RecordHealthCheck(
			hc.backendName, "failure", checkDuration,
		)
		// Close stale connection on error
		hc.closeGRPCConn(addr)
		return
	}

	serving := healthpb.HealthCheckResponse_SERVING
	if resp.GetStatus() == serving {
		hc.recordSuccess(host)
		bm.RecordHealthCheck(
			hc.backendName, "success", checkDuration,
		)
	} else {
		hc.recordFailure(host, nil)
		bm.RecordHealthCheck(
			hc.backendName, "failure", checkDuration,
		)
	}
}

// getGRPCConn returns a pooled gRPC connection for the address.
func (hc *HealthChecker) getGRPCConn(
	addr string,
) (*grpc.ClientConn, error) {
	hc.grpcMu.Lock()
	defer hc.grpcMu.Unlock()

	if conn, ok := hc.grpcConns[addr]; ok {
		state := conn.GetState()
		if state != connectivity.Shutdown &&
			state != connectivity.TransientFailure {
			return conn, nil
		}
		// Close stale connection
		if err := conn.Close(); err != nil {
			hc.logger.Warn(
				"failed to close stale gRPC connection",
				observability.String("addr", addr),
				observability.Error(err),
			)
		}
		delete(hc.grpcConns, addr)
	}

	creds := hc.grpcCreds
	if creds == nil {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, err
	}

	hc.grpcConns[addr] = conn
	return conn, nil
}

// closeGRPCConn closes and removes a pooled gRPC connection.
func (hc *HealthChecker) closeGRPCConn(addr string) {
	hc.grpcMu.Lock()
	defer hc.grpcMu.Unlock()

	if conn, ok := hc.grpcConns[addr]; ok {
		if err := conn.Close(); err != nil {
			hc.logger.Warn(
				"failed to close gRPC connection",
				observability.String("addr", addr),
				observability.Error(err),
			)
		}
		delete(hc.grpcConns, addr)
	}
}

// closeAllGRPCConns closes all pooled gRPC connections.
func (hc *HealthChecker) closeAllGRPCConns() {
	hc.grpcMu.Lock()
	defer hc.grpcMu.Unlock()

	for addr, conn := range hc.grpcConns {
		if err := conn.Close(); err != nil {
			hc.logger.Warn(
				"failed to close gRPC connection",
				observability.String("addr", addr),
				observability.Error(err),
			)
		}
		delete(hc.grpcConns, addr)
	}
}

// recordSuccess records a successful health check.
func (hc *HealthChecker) recordSuccess(host *Host) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.healthyCounts[host]++
	hc.unhealthyCounts[host] = 0

	if hc.healthyCounts[host] >= hc.healthyThreshold {
		if host.Status() != StatusHealthy {
			hc.logger.Info("host became healthy",
				observability.String("address", host.Address),
				observability.Int("port", host.Port),
			)
			host.SetStatus(StatusHealthy)
			// Record backend-level health status (1=healthy)
			backendmetrics.GetBackendMetrics().
				HealthCheckStatus.
				WithLabelValues(hc.backendName).Set(1)
			backendmetrics.GetBackendMetrics().
				ConsecutiveFailures.
				WithLabelValues(hc.backendName).Set(0)
			if hc.onStatusChange != nil {
				hostAddr := net.JoinHostPort(
					host.Address, strconv.Itoa(host.Port),
				)
				hc.onStatusChange(
					hc.backendName, hostAddr, true,
				)
			}
		}
	}
}

// recordFailure records a failed health check.
func (hc *HealthChecker) recordFailure(host *Host, err error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.unhealthyCounts[host]++
	hc.healthyCounts[host] = 0

	// Record backend-level consecutive failures gauge
	backendmetrics.GetBackendMetrics().
		ConsecutiveFailures.
		WithLabelValues(hc.backendName).
		Set(float64(hc.unhealthyCounts[host]))

	if hc.unhealthyCounts[host] >= hc.unhealthyThreshold {
		if host.Status() != StatusUnhealthy {
			hc.logger.Warn("host became unhealthy",
				observability.String("address", host.Address),
				observability.Int("port", host.Port),
				observability.Error(err),
			)
			host.SetStatus(StatusUnhealthy)
			// Record backend-level health status (0=unhealthy)
			backendmetrics.GetBackendMetrics().
				HealthCheckStatus.
				WithLabelValues(hc.backendName).Set(0)
			if hc.onStatusChange != nil {
				hostAddr := net.JoinHostPort(
					host.Address, strconv.Itoa(host.Port),
				)
				hc.onStatusChange(
					hc.backendName, hostAddr, false,
				)
			}
		}
	}
}

// IsRunning returns true if the health checker is running.
func (hc *HealthChecker) IsRunning() bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return hc.running
}
