package health

import (
	"context"
	"sync"

	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// HealthServer implements the grpc.health.v1.Health service.
type HealthServer struct {
	healthpb.UnimplementedHealthServer
	services map[string]healthpb.HealthCheckResponse_ServingStatus
	watchers map[string][]chan healthpb.HealthCheckResponse_ServingStatus
	mu       sync.RWMutex
	logger   observability.Logger
	shutdown bool
}

// HealthOption is a functional option for configuring the health server.
type HealthOption func(*HealthServer)

// WithHealthLogger sets the logger for the health server.
func WithHealthLogger(logger observability.Logger) HealthOption {
	return func(hs *HealthServer) {
		hs.logger = logger
	}
}

// NewHealthServer creates a new health server.
func NewHealthServer(opts ...HealthOption) *HealthServer {
	hs := &HealthServer{
		services: make(map[string]healthpb.HealthCheckResponse_ServingStatus),
		watchers: make(map[string][]chan healthpb.HealthCheckResponse_ServingStatus),
		logger:   observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(hs)
	}

	// Set overall health to serving by default
	hs.services[""] = healthpb.HealthCheckResponse_SERVING

	return hs
}

// Check implements the Check RPC.
func (hs *HealthServer) Check(
	ctx context.Context,
	req *healthpb.HealthCheckRequest,
) (*healthpb.HealthCheckResponse, error) {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	if hs.shutdown {
		return &healthpb.HealthCheckResponse{
			Status: healthpb.HealthCheckResponse_NOT_SERVING,
		}, nil
	}

	service := req.GetService()
	servingStatus, ok := hs.services[service]
	if !ok {
		// If service is not registered, return NOT_FOUND for specific services
		// but SERVING for empty service (overall health)
		if service == "" {
			return &healthpb.HealthCheckResponse{
				Status: healthpb.HealthCheckResponse_SERVING,
			}, nil
		}
		return nil, statusError(codes.NotFound, "service not found: %s", service)
	}

	return &healthpb.HealthCheckResponse{
		Status: servingStatus,
	}, nil
}

// Watch implements the Watch RPC for streaming health updates.
func (hs *HealthServer) Watch(
	req *healthpb.HealthCheckRequest,
	stream healthpb.Health_WatchServer,
) error {
	service := req.GetService()

	// Create channel for updates
	updateCh := make(chan healthpb.HealthCheckResponse_ServingStatus, 1)

	// Register watcher
	hs.mu.Lock()
	hs.watchers[service] = append(hs.watchers[service], updateCh)

	// Send initial status
	initialStatus, ok := hs.services[service]
	if !ok {
		if service == "" {
			initialStatus = healthpb.HealthCheckResponse_SERVING
		} else {
			initialStatus = healthpb.HealthCheckResponse_SERVICE_UNKNOWN
		}
	}
	hs.mu.Unlock()

	// Send initial status
	if err := stream.Send(&healthpb.HealthCheckResponse{Status: initialStatus}); err != nil {
		hs.removeWatcher(service, updateCh)
		return err
	}

	// Watch for updates
	for {
		select {
		case servingStatus := <-updateCh:
			if err := stream.Send(&healthpb.HealthCheckResponse{Status: servingStatus}); err != nil {
				hs.removeWatcher(service, updateCh)
				return err
			}
		case <-stream.Context().Done():
			hs.removeWatcher(service, updateCh)
			return stream.Context().Err()
		}
	}
}

// SetServingStatus sets the serving status for a service.
func (hs *HealthServer) SetServingStatus(service string, servingStatus healthpb.HealthCheckResponse_ServingStatus) {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if hs.shutdown {
		return
	}

	hs.services[service] = servingStatus

	hs.logger.Debug("health status updated",
		observability.String("service", service),
		observability.String("status", servingStatus.String()),
	)

	// Notify watchers
	hs.notifyWatchers(service, servingStatus)
}

// Shutdown sets all services to NOT_SERVING.
func (hs *HealthServer) Shutdown() {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	hs.shutdown = true

	// Set all services to NOT_SERVING
	for service := range hs.services {
		hs.services[service] = healthpb.HealthCheckResponse_NOT_SERVING
		hs.notifyWatchers(service, healthpb.HealthCheckResponse_NOT_SERVING)
	}

	hs.logger.Info("health server shutdown")
}

// Resume resumes the health server after shutdown.
func (hs *HealthServer) Resume() {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	hs.shutdown = false

	// Set overall health to serving
	hs.services[""] = healthpb.HealthCheckResponse_SERVING
	hs.notifyWatchers("", healthpb.HealthCheckResponse_SERVING)

	hs.logger.Info("health server resumed")
}

// GetServingStatus returns the serving status for a service.
func (hs *HealthServer) GetServingStatus(service string) (healthpb.HealthCheckResponse_ServingStatus, bool) {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	servingStatus, ok := hs.services[service]
	return servingStatus, ok
}

// GetAllStatuses returns all service statuses.
func (hs *HealthServer) GetAllStatuses() map[string]healthpb.HealthCheckResponse_ServingStatus {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	result := make(map[string]healthpb.HealthCheckResponse_ServingStatus, len(hs.services))
	for k, v := range hs.services {
		result[k] = v
	}
	return result
}

// notifyWatchers notifies all watchers of a status change.
// Must be called with lock held.
func (hs *HealthServer) notifyWatchers(service string, servingStatus healthpb.HealthCheckResponse_ServingStatus) {
	watchers := hs.watchers[service]
	for _, ch := range watchers {
		select {
		case ch <- servingStatus:
		default:
			// Channel full, skip
		}
	}
}

// removeWatcher removes a watcher channel.
func (hs *HealthServer) removeWatcher(service string, ch chan healthpb.HealthCheckResponse_ServingStatus) {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	watchers := hs.watchers[service]
	for i, w := range watchers {
		if w == ch {
			hs.watchers[service] = append(watchers[:i], watchers[i+1:]...)
			close(ch)
			break
		}
	}
}

// statusError creates a gRPC status error.
func statusError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, format, args...)
}
