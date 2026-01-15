package grpc

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// HealthServer implements the gRPC health check service.
type HealthServer struct {
	healthpb.UnimplementedHealthServer
	checks map[string]func() healthpb.HealthCheckResponse_ServingStatus
	status map[string]healthpb.HealthCheckResponse_ServingStatus
	mu     sync.RWMutex
}

// NewHealthServer creates a new health server.
func NewHealthServer() *HealthServer {
	return &HealthServer{
		checks: make(map[string]func() healthpb.HealthCheckResponse_ServingStatus),
		status: make(map[string]healthpb.HealthCheckResponse_ServingStatus),
	}
}

// Check implements the Health.Check RPC.
func (s *HealthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	service := req.GetService()

	// Check if there's a dynamic check function
	if checkFunc, ok := s.checks[service]; ok {
		return &healthpb.HealthCheckResponse{
			Status: checkFunc(),
		}, nil
	}

	// Check static status
	if status, ok := s.status[service]; ok {
		return &healthpb.HealthCheckResponse{
			Status: status,
		}, nil
	}

	// If service is empty, return overall status
	if service == "" {
		// Default to serving if no status is set
		return &healthpb.HealthCheckResponse{
			Status: healthpb.HealthCheckResponse_SERVING,
		}, nil
	}

	return nil, status.Errorf(codes.NotFound, "unknown service: %s", service)
}

// Watch implements the Health.Watch RPC.
func (s *HealthServer) Watch(req *healthpb.HealthCheckRequest, stream healthpb.Health_WatchServer) error {
	service := req.GetService()

	// Send initial status
	s.mu.RLock()
	var currentStatus healthpb.HealthCheckResponse_ServingStatus

	if checkFunc, ok := s.checks[service]; ok {
		currentStatus = checkFunc()
	} else if st, ok := s.status[service]; ok {
		currentStatus = st
	} else if service == "" {
		currentStatus = healthpb.HealthCheckResponse_SERVING
	} else {
		s.mu.RUnlock()
		return status.Errorf(codes.NotFound, "unknown service: %s", service)
	}
	s.mu.RUnlock()

	if err := stream.Send(&healthpb.HealthCheckResponse{Status: currentStatus}); err != nil {
		return err
	}

	// For simplicity, we don't implement continuous watching
	// In a production system, you would use channels to notify of status changes
	<-stream.Context().Done()
	return stream.Context().Err()
}

// SetServingStatus sets the serving status for a service.
func (s *HealthServer) SetServingStatus(service string, status healthpb.HealthCheckResponse_ServingStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status[service] = status
}

// SetCheck sets a dynamic check function for a service.
func (s *HealthServer) SetCheck(service string, check func() healthpb.HealthCheckResponse_ServingStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks[service] = check
}

// RemoveCheck removes a check for a service.
func (s *HealthServer) RemoveCheck(service string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.checks, service)
	delete(s.status, service)
}

// Shutdown sets all services to NOT_SERVING.
func (s *HealthServer) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for service := range s.status {
		s.status[service] = healthpb.HealthCheckResponse_NOT_SERVING
	}
	s.status[""] = healthpb.HealthCheckResponse_NOT_SERVING
}

// Resume sets all services to SERVING.
func (s *HealthServer) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for service := range s.status {
		s.status[service] = healthpb.HealthCheckResponse_SERVING
	}
	s.status[""] = healthpb.HealthCheckResponse_SERVING
}

// Register registers the health server with a gRPC server.
func (s *HealthServer) Register(server *grpc.Server) {
	healthpb.RegisterHealthServer(server, s)
}

// HealthChecker is a helper for creating health check functions.
type HealthChecker struct {
	checks []func() bool
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		checks: make([]func() bool, 0),
	}
}

// AddCheck adds a health check function.
func (c *HealthChecker) AddCheck(check func() bool) {
	c.checks = append(c.checks, check)
}

// Check runs all checks and returns the overall status.
func (c *HealthChecker) Check() healthpb.HealthCheckResponse_ServingStatus {
	for _, check := range c.checks {
		if !check() {
			return healthpb.HealthCheckResponse_NOT_SERVING
		}
	}
	return healthpb.HealthCheckResponse_SERVING
}

// ToCheckFunc converts the health checker to a check function.
func (c *HealthChecker) ToCheckFunc() func() healthpb.HealthCheckResponse_ServingStatus {
	return c.Check
}
