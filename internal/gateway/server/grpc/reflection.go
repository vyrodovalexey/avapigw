package grpc

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// EnableReflection enables gRPC reflection for debugging.
// This allows tools like grpcurl to discover services and methods.
func EnableReflection(server *grpc.Server) {
	reflection.Register(server)
}

// ReflectionConfig holds configuration for gRPC reflection.
type ReflectionConfig struct {
	// Enabled indicates whether reflection is enabled.
	Enabled bool
	// ServiceNames is a list of service names to expose via reflection.
	// If empty, all services are exposed.
	ServiceNames []string
}

// DefaultReflectionConfig returns a default reflection configuration.
func DefaultReflectionConfig() *ReflectionConfig {
	return &ReflectionConfig{
		Enabled:      false,
		ServiceNames: nil,
	}
}

// RegisterReflection registers reflection with the given configuration.
func RegisterReflection(server *grpc.Server, config *ReflectionConfig) {
	if config == nil || !config.Enabled {
		return
	}

	// Register reflection
	// Note: The standard reflection package doesn't support filtering services
	// For filtered reflection, you would need a custom implementation
	reflection.Register(server)
}
