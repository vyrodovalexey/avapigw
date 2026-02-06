// Package grpc provides gRPC server and client for operator-gateway communication.
package grpc

import "time"

// gRPC server keepalive parameters.
const (
	// DefaultMaxConnectionIdle is the maximum time a connection can be idle before being closed.
	DefaultMaxConnectionIdle = 5 * time.Minute

	// DefaultMaxConnectionAge is the maximum age of a connection before it's closed.
	DefaultMaxConnectionAge = 30 * time.Minute

	// DefaultMaxConnectionAgeGrace is the grace period for connection age.
	DefaultMaxConnectionAgeGrace = 5 * time.Second

	// DefaultKeepaliveTime is the interval for keepalive pings.
	DefaultKeepaliveTime = 30 * time.Second

	// DefaultKeepaliveTimeout is the timeout for keepalive pings.
	DefaultKeepaliveTimeout = 10 * time.Second

	// DefaultMinKeepaliveTime is the minimum time between keepalive pings from clients.
	DefaultMinKeepaliveTime = 10 * time.Second
)

// gRPC server message size defaults.
const (
	// DefaultMaxMessageSize is the default maximum message size in bytes (4MB).
	DefaultMaxMessageSize = 4 * 1024 * 1024
)

// gRPC server defaults.
const (
	// DefaultPort is the default gRPC server port.
	DefaultPort = 9444

	// DefaultMaxConcurrentStreams is the default maximum number of concurrent streams.
	DefaultMaxConcurrentStreams = 100
)
