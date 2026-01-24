package server

import (
	"crypto/tls"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// Option is a functional option for configuring the gRPC server.
type Option func(*Server)

// WithLogger sets the logger for the server.
func WithLogger(logger observability.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

// WithMaxConcurrentStreams sets the maximum number of concurrent streams per connection.
func WithMaxConcurrentStreams(n uint32) Option {
	return func(s *Server) {
		s.maxConcurrentStreams = n
	}
}

// WithMaxRecvMsgSize sets the maximum message size the server can receive.
func WithMaxRecvMsgSize(size int) Option {
	return func(s *Server) {
		s.maxRecvMsgSize = size
	}
}

// WithMaxSendMsgSize sets the maximum message size the server can send.
func WithMaxSendMsgSize(size int) Option {
	return func(s *Server) {
		s.maxSendMsgSize = size
	}
}

// WithKeepaliveParams sets the keepalive parameters for the server.
func WithKeepaliveParams(kp keepalive.ServerParameters) Option {
	return func(s *Server) {
		s.keepaliveParams = &kp
	}
}

// WithKeepaliveEnforcementPolicy sets the keepalive enforcement policy.
func WithKeepaliveEnforcementPolicy(kep keepalive.EnforcementPolicy) Option {
	return func(s *Server) {
		s.keepaliveEnforcement = &kep
	}
}

// WithUnaryInterceptors adds unary interceptors to the server.
func WithUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) Option {
	return func(s *Server) {
		s.unaryInterceptors = append(s.unaryInterceptors, interceptors...)
	}
}

// WithStreamInterceptors adds stream interceptors to the server.
func WithStreamInterceptors(interceptors ...grpc.StreamServerInterceptor) Option {
	return func(s *Server) {
		s.streamInterceptors = append(s.streamInterceptors, interceptors...)
	}
}

// WithTLSCredentials sets TLS credentials for the server.
func WithTLSCredentials(certFile, keyFile string) Option {
	return func(s *Server) {
		s.tlsCertFile = certFile
		s.tlsKeyFile = keyFile
	}
}

// WithAddress sets the address for the server to listen on.
func WithAddress(addr string) Option {
	return func(s *Server) {
		s.address = addr
	}
}

// WithUnknownServiceHandler sets the handler for unknown services.
// This is used for transparent proxying.
func WithUnknownServiceHandler(handler grpc.StreamHandler) Option {
	return func(s *Server) {
		s.unknownServiceHandler = handler
	}
}

// WithReflection enables gRPC reflection service.
func WithReflection(enabled bool) Option {
	return func(s *Server) {
		s.reflectionEnabled = enabled
	}
}

// WithHealthService enables gRPC health service.
func WithHealthService(enabled bool) Option {
	return func(s *Server) {
		s.healthServiceEnabled = enabled
	}
}

// WithConnectionTimeout sets the connection timeout.
func WithConnectionTimeout(timeout time.Duration) Option {
	return func(s *Server) {
		s.connectionTimeout = timeout
	}
}

// WithGracefulStopTimeout sets the graceful stop timeout.
func WithGracefulStopTimeout(timeout time.Duration) Option {
	return func(s *Server) {
		s.gracefulStopTimeout = timeout
	}
}

// WithTLSManager sets the TLS manager for the server.
func WithTLSManager(manager *tlspkg.Manager) Option {
	return func(s *Server) {
		s.tlsManager = manager
	}
}

// WithTLSMetrics sets the TLS metrics for the server.
func WithTLSMetrics(metrics tlspkg.MetricsRecorder) Option {
	return func(s *Server) {
		s.tlsMetrics = metrics
	}
}

// WithTLSConfig sets the TLS configuration directly.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(s *Server) {
		s.tlsConfig = tlsConfig
	}
}

// WithInsecure enables insecure mode (no TLS) for development.
func WithInsecure() Option {
	return func(s *Server) {
		s.insecure = true
	}
}

// WithALPNEnforcement enables ALPN protocol enforcement.
func WithALPNEnforcement(enabled bool) Option {
	return func(s *Server) {
		s.requireALPN = enabled
	}
}

// WithClientCertMetadata enables extraction of client certificate identity to metadata.
func WithClientCertMetadata(enabled bool) Option {
	return func(s *Server) {
		s.extractClientCertMetadata = enabled
	}
}
