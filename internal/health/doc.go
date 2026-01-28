// Package health provides health check and readiness probe endpoints
// for the API Gateway.
//
// This package implements Kubernetes-compatible health and readiness
// endpoints with extensible check registration and detailed status
// reporting.
//
// # Features
//
//   - Liveness probe endpoint (/healthz)
//   - Readiness probe endpoint (/readyz)
//   - Extensible health check registration
//   - Detailed status reporting with uptime and resource usage
//   - Go runtime metrics (goroutines, memory)
//   - Hostname and version information
//
// # Usage
//
// Create a health checker and register checks:
//
//	checker := health.NewChecker(version, logger)
//
//	checker.RegisterCheck("database", func() health.Check {
//	    return health.Check{
//	        Status:  health.StatusHealthy,
//	        Message: "connected",
//	    }
//	})
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/healthz", checker.HealthHandler)
//	mux.HandleFunc("/readyz", checker.ReadinessHandler)
package health
