// Package config provides configuration types and loading for the
// API Gateway.
//
// This package defines the complete configuration model, YAML loading
// with environment variable substitution, validation, and file
// watching for hot-reload support.
//
// # Features
//
//   - YAML configuration file loading
//   - Environment variable substitution with ${VAR:-default} syntax
//   - Configuration validation with detailed error reporting
//   - File watching for configuration hot-reload
//   - gRPC and HTTP route configuration
//   - Backend, authentication, authorization, and observability config
//
// # Configuration Loading
//
// Load configuration from a YAML file:
//
//	loader := config.NewLoader()
//	cfg, err := loader.LoadFile("gateway.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # File Watching
//
// Watch for configuration changes:
//
//	watcher, err := config.NewWatcher(configPath, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	watcher.OnChange(func(cfg *config.GatewayConfig) {
//	    // Handle configuration update
//	})
//
//	watcher.Start(ctx)
package config
