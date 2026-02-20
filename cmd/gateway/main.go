// Package main is the entry point for the API Gateway.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/gateway/operator"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Version information (set at build time).
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

// exitFunc is the function called to terminate the process.
// It defaults to os.Exit but can be overridden in tests.
var exitFunc = os.Exit

// cliFlags holds command line flags.
type cliFlags struct {
	configPath  string
	logLevel    string
	logFormat   string
	showVersion bool

	// Operator mode flags
	operatorMode                  bool
	operatorAddress               string
	gatewayName                   string
	gatewayNamespace              string
	operatorTLS                   bool
	operatorCAFile                string
	operatorCertFile              string
	operatorKeyFile               string
	operatorNamespaces            string
	operatorTLSInsecureSkipVerify bool
}

func main() {
	flags := parseFlags()

	if flags.showVersion {
		printVersion()
		return
	}

	logger := initLogger(flags)
	defer func() { _ = logger.Sync() }()

	// Check if operator mode is enabled
	if flags.operatorMode {
		runOperatorMode(flags, logger)
		return
	}

	// Standard file-based configuration mode
	cfg := loadAndValidateConfig(flags.configPath, logger)
	initClientIPExtractor(cfg, logger)
	app := initApplication(cfg, logger)

	runGateway(app, flags.configPath, logger)
}

// parseFlags parses command line flags.
func parseFlags() cliFlags {
	configPath := flag.String("config", getEnvOrDefault("GATEWAY_CONFIG_PATH", "configs/gateway.yaml"),
		"Path to configuration file")
	logLevel := flag.String("log-level", getEnvOrDefault("GATEWAY_LOG_LEVEL", "info"),
		"Log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", getEnvOrDefault("GATEWAY_LOG_FORMAT", "json"),
		"Log format (json, console)")
	showVersion := flag.Bool("version", false, "Show version information")

	// Operator mode flags
	operatorMode := flag.Bool("operator-mode", getEnvBool("GATEWAY_OPERATOR_MODE", false),
		"Enable operator mode (receive configuration from operator)")
	operatorAddress := flag.String("operator-address", getEnvOrDefault("GATEWAY_OPERATOR_ADDRESS", ""),
		"Operator gRPC server address (host:port)")
	gatewayName := flag.String("gateway-name", getEnvOrDefault("GATEWAY_NAME", ""),
		"Gateway name for operator registration")
	gatewayNamespace := flag.String("gateway-namespace", getEnvOrDefault("GATEWAY_NAMESPACE", "default"),
		"Gateway namespace for operator registration")
	operatorTLS := flag.Bool("operator-tls", getEnvBool("GATEWAY_OPERATOR_TLS", false),
		"Enable TLS for operator connection")
	operatorCAFile := flag.String("operator-ca-file", getEnvOrDefault("GATEWAY_OPERATOR_CA_FILE", ""),
		"CA certificate file for operator TLS")
	operatorCertFile := flag.String("operator-cert-file", getEnvOrDefault("GATEWAY_OPERATOR_CERT_FILE", ""),
		"Client certificate file for operator mTLS")
	operatorKeyFile := flag.String("operator-key-file", getEnvOrDefault("GATEWAY_OPERATOR_KEY_FILE", ""),
		"Client key file for operator mTLS")
	operatorNamespaces := flag.String("operator-namespaces", getEnvOrDefault("GATEWAY_OPERATOR_NAMESPACES", ""),
		"Comma-separated list of namespaces to watch (empty = all)")
	operatorTLSInsecureSkipVerify := flag.Bool("operator-tls-insecure",
		getEnvBool("GATEWAY_OPERATOR_TLS_INSECURE", false),
		"Skip TLS certificate verification for operator connection (dev/test only)")

	flag.Parse()

	return cliFlags{
		configPath:                    *configPath,
		logLevel:                      *logLevel,
		logFormat:                     *logFormat,
		showVersion:                   *showVersion,
		operatorMode:                  *operatorMode,
		operatorAddress:               *operatorAddress,
		gatewayName:                   *gatewayName,
		gatewayNamespace:              *gatewayNamespace,
		operatorTLS:                   *operatorTLS,
		operatorCAFile:                *operatorCAFile,
		operatorCertFile:              *operatorCertFile,
		operatorKeyFile:               *operatorKeyFile,
		operatorNamespaces:            *operatorNamespaces,
		operatorTLSInsecureSkipVerify: *operatorTLSInsecureSkipVerify,
	}
}

// buildOperatorConfig builds the operator client configuration from CLI flags.
func buildOperatorConfig(flags cliFlags) *operator.Config {
	cfg := operator.DefaultConfig()
	cfg.Enabled = true
	cfg.Address = flags.operatorAddress
	cfg.GatewayName = flags.gatewayName
	cfg.GatewayNamespace = flags.gatewayNamespace
	cfg.GatewayVersion = version

	// Parse namespaces
	if flags.operatorNamespaces != "" {
		cfg.Namespaces = strings.Split(flags.operatorNamespaces, ",")
		for i := range cfg.Namespaces {
			cfg.Namespaces[i] = strings.TrimSpace(cfg.Namespaces[i])
		}
	}

	// Configure TLS
	if flags.operatorTLS {
		cfg.TLS = &operator.TLSConfig{
			Enabled:            true,
			CAFile:             flags.operatorCAFile,
			CertFile:           flags.operatorCertFile,
			KeyFile:            flags.operatorKeyFile,
			InsecureSkipVerify: flags.operatorTLSInsecureSkipVerify,
		}
	}

	// Configure backoff
	cfg.ReconnectBackoff = operator.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		MaxRetries:      0, // Unlimited retries
	}

	return cfg
}

// printVersion prints version information and exits.
func printVersion() {
	fmt.Printf("avapigw version %s\n", version)
	fmt.Printf("  Build time: %s\n", buildTime)
	fmt.Printf("  Git commit: %s\n", gitCommit)
}

// initLogger initializes the logger.
func initLogger(flags cliFlags) observability.Logger {
	logger, err := observability.NewLogger(observability.LogConfig{
		Level:  flags.logLevel,
		Format: flags.logFormat,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		exitFunc(1)
		return nil // unreachable in production; allows test to continue
	}

	observability.SetGlobalLogger(logger)
	return logger
}

// fatalWithSync logs a fatal message and ensures logger is synced before exit.
func fatalWithSync(logger observability.Logger, msg string, fields ...observability.Field) {
	logger.Error(msg, fields...)
	_ = logger.Sync()
	exitFunc(1)
}
