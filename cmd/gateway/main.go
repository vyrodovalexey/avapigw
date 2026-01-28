// Package main is the entry point for the API Gateway.
package main

import (
	"flag"
	"fmt"
	"os"

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
}

func main() {
	flags := parseFlags()

	if flags.showVersion {
		printVersion()
		return
	}

	logger := initLogger(flags)
	defer func() { _ = logger.Sync() }()

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
	flag.Parse()

	return cliFlags{
		configPath:  *configPath,
		logLevel:    *logLevel,
		logFormat:   *logFormat,
		showVersion: *showVersion,
	}
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
