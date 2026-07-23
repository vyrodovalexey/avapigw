package redisclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// vaultReadTimeout bounds a single Vault KV read during password resolution.
const vaultReadTimeout = 10 * time.Second

// pingTimeout bounds a single connectivity check performed at start-up.
const pingTimeout = 5 * time.Second

// PingMode controls how New treats initial connectivity failures.
type PingMode int

const (
	// PingRequired fails client construction when the initial
	// connectivity check does not succeed after all retries.
	PingRequired PingMode = iota

	// PingBestEffort logs initial connectivity failures but returns the
	// client anyway; go-redis reconnects transparently once the server
	// becomes reachable. This mode backs fail-open consumers that must
	// not couple their own availability to Redis availability.
	PingBestEffort
)

// Config describes a Redis connection in standalone or Sentinel mode.
// Exactly one of URL or Sentinel must be set; Sentinel takes precedence
// when both carry values (callers are expected to validate exclusivity).
type Config struct {
	// URL is the Redis connection URL for standalone mode.
	URL string

	// Sentinel contains Redis Sentinel configuration for high availability.
	Sentinel *config.RedisSentinelConfig

	// PoolSize is the maximum number of connections in the pool.
	PoolSize int

	// ConnectTimeout is the dial timeout.
	ConnectTimeout time.Duration

	// ReadTimeout is the timeout for read operations.
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations.
	WriteTimeout time.Duration

	// TLS contains TLS configuration for Redis connections.
	TLS *config.TLSConfig

	// PasswordVaultPath is the Vault path for the standalone Redis password.
	PasswordVaultPath string

	// Retry configures the exponential backoff used for the initial
	// connectivity check.
	Retry *config.RedisRetryConfig
}

// FromRateLimitRedisConfig maps the rate limiter Redis configuration onto
// the shared client configuration.
func FromRateLimitRedisConfig(rc *config.RateLimitRedisConfig) *Config {
	if rc == nil {
		return nil
	}
	return &Config{
		URL:               rc.URL,
		Sentinel:          rc.Sentinel,
		PoolSize:          rc.PoolSize,
		ConnectTimeout:    rc.ConnectTimeout.Duration(),
		ReadTimeout:       rc.ReadTimeout.Duration(),
		WriteTimeout:      rc.WriteTimeout.Duration(),
		TLS:               rc.TLS,
		PasswordVaultPath: rc.PasswordVaultPath,
		Retry:             rc.Retry,
	}
}

// FromRedisCacheConfig maps the cache Redis configuration onto the shared
// client configuration. It exists so the cache subsystem can migrate to
// this package without another mapping layer.
func FromRedisCacheConfig(rc *config.RedisCacheConfig) *Config {
	if rc == nil {
		return nil
	}
	return &Config{
		URL:               rc.URL,
		Sentinel:          rc.Sentinel,
		PoolSize:          rc.PoolSize,
		ConnectTimeout:    rc.ConnectTimeout.Duration(),
		ReadTimeout:       rc.ReadTimeout.Duration(),
		WriteTimeout:      rc.WriteTimeout.Duration(),
		TLS:               rc.TLS,
		PasswordVaultPath: rc.PasswordVaultPath,
		Retry:             rc.Retry,
	}
}

// Option customizes client construction.
type Option func(*options)

// options holds optional dependencies for client construction.
type options struct {
	vaultClient vault.Client
	dialer      func(ctx context.Context, network, addr string) (net.Conn, error)
	pingMode    PingMode
}

// WithVaultClient supplies a Vault client for resolving Redis passwords
// referenced by Vault paths in the configuration.
func WithVaultClient(client vault.Client) Option {
	return func(o *options) {
		o.vaultClient = client
	}
}

// WithDialer overrides the network dialer (used in tests for Docker or
// miniredis networking).
func WithDialer(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(o *options) {
		o.dialer = dialer
	}
}

// WithPingMode sets the initial connectivity check mode (default PingRequired).
func WithPingMode(mode PingMode) Option {
	return func(o *options) {
		o.pingMode = mode
	}
}

// New builds a Redis client (standalone or Sentinel failover, depending on
// cfg), resolves Vault-referenced passwords, and verifies connectivity with
// exponential-backoff retry. The context bounds Vault reads and the
// connectivity check and honors caller cancellation.
//
// The caller's cfg is never mutated: resolved passwords live only in copies
// so secrets do not leak back into shared configuration structs.
func New(
	ctx context.Context, cfg *Config, logger observability.Logger, opts ...Option,
) (redis.UniversalClient, error) {
	if cfg == nil {
		return nil, errors.New("redis configuration is required")
	}
	if logger == nil {
		logger = observability.NopLogger()
	}

	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	resolved, err := resolvePasswords(ctx, cfg, o.vaultClient, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve redis passwords: %w", err)
	}

	client, err := buildClient(resolved, o)
	if err != nil {
		return nil, err
	}

	if err := pingWithRetry(ctx, client, resolved.Retry, logger); err != nil {
		if o.pingMode == PingRequired {
			_ = client.Close()
			return nil, fmt.Errorf("redis connection failed: %w", err)
		}
		logger.Error("redis initial connectivity check failed; continuing (best-effort ping mode)",
			observability.Error(err),
		)
	}

	return client, nil
}

// buildClient dispatches between Sentinel failover and standalone modes.
func buildClient(cfg *Config, o *options) (redis.UniversalClient, error) {
	if !cfg.Sentinel.IsEmpty() {
		foOpts, err := BuildFailoverOptions(cfg, o.dialer)
		if err != nil {
			return nil, err
		}
		return redis.NewFailoverClient(foOpts), nil
	}

	if cfg.URL == "" {
		return nil, errors.New("redis URL is required for standalone mode")
	}

	stOpts, err := BuildStandaloneOptions(cfg)
	if err != nil {
		return nil, err
	}
	if o.dialer != nil {
		stOpts.Dialer = o.dialer
	}
	return redis.NewClient(stOpts), nil
}

// BuildStandaloneOptions maps the shared configuration onto go-redis
// standalone options. It is exported so tests can verify the mapping
// without opening network connections.
func BuildStandaloneOptions(cfg *Config) (*redis.Options, error) {
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %w", err)
	}

	if cfg.PoolSize > 0 {
		opts.PoolSize = cfg.PoolSize
	}
	if cfg.ConnectTimeout > 0 {
		opts.DialTimeout = cfg.ConnectTimeout
	}
	if cfg.ReadTimeout > 0 {
		opts.ReadTimeout = cfg.ReadTimeout
	}
	if cfg.WriteTimeout > 0 {
		opts.WriteTimeout = cfg.WriteTimeout
	}

	tlsCfg, err := tlsConfigFor(cfg, opts.TLSConfig)
	if err != nil {
		return nil, err
	}
	opts.TLSConfig = tlsCfg

	return opts, nil
}

// BuildFailoverOptions maps the shared configuration onto go-redis Sentinel
// failover options. It is exported so tests can verify the mapping without
// a live Sentinel deployment.
func BuildFailoverOptions(
	cfg *Config, dialer func(ctx context.Context, network, addr string) (net.Conn, error),
) (*redis.FailoverOptions, error) {
	sentinel := cfg.Sentinel
	opts := &redis.FailoverOptions{
		MasterName:       sentinel.MasterName,
		SentinelAddrs:    sentinel.SentinelAddrs,
		SentinelPassword: sentinel.SentinelPassword,
		Password:         sentinel.Password,
		DB:               sentinel.DB,
	}

	if dialer != nil {
		opts.Dialer = dialer
	}
	if cfg.PoolSize > 0 {
		opts.PoolSize = cfg.PoolSize
	}
	if cfg.ConnectTimeout > 0 {
		opts.DialTimeout = cfg.ConnectTimeout
	}
	if cfg.ReadTimeout > 0 {
		opts.ReadTimeout = cfg.ReadTimeout
	}
	if cfg.WriteTimeout > 0 {
		opts.WriteTimeout = cfg.WriteTimeout
	}

	tlsCfg, err := tlsConfigFor(cfg, opts.TLSConfig)
	if err != nil {
		return nil, err
	}
	opts.TLSConfig = tlsCfg

	return opts, nil
}

// tlsConfigFor returns the TLS client configuration when TLS is enabled,
// otherwise the existing configuration (which may come from a rediss:// URL).
func tlsConfigFor(cfg *Config, existing *tls.Config) (*tls.Config, error) {
	if cfg.TLS == nil || !cfg.TLS.Enabled {
		return existing, nil
	}
	return NewTLSConfig(cfg.TLS)
}

// NewTLSConfig builds a *tls.Config from the shared Redis TLS configuration,
// honoring the client certificate (certFile/keyFile for mTLS-to-Redis), the
// private CA bundle (caFile), the min/max protocol versions, and
// insecureSkipVerify. A clear error is returned when a referenced file is
// unreadable or unparsable so misconfigured TLS never silently degrades to
// system-trust-only. It is shared by the redisclient and cache Redis
// builders.
func NewTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // User-configurable for dev environments
		MinVersion:         tls.VersionTLS12,
	}

	if cfg.MinVersion != "" {
		tlsCfg.MinVersion = tlspkg.TLSVersion(cfg.MinVersion).ToTLSVersion()
	}
	if cfg.MaxVersion != "" {
		tlsCfg.MaxVersion = tlspkg.TLSVersion(cfg.MaxVersion).ToTLSVersion()
	}

	if err := loadRedisClientCertificate(cfg, tlsCfg); err != nil {
		return nil, err
	}
	if err := loadRedisCA(cfg, tlsCfg); err != nil {
		return nil, err
	}

	return tlsCfg, nil
}

// loadRedisClientCertificate loads the X.509 client keypair for
// mTLS-to-Redis when configured. Both certFile and keyFile must be present.
func loadRedisClientCertificate(cfg *config.TLSConfig, tlsCfg *tls.Config) error {
	if cfg.CertFile == "" && cfg.KeyFile == "" {
		return nil
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return errors.New("redis TLS requires both certFile and keyFile for a client certificate")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load redis TLS client certificate (certFile=%s): %w",
			cfg.CertFile, err)
	}
	tlsCfg.Certificates = []tls.Certificate{cert}
	return nil
}

// loadRedisCA loads the private CA bundle used to verify the Redis server
// certificate when configured.
func loadRedisCA(cfg *config.TLSConfig, tlsCfg *tls.Config) error {
	if cfg.CAFile == "" {
		return nil
	}

	caPEM, err := os.ReadFile(cfg.CAFile) // #nosec G304 -- path comes from validated gateway configuration
	if err != nil {
		return fmt.Errorf("failed to read redis TLS CA file %s: %w", cfg.CAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("failed to parse redis TLS CA file %s: no valid PEM certificates", cfg.CAFile)
	}
	tlsCfg.RootCAs = pool
	return nil
}

// pingWithRetry verifies connectivity using exponential backoff. Each
// attempt is bounded by pingTimeout; the whole loop honors ctx.
func pingWithRetry(
	ctx context.Context, client redis.UniversalClient, retryCfg *config.RedisRetryConfig,
	logger observability.Logger,
) error {
	cfg := &retry.Config{
		MaxRetries:     retryCfg.GetMaxRetries(),
		InitialBackoff: retryCfg.GetInitialBackoff().Duration(),
		MaxBackoff:     retryCfg.GetMaxBackoff().Duration(),
		JitterFactor:   retry.DefaultJitterFactor,
	}

	return retry.Do(ctx, cfg, func() error {
		pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
		defer cancel()
		return client.Ping(pingCtx).Err()
	}, &retry.Options{
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			logger.Warn("redis connectivity check failed, retrying",
				observability.Int("attempt", attempt),
				observability.Duration("backoff", backoff),
				observability.Error(err),
			)
		},
	})
}

// resolvePasswords resolves Vault-referenced passwords and returns a copy
// of cfg carrying the resolved secrets. The input cfg (and its Sentinel
// block) is never mutated.
func resolvePasswords(
	ctx context.Context, cfg *Config, vaultClient vault.Client, logger observability.Logger,
) (*Config, error) {
	resolved := *cfg
	if cfg.Sentinel != nil {
		sentinelCopy := *cfg.Sentinel
		resolved.Sentinel = &sentinelCopy
	}

	if !hasVaultPaths(cfg) {
		return &resolved, nil
	}

	if vaultClient == nil || !vaultClient.IsEnabled() {
		logger.Warn("redis vault paths configured but vault client is not available")
		return &resolved, nil
	}

	if err := resolveStandalonePassword(ctx, &resolved, vaultClient, logger); err != nil {
		return nil, err
	}
	if err := resolveSentinelPasswords(ctx, resolved.Sentinel, vaultClient, logger); err != nil {
		return nil, err
	}

	return &resolved, nil
}

// hasVaultPaths reports whether any Vault password paths are configured.
func hasVaultPaths(cfg *Config) bool {
	if cfg.PasswordVaultPath != "" {
		return true
	}
	if cfg.Sentinel == nil {
		return false
	}
	return cfg.Sentinel.PasswordVaultPath != "" || cfg.Sentinel.SentinelPasswordVaultPath != ""
}

// resolveStandalonePassword reads the standalone Redis password from Vault
// and injects it into the connection URL.
func resolveStandalonePassword(
	ctx context.Context, cfg *Config, vaultClient vault.Client, logger observability.Logger,
) error {
	if cfg.PasswordVaultPath == "" {
		return nil
	}

	pw, err := ReadVaultPassword(ctx, vaultClient, cfg.PasswordVaultPath)
	if err != nil {
		return fmt.Errorf("failed to read redis password from vault path %s: %w", cfg.PasswordVaultPath, err)
	}

	withPassword, err := applyPasswordToURL(cfg.URL, pw)
	if err != nil {
		return fmt.Errorf("failed to apply vault password to redis URL: %w", err)
	}
	cfg.URL = withPassword

	logger.Info("redis password resolved from vault",
		observability.String("vaultPath", cfg.PasswordVaultPath))
	return nil
}

// resolveSentinelPasswords resolves the master and Sentinel passwords from Vault.
func resolveSentinelPasswords(
	ctx context.Context, sentinel *config.RedisSentinelConfig, vaultClient vault.Client,
	logger observability.Logger,
) error {
	if sentinel == nil {
		return nil
	}

	if sentinel.PasswordVaultPath != "" {
		pw, err := ReadVaultPassword(ctx, vaultClient, sentinel.PasswordVaultPath)
		if err != nil {
			return fmt.Errorf("failed to read redis master password from vault: %w", err)
		}
		sentinel.Password = pw
		logger.Info("redis sentinel master password resolved from vault",
			observability.String("vaultPath", sentinel.PasswordVaultPath))
	}

	if sentinel.SentinelPasswordVaultPath != "" {
		pw, err := ReadVaultPassword(ctx, vaultClient, sentinel.SentinelPasswordVaultPath)
		if err != nil {
			return fmt.Errorf("failed to read sentinel password from vault: %w", err)
		}
		sentinel.SentinelPassword = pw
		logger.Info("redis sentinel password resolved from vault",
			observability.String("vaultPath", sentinel.SentinelPasswordVaultPath))
	}

	return nil
}

// ReadVaultPassword reads a password from a Vault KV path. The path format
// is "mount/path" and the secret must contain a "password" key. The read
// honors the caller's context and is additionally bounded by vaultReadTimeout.
func ReadVaultPassword(ctx context.Context, vaultClient vault.Client, vaultPath string) (string, error) {
	parts := strings.SplitN(vaultPath, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid vault path format %q, expected mount/path", vaultPath)
	}

	mount, path := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, vaultReadTimeout)
	defer cancel()

	data, err := vaultClient.KV().Read(ctx, mount, path)
	if err != nil {
		return "", fmt.Errorf("vault read failed: %w", err)
	}

	pw, ok := data["password"].(string)
	if !ok || pw == "" {
		return "", fmt.Errorf("vault secret at %q does not contain a valid 'password' key", vaultPath)
	}

	return pw, nil
}

// applyPasswordToURL injects the given password into a Redis URL,
// preserving any username already present.
func applyPasswordToURL(rawURL, password string) (string, error) {
	if rawURL == "" {
		return "", nil
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse redis URL: %w", err)
	}

	var username string
	if parsedURL.User != nil {
		username = parsedURL.User.Username()
	}
	parsedURL.User = url.UserPassword(username, password)
	return parsedURL.String(), nil
}
