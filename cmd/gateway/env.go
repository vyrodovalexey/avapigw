package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// warnInvalidEnvValue is the log message emitted when an environment variable
// holds a value that cannot be parsed. The variable is ignored and the
// previous (file-based or default) value is kept, but the misconfiguration is
// surfaced instead of silently swallowed.
const warnInvalidEnvValue = "invalid environment variable value; using default"

// Redis Sentinel environment variable names.
const (
	// envRedisSentinelMasterName overrides the Redis Sentinel master name.
	envRedisSentinelMasterName = "REDIS_SENTINEL_MASTER_NAME"

	// envRedisSentinelAddrs overrides the Redis Sentinel addresses (comma-separated).
	envRedisSentinelAddrs = "REDIS_SENTINEL_ADDRS"

	// envRedisSentinelPassword overrides the Redis Sentinel authentication password.
	envRedisSentinelPassword = "REDIS_SENTINEL_PASSWORD"

	// envRedisMasterPassword overrides the Redis master password for Sentinel connections.
	envRedisMasterPassword = "REDIS_MASTER_PASSWORD"
)

// Vault client connection environment variable names. They override the
// corresponding spec.vault fields per-field (ENV > file > defaults) and are
// the legacy env-only configuration surface when spec.vault is absent.
const (
	// envVaultAddr overrides spec.vault.address and (legacy trigger) forces
	// the vault client on.
	envVaultAddr = "VAULT_ADDR"

	// envVaultAuthMethod overrides spec.vault.authMethod.
	envVaultAuthMethod = "VAULT_AUTH_METHOD"

	// envVaultToken overrides spec.vault.token (and clears tokenFile).
	envVaultToken = "VAULT_TOKEN"

	// envVaultNamespace overrides spec.vault.namespace.
	envVaultNamespace = "VAULT_NAMESPACE"

	// envVaultCACert overrides spec.vault.tls.caCert.
	envVaultCACert = "VAULT_CACERT"

	// envVaultCAPath overrides spec.vault.tls.caPath.
	envVaultCAPath = "VAULT_CAPATH"

	// envVaultClientCert overrides spec.vault.tls.clientCert.
	envVaultClientCert = "VAULT_CLIENT_CERT"

	// envVaultClientKey overrides spec.vault.tls.clientKey.
	envVaultClientKey = "VAULT_CLIENT_KEY"

	// envVaultSkipVerify overrides spec.vault.tls.skipVerify.
	envVaultSkipVerify = "VAULT_SKIP_VERIFY"

	// envVaultK8sRole overrides spec.vault.kubernetes.role.
	envVaultK8sRole = "VAULT_K8S_ROLE"

	// envVaultK8sMountPath overrides spec.vault.kubernetes.mountPath.
	envVaultK8sMountPath = "VAULT_K8S_MOUNT_PATH"

	// envVaultK8sTokenPath overrides spec.vault.kubernetes.tokenPath.
	envVaultK8sTokenPath = "VAULT_K8S_TOKEN_PATH" //nolint:gosec // G101: environment variable NAME, not a credential

	// envVaultAppRoleRoleID overrides spec.vault.appRole.roleId.
	envVaultAppRoleRoleID = "VAULT_APPROLE_ROLE_ID"

	// envVaultAppRoleSecretID overrides spec.vault.appRole.secretId (and
	// clears secretIdFile).
	envVaultAppRoleSecretID = "VAULT_APPROLE_SECRET_ID" //nolint:gosec // G101: env var NAME, not a credential

	// envVaultAppRoleMountPath overrides spec.vault.appRole.mountPath.
	envVaultAppRoleMountPath = "VAULT_APPROLE_MOUNT_PATH"
)

// Redis cache feature environment variable names.
const (
	// envRedisTTLJitter overrides the Redis TTL jitter factor (e.g., "0.1" for 10%).
	envRedisTTLJitter = "REDIS_TTL_JITTER"

	// envRedisHashKeys enables key hashing ("true"/"false").
	envRedisHashKeys = "REDIS_HASH_KEYS"

	// envRedisPasswordVaultPath overrides the Vault path for Redis password.
	envRedisPasswordVaultPath = "REDIS_PASSWORD_VAULT_PATH"

	// envRedisSentinelPasswordVaultPath overrides the Vault path for Redis master password.
	envRedisSentinelPasswordVaultPath = "REDIS_SENTINEL_PASSWORD_VAULT_PATH"

	// envRedisSentinelSentinelPasswordVaultPath overrides the Vault path for Sentinel password.
	envRedisSentinelSentinelPasswordVaultPath = "REDIS_SENTINEL_SENTINEL_PASSWORD_VAULT_PATH"
)

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool returns the environment variable as a boolean or a default.
// Accepts "true", "1", "yes", "on" / "false", "0", "no", "off"
// (case-insensitive). Any other non-empty value is reported with a warning
// naming the variable and the offending value, then the default is used.
func getEnvBool(key string, defaultValue bool, logger observability.Logger) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	// Parse common boolean representations
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		ensureEnvLogger(logger).Warn(warnInvalidEnvValue,
			observability.String("variable", key),
			observability.String("value", value),
			observability.Bool("default", defaultValue),
		)
		return defaultValue
	}
}

// ensureEnvLogger returns logger, falling back to the process-wide logger so
// env parse warnings are never silently dropped by a nil injection.
func ensureEnvLogger(logger observability.Logger) observability.Logger {
	if logger != nil {
		return logger
	}
	return observability.L()
}

// applyRedisSentinelEnv applies Redis Sentinel environment variable overrides
// to the given RedisCacheConfig. Environment variables take priority over
// file-based configuration values.
func applyRedisSentinelEnv(redisCfg *config.RedisCacheConfig) {
	if redisCfg == nil {
		return
	}

	masterName := os.Getenv(envRedisSentinelMasterName)
	sentinelAddrs := os.Getenv(envRedisSentinelAddrs)
	sentinelPassword := os.Getenv(envRedisSentinelPassword)
	masterPassword := os.Getenv(envRedisMasterPassword)

	// If no sentinel env vars are set, nothing to do
	if masterName == "" && sentinelAddrs == "" && sentinelPassword == "" && masterPassword == "" {
		return
	}

	// Initialize sentinel config if not present
	if redisCfg.Sentinel == nil {
		redisCfg.Sentinel = &config.RedisSentinelConfig{}
	}

	if masterName != "" {
		redisCfg.Sentinel.MasterName = masterName
	}

	if sentinelAddrs != "" {
		addrs := strings.Split(sentinelAddrs, ",")
		trimmed := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if a := strings.TrimSpace(addr); a != "" {
				trimmed = append(trimmed, a)
			}
		}
		redisCfg.Sentinel.SentinelAddrs = trimmed
	}

	if sentinelPassword != "" {
		redisCfg.Sentinel.SentinelPassword = sentinelPassword
	}

	if masterPassword != "" {
		redisCfg.Sentinel.Password = masterPassword
	}
}

// applyRedisFeatureEnv applies Redis feature environment variable overrides
// (TTL jitter, hash keys, vault paths) to the given RedisCacheConfig.
// Environment variables take priority over file-based configuration values.
// Unparsable values are reported via logger and the existing value is kept.
func applyRedisFeatureEnv(redisCfg *config.RedisCacheConfig, logger observability.Logger) {
	if redisCfg == nil {
		return
	}
	logger = ensureEnvLogger(logger)

	// TTL jitter
	if jitterStr := os.Getenv(envRedisTTLJitter); jitterStr != "" {
		jitter, err := strconv.ParseFloat(jitterStr, 64)
		if err != nil {
			logger.Warn(warnInvalidEnvValue,
				observability.String("variable", envRedisTTLJitter),
				observability.String("value", jitterStr),
				observability.Float64("default", redisCfg.TTLJitter),
				observability.Error(err),
			)
		} else {
			redisCfg.TTLJitter = jitter
		}
	}

	// Hash keys ("true"/"false"). getEnvBool keeps the current value and
	// warns when the variable holds an invalid boolean representation.
	redisCfg.HashKeys = getEnvBool(envRedisHashKeys, redisCfg.HashKeys, logger)

	// Vault paths for passwords
	if vaultPath := os.Getenv(envRedisPasswordVaultPath); vaultPath != "" {
		redisCfg.PasswordVaultPath = vaultPath
	}

	if vaultPath := os.Getenv(envRedisSentinelPasswordVaultPath); vaultPath != "" {
		if redisCfg.Sentinel == nil {
			redisCfg.Sentinel = &config.RedisSentinelConfig{}
		}
		redisCfg.Sentinel.PasswordVaultPath = vaultPath
	}

	if vaultPath := os.Getenv(envRedisSentinelSentinelPasswordVaultPath); vaultPath != "" {
		if redisCfg.Sentinel == nil {
			redisCfg.Sentinel = &config.RedisSentinelConfig{}
		}
		redisCfg.Sentinel.SentinelPasswordVaultPath = vaultPath
	}
}

// applyVaultEnv applies VAULT_* environment variable overrides to the
// spec.vault section and returns the EFFECTIVE vault configuration
// (ENV > config file > defaults, per-field). The input is never mutated.
//
// Behavior matrix:
//   - nil section, no VAULT_ADDR  → nil (vault stays off unless PKI needs it;
//     that legacy path is handled by needsVaultTLS/initVaultClient).
//   - nil section, VAULT_ADDR set → a section is synthesized purely from the
//     environment (legacy env-only path, byte-for-byte equivalent).
//   - section present            → deep-copied, then each set variable
//     overrides its field; VAULT_ADDR also forces Enabled=true (legacy
//     trigger semantics).
//
// Only field NAMES are logged on override — never values (tokens/secrets
// must not leak into logs).
func applyVaultEnv(vcfg *config.VaultConfig, logger observability.Logger) *config.VaultConfig {
	logger = ensureEnvLogger(logger)

	addr := os.Getenv(envVaultAddr)
	if vcfg == nil && addr == "" {
		return nil
	}

	effective := vcfg.Clone()
	if effective == nil {
		effective = &config.VaultConfig{}
	}

	applyVaultCoreEnv(effective, vcfg, addr, logger)
	applyVaultTLSEnv(effective, logger)
	applyVaultAuthBlockEnv(effective, logger)

	return effective
}

// vaultEnvPreValidateTransform returns the config-watcher pre-validate hook
// that applies the SAME Vault environment overlay used at boot
// (loadAndValidateConfig), so the watcher validates and delivers the
// EFFECTIVE configuration. Without it, a deployment whose vault address
// lives only in VAULT_ADDR (Helm env-mixed pattern: spec.vault enabled with
// tokenFile but no address) would fail raw-file validation on EVERY file
// change, silently disabling all hot reload for that deployment.
//
// The watcher hands the hook a defensive shallow copy, and applyVaultEnv
// clones the section itself, so the raw parsed configuration is never
// mutated.
func vaultEnvPreValidateTransform(logger observability.Logger) config.PreValidateTransform {
	return func(cfg *config.GatewayConfig) *config.GatewayConfig {
		cfg.Spec.Vault = applyVaultEnv(cfg.Spec.Vault, logger)
		return cfg
	}
}

// logVaultEnvOverride emits the per-field override debug log. Only the field
// NAME is logged — never the value.
func logVaultEnvOverride(logger observability.Logger, field string) {
	logger.Debug("vault config field overridden by environment",
		observability.String("field", field),
	)
}

// overlayVaultString applies a non-empty environment value to dst and emits
// the per-field debug log.
func overlayVaultString(dst *string, envValue, field string, logger observability.Logger) {
	if envValue == "" {
		return
	}
	*dst = envValue
	logVaultEnvOverride(logger, field)
}

// applyVaultCoreEnv overlays address, auth method, token, and namespace.
// fileCfg is the pre-overlay section (nil when synthesized) used to detect
// the enabled:false vs VAULT_ADDR conflict.
func applyVaultCoreEnv(
	effective, fileCfg *config.VaultConfig,
	addr string,
	logger observability.Logger,
) {
	if addr != "" {
		if fileCfg != nil && !fileCfg.Enabled {
			logger.Warn("spec.vault.enabled is false but VAULT_ADDR is set; " +
				"environment wins and the vault client will be initialized")
		}
		effective.Address = addr
		// Legacy trigger semantics: a configured VAULT_ADDR turns the
		// client on even when the file section is absent or disabled.
		effective.Enabled = true
		logVaultEnvOverride(logger, "address")
	}

	overlayVaultString(&effective.AuthMethod, os.Getenv(envVaultAuthMethod), "authMethod", logger)

	if token := os.Getenv(envVaultToken); token != "" {
		effective.Token = token
		// The env token wins over a file-referenced token per-field; clearing
		// tokenFile keeps the exactly-one(token|tokenFile) validation
		// invariant coherent with the ENV > file precedence rule.
		effective.TokenFile = ""
		logVaultEnvOverride(logger, "token")
	}

	overlayVaultString(&effective.Namespace, os.Getenv(envVaultNamespace), "namespace", logger)
}

// applyVaultTLSEnv overlays the TLS block, lazily creating it when any TLS
// environment variable is set (mirrors the legacy env-only construction).
// VAULT_SKIP_VERIFY is parsed via getEnvBool: invalid values are reported
// with a warning naming the variable and the previous value is kept.
func applyVaultTLSEnv(effective *config.VaultConfig, logger observability.Logger) {
	caCert := os.Getenv(envVaultCACert)
	caPath := os.Getenv(envVaultCAPath)
	clientCert := os.Getenv(envVaultClientCert)
	clientKey := os.Getenv(envVaultClientKey)
	skipRaw := os.Getenv(envVaultSkipVerify)

	if effective.TLS == nil {
		anyStringSet := caCert != "" || caPath != "" || clientCert != "" || clientKey != ""
		// A false (or invalid → default false) skipVerify with no other TLS
		// variable does not warrant a TLS block, matching legacy behavior.
		if !anyStringSet && !getEnvBool(envVaultSkipVerify, false, logger) {
			return
		}
		effective.TLS = &config.VaultClientTLSConfig{}
	}

	overlayVaultString(&effective.TLS.CACert, caCert, "tls.caCert", logger)
	overlayVaultString(&effective.TLS.CAPath, caPath, "tls.caPath", logger)
	overlayVaultString(&effective.TLS.ClientCert, clientCert, "tls.clientCert", logger)
	overlayVaultString(&effective.TLS.ClientKey, clientKey, "tls.clientKey", logger)

	if skipRaw != "" {
		effective.TLS.SkipVerify = getEnvBool(envVaultSkipVerify, effective.TLS.SkipVerify, logger)
		logVaultEnvOverride(logger, "tls.skipVerify")
	}
}

// applyVaultAuthBlockEnv overlays the sub-block of the EFFECTIVE auth method
// (post-overlay), lazily creating it so a pure-env configuration works
// without a file section. Variables of non-selected methods are intentionally
// ignored, mirroring the legacy env-only construction.
func applyVaultAuthBlockEnv(effective *config.VaultConfig, logger observability.Logger) {
	switch effective.EffectiveAuthMethod() {
	case config.VaultAuthMethodKubernetes:
		if effective.Kubernetes == nil {
			effective.Kubernetes = &config.VaultKubernetesAuthConfig{}
		}
		overlayVaultString(&effective.Kubernetes.Role, os.Getenv(envVaultK8sRole), "kubernetes.role", logger)
		overlayVaultString(&effective.Kubernetes.MountPath,
			os.Getenv(envVaultK8sMountPath), "kubernetes.mountPath", logger)
		overlayVaultString(&effective.Kubernetes.TokenPath,
			os.Getenv(envVaultK8sTokenPath), "kubernetes.tokenPath", logger)
	case config.VaultAuthMethodAppRole:
		if effective.AppRole == nil {
			effective.AppRole = &config.VaultAppRoleAuthConfig{}
		}
		overlayVaultString(&effective.AppRole.RoleID, os.Getenv(envVaultAppRoleRoleID), "appRole.roleId", logger)
		if secretID := os.Getenv(envVaultAppRoleSecretID); secretID != "" {
			effective.AppRole.SecretID = secretID
			// Env secretId wins over the file reference per-field (same
			// rationale as token/tokenFile above).
			effective.AppRole.SecretIDFile = ""
			logVaultEnvOverride(logger, "appRole.secretId")
		}
		overlayVaultString(&effective.AppRole.MountPath,
			os.Getenv(envVaultAppRoleMountPath), "appRole.mountPath", logger)
	}
}

// applyRedisSentinelEnvToConfig applies Redis Sentinel environment variable overrides
// to all Redis cache configurations in the gateway config. This includes route-level
// cache configurations that use Redis. Parse failures are reported via logger.
func applyRedisSentinelEnvToConfig(cfg *config.GatewayConfig, logger observability.Logger) {
	if cfg == nil {
		return
	}

	// Apply to route-level cache configs
	for i := range cfg.Spec.Routes {
		route := &cfg.Spec.Routes[i]
		if route.Cache != nil && route.Cache.Type == config.CacheTypeRedis && route.Cache.Redis != nil {
			applyRedisSentinelEnv(route.Cache.Redis)
			applyRedisFeatureEnv(route.Cache.Redis, logger)
		}
	}
}
