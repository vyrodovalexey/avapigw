package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Vault startup authentication retry defaults, used when spec.vault.auth does
// not override them. Extracted as named constants (previously inline magic
// numbers) so the config-driven knobs and the defaults share one source.
const (
	// defaultVaultAuthMaxRetries bounds the Authenticate retry attempts.
	defaultVaultAuthMaxRetries = 3

	// defaultVaultAuthInitialBackoff is the first retry backoff.
	defaultVaultAuthInitialBackoff = 1 * time.Second

	// defaultVaultAuthMaxBackoff caps the exponential retry backoff.
	defaultVaultAuthMaxBackoff = 10 * time.Second

	// defaultVaultAuthTimeout bounds the whole authentication retry loop.
	defaultVaultAuthTimeout = 30 * time.Second
)

// needsVaultTLS checks if any listener or route in the configuration
// requires Vault-based TLS certificate management (PKI issuance).
func needsVaultTLS(cfg *config.GatewayConfig) bool {
	return cfg.Spec.RequiresVaultTLS()
}

// needsVault returns true when the Vault client should be initialized.
// This is the case when any listener/route requires Vault TLS, when the
// effective spec.vault section is enabled, or when the VAULT_ADDR
// environment variable is set (backends may need Vault for mTLS
// certificates, basic-auth credentials from KV, or OIDC token acquisition).
//
// The configuration passed here is expected to be the EFFECTIVE one
// (post applyVaultEnv overlay), so an env-only setup already has
// Spec.Vault.Enabled=true; the VAULT_ADDR check remains as a safety net for
// callers that skip the overlay.
func needsVault(cfg *config.GatewayConfig) bool {
	if needsVaultTLS(cfg) {
		return true
	}
	if cfg.Spec.Vault != nil && cfg.Spec.Vault.Enabled {
		return true
	}
	return os.Getenv(envVaultAddr) != ""
}

// initVaultClient creates and authenticates a Vault client from the EFFECTIVE
// vault configuration (spec.vault after the applyVaultEnv overlay — ENV wins
// per-field). A nil vcfg preserves the legacy PKI-only path: client
// construction fails fast with a clear "address is required" error exactly as
// before spec.vault existed.
func initVaultClient(vcfg *config.VaultConfig, logger observability.Logger) vault.Client {
	vaultCfg, err := convertVaultClientConfig(vcfg)
	if err != nil {
		fatalWithSync(logger, "invalid vault client configuration", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	client, err := vault.New(vaultCfg, logger)
	if err != nil {
		fatalWithSync(logger, "failed to create vault client", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	// Retry Vault authentication with exponential backoff in case Vault is
	// temporarily unavailable during startup. Knobs come from spec.vault.auth
	// with the historical constants as defaults.
	authRetryCfg, authTimeout := vaultAuthRetrySettings(vcfg)

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()

	authErr := retry.Do(ctx, authRetryCfg, func() error {
		return client.Authenticate(ctx)
	}, &retry.Options{
		OnRetry: func(attempt int, retryErr error, backoff time.Duration) {
			logger.Warn("vault authentication failed, retrying",
				observability.Int("attempt", attempt),
				observability.Duration("backoff", backoff),
				observability.Error(retryErr),
			)
		},
	})
	if authErr != nil {
		_ = client.Close()
		fatalWithSync(logger, "failed to authenticate with vault after retries", observability.Error(authErr))
		return nil // unreachable in production; allows test to continue
	}

	logger.Info("vault client initialized",
		observability.String("address", vaultCfg.Address),
		observability.String("auth_method", string(vaultCfg.AuthMethod)),
	)

	return client
}

// vaultAuthRetrySettings derives the startup authentication retry
// configuration and overall timeout from spec.vault.auth, falling back to
// the historical defaults for unset (non-positive) values.
func vaultAuthRetrySettings(vcfg *config.VaultConfig) (*retry.Config, time.Duration) {
	retryCfg := &retry.Config{
		MaxRetries:     defaultVaultAuthMaxRetries,
		InitialBackoff: defaultVaultAuthInitialBackoff,
		MaxBackoff:     defaultVaultAuthMaxBackoff,
		JitterFactor:   retry.DefaultJitterFactor,
	}
	timeout := defaultVaultAuthTimeout

	if vcfg == nil || vcfg.Auth == nil {
		return retryCfg, timeout
	}

	auth := vcfg.Auth
	if auth.MaxRetries > 0 {
		retryCfg.MaxRetries = auth.MaxRetries
	}
	if auth.InitialBackoff.Duration() > 0 {
		retryCfg.InitialBackoff = auth.InitialBackoff.Duration()
	}
	if auth.MaxBackoff.Duration() > 0 {
		retryCfg.MaxBackoff = auth.MaxBackoff.Duration()
	}
	if auth.Timeout.Duration() > 0 {
		timeout = auth.Timeout.Duration()
	}

	return retryCfg, timeout
}

// convertVaultClientConfig maps the effective spec.vault section into the
// vault package configuration (mirrors the internal/gateway
// vault_tls_convert.go mapping-function precedent). TokenFile/SecretIDFile
// references are resolved here — at client init, not at config parse — so
// internal/vault stays free of file I/O; a read failure is a fatal init
// error surfaced by the caller.
//
// NOTE (residual env passthrough): the underlying HashiCorp client is built
// from vaultapi.DefaultConfig(), which itself reads client-tuning variables
// we do not model (VAULT_CLIENT_TIMEOUT, VAULT_MAX_RETRIES, VAULT_RATE_LIMIT,
// VAULT_SRV_LOOKUP, ...). Every field modeled HERE is explicitly set after
// that read, so the per-field ENV > file > default contract holds for all
// modeled fields; unmodeled tuning variables intentionally pass through —
// the configuration file does not fully describe the client.
func convertVaultClientConfig(vcfg *config.VaultConfig) (*vault.Config, error) {
	if vcfg == nil {
		// Legacy PKI-only path (no spec.vault, no VAULT_ADDR): preserve the
		// pre-spec.vault behavior where the client was force-enabled and
		// construction failed fast with "address is required".
		return &vault.Config{Enabled: true, AuthMethod: vault.AuthMethodToken}, nil
	}

	out := &vault.Config{
		// Gating (needsVault) already decided the client must exist; a
		// disabled-section config only reaches this point when PKI issuance
		// requires the client, where the validator has rejected the
		// explicit enabled:false conflict beforehand.
		Enabled:    true,
		Address:    vcfg.Address,
		Namespace:  vcfg.Namespace,
		AuthMethod: vault.AuthMethod(vcfg.EffectiveAuthMethod()),
		Token:      vcfg.Token,
	}

	convertVaultAuthBlocks(vcfg, out)
	convertVaultTLSBlock(vcfg, out)
	convertVaultCacheRetry(vcfg, out)

	if err := resolveVaultFileSecrets(vcfg, out); err != nil {
		return nil, err
	}

	return out, nil
}

// convertVaultAuthBlocks maps the sub-block of the selected auth method,
// mirroring the legacy env-only construction (blocks of non-selected methods
// are not carried). Mount/token path defaults are normalized through the
// vault package accessors so the resulting struct matches the legacy one
// byte-for-byte.
func convertVaultAuthBlocks(vcfg *config.VaultConfig, out *vault.Config) {
	switch out.AuthMethod {
	case vault.AuthMethodKubernetes:
		k8s := vcfg.Kubernetes
		if k8s == nil {
			k8s = &config.VaultKubernetesAuthConfig{}
		}
		out.Kubernetes = &vault.KubernetesAuthConfig{
			Role:      k8s.Role,
			MountPath: k8s.MountPath,
			TokenPath: k8s.TokenPath,
		}
		out.Kubernetes.MountPath = out.Kubernetes.GetMountPath()
		out.Kubernetes.TokenPath = out.Kubernetes.GetTokenPath()
	case vault.AuthMethodAppRole:
		appRole := vcfg.AppRole
		if appRole == nil {
			appRole = &config.VaultAppRoleAuthConfig{}
		}
		out.AppRole = &vault.AppRoleAuthConfig{
			RoleID:    appRole.RoleID,
			SecretID:  appRole.SecretID,
			MountPath: appRole.MountPath,
		}
		out.AppRole.MountPath = out.AppRole.GetMountPath()
	case vault.AuthMethodToken:
		// Token auth carries no sub-block; the token itself is mapped by the
		// caller and optionally resolved from tokenFile afterwards.
	}
}

// convertVaultTLSBlock maps the TLS-to-Vault block when present.
func convertVaultTLSBlock(vcfg *config.VaultConfig, out *vault.Config) {
	tls := vcfg.TLS
	if tls == nil {
		return
	}
	out.TLS = &vault.VaultTLSConfig{
		CACert:     tls.CACert,
		CAPath:     tls.CAPath,
		ClientCert: tls.ClientCert,
		ClientKey:  tls.ClientKey,
		ServerName: tls.ServerName,
		SkipVerify: tls.SkipVerify,
	}
}

// convertVaultCacheRetry maps cache and retry tuning (config.Duration →
// time.Duration). Absent blocks keep the vault package defaults, exactly as
// the legacy env-only path (which never set them).
func convertVaultCacheRetry(vcfg *config.VaultConfig, out *vault.Config) {
	if cache := vcfg.Cache; cache != nil {
		out.Cache = &vault.CacheConfig{
			Enabled: cache.Enabled,
			TTL:     cache.TTL.Duration(),
			MaxSize: cache.MaxSize,
		}
	}
	if retryCfg := vcfg.Retry; retryCfg != nil {
		out.Retry = &vault.RetryConfig{
			MaxRetries:  retryCfg.MaxRetries,
			BackoffBase: retryCfg.BackoffBase.Duration(),
			BackoffMax:  retryCfg.BackoffMax.Duration(),
		}
	}
}

// resolveVaultFileSecrets reads tokenFile/secretIdFile references into the
// mapped configuration. Inline values win when both are somehow present
// (validation rejects that combination for file-based mode; the env overlay
// clears the file reference on override), keeping the resolution
// deterministic even for callers that skip validation.
func resolveVaultFileSecrets(vcfg *config.VaultConfig, out *vault.Config) error {
	if vcfg.TokenFile != "" && out.Token == "" {
		token, err := readVaultSecretFile(vcfg.TokenFile)
		if err != nil {
			return fmt.Errorf("failed to read vault token file %q: %w", vcfg.TokenFile, err)
		}
		out.Token = token
	}

	if out.AppRole != nil && vcfg.AppRole != nil &&
		vcfg.AppRole.SecretIDFile != "" && out.AppRole.SecretID == "" {
		secretID, err := readVaultSecretFile(vcfg.AppRole.SecretIDFile)
		if err != nil {
			return fmt.Errorf("failed to read vault approle secretId file %q: %w",
				vcfg.AppRole.SecretIDFile, err)
		}
		out.AppRole.SecretID = secretID
	}

	return nil
}

// readVaultSecretFile reads secret material (vault token or approle secretId)
// from a file, stripping surrounding whitespace and the trailing newline that
// `vault login` and Kubernetes Secret mounts typically leave behind.
func readVaultSecretFile(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from validated gateway configuration
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// createVaultProviderFactory creates a VaultProviderFactory from a Vault client.
// The factory creates CertificateProviders that use Vault PKI to issue and renew certificates.
func createVaultProviderFactory(client vault.Client) tlspkg.VaultProviderFactory {
	return func(tlsCfg *tlspkg.VaultTLSConfig, logger observability.Logger) (tlspkg.CertificateProvider, error) {
		providerCfg := &vault.VaultProviderConfig{
			PKIMount:    tlsCfg.PKIMount,
			Role:        tlsCfg.Role,
			CommonName:  tlsCfg.CommonName,
			AltNames:    tlsCfg.AltNames,
			TTL:         tlsCfg.TTL,
			RenewBefore: tlsCfg.RenewBefore,
		}

		provider, err := vault.NewVaultProvider(client, providerCfg,
			vault.WithVaultProviderLogger(logger),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create vault provider: %w", err)
		}

		return provider, nil
	}
}
