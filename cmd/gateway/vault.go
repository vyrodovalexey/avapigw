package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// needsVaultTLS checks if any listener or route in the configuration
// requires Vault-based TLS certificate management.
func needsVaultTLS(cfg *config.GatewayConfig) bool {
	// Check HTTP listeners
	for _, l := range cfg.Spec.Listeners {
		if l.TLS != nil && l.TLS.Vault != nil && l.TLS.Vault.Enabled {
			return true
		}
		// Check gRPC listener TLS
		if l.GRPC != nil && l.GRPC.TLS != nil && l.GRPC.TLS.Vault != nil && l.GRPC.TLS.Vault.Enabled {
			return true
		}
	}
	// Check route-level TLS
	for _, r := range cfg.Spec.Routes {
		if r.TLS != nil && r.TLS.Vault != nil && r.TLS.Vault.Enabled {
			return true
		}
	}
	return false
}

// initVaultClient creates and authenticates a Vault client using environment variables.
// It uses the standard Vault environment variables: VAULT_ADDR, VAULT_TOKEN,
// VAULT_CACERT, VAULT_CAPATH, VAULT_CLIENT_CERT, VAULT_CLIENT_KEY, VAULT_SKIP_VERIFY,
// VAULT_NAMESPACE.
// For Kubernetes deployments, set VAULT_AUTH_METHOD=kubernetes and VAULT_K8S_ROLE.
func initVaultClient(logger observability.Logger) vault.Client {
	authMethod := vault.AuthMethod(getEnvOrDefault("VAULT_AUTH_METHOD", "token"))

	vaultCfg := &vault.Config{
		Enabled:    true,
		Address:    os.Getenv("VAULT_ADDR"),
		AuthMethod: authMethod,
		Token:      os.Getenv("VAULT_TOKEN"),
		Namespace:  os.Getenv("VAULT_NAMESPACE"),
	}

	// Configure TLS for Vault connection if any TLS env vars are set
	caCert := os.Getenv("VAULT_CACERT")
	caPath := os.Getenv("VAULT_CAPATH")
	clientCert := os.Getenv("VAULT_CLIENT_CERT")
	clientKey := os.Getenv("VAULT_CLIENT_KEY")
	skipVerify, _ := strconv.ParseBool(os.Getenv("VAULT_SKIP_VERIFY"))

	if caCert != "" || caPath != "" || clientCert != "" || clientKey != "" || skipVerify {
		vaultCfg.TLS = &vault.VaultTLSConfig{
			CACert:     caCert,
			CAPath:     caPath,
			ClientCert: clientCert,
			ClientKey:  clientKey,
			SkipVerify: skipVerify,
		}
	}

	// Configure Kubernetes auth if applicable
	if authMethod == vault.AuthMethodKubernetes {
		vaultCfg.Kubernetes = &vault.KubernetesAuthConfig{
			Role:      os.Getenv("VAULT_K8S_ROLE"),
			MountPath: getEnvOrDefault("VAULT_K8S_MOUNT_PATH", "kubernetes"),
			TokenPath: getEnvOrDefault("VAULT_K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		}
	}

	// Configure AppRole auth if applicable
	if authMethod == vault.AuthMethodAppRole {
		vaultCfg.AppRole = &vault.AppRoleAuthConfig{
			RoleID:    os.Getenv("VAULT_APPROLE_ROLE_ID"),
			SecretID:  os.Getenv("VAULT_APPROLE_SECRET_ID"),
			MountPath: getEnvOrDefault("VAULT_APPROLE_MOUNT_PATH", "approle"),
		}
	}

	client, err := vault.New(vaultCfg, logger)
	if err != nil {
		fatalWithSync(logger, "failed to create vault client", observability.Error(err))
		return nil // unreachable in production; allows test to continue
	}

	// Retry Vault authentication with exponential backoff in case Vault is
	// temporarily unavailable during startup.
	authRetryCfg := &retry.Config{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     10 * time.Second,
		JitterFactor:   retry.DefaultJitterFactor,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
		observability.String("auth_method", string(authMethod)),
	)

	return client
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
