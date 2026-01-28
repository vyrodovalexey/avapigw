package auth

import (
	"context"
	"net/http"

	"google.golang.org/grpc"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Provider is the interface for backend authentication providers.
type Provider interface {
	// Name returns the provider name.
	Name() string

	// Type returns the authentication type (jwt, basic, mtls).
	Type() string

	// ApplyHTTP applies authentication to an HTTP request.
	ApplyHTTP(ctx context.Context, req *http.Request) error

	// ApplyGRPC returns gRPC dial options for authentication.
	ApplyGRPC(ctx context.Context) ([]grpc.DialOption, error)

	// Refresh refreshes the authentication credentials if needed.
	Refresh(ctx context.Context) error

	// Close closes the provider and releases resources.
	Close() error
}

// ProviderOption is a functional option for configuring providers.
type ProviderOption func(interface{})

// WithLogger sets the logger for the provider.
func WithLogger(logger observability.Logger) ProviderOption {
	return func(p interface{}) {
		switch provider := p.(type) {
		case *JWTProvider:
			provider.logger = logger
		case *BasicProvider:
			provider.logger = logger
		case *MTLSProvider:
			provider.logger = logger
		}
	}
}

// WithMetrics sets the metrics for the provider.
func WithMetrics(metrics *Metrics) ProviderOption {
	return func(p interface{}) {
		switch provider := p.(type) {
		case *JWTProvider:
			provider.metrics = metrics
		case *BasicProvider:
			provider.metrics = metrics
		case *MTLSProvider:
			provider.metrics = metrics
		}
	}
}

// WithVaultClient sets the Vault client for the provider.
func WithVaultClient(client vault.Client) ProviderOption {
	return func(p interface{}) {
		switch provider := p.(type) {
		case *JWTProvider:
			provider.vault = client
		case *BasicProvider:
			provider.vault = client
		case *MTLSProvider:
			provider.vault = client
		}
	}
}

// NopProvider is a no-op provider that does nothing.
type NopProvider struct{}

// Name returns the provider name.
func (p *NopProvider) Name() string {
	return "nop"
}

// Type returns the authentication type.
func (p *NopProvider) Type() string {
	return "none"
}

// ApplyHTTP does nothing.
func (p *NopProvider) ApplyHTTP(_ context.Context, _ *http.Request) error {
	return nil
}

// ApplyGRPC returns empty dial options.
func (p *NopProvider) ApplyGRPC(_ context.Context) ([]grpc.DialOption, error) {
	return nil, nil
}

// Refresh does nothing.
func (p *NopProvider) Refresh(_ context.Context) error {
	return nil
}

// Close does nothing.
func (p *NopProvider) Close() error {
	return nil
}

// Ensure NopProvider implements Provider.
var _ Provider = (*NopProvider)(nil)
