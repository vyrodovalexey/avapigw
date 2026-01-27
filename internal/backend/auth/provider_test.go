package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNopProvider_Name(t *testing.T) {
	t.Parallel()

	provider := &NopProvider{}
	assert.Equal(t, "nop", provider.Name())
}

func TestNopProvider_Type(t *testing.T) {
	t.Parallel()

	provider := &NopProvider{}
	assert.Equal(t, "none", provider.Type())
}

func TestNopProvider_ApplyHTTP(t *testing.T) {
	t.Parallel()

	provider := &NopProvider{}
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	err = provider.ApplyHTTP(context.Background(), req)
	assert.NoError(t, err)
}

func TestNopProvider_ApplyGRPC(t *testing.T) {
	t.Parallel()

	provider := &NopProvider{}
	opts, err := provider.ApplyGRPC(context.Background())

	assert.NoError(t, err)
	assert.Nil(t, opts)
}

func TestNopProvider_Refresh(t *testing.T) {
	t.Parallel()

	provider := &NopProvider{}
	err := provider.Refresh(context.Background())
	assert.NoError(t, err)
}

func TestNopProvider_Close(t *testing.T) {
	t.Parallel()

	provider := &NopProvider{}
	err := provider.Close()
	assert.NoError(t, err)
}

func TestNopProvider_ImplementsProvider(t *testing.T) {
	t.Parallel()

	var _ Provider = (*NopProvider)(nil)
}

func TestWithLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()

	t.Run("applies to JWTProvider", func(t *testing.T) {
		t.Parallel()

		provider := &JWTProvider{}
		opt := WithLogger(logger)
		opt(provider)

		assert.NotNil(t, provider.logger)
	})

	t.Run("applies to BasicProvider", func(t *testing.T) {
		t.Parallel()

		provider := &BasicProvider{}
		opt := WithLogger(logger)
		opt(provider)

		assert.NotNil(t, provider.logger)
	})

	t.Run("applies to MTLSProvider", func(t *testing.T) {
		t.Parallel()

		provider := &MTLSProvider{}
		opt := WithLogger(logger)
		opt(provider)

		assert.NotNil(t, provider.logger)
	})
}

func TestWithMetrics(t *testing.T) {
	t.Parallel()

	metrics := NopMetrics()

	t.Run("applies to JWTProvider", func(t *testing.T) {
		t.Parallel()

		provider := &JWTProvider{}
		opt := WithMetrics(metrics)
		opt(provider)

		assert.NotNil(t, provider.metrics)
	})

	t.Run("applies to BasicProvider", func(t *testing.T) {
		t.Parallel()

		provider := &BasicProvider{}
		opt := WithMetrics(metrics)
		opt(provider)

		assert.NotNil(t, provider.metrics)
	})

	t.Run("applies to MTLSProvider", func(t *testing.T) {
		t.Parallel()

		provider := &MTLSProvider{}
		opt := WithMetrics(metrics)
		opt(provider)

		assert.NotNil(t, provider.metrics)
	})
}

func TestWithVaultClient(t *testing.T) {
	t.Parallel()

	// Test with nil vault client (just ensure no panic)
	t.Run("applies to JWTProvider with nil", func(t *testing.T) {
		t.Parallel()

		provider := &JWTProvider{}
		opt := WithVaultClient(nil)
		opt(provider)

		assert.Nil(t, provider.vault)
	})

	t.Run("applies to BasicProvider with nil", func(t *testing.T) {
		t.Parallel()

		provider := &BasicProvider{}
		opt := WithVaultClient(nil)
		opt(provider)

		assert.Nil(t, provider.vault)
	})

	t.Run("applies to MTLSProvider with nil", func(t *testing.T) {
		t.Parallel()

		provider := &MTLSProvider{}
		opt := WithVaultClient(nil)
		opt(provider)

		assert.Nil(t, provider.vault)
	})
}
