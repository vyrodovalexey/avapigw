package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewDiscoveryClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		opts    []DiscoveryClientOption
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config is required",
		},
		{
			name: "valid config",
			config: &Config{
				Enabled: true,
				Providers: []ProviderConfig{
					{
						Name:     "test",
						Issuer:   "https://issuer.example.com",
						ClientID: "client-id",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "with custom HTTP client",
			config: &Config{
				Enabled: true,
			},
			opts: []DiscoveryClientOption{
				WithDiscoveryHTTPClient(&http.Client{Timeout: 10 * time.Second}),
			},
			wantErr: false,
		},
		{
			name: "with logger",
			config: &Config{
				Enabled: true,
			},
			opts: []DiscoveryClientOption{
				WithDiscoveryLogger(observability.NopLogger()),
			},
			wantErr: false,
		},
		{
			name: "with metrics",
			config: &Config{
				Enabled: true,
			},
			opts: []DiscoveryClientOption{
				WithDiscoveryMetrics(NewMetrics("test")),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := NewDiscoveryClient(tt.config, tt.opts...)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestDiscoveryClient_GetDiscovery(t *testing.T) {
	t.Parallel()

	// Create a test server that returns a valid discovery document
	discoveryDoc := &DiscoveryDocument{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		TokenEndpoint:         "https://issuer.example.com/token",
		UserinfoEndpoint:      "https://issuer.example.com/userinfo",
		JWKSUri:               "https://issuer.example.com/.well-known/jwks.json",
		ScopesSupported:       []string{"openid", "profile", "email"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc)
	}))
	defer server.Close()

	config := &Config{
		Enabled:           true,
		DiscoveryCacheTTL: time.Hour,
		Providers: []ProviderConfig{
			{
				Name:         "test",
				Issuer:       "https://issuer.example.com",
				DiscoveryURL: server.URL,
				ClientID:     "client-id",
			},
		},
	}

	client, err := NewDiscoveryClient(config)
	require.NoError(t, err)

	// First call - should fetch from server
	doc, err := client.GetDiscovery(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.com", doc.Issuer)
	assert.Equal(t, "https://issuer.example.com/authorize", doc.AuthorizationEndpoint)
	assert.Equal(t, "https://issuer.example.com/token", doc.TokenEndpoint)
	assert.Equal(t, "https://issuer.example.com/userinfo", doc.UserinfoEndpoint)
	assert.Equal(t, "https://issuer.example.com/.well-known/jwks.json", doc.JWKSUri)

	// Second call - should return from cache
	doc2, err := client.GetDiscovery(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, doc.Issuer, doc2.Issuer)
}

func TestDiscoveryClient_GetDiscovery_ProviderNotFound(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Providers: []ProviderConfig{
			{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
			},
		},
	}

	client, err := NewDiscoveryClient(config)
	require.NoError(t, err)

	_, err = client.GetDiscovery(context.Background(), "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "provider nonexistent not found")
}

func TestDiscoveryClient_GetDiscovery_ServerError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := &Config{
		Enabled: true,
		Providers: []ProviderConfig{
			{
				Name:         "test",
				Issuer:       "https://issuer.example.com",
				DiscoveryURL: server.URL,
				ClientID:     "client-id",
			},
		},
	}

	client, err := NewDiscoveryClient(config)
	require.NoError(t, err)

	_, err = client.GetDiscovery(context.Background(), "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestDiscoveryClient_GetDiscovery_InvalidJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	config := &Config{
		Enabled: true,
		Providers: []ProviderConfig{
			{
				Name:         "test",
				Issuer:       "https://issuer.example.com",
				DiscoveryURL: server.URL,
				ClientID:     "client-id",
			},
		},
	}

	client, err := NewDiscoveryClient(config)
	require.NoError(t, err)

	_, err = client.GetDiscovery(context.Background(), "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse discovery document")
}

func TestDiscoveryClient_GetDiscovery_IssuerMismatch(t *testing.T) {
	t.Parallel()

	discoveryDoc := &DiscoveryDocument{
		Issuer:                "https://different-issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		TokenEndpoint:         "https://issuer.example.com/token",
		JWKSUri:               "https://issuer.example.com/.well-known/jwks.json",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc)
	}))
	defer server.Close()

	config := &Config{
		Enabled: true,
		Providers: []ProviderConfig{
			{
				Name:         "test",
				Issuer:       "https://issuer.example.com",
				DiscoveryURL: server.URL,
				ClientID:     "client-id",
			},
		},
	}

	client, err := NewDiscoveryClient(config)
	require.NoError(t, err)

	_, err = client.GetDiscovery(context.Background(), "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer mismatch")
}

func TestDiscoveryClient_Refresh(t *testing.T) {
	t.Parallel()

	callCount := 0
	discoveryDoc := &DiscoveryDocument{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		TokenEndpoint:         "https://issuer.example.com/token",
		JWKSUri:               "https://issuer.example.com/.well-known/jwks.json",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc)
	}))
	defer server.Close()

	config := &Config{
		Enabled:           true,
		DiscoveryCacheTTL: time.Hour,
		Providers: []ProviderConfig{
			{
				Name:         "test",
				Issuer:       "https://issuer.example.com",
				DiscoveryURL: server.URL,
				ClientID:     "client-id",
			},
		},
	}

	client, err := NewDiscoveryClient(config)
	require.NoError(t, err)

	// First call
	_, err = client.GetDiscovery(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call - should use cache
	_, err = client.GetDiscovery(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Refresh - should fetch again
	err = client.Refresh(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}

func TestDiscoveryClient_Close(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
	}

	client, err := NewDiscoveryClient(config)
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

func TestDiscoveryClient_CacheExpiration(t *testing.T) {
	t.Parallel()

	callCount := 0
	discoveryDoc := &DiscoveryDocument{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		TokenEndpoint:         "https://issuer.example.com/token",
		JWKSUri:               "https://issuer.example.com/.well-known/jwks.json",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc)
	}))
	defer server.Close()

	config := &Config{
		Enabled:           true,
		DiscoveryCacheTTL: 1 * time.Millisecond, // Very short TTL
		Providers: []ProviderConfig{
			{
				Name:         "test",
				Issuer:       "https://issuer.example.com",
				DiscoveryURL: server.URL,
				ClientID:     "client-id",
			},
		},
	}

	client, err := NewDiscoveryClient(config)
	require.NoError(t, err)

	// First call
	_, err = client.GetDiscovery(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Wait for cache to expire
	time.Sleep(10 * time.Millisecond)

	// Second call - cache should be expired
	_, err = client.GetDiscovery(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}

func TestDiscoveryClient_DefaultCacheTTL(t *testing.T) {
	t.Parallel()

	discoveryDoc := &DiscoveryDocument{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		TokenEndpoint:         "https://issuer.example.com/token",
		JWKSUri:               "https://issuer.example.com/.well-known/jwks.json",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc)
	}))
	defer server.Close()

	config := &Config{
		Enabled:           true,
		DiscoveryCacheTTL: 0, // Should default to 1 hour
		Providers: []ProviderConfig{
			{
				Name:         "test",
				Issuer:       "https://issuer.example.com",
				DiscoveryURL: server.URL,
				ClientID:     "client-id",
			},
		},
	}

	client, err := NewDiscoveryClient(config)
	require.NoError(t, err)

	_, err = client.GetDiscovery(context.Background(), "test")
	require.NoError(t, err)
}

func TestDiscoveryDocument_Fields(t *testing.T) {
	t.Parallel()

	doc := &DiscoveryDocument{
		Issuer:                            "https://issuer.example.com",
		AuthorizationEndpoint:             "https://issuer.example.com/authorize",
		TokenEndpoint:                     "https://issuer.example.com/token",
		UserinfoEndpoint:                  "https://issuer.example.com/userinfo",
		JWKSUri:                           "https://issuer.example.com/.well-known/jwks.json",
		RegistrationEndpoint:              "https://issuer.example.com/register",
		ScopesSupported:                   []string{"openid", "profile", "email"},
		ResponseTypesSupported:            []string{"code", "token", "id_token"},
		ResponseModesSupported:            []string{"query", "fragment"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256", "ES256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat"},
		IntrospectionEndpoint:             "https://issuer.example.com/introspect",
		RevocationEndpoint:                "https://issuer.example.com/revoke",
		EndSessionEndpoint:                "https://issuer.example.com/logout",
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
	}

	// Verify all fields are set correctly
	assert.Equal(t, "https://issuer.example.com", doc.Issuer)
	assert.Equal(t, "https://issuer.example.com/authorize", doc.AuthorizationEndpoint)
	assert.Equal(t, "https://issuer.example.com/token", doc.TokenEndpoint)
	assert.Equal(t, "https://issuer.example.com/userinfo", doc.UserinfoEndpoint)
	assert.Equal(t, "https://issuer.example.com/.well-known/jwks.json", doc.JWKSUri)
	assert.Equal(t, "https://issuer.example.com/register", doc.RegistrationEndpoint)
	assert.Equal(t, []string{"openid", "profile", "email"}, doc.ScopesSupported)
	assert.Equal(t, []string{"code", "token", "id_token"}, doc.ResponseTypesSupported)
	assert.Equal(t, []string{"query", "fragment"}, doc.ResponseModesSupported)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, doc.GrantTypesSupported)
	assert.Equal(t, []string{"public"}, doc.SubjectTypesSupported)
	assert.Equal(t, []string{"RS256", "ES256"}, doc.IDTokenSigningAlgValuesSupported)
	assert.Equal(t, []string{"client_secret_basic", "client_secret_post"}, doc.TokenEndpointAuthMethodsSupported)
	assert.Equal(t, []string{"sub", "iss", "aud", "exp", "iat"}, doc.ClaimsSupported)
	assert.Equal(t, "https://issuer.example.com/introspect", doc.IntrospectionEndpoint)
	assert.Equal(t, "https://issuer.example.com/revoke", doc.RevocationEndpoint)
	assert.Equal(t, "https://issuer.example.com/logout", doc.EndSessionEndpoint)
	assert.Equal(t, []string{"S256", "plain"}, doc.CodeChallengeMethodsSupported)
}
