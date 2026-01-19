// Package oauth provides OAuth2 client credentials flow for the API Gateway.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// =============================================================================
// TokenResponse Tests
// =============================================================================

func TestTokenResponse_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "expired token",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  true,
		},
		{
			name:      "valid token",
			expiresAt: time.Now().Add(1 * time.Hour),
			expected:  false,
		},
		{
			name:      "just expired token",
			expiresAt: time.Now().Add(-1 * time.Second),
			expected:  true,
		},
		{
			name:      "about to expire token",
			expiresAt: time.Now().Add(1 * time.Second),
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &TokenResponse{
				AccessToken: "test-token",
				ExpiresAt:   tt.expiresAt,
			}
			assert.Equal(t, tt.expected, token.IsExpired())
		})
	}
}

func TestTokenResponse_IsExpiredWithBuffer(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		buffer    time.Duration
		expected  bool
	}{
		{
			name:      "expired with buffer",
			expiresAt: time.Now().Add(30 * time.Second),
			buffer:    1 * time.Minute,
			expected:  true,
		},
		{
			name:      "valid with buffer",
			expiresAt: time.Now().Add(2 * time.Minute),
			buffer:    1 * time.Minute,
			expected:  false,
		},
		{
			name:      "zero buffer - expired",
			expiresAt: time.Now().Add(-1 * time.Second),
			buffer:    0,
			expected:  true,
		},
		{
			name:      "zero buffer - valid",
			expiresAt: time.Now().Add(1 * time.Minute),
			buffer:    0,
			expected:  false,
		},
		{
			name:      "large buffer",
			expiresAt: time.Now().Add(1 * time.Hour),
			buffer:    2 * time.Hour,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &TokenResponse{
				AccessToken: "test-token",
				ExpiresAt:   tt.expiresAt,
			}
			assert.Equal(t, tt.expected, token.IsExpiredWithBuffer(tt.buffer))
		})
	}
}

// =============================================================================
// Config Tests
// =============================================================================

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 60*time.Second, config.RefreshBuffer)
	assert.Empty(t, config.TokenEndpoint)
	assert.Empty(t, config.ClientID)
	assert.Empty(t, config.ClientSecret)
	assert.Nil(t, config.Scopes)
	assert.Nil(t, config.HTTPClient)
	assert.Nil(t, config.Logger)
}

// =============================================================================
// Client Tests
// =============================================================================

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			errorMsg:    "config is required",
		},
		{
			name: "missing token endpoint",
			config: &Config{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			expectError: true,
			errorMsg:    ErrMissingTokenEndpoint.Error(),
		},
		{
			name: "missing client ID",
			config: &Config{
				TokenEndpoint: "https://example.com/token",
				ClientSecret:  "client-secret",
			},
			expectError: true,
			errorMsg:    ErrMissingClientID.Error(),
		},
		{
			name: "missing client secret",
			config: &Config{
				TokenEndpoint: "https://example.com/token",
				ClientID:      "client-id",
			},
			expectError: true,
			errorMsg:    ErrMissingClientSecret.Error(),
		},
		{
			name: "valid config with defaults",
			config: &Config{
				TokenEndpoint: "https://example.com/token",
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
			},
			expectError: false,
		},
		{
			name: "valid config with all fields",
			config: &Config{
				TokenEndpoint: "https://example.com/token",
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
				Scopes:        []string{"read", "write"},
				Timeout:       10 * time.Second,
				RefreshBuffer: 30 * time.Second,
				HTTPClient:    &http.Client{},
				Logger:        zaptest.NewLogger(t),
			},
			expectError: false,
		},
		{
			name: "zero timeout uses default",
			config: &Config{
				TokenEndpoint: "https://example.com/token",
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
				Timeout:       0,
			},
			expectError: false,
		},
		{
			name: "negative timeout uses default",
			config: &Config{
				TokenEndpoint: "https://example.com/token",
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
				Timeout:       -1 * time.Second,
			},
			expectError: false,
		},
		{
			name: "zero refresh buffer uses default",
			config: &Config{
				TokenEndpoint: "https://example.com/token",
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
				RefreshBuffer: 0,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestClient_FetchToken(t *testing.T) {
	tests := []struct {
		name          string
		serverHandler http.HandlerFunc
		scopes        []string
		expectError   bool
		errorContains string
		validateToken func(t *testing.T, token *TokenResponse)
	}{
		{
			name: "successful token fetch",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", r.Header.Get("Accept"))

				err := r.ParseForm()
				require.NoError(t, err)
				assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
				assert.Equal(t, "test-client-id", r.Form.Get("client_id"))
				assert.Equal(t, "test-client-secret", r.Form.Get("client_secret"))

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "test-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
					"scope":        "read write",
				})
			},
			expectError: false,
			validateToken: func(t *testing.T, token *TokenResponse) {
				assert.Equal(t, "test-access-token", token.AccessToken)
				assert.Equal(t, "Bearer", token.TokenType)
				assert.Equal(t, int64(3600), token.ExpiresIn)
				assert.Equal(t, "read write", token.Scope)
				assert.False(t, token.IsExpired())
			},
		},
		{
			name:   "successful token fetch with scopes",
			scopes: []string{"read", "write", "admin"},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				err := r.ParseForm()
				require.NoError(t, err)
				assert.Equal(t, "read write admin", r.Form.Get("scope"))

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "scoped-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			},
			expectError: false,
			validateToken: func(t *testing.T, token *TokenResponse) {
				assert.Equal(t, "scoped-token", token.AccessToken)
			},
		},
		{
			name: "token without expires_in uses default",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "no-expiry-token",
					"token_type":   "Bearer",
				})
			},
			expectError: false,
			validateToken: func(t *testing.T, token *TokenResponse) {
				assert.Equal(t, "no-expiry-token", token.AccessToken)
				// Should default to 1 hour
				assert.True(t, token.ExpiresAt.After(time.Now().Add(59*time.Minute)))
			},
		},
		{
			name: "server returns error status",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error": "invalid_client"}`))
			},
			expectError:   true,
			errorContains: "token request failed",
		},
		{
			name: "server returns 500",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "server_error"}`))
			},
			expectError:   true,
			errorContains: "token request failed",
		},
		{
			name: "server returns invalid JSON",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{invalid json}`))
			},
			expectError:   true,
			errorContains: "invalid token response",
		},
		{
			name: "token with refresh token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token":  "access-token",
					"token_type":    "Bearer",
					"expires_in":    3600,
					"refresh_token": "refresh-token",
				})
			},
			expectError: false,
			validateToken: func(t *testing.T, token *TokenResponse) {
				assert.Equal(t, "access-token", token.AccessToken)
				assert.Equal(t, "refresh-token", token.RefreshToken)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &Config{
				TokenEndpoint: server.URL,
				ClientID:      "test-client-id",
				ClientSecret:  "test-client-secret",
				Scopes:        tt.scopes,
				Logger:        zaptest.NewLogger(t),
			}

			client, err := NewClient(config)
			require.NoError(t, err)

			token, err := client.FetchToken(context.Background())

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, token)
			} else {
				require.NoError(t, err)
				require.NotNil(t, token)
				if tt.validateToken != nil {
					tt.validateToken(t, token)
				}
			}
		})
	}
}

func TestClient_FetchToken_NetworkError(t *testing.T) {
	config := &Config{
		TokenEndpoint: "http://localhost:1", // Invalid port
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Timeout:       1 * time.Second,
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	token, err := client.FetchToken(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenRequestFailed))
	assert.Nil(t, token)
}

func TestClient_FetchToken_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Simulate slow server
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	token, err := client.FetchToken(ctx)
	require.Error(t, err)
	assert.Nil(t, token)
}

func TestClient_GetToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "token-" + string(rune('0'+callCount)),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		RefreshBuffer: 60 * time.Second,
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	// First call should fetch token
	token1, err := client.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token1.AccessToken)
	assert.Equal(t, 1, callCount)

	// Second call should return cached token
	token2, err := client.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token2.AccessToken)
	assert.Equal(t, 1, callCount) // No additional call
}

func TestClient_GetToken_ExpiredToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "token-" + string(rune('0'+callCount)),
			"token_type":   "Bearer",
			"expires_in":   1, // Very short expiry
		})
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		RefreshBuffer: 0, // No buffer
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	// First call
	token1, err := client.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	// Second call should fetch new token
	token2, err := client.GetToken(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, token1.AccessToken, token2.AccessToken)
	assert.Equal(t, 2, callCount)
}

func TestClient_GetAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "my-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	accessToken, err := client.GetAccessToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "my-access-token", accessToken)
}

func TestClient_GetAccessToken_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	accessToken, err := client.GetAccessToken(context.Background())
	require.Error(t, err)
	assert.Empty(t, accessToken)
}

func TestClient_InvalidateToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "token-" + string(rune('0'+callCount)),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	// Fetch initial token
	token1, err := client.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token1.AccessToken)
	assert.Equal(t, 1, callCount)

	// Invalidate token
	client.InvalidateToken()

	// Next call should fetch new token
	token2, err := client.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-2", token2.AccessToken)
	assert.Equal(t, 2, callCount)
}

func TestClient_RoundTripper(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "bearer-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	config := &Config{
		TokenEndpoint: tokenServer.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	// Create a test server that checks for Authorization header
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer bearer-token", authHeader)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer apiServer.Close()

	// Create HTTP client with OAuth2 round tripper
	httpClient := &http.Client{
		Transport: client.RoundTripper(nil),
	}

	req, err := http.NewRequest(http.MethodGet, apiServer.URL, nil)
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClient_RoundTripper_WithBaseTransport(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	config := &Config{
		TokenEndpoint: tokenServer.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	// Use custom base transport
	baseTransport := &http.Transport{
		MaxIdleConns: 10,
	}

	rt := client.RoundTripper(baseTransport)
	assert.NotNil(t, rt)
}

func TestClient_RoundTripper_TokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer tokenServer.Close()

	config := &Config{
		TokenEndpoint: tokenServer.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	httpClient := &http.Client{
		Transport: client.RoundTripper(nil),
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	_, err = httpClient.Do(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get OAuth2 token")
}

func TestClient_StartAutoRefresh(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "auto-refresh-token",
			"token_type":   "Bearer",
			"expires_in":   2, // Short expiry for testing
		})
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		RefreshBuffer: 1 * time.Second,
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start auto refresh
	client.StartAutoRefresh(ctx)

	// Wait for initial fetch and at least one refresh
	time.Sleep(3 * time.Second)

	mu.Lock()
	count := callCount
	mu.Unlock()

	// Should have fetched at least twice (initial + refresh)
	assert.GreaterOrEqual(t, count, 2)
}

func TestClient_StartAutoRefresh_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	client.StartAutoRefresh(ctx)

	// Cancel immediately
	cancel()

	// Give goroutine time to exit
	time.Sleep(100 * time.Millisecond)
}

func TestClient_ConcurrentAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "concurrent-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	var wg sync.WaitGroup
	errChan := make(chan error, 100)

	// Concurrent token fetches
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.GetToken(context.Background())
			if err != nil {
				errChan <- err
			}
		}()
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("unexpected error: %v", err)
	}
}

// =============================================================================
// TokenSource Tests
// =============================================================================

func TestNewClientTokenSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "source-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	source := NewClientTokenSource(client)
	assert.NotNil(t, source)
}

func TestClientTokenSource_Token(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "client-source-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	config := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		Logger:        zaptest.NewLogger(t),
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	source := NewClientTokenSource(client)

	token, err := source.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "client-source-token", token.AccessToken)
}

func TestNewStaticTokenSource(t *testing.T) {
	source := NewStaticTokenSource("static-access-token")
	assert.NotNil(t, source)
	assert.NotNil(t, source.token)
	assert.Equal(t, "static-access-token", source.token.AccessToken)
	assert.Equal(t, "Bearer", source.token.TokenType)
	assert.False(t, source.token.IsExpired())
}

func TestStaticTokenSource_Token(t *testing.T) {
	tests := []struct {
		name        string
		accessToken string
	}{
		{
			name:        "simple token",
			accessToken: "simple-token",
		},
		{
			name:        "empty token",
			accessToken: "",
		},
		{
			name:        "long token",
			accessToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := NewStaticTokenSource(tt.accessToken)

			token, err := source.Token(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.accessToken, token.AccessToken)
			assert.Equal(t, "Bearer", token.TokenType)
		})
	}
}

func TestStaticTokenSource_NeverExpires(t *testing.T) {
	source := NewStaticTokenSource("never-expires-token")

	token, err := source.Token(context.Background())
	require.NoError(t, err)

	// Token should not expire for a very long time (100 years)
	assert.True(t, token.ExpiresAt.After(time.Now().Add(99*365*24*time.Hour)))
	assert.False(t, token.IsExpired())
	assert.False(t, token.IsExpiredWithBuffer(24*time.Hour))
}

// =============================================================================
// IntrospectionClient Tests
// =============================================================================

func TestNewIntrospectionClient(t *testing.T) {
	tests := []struct {
		name        string
		config      *IntrospectionConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			errorMsg:    "config is required",
		},
		{
			name: "missing introspection endpoint",
			config: &IntrospectionConfig{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			expectError: true,
			errorMsg:    "introspection endpoint is required",
		},
		{
			name: "valid config minimal",
			config: &IntrospectionConfig{
				IntrospectionEndpoint: "https://example.com/introspect",
			},
			expectError: false,
		},
		{
			name: "valid config with all fields",
			config: &IntrospectionConfig{
				IntrospectionEndpoint: "https://example.com/introspect",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
				Timeout:               10 * time.Second,
				HTTPClient:            &http.Client{},
				Logger:                zaptest.NewLogger(t),
			},
			expectError: false,
		},
		{
			name: "zero timeout uses default",
			config: &IntrospectionConfig{
				IntrospectionEndpoint: "https://example.com/introspect",
				Timeout:               0,
			},
			expectError: false,
		},
		{
			name: "negative timeout uses default",
			config: &IntrospectionConfig{
				IntrospectionEndpoint: "https://example.com/introspect",
				Timeout:               -1 * time.Second,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewIntrospectionClient(tt.config)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestIntrospectionClient_Introspect(t *testing.T) {
	tests := []struct {
		name          string
		serverHandler http.HandlerFunc
		clientID      string
		clientSecret  string
		token         string
		expectError   bool
		errorContains string
		validateResp  func(t *testing.T, resp *TokenIntrospectionResponse)
	}{
		{
			name: "active token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

				err := r.ParseForm()
				require.NoError(t, err)
				assert.Equal(t, "test-token", r.Form.Get("token"))

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"active":     true,
					"scope":      "read write",
					"client_id":  "my-client",
					"username":   "user@example.com",
					"token_type": "Bearer",
					"exp":        time.Now().Add(1 * time.Hour).Unix(),
					"iat":        time.Now().Unix(),
					"sub":        "user-123",
					"iss":        "https://issuer.example.com",
				})
			},
			token:       "test-token",
			expectError: false,
			validateResp: func(t *testing.T, resp *TokenIntrospectionResponse) {
				assert.True(t, resp.Active)
				assert.Equal(t, "read write", resp.Scope)
				assert.Equal(t, "my-client", resp.ClientID)
				assert.Equal(t, "user@example.com", resp.Username)
				assert.Equal(t, "Bearer", resp.TokenType)
				assert.Equal(t, "user-123", resp.Sub)
				assert.Equal(t, "https://issuer.example.com", resp.Iss)
			},
		},
		{
			name: "inactive token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"active": false,
				})
			},
			token:       "expired-token",
			expectError: false,
			validateResp: func(t *testing.T, resp *TokenIntrospectionResponse) {
				assert.False(t, resp.Active)
			},
		},
		{
			name: "with client credentials",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				username, password, ok := r.BasicAuth()
				assert.True(t, ok)
				assert.Equal(t, "introspect-client", username)
				assert.Equal(t, "introspect-secret", password)

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"active": true,
				})
			},
			clientID:     "introspect-client",
			clientSecret: "introspect-secret",
			token:        "token-with-auth",
			expectError:  false,
			validateResp: func(t *testing.T, resp *TokenIntrospectionResponse) {
				assert.True(t, resp.Active)
			},
		},
		{
			name: "server error",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "server_error"}`))
			},
			token:         "error-token",
			expectError:   true,
			errorContains: "introspection failed",
		},
		{
			name: "unauthorized",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error": "invalid_client"}`))
			},
			token:         "unauth-token",
			expectError:   true,
			errorContains: "introspection failed",
		},
		{
			name: "invalid JSON response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{invalid json}`))
			},
			token:         "invalid-json-token",
			expectError:   true,
			errorContains: "failed to parse introspection response",
		},
		{
			name: "full response with all fields",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"active":     true,
					"scope":      "openid profile email",
					"client_id":  "full-client",
					"username":   "fulluser",
					"token_type": "Bearer",
					"exp":        1735689600,
					"iat":        1735686000,
					"nbf":        1735686000,
					"sub":        "subject-id",
					"aud":        "audience",
					"iss":        "https://issuer.com",
					"jti":        "jwt-id-123",
				})
			},
			token:       "full-token",
			expectError: false,
			validateResp: func(t *testing.T, resp *TokenIntrospectionResponse) {
				assert.True(t, resp.Active)
				assert.Equal(t, "openid profile email", resp.Scope)
				assert.Equal(t, "full-client", resp.ClientID)
				assert.Equal(t, "fulluser", resp.Username)
				assert.Equal(t, "Bearer", resp.TokenType)
				assert.Equal(t, int64(1735689600), resp.Exp)
				assert.Equal(t, int64(1735686000), resp.Iat)
				assert.Equal(t, int64(1735686000), resp.Nbf)
				assert.Equal(t, "subject-id", resp.Sub)
				assert.Equal(t, "https://issuer.com", resp.Iss)
				assert.Equal(t, "jwt-id-123", resp.Jti)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &IntrospectionConfig{
				IntrospectionEndpoint: server.URL,
				ClientID:              tt.clientID,
				ClientSecret:          tt.clientSecret,
				Logger:                zaptest.NewLogger(t),
			}

			client, err := NewIntrospectionClient(config)
			require.NoError(t, err)

			resp, err := client.Introspect(context.Background(), tt.token)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				if tt.validateResp != nil {
					tt.validateResp(t, resp)
				}
			}
		})
	}
}

func TestIntrospectionClient_Introspect_NetworkError(t *testing.T) {
	config := &IntrospectionConfig{
		IntrospectionEndpoint: "http://localhost:1", // Invalid port
		Timeout:               1 * time.Second,
		Logger:                zaptest.NewLogger(t),
	}

	client, err := NewIntrospectionClient(config)
	require.NoError(t, err)

	resp, err := client.Introspect(context.Background(), "test-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "introspection request failed")
	assert.Nil(t, resp)
}

func TestIntrospectionClient_Introspect_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Simulate slow server
	}))
	defer server.Close()

	config := &IntrospectionConfig{
		IntrospectionEndpoint: server.URL,
		Logger:                zaptest.NewLogger(t),
	}

	client, err := NewIntrospectionClient(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	resp, err := client.Introspect(ctx, "test-token")
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestIntrospectionClient_IsActive(t *testing.T) {
	tests := []struct {
		name          string
		serverHandler http.HandlerFunc
		token         string
		expectActive  bool
		expectError   bool
	}{
		{
			name: "active token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"active": true,
				})
			},
			token:        "active-token",
			expectActive: true,
			expectError:  false,
		},
		{
			name: "inactive token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"active": false,
				})
			},
			token:        "inactive-token",
			expectActive: false,
			expectError:  false,
		},
		{
			name: "server error",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			token:        "error-token",
			expectActive: false,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &IntrospectionConfig{
				IntrospectionEndpoint: server.URL,
				Logger:                zaptest.NewLogger(t),
			}

			client, err := NewIntrospectionClient(config)
			require.NoError(t, err)

			active, err := client.IsActive(context.Background(), tt.token)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectActive, active)
			}
		})
	}
}

// =============================================================================
// Error Variables Tests
// =============================================================================

func TestErrorVariables(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrTokenRequestFailed",
			err:      ErrTokenRequestFailed,
			expected: "token request failed",
		},
		{
			name:     "ErrInvalidResponse",
			err:      ErrInvalidResponse,
			expected: "invalid token response",
		},
		{
			name:     "ErrTokenExpired",
			err:      ErrTokenExpired,
			expected: "token expired",
		},
		{
			name:     "ErrMissingClientID",
			err:      ErrMissingClientID,
			expected: "missing client ID",
		},
		{
			name:     "ErrMissingClientSecret",
			err:      ErrMissingClientSecret,
			expected: "missing client secret",
		},
		{
			name:     "ErrMissingTokenEndpoint",
			err:      ErrMissingTokenEndpoint,
			expected: "missing token endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

// =============================================================================
// Integration-like Tests
// =============================================================================

func TestClient_FullWorkflow(t *testing.T) {
	// Simulate a full OAuth2 workflow
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "workflow-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "api:read api:write",
		})
	}))
	defer tokenServer.Close()

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		token := r.Form.Get("token")
		if token == "workflow-token" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active":     true,
				"scope":      "api:read api:write",
				"client_id":  "workflow-client",
				"token_type": "Bearer",
			})
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active": false,
			})
		}
	}))
	defer introspectionServer.Close()

	// Create OAuth2 client
	oauthConfig := &Config{
		TokenEndpoint: tokenServer.URL,
		ClientID:      "workflow-client",
		ClientSecret:  "workflow-secret",
		Scopes:        []string{"api:read", "api:write"},
		Logger:        zaptest.NewLogger(t),
	}

	oauthClient, err := NewClient(oauthConfig)
	require.NoError(t, err)

	// Get token
	token, err := oauthClient.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "workflow-token", token.AccessToken)

	// Create introspection client
	introspectionConfig := &IntrospectionConfig{
		IntrospectionEndpoint: introspectionServer.URL,
		ClientID:              "workflow-client",
		ClientSecret:          "workflow-secret",
		Logger:                zaptest.NewLogger(t),
	}

	introspectionClient, err := NewIntrospectionClient(introspectionConfig)
	require.NoError(t, err)

	// Introspect the token
	active, err := introspectionClient.IsActive(context.Background(), token.AccessToken)
	require.NoError(t, err)
	assert.True(t, active)

	// Introspect an invalid token
	active, err = introspectionClient.IsActive(context.Background(), "invalid-token")
	require.NoError(t, err)
	assert.False(t, active)
}

func TestTokenSource_Interface(t *testing.T) {
	// Verify that both token sources implement the TokenSource interface
	var _ TokenSource = (*ClientTokenSource)(nil)
	var _ TokenSource = (*StaticTokenSource)(nil)
}
