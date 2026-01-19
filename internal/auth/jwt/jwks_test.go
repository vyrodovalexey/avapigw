package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Sample JWKS for testing
var testJWKS = JSONWebKeySet{
	Keys: []JSONWebKey{
		{
			Kty: "RSA",
			Kid: "key-1",
			Alg: "RS256",
			Use: "sig",
			N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			E:   "AQAB",
		},
		{
			Kty: "RSA",
			Kid: "key-2",
			Alg: "RS384",
			Use: "sig",
			N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			E:   "AQAB",
		},
	},
}

func TestNewJWKSCache(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	tests := []struct {
		name        string
		url         string
		ttl         time.Duration
		expectedTTL time.Duration
	}{
		{
			name:        "With valid TTL",
			url:         "https://example.com/.well-known/jwks.json",
			ttl:         30 * time.Minute,
			expectedTTL: 30 * time.Minute,
		},
		{
			name:        "With zero TTL defaults to 1 hour",
			url:         "https://example.com/.well-known/jwks.json",
			ttl:         0,
			expectedTTL: time.Hour,
		},
		{
			name:        "With negative TTL defaults to 1 hour",
			url:         "https://example.com/.well-known/jwks.json",
			ttl:         -1 * time.Minute,
			expectedTTL: time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cache := NewJWKSCache(tt.url, tt.ttl, logger)

			assert.NotNil(t, cache)
			assert.Equal(t, tt.url, cache.url)
			assert.Equal(t, tt.expectedTTL, cache.ttl)
			assert.NotNil(t, cache.httpClient)
			assert.NotNil(t, cache.stopCh)
		})
	}
}

func TestNewJWKSCacheWithClient(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	customClient := &http.Client{Timeout: 60 * time.Second}

	cache := NewJWKSCacheWithClient("https://example.com/.well-known/jwks.json", time.Hour, customClient, logger)

	assert.NotNil(t, cache)
	assert.Equal(t, customClient, cache.httpClient)
}

func TestNewJWKSCacheWithClient_NilClient(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	cache := NewJWKSCacheWithClient("https://example.com/.well-known/jwks.json", time.Hour, nil, logger)

	assert.NotNil(t, cache)
	assert.NotNil(t, cache.httpClient)
}

func TestJWKSCache_Refresh(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testJWKS)
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, time.Hour, logger)

	err := cache.Refresh(context.Background())
	require.NoError(t, err)

	assert.NotNil(t, cache.keys)
	assert.Len(t, cache.keys.Keys, 2)
	assert.False(t, cache.lastFetch.IsZero())
}

func TestJWKSCache_Refresh_Error(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantError  bool
		errContain string
	}{
		{
			name: "Server returns 500",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Internal Server Error"))
			},
			wantError:  true,
			errContain: "status 500",
		},
		{
			name: "Server returns 404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantError:  true,
			errContain: "status 404",
		},
		{
			name: "Invalid JSON response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte("not valid json"))
			},
			wantError:  true,
			errContain: "failed to parse JWKS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			cache := NewJWKSCache(server.URL, time.Hour, logger)
			err := cache.Refresh(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContain)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestJWKSCache_Refresh_InvalidURL(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	cache := NewJWKSCache("http://invalid-host-that-does-not-exist.local", time.Hour, logger)

	err := cache.Refresh(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")
}

func TestJWKSCache_GetKey(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testJWKS)
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, time.Hour, logger)

	// Get key by ID
	key, err := cache.GetKey("key-1")
	require.NoError(t, err)
	assert.Equal(t, "key-1", key.Kid)
	assert.Equal(t, "RS256", key.Alg)

	// Get another key
	key, err = cache.GetKey("key-2")
	require.NoError(t, err)
	assert.Equal(t, "key-2", key.Kid)
	assert.Equal(t, "RS384", key.Alg)
}

func TestJWKSCache_GetKey_NotFound(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testJWKS)
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, time.Hour, logger)

	_, err := cache.GetKey("nonexistent-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestJWKSCache_GetKey_EmptyKid(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testJWKS)
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, time.Hour, logger)

	// Empty kid should return the first key
	key, err := cache.GetKey("")
	require.NoError(t, err)
	assert.Equal(t, "key-1", key.Kid)
}

func TestJWKSCache_GetKeys(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testJWKS)
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, time.Hour, logger)

	keys, err := cache.GetKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestJWKSCache_GetKeys_NoJWKS(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	// Server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, time.Hour, logger)

	_, err := cache.GetKeys()
	assert.Error(t, err)
}

func TestJWKSCache_LastFetch(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testJWKS)
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, time.Hour, logger)

	// Before refresh
	assert.True(t, cache.LastFetch().IsZero())

	// After refresh
	err := cache.Refresh(context.Background())
	require.NoError(t, err)

	assert.False(t, cache.LastFetch().IsZero())
}

func TestJWKSCache_URL(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	url := "https://example.com/.well-known/jwks.json"

	cache := NewJWKSCache(url, time.Hour, logger)
	assert.Equal(t, url, cache.URL())
}

func TestJWKSCache_Stop(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	cache := NewJWKSCache("https://example.com/.well-known/jwks.json", time.Hour, logger)

	// Should not panic
	cache.Stop()
	assert.True(t, cache.stopped)

	// Calling Stop again should not panic
	cache.Stop()
}

func TestJSONWebKey_ToRSAPublicKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		jwk       JSONWebKey
		wantError bool
		errMsg    string
	}{
		{
			name: "Valid RSA key",
			jwk: JSONWebKey{
				Kty: "RSA",
				N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				E:   "AQAB",
			},
			wantError: false,
		},
		{
			name: "Non-RSA key type",
			jwk: JSONWebKey{
				Kty: "EC",
				N:   "test",
				E:   "AQAB",
			},
			wantError: true,
			errMsg:    "key type is not RSA",
		},
		{
			name: "Invalid modulus encoding",
			jwk: JSONWebKey{
				Kty: "RSA",
				N:   "!!!invalid!!!",
				E:   "AQAB",
			},
			wantError: true,
			errMsg:    "failed to decode modulus",
		},
		{
			name: "Invalid exponent encoding",
			jwk: JSONWebKey{
				Kty: "RSA",
				N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				E:   "!!!invalid!!!",
			},
			wantError: true,
			errMsg:    "failed to decode exponent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, err := tt.jwk.ToRSAPublicKey()

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
				assert.NotNil(t, key.N)
				assert.NotZero(t, key.E)
			}
		})
	}
}

func TestParseJWKSFromBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      []byte
		wantError bool
	}{
		{
			name: "Valid JWKS",
			data: []byte(`{"keys":[{"kty":"RSA","kid":"key-1","n":"test","e":"AQAB"}]}`),
		},
		{
			name:      "Invalid JSON",
			data:      []byte(`not valid json`),
			wantError: true,
		},
		{
			name: "Empty keys array",
			data: []byte(`{"keys":[]}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			jwks, err := ParseJWKSFromBytes(tt.data)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, jwks)
			}
		})
	}
}

func TestParseJWKFromBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      []byte
		wantError bool
	}{
		{
			name: "Valid JWK",
			data: []byte(`{"kty":"RSA","kid":"key-1","n":"test","e":"AQAB"}`),
		},
		{
			name:      "Invalid JSON",
			data:      []byte(`not valid json`),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			jwk, err := ParseJWKFromBytes(tt.data)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, jwk)
			}
		})
	}
}

func TestParseRSAPublicKeyFromPEM(t *testing.T) {
	t.Parallel()

	// Valid RSA public key in PEM format
	validPEM := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt
7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0
zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f
M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK
gwIDAQAB
-----END PUBLIC KEY-----`)

	tests := []struct {
		name      string
		pemData   []byte
		wantError bool
		errMsg    string
	}{
		{
			name:    "Valid PEM",
			pemData: validPEM,
		},
		{
			name:      "Invalid PEM",
			pemData:   []byte("not a pem"),
			wantError: true,
			errMsg:    "failed to decode PEM block",
		},
		{
			name: "Invalid key data",
			pemData: []byte(`-----BEGIN PUBLIC KEY-----
aW52YWxpZA==
-----END PUBLIC KEY-----`),
			wantError: true,
			errMsg:    "failed to parse public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, err := ParseRSAPublicKeyFromPEM(tt.pemData)

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

func TestNewLocalJWKS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      []byte
		wantError bool
	}{
		{
			name: "Valid JWKS",
			data: []byte(`{"keys":[{"kty":"RSA","kid":"key-1","n":"test","e":"AQAB"}]}`),
		},
		{
			name:      "Invalid JSON",
			data:      []byte(`not valid json`),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			jwks, err := NewLocalJWKS(tt.data)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, jwks)
			}
		})
	}
}

func TestLocalJWKS_GetKey(t *testing.T) {
	t.Parallel()

	data := []byte(`{"keys":[{"kty":"RSA","kid":"key-1","n":"test","e":"AQAB"},{"kty":"RSA","kid":"key-2","n":"test2","e":"AQAB"}]}`)
	jwks, err := NewLocalJWKS(data)
	require.NoError(t, err)

	tests := []struct {
		name      string
		kid       string
		wantError bool
	}{
		{
			name: "Existing key",
			kid:  "key-1",
		},
		{
			name: "Another existing key",
			kid:  "key-2",
		},
		{
			name: "Empty kid returns first key",
			kid:  "",
		},
		{
			name:      "Non-existent key",
			kid:       "nonexistent",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, err := jwks.GetKey(tt.kid)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

func TestLocalJWKS_GetKey_NilKeys(t *testing.T) {
	t.Parallel()

	jwks := &LocalJWKS{}
	_, err := jwks.GetKey("any")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no JWKS configured")
}

func TestLocalJWKS_GetKeys(t *testing.T) {
	t.Parallel()

	data := []byte(`{"keys":[{"kty":"RSA","kid":"key-1","n":"test","e":"AQAB"},{"kty":"RSA","kid":"key-2","n":"test2","e":"AQAB"}]}`)
	jwks, err := NewLocalJWKS(data)
	require.NoError(t, err)

	keys := jwks.GetKeys()
	assert.Len(t, keys, 2)
}

func TestLocalJWKS_GetKeys_NilKeys(t *testing.T) {
	t.Parallel()

	jwks := &LocalJWKS{}
	keys := jwks.GetKeys()
	assert.Nil(t, keys)
}

func TestLocalJWKS_Update(t *testing.T) {
	t.Parallel()

	initialData := []byte(`{"keys":[{"kty":"RSA","kid":"key-1","n":"test","e":"AQAB"}]}`)
	jwks, err := NewLocalJWKS(initialData)
	require.NoError(t, err)

	assert.Len(t, jwks.GetKeys(), 1)

	// Update with new data
	newData := []byte(`{"keys":[{"kty":"RSA","kid":"key-1","n":"test","e":"AQAB"},{"kty":"RSA","kid":"key-2","n":"test2","e":"AQAB"}]}`)
	err = jwks.Update(newData)
	require.NoError(t, err)

	assert.Len(t, jwks.GetKeys(), 2)
}

func TestLocalJWKS_Update_InvalidData(t *testing.T) {
	t.Parallel()

	initialData := []byte(`{"keys":[{"kty":"RSA","kid":"key-1","n":"test","e":"AQAB"}]}`)
	jwks, err := NewLocalJWKS(initialData)
	require.NoError(t, err)

	err = jwks.Update([]byte(`not valid json`))
	assert.Error(t, err)

	// Original keys should still be there
	assert.Len(t, jwks.GetKeys(), 1)
}
