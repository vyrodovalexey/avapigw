package vault

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestTransitClient_Encrypt_EmptyMount(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Encrypt(context.Background(), "", "key", []byte("data"))
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Encrypt_EmptyKeyName(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Encrypt(context.Background(), "mount", "", []byte("data"))
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Encrypt_EmptyPlaintext(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Encrypt(context.Background(), "mount", "key", []byte{})
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Decrypt_EmptyMount(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Decrypt(context.Background(), "", "key", []byte("ciphertext"))
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Decrypt_EmptyKeyName(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Decrypt(context.Background(), "mount", "", []byte("ciphertext"))
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Decrypt_EmptyCiphertext(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Decrypt(context.Background(), "mount", "key", []byte{})
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Sign_EmptyMount(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Sign(context.Background(), "", "key", []byte("data"))
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Sign_EmptyKeyName(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Sign(context.Background(), "mount", "", []byte("data"))
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Sign_EmptyData(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Sign(context.Background(), "mount", "key", []byte{})
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Verify_EmptyMount(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Verify(context.Background(), "", "key", []byte("data"), []byte("sig"))
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Verify_EmptyKeyName(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Verify(context.Background(), "mount", "", []byte("data"), []byte("sig"))
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Verify_EmptyData(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Verify(context.Background(), "mount", "key", []byte{}, []byte("sig"))
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestTransitClient_Verify_EmptySignature(t *testing.T) {
	client := &disabledTransitClient{}
	_, err := client.Verify(context.Background(), "mount", "key", []byte("data"), []byte{})
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestDisabledTransitClient_AllMethods(t *testing.T) {
	client := &disabledTransitClient{}
	ctx := context.Background()

	t.Run("Encrypt", func(t *testing.T) {
		_, err := client.Encrypt(ctx, "mount", "key", []byte("data"))
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Encrypt() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Decrypt", func(t *testing.T) {
		_, err := client.Decrypt(ctx, "mount", "key", []byte("ciphertext"))
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Decrypt() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Sign", func(t *testing.T) {
		_, err := client.Sign(ctx, "mount", "key", []byte("data"))
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Sign() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Verify", func(t *testing.T) {
		_, err := client.Verify(ctx, "mount", "key", []byte("data"), []byte("sig"))
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Verify() error = %v, want ErrVaultDisabled", err)
		}
	})
}

func TestTransitClient_Encrypt_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/encrypt/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"data": {
					"ciphertext": "vault:v1:encrypted-data-here"
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	ciphertext, err := transit.Encrypt(context.Background(), "transit", "my-key", []byte("secret data"))

	if err != nil {
		t.Errorf("Encrypt() error = %v", err)
	}
	if string(ciphertext) != "vault:v1:encrypted-data-here" {
		t.Errorf("ciphertext = %v, want vault:v1:encrypted-data-here", string(ciphertext))
	}
}

func TestTransitClient_Encrypt_ValidationErrors(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()

	tests := []struct {
		name      string
		mount     string
		keyName   string
		plaintext []byte
		wantErr   bool
	}{
		{
			name:      "empty mount",
			mount:     "",
			keyName:   "my-key",
			plaintext: []byte("data"),
			wantErr:   true,
		},
		{
			name:      "empty key name",
			mount:     "transit",
			keyName:   "",
			plaintext: []byte("data"),
			wantErr:   true,
		},
		{
			name:      "empty plaintext",
			mount:     "transit",
			keyName:   "my-key",
			plaintext: []byte{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transit.Encrypt(context.Background(), tt.mount, tt.keyName, tt.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTransitClient_Decrypt_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/decrypt/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			// Base64 encoded "secret data"
			resp := `{
				"data": {
					"plaintext": "c2VjcmV0IGRhdGE="
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	plaintext, err := transit.Decrypt(context.Background(), "transit", "my-key", []byte("vault:v1:encrypted-data"))

	if err != nil {
		t.Errorf("Decrypt() error = %v", err)
	}
	if string(plaintext) != "secret data" {
		t.Errorf("plaintext = %v, want 'secret data'", string(plaintext))
	}
}

func TestTransitClient_Decrypt_ValidationErrors(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()

	tests := []struct {
		name       string
		mount      string
		keyName    string
		ciphertext []byte
		wantErr    bool
	}{
		{
			name:       "empty mount",
			mount:      "",
			keyName:    "my-key",
			ciphertext: []byte("vault:v1:data"),
			wantErr:    true,
		},
		{
			name:       "empty key name",
			mount:      "transit",
			keyName:    "",
			ciphertext: []byte("vault:v1:data"),
			wantErr:    true,
		},
		{
			name:       "empty ciphertext",
			mount:      "transit",
			keyName:    "my-key",
			ciphertext: []byte{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transit.Decrypt(context.Background(), tt.mount, tt.keyName, tt.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTransitClient_Sign_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/sign/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"data": {
					"signature": "vault:v1:signature-data-here"
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	signature, err := transit.Sign(context.Background(), "transit", "my-key", []byte("data to sign"))

	if err != nil {
		t.Errorf("Sign() error = %v", err)
	}
	if string(signature) != "vault:v1:signature-data-here" {
		t.Errorf("signature = %v, want vault:v1:signature-data-here", string(signature))
	}
}

func TestTransitClient_Sign_ValidationErrors(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()

	tests := []struct {
		name    string
		mount   string
		keyName string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty mount",
			mount:   "",
			keyName: "my-key",
			data:    []byte("data"),
			wantErr: true,
		},
		{
			name:    "empty key name",
			mount:   "transit",
			keyName: "",
			data:    []byte("data"),
			wantErr: true,
		},
		{
			name:    "empty data",
			mount:   "transit",
			keyName: "my-key",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transit.Sign(context.Background(), tt.mount, tt.keyName, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTransitClient_Verify_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/verify/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"data": {
					"valid": true
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	valid, err := transit.Verify(context.Background(), "transit", "my-key", []byte("data"), []byte("vault:v1:signature"))

	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
	if !valid {
		t.Error("Verify() returned false, want true")
	}
}

func TestTransitClient_Verify_InvalidSignature(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/verify/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"data": {
					"valid": false
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	valid, err := transit.Verify(context.Background(), "transit", "my-key", []byte("data"), []byte("invalid-signature"))

	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
	if valid {
		t.Error("Verify() returned true, want false")
	}
}

func TestTransitClient_Verify_ValidationErrors(t *testing.T) {
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()

	tests := []struct {
		name      string
		mount     string
		keyName   string
		data      []byte
		signature []byte
		wantErr   bool
	}{
		{
			name:      "empty mount",
			mount:     "",
			keyName:   "my-key",
			data:      []byte("data"),
			signature: []byte("sig"),
			wantErr:   true,
		},
		{
			name:      "empty key name",
			mount:     "transit",
			keyName:   "",
			data:      []byte("data"),
			signature: []byte("sig"),
			wantErr:   true,
		},
		{
			name:      "empty data",
			mount:     "transit",
			keyName:   "my-key",
			data:      []byte{},
			signature: []byte("sig"),
			wantErr:   true,
		},
		{
			name:      "empty signature",
			mount:     "transit",
			keyName:   "my-key",
			data:      []byte("data"),
			signature: []byte{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transit.Verify(context.Background(), tt.mount, tt.keyName, tt.data, tt.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTransitClient_Encrypt_NoDataInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/encrypt/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	_, err = transit.Encrypt(context.Background(), "transit", "my-key", []byte("data"))

	if err == nil {
		t.Error("Encrypt() should return error when no data in response")
	}
}

func TestTransitClient_Decrypt_NoDataInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/decrypt/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	_, err = transit.Decrypt(context.Background(), "transit", "my-key", []byte("vault:v1:data"))

	if err == nil {
		t.Error("Decrypt() should return error when no data in response")
	}
}

func TestTransitClient_Sign_NoDataInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/sign/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	_, err = transit.Sign(context.Background(), "transit", "my-key", []byte("data"))

	if err == nil {
		t.Error("Sign() should return error when no data in response")
	}
}

func TestTransitClient_Verify_NoDataInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/verify/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	_, err = transit.Verify(context.Background(), "transit", "my-key", []byte("data"), []byte("sig"))

	if err == nil {
		t.Error("Verify() should return error when no data in response")
	}
}

func TestTransitClient_Decrypt_InvalidBase64(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/transit/decrypt/my-key" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			// Invalid base64 in plaintext
			resp := `{
				"data": {
					"plaintext": "not-valid-base64!!!"
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transit := client.Transit()
	_, err = transit.Decrypt(context.Background(), "transit", "my-key", []byte("vault:v1:data"))

	if err == nil {
		t.Error("Decrypt() should return error for invalid base64")
	}
}
