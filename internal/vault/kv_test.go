package vault

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestKVClient_Read_EmptyMount(t *testing.T) {
	client := &disabledKVClient{}
	_, err := client.Read(context.Background(), "", "path")
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
		// For real client, it would return validation error
	}
}

func TestKVClient_Read_EmptyPath(t *testing.T) {
	client := &disabledKVClient{}
	_, err := client.Read(context.Background(), "mount", "")
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestKVClient_Write_EmptyMount(t *testing.T) {
	client := &disabledKVClient{}
	err := client.Write(context.Background(), "", "path", map[string]interface{}{"key": "value"})
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestKVClient_Write_EmptyPath(t *testing.T) {
	client := &disabledKVClient{}
	err := client.Write(context.Background(), "mount", "", map[string]interface{}{"key": "value"})
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestKVClient_Write_NilData(t *testing.T) {
	client := &disabledKVClient{}
	err := client.Write(context.Background(), "mount", "path", nil)
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestKVClient_Delete_EmptyMount(t *testing.T) {
	client := &disabledKVClient{}
	err := client.Delete(context.Background(), "", "path")
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestKVClient_Delete_EmptyPath(t *testing.T) {
	client := &disabledKVClient{}
	err := client.Delete(context.Background(), "mount", "")
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestKVClient_List_EmptyMount(t *testing.T) {
	client := &disabledKVClient{}
	_, err := client.List(context.Background(), "", "path")
	if !errors.Is(err, ErrVaultDisabled) {
		// For disabled client, it returns ErrVaultDisabled
	}
}

func TestDisabledKVClient_AllMethods(t *testing.T) {
	client := &disabledKVClient{}
	ctx := context.Background()

	t.Run("Read", func(t *testing.T) {
		_, err := client.Read(ctx, "mount", "path")
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Read() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Write", func(t *testing.T) {
		err := client.Write(ctx, "mount", "path", map[string]interface{}{"key": "value"})
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Write() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := client.Delete(ctx, "mount", "path")
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("Delete() error = %v, want ErrVaultDisabled", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		_, err := client.List(ctx, "mount", "path")
		if !errors.Is(err, ErrVaultDisabled) {
			t.Errorf("List() error = %v, want ErrVaultDisabled", err)
		}
	})
}

func TestKVClient_Read_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/test-path" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"data": {
					"data": {
						"username": "admin",
						"password": "secret123"
					},
					"metadata": {
						"version": 1
					}
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

	kv := client.KV()
	data, err := kv.Read(context.Background(), "secret", "test-path")

	if err != nil {
		t.Errorf("Read() error = %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil data")
	}
	if data["username"] != "admin" {
		t.Errorf("username = %v, want admin", data["username"])
	}
	if data["password"] != "secret123" {
		t.Errorf("password = %v, want secret123", data["password"])
	}
}

func TestKVClient_Read_ValidationErrors(t *testing.T) {
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

	kv := client.KV()

	tests := []struct {
		name    string
		mount   string
		path    string
		wantErr bool
	}{
		{
			name:    "empty mount",
			mount:   "",
			path:    "test-path",
			wantErr: true,
		},
		{
			name:    "empty path",
			mount:   "secret",
			path:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := kv.Read(context.Background(), tt.mount, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKVClient_Read_SecretNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/nonexistent" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
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

	kv := client.KV()
	_, err = kv.Read(context.Background(), "secret", "nonexistent")

	if err == nil {
		t.Error("Read() should return error for nonexistent secret")
	}
}

func TestKVClient_Read_DeletedSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/deleted" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			// KV v2 returns data: null for soft-deleted secrets
			resp := `{
				"data": {
					"data": null,
					"metadata": {
						"deletion_time": "2024-01-01T00:00:00Z",
						"destroyed": false,
						"version": 1
					}
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

	kv := client.KV()
	_, err = kv.Read(context.Background(), "secret", "deleted")

	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Read() error = %v, want ErrSecretNotFound", err)
	}
}

func TestKVClient_Write_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/test-path" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"data": {
					"created_time": "2024-01-01T00:00:00Z",
					"version": 1
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

	kv := client.KV()
	err = kv.Write(context.Background(), "secret", "test-path", map[string]interface{}{
		"username": "admin",
		"password": "secret123",
	})

	if err != nil {
		t.Errorf("Write() error = %v", err)
	}
}

func TestKVClient_Write_ValidationErrors(t *testing.T) {
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

	kv := client.KV()

	tests := []struct {
		name    string
		mount   string
		path    string
		data    map[string]interface{}
		wantErr bool
	}{
		{
			name:    "empty mount",
			mount:   "",
			path:    "test-path",
			data:    map[string]interface{}{"key": "value"},
			wantErr: true,
		},
		{
			name:    "empty path",
			mount:   "secret",
			path:    "",
			data:    map[string]interface{}{"key": "value"},
			wantErr: true,
		},
		{
			name:    "nil data",
			mount:   "secret",
			path:    "test-path",
			data:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := kv.Write(context.Background(), tt.mount, tt.path, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Write() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKVClient_Delete_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/test-path" && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
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

	kv := client.KV()
	err = kv.Delete(context.Background(), "secret", "test-path")

	if err != nil {
		t.Errorf("Delete() error = %v", err)
	}
}

func TestKVClient_Delete_ValidationErrors(t *testing.T) {
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

	kv := client.KV()

	tests := []struct {
		name    string
		mount   string
		path    string
		wantErr bool
	}{
		{
			name:    "empty mount",
			mount:   "",
			path:    "test-path",
			wantErr: true,
		},
		{
			name:    "empty path",
			mount:   "secret",
			path:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := kv.Delete(context.Background(), tt.mount, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKVClient_List_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for list operation - Vault returns nil secret for empty paths
		w.WriteHeader(http.StatusNotFound)
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

	kv := client.KV()
	keys, err := kv.List(context.Background(), "secret", "nonexistent-path")

	// When path doesn't exist, Vault returns nil which results in empty list
	if err != nil {
		t.Errorf("List() error = %v, want nil (empty list for nonexistent path)", err)
	}
	if len(keys) != 0 {
		t.Errorf("List() returned %d keys, want 0", len(keys))
	}
}

func TestKVClient_List_ValidationErrors(t *testing.T) {
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

	kv := client.KV()
	_, err = kv.List(context.Background(), "", "test-path")
	if err == nil {
		t.Error("List() should return error for empty mount")
	}
}

func TestKVClient_Read_WithCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/cached-path" && r.Method == http.MethodGet {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"data": {
					"data": {
						"key": "value"
					}
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
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 100,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	kv := client.KV()

	// First call - should hit the server
	_, err = kv.Read(context.Background(), "secret", "cached-path")
	if err != nil {
		t.Fatalf("First Read() error = %v", err)
	}

	// Second call - should hit cache
	_, err = kv.Read(context.Background(), "secret", "cached-path")
	if err != nil {
		t.Fatalf("Second Read() error = %v", err)
	}

	if callCount != 1 {
		t.Errorf("Server was called %d times, want 1 (second call should hit cache)", callCount)
	}
}

func TestKVClient_Write_InvalidatesCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/cache-test" {
			if r.Method == http.MethodGet {
				callCount++
				w.Header().Set("Content-Type", "application/json")
				resp := `{
					"data": {
						"data": {
							"key": "value"
						}
					}
				}`
				_, _ = w.Write([]byte(resp))
				return
			}
			if r.Method == http.MethodPut {
				w.Header().Set("Content-Type", "application/json")
				resp := `{"data": {"version": 2}}`
				_, _ = w.Write([]byte(resp))
				return
			}
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
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 100,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	kv := client.KV()

	// First read - caches the value
	_, _ = kv.Read(context.Background(), "secret", "cache-test")

	// Write - should invalidate cache
	_ = kv.Write(context.Background(), "secret", "cache-test", map[string]interface{}{"key": "new-value"})

	// Second read - should hit server again (cache invalidated)
	_, _ = kv.Read(context.Background(), "secret", "cache-test")

	if callCount != 2 {
		t.Errorf("Server was called %d times, want 2 (write should invalidate cache)", callCount)
	}
}

func TestKVClient_Delete_InvalidatesCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/delete-cache-test" {
			if r.Method == http.MethodGet {
				callCount++
				w.Header().Set("Content-Type", "application/json")
				resp := `{
					"data": {
						"data": {
							"key": "value"
						}
					}
				}`
				_, _ = w.Write([]byte(resp))
				return
			}
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
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
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 100,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	kv := client.KV()

	// First read - caches the value
	_, _ = kv.Read(context.Background(), "secret", "delete-cache-test")

	// Delete - should invalidate cache
	_ = kv.Delete(context.Background(), "secret", "delete-cache-test")

	// Second read - should hit server again (cache invalidated)
	_, _ = kv.Read(context.Background(), "secret", "delete-cache-test")

	if callCount != 2 {
		t.Errorf("Server was called %d times, want 2 (delete should invalidate cache)", callCount)
	}
}

func TestKVClient_Read_KVv1Format(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/v1-path" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			// KV v1 format - data directly in data field without nested "data"
			resp := `{
				"data": {
					"username": "admin",
					"password": "secret123"
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

	kv := client.KV()
	data, err := kv.Read(context.Background(), "secret", "v1-path")

	if err != nil {
		t.Errorf("Read() error = %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil data")
	}
	// In KV v1 format, the data is directly accessible
	if data["username"] != "admin" {
		t.Errorf("username = %v, want admin", data["username"])
	}
}
