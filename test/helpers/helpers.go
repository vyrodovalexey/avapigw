// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// TestConfig holds test configuration from environment variables.
type TestConfig struct {
	Backend1URL string
	Backend2URL string
	GatewayPort int
}

// GetTestConfig returns test configuration from environment variables.
func GetTestConfig() TestConfig {
	cfg := TestConfig{
		Backend1URL: getEnvOrDefault("TEST_BACKEND1_URL", "http://127.0.0.1:8801"),
		Backend2URL: getEnvOrDefault("TEST_BACKEND2_URL", "http://127.0.0.1:8802"),
		GatewayPort: 18080,
	}
	return cfg
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetTestDataPath returns the path to the testdata directory.
func GetTestDataPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata")
}

// GetTestConfigPath returns the path to a test configuration file.
func GetTestConfigPath(name string) string {
	return filepath.Join(GetTestDataPath(), name)
}

// LoadTestConfig loads a test configuration file.
func LoadTestConfig(name string) (*config.GatewayConfig, error) {
	path := GetTestConfigPath(name)
	return config.LoadConfig(path)
}

// GatewayInstance represents a running gateway instance for testing.
type GatewayInstance struct {
	Gateway  *gateway.Gateway
	Config   *config.GatewayConfig
	Router   *router.Router
	Registry *backend.Registry
	Proxy    *proxy.ReverseProxy
	BaseURL  string
}

// StartGateway starts a gateway instance with the given configuration.
func StartGateway(ctx context.Context, configPath string) (*GatewayInstance, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return StartGatewayWithConfig(ctx, cfg)
}

// StartGatewayWithConfig starts a gateway instance with the given configuration struct.
func StartGatewayWithConfig(ctx context.Context, cfg *config.GatewayConfig) (*GatewayInstance, error) {
	logger := observability.NopLogger()

	// Create router
	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		return nil, fmt.Errorf("failed to load routes: %w", err)
	}

	// Create backend registry
	registry := backend.NewRegistry(logger)
	if err := registry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		return nil, fmt.Errorf("failed to load backends: %w", err)
	}

	// Start backends
	if err := registry.StartAll(ctx); err != nil {
		return nil, fmt.Errorf("failed to start backends: %w", err)
	}

	// Create proxy
	p := proxy.NewReverseProxy(r, registry, proxy.WithProxyLogger(logger))

	// Create gateway
	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(p),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gateway: %w", err)
	}

	// Start gateway
	if err := gw.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start gateway: %w", err)
	}

	// Determine base URL
	port := 8080
	if len(cfg.Spec.Listeners) > 0 {
		port = cfg.Spec.Listeners[0].Port
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	return &GatewayInstance{
		Gateway:  gw,
		Config:   cfg,
		Router:   r,
		Registry: registry,
		Proxy:    p,
		BaseURL:  baseURL,
	}, nil
}

// Stop stops the gateway instance.
func (gi *GatewayInstance) Stop(ctx context.Context) error {
	if gi.Registry != nil {
		_ = gi.Registry.StopAll(ctx)
	}
	if gi.Gateway != nil {
		return gi.Gateway.Stop(ctx)
	}
	return nil
}

// WaitForReady waits for a URL to become ready.
func WaitForReady(url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	client := &http.Client{Timeout: 2 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %s to become ready", url)
		case <-ticker.C:
			resp, err := client.Get(url)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 500 {
					return nil
				}
			}
		}
	}
}

// WaitForBackendReady waits for a backend to become ready.
func WaitForBackendReady(url string, timeout time.Duration) error {
	return WaitForReady(url+"/health", timeout)
}

// HTTPClient returns an HTTP client for testing.
func HTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// MakeRequest makes an HTTP request and returns the response.
func MakeRequest(method, url string, body interface{}) (*http.Response, error) {
	return MakeRequestWithHeaders(method, url, body, nil)
}

// MakeRequestWithHeaders makes an HTTP request with custom headers.
func MakeRequestWithHeaders(method, url string, body interface{}, headers map[string]string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := HTTPClient()
	return client.Do(req)
}

// ReadResponseBody reads and returns the response body as a string.
func ReadResponseBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ReadJSONResponse reads and unmarshals the response body.
func ReadJSONResponse(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

// BackendResponse represents a typical backend response.
type BackendResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Error   string      `json:"error,omitempty"`
}

// ItemResponse represents an item from the backend.
type ItemResponse struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	CreatedAt   string  `json:"created_at,omitempty"`
	UpdatedAt   string  `json:"updated_at,omitempty"`
}

// CreateItemRequest represents a request to create an item.
type CreateItemRequest struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
}

// HealthResponse represents a health check response.
type HealthResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	} `json:"data"`
}

// IsBackendAvailable checks if a backend is available.
func IsBackendAvailable(url string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// SkipIfBackendUnavailable skips the test if the backend is not available.
func SkipIfBackendUnavailable(t interface{ Skip(...interface{}) }, url string) {
	if !IsBackendAvailable(url) {
		t.Skip("Backend not available at", url, "- skipping test")
	}
}

// CreateTestItem creates a test item on the backend.
func CreateTestItem(backendURL string, item CreateItemRequest) (*ItemResponse, error) {
	resp, err := MakeRequest(http.MethodPost, backendURL+"/api/v1/items", item)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Success bool         `json:"success"`
		Data    ItemResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// DeleteTestItem deletes a test item from the backend.
func DeleteTestItem(backendURL string, id string) error {
	resp, err := MakeRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/items/%s", backendURL, id), nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// GetFreePort returns a free port for testing.
func GetFreePort() (int, error) {
	// For simplicity, we use a fixed range of ports for testing
	// In production tests, you might want to use net.Listen to find a free port
	return 18080 + int(time.Now().UnixNano()%1000), nil
}

// RetryWithBackoff retries a function with exponential backoff.
func RetryWithBackoff(ctx context.Context, maxRetries int, fn func() error) error {
	var lastErr error
	backoff := 100 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}
	}

	return lastErr
}
