// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// GraphQLTestConfig holds GraphQL test configuration from environment variables.
type GraphQLTestConfig struct {
	Backend1URL string
	Backend2URL string
	GatewayPort int
}

// GetGraphQLTestConfig returns GraphQL test configuration from environment variables.
func GetGraphQLTestConfig() GraphQLTestConfig {
	cfg := GraphQLTestConfig{
		Backend1URL: getEnvOrDefault("TEST_GRAPHQL_BACKEND1_URL", "http://127.0.0.1:8801"),
		Backend2URL: getEnvOrDefault("TEST_GRAPHQL_BACKEND2_URL", "http://127.0.0.1:8802"),
		GatewayPort: 18080,
	}
	return cfg
}

// IsGraphQLBackendAvailable checks if a GraphQL backend is available by performing an HTTP health check.
func IsGraphQLBackendAvailable(url string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// SkipIfGraphQLBackendUnavailable skips the test if the GraphQL backend is not available.
func SkipIfGraphQLBackendUnavailable(t interface{ Skip(...interface{}) }, url string) {
	if !IsGraphQLBackendAvailable(url) {
		t.Skip("GraphQL backend not available at", url, "- skipping test")
	}
}

// GraphQLTestBackendInfo contains information about a GraphQL test backend.
type GraphQLTestBackendInfo struct {
	Address string
	Host    string
	Port    int
}

// GetGraphQLBackendInfo parses backend address into structured info.
// It handles both plain host:port and full URLs (http://host:port).
func GetGraphQLBackendInfo(address string) GraphQLTestBackendInfo {
	// Try parsing as a URL first (handles http://host:port format)
	if u, err := url.Parse(address); err == nil && u.Scheme != "" && u.Host != "" {
		host := u.Hostname()
		port := 0
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		return GraphQLTestBackendInfo{
			Address: address,
			Host:    host,
			Port:    port,
		}
	}
	// Fall back to plain host:port parsing
	return GraphQLTestBackendInfo{
		Address: address,
		Host:    parseHost(address),
		Port:    parsePort(address),
	}
}

// GraphQLResponse represents a standard GraphQL response.
type GraphQLResponse struct {
	Data       json.RawMessage `json:"data,omitempty"`
	Errors     []GraphQLError  `json:"errors,omitempty"`
	Extensions json.RawMessage `json:"extensions,omitempty"`
}

// GraphQLError represents a GraphQL error.
type GraphQLError struct {
	Message    string                 `json:"message"`
	Path       []interface{}          `json:"path,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// MakeGraphQLRequest sends a GraphQL POST request with the given query and variables.
func MakeGraphQLRequest(url, query string, variables map[string]interface{}) (*http.Response, error) {
	body := map[string]interface{}{
		"query": query,
	}
	if variables != nil {
		body["variables"] = variables
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := HTTPClient()
	return client.Do(req)
}

// ReadGraphQLResponse reads and parses a GraphQL response from an HTTP response.
func ReadGraphQLResponse(resp *http.Response) (*GraphQLResponse, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var gqlResp GraphQLResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return nil, fmt.Errorf("failed to parse GraphQL response: %w", err)
	}

	return &gqlResp, nil
}

// WaitForGraphQLReady waits for a GraphQL endpoint to become ready.
func WaitForGraphQLReady(url string, timeout time.Duration) error {
	return WaitForReady(url+"/health", timeout)
}

// parseURLHostPort extracts host and port from a URL string (http://host:port) or plain host:port.
func parseURLHostPort(address string) (string, int) {
	if u, err := url.Parse(address); err == nil && u.Scheme != "" && u.Host != "" {
		host := u.Hostname()
		port := 0
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		return host, port
	}
	return parseHost(address), parsePort(address)
}

// CreateGraphQLTestConfig creates a test configuration with GraphQL routes and backends.
func CreateGraphQLTestConfig(port int, backend1URL, backend2URL string) *config.GatewayConfig {
	introspectionEnabled := true
	b1Host, b1Port := parseURLHostPort(backend1URL)
	b2Host, b2Port := parseURLHostPort(backend2URL)
	return &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: config.Metadata{
			Name: "graphql-test-gateway",
		},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Port:     port,
					Protocol: "HTTP",
					Bind:     "0.0.0.0",
				},
			},
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "test-graphql",
					Match: []config.GraphQLRouteMatch{
						{
							Path: &config.StringMatch{Exact: "/graphql"},
						},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: b1Host,
								Port: b1Port,
							},
							Weight: 100,
						},
					},
					Timeout:              config.Duration(30 * time.Second),
					DepthLimit:           10,
					ComplexityLimit:      100,
					IntrospectionEnabled: &introspectionEnabled,
				},
			},
			GraphQLBackends: []config.GraphQLBackend{
				{
					Name: "graphql-backend-1",
					Hosts: []config.BackendHost{
						{
							Address: b1Host,
							Port:    b1Port,
							Weight:  1,
						},
					},
					HealthCheck: &config.HealthCheck{
						Path:               "/health",
						Interval:           config.Duration(5 * time.Second),
						Timeout:            config.Duration(3 * time.Second),
						HealthyThreshold:   2,
						UnhealthyThreshold: 3,
					},
					LoadBalancer: &config.LoadBalancer{
						Algorithm: "roundRobin",
					},
				},
				{
					Name: "graphql-backend-2",
					Hosts: []config.BackendHost{
						{
							Address: b2Host,
							Port:    b2Port,
							Weight:  1,
						},
					},
				},
			},
		},
	}
}

// GraphQLEnvConfig returns configuration based on environment variables.
type GraphQLEnvConfig struct {
	Backend1URL string
	Backend2URL string
}

// LoadGraphQLEnvConfig loads GraphQL configuration from environment variables.
func LoadGraphQLEnvConfig() GraphQLEnvConfig {
	return GraphQLEnvConfig{
		Backend1URL: os.Getenv("TEST_GRAPHQL_BACKEND1_URL"),
		Backend2URL: os.Getenv("TEST_GRAPHQL_BACKEND2_URL"),
	}
}

// mockGraphQLRequest represents a parsed GraphQL request body for the mock backend.
type mockGraphQLRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// NewMockGraphQLBackend creates a mock GraphQL backend server for integration testing.
// The mock serves POST /graphql and GET /health endpoints, returning realistic
// GraphQL JSON responses based on the query content.
func NewMockGraphQLBackend(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONResponse(w, http.StatusBadRequest, `{"errors":[{"message":"failed to read body"}]}`)
			return
		}
		defer r.Body.Close()

		var gqlReq mockGraphQLRequest
		if err := json.Unmarshal(body, &gqlReq); err != nil {
			writeJSONResponse(w, http.StatusBadRequest, `{"errors":[{"message":"invalid JSON"}]}`)
			return
		}

		response := resolveGraphQLMockResponse(gqlReq.Query)
		writeJSONResponse(w, http.StatusOK, response)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server
}

// resolveGraphQLMockResponse determines the appropriate mock response based on the query content.
func resolveGraphQLMockResponse(query string) string {
	q := strings.ToLower(strings.TrimSpace(query))

	switch {
	case strings.Contains(q, "__schema"):
		return `{"data":{"__schema":{"types":[{"name":"Query"},{"name":"Item"},{"name":"Mutation"}]}}}`
	case strings.Contains(q, "__type"):
		return `{"data":{"__type":{"name":"Item","fields":[{"name":"id"},{"name":"name"},{"name":"description"}]}}}`
	case strings.Contains(q, "createitem"):
		return `{"data":{"createItem":{"id":"4","name":"New Item","description":"Created via mutation"}}}`
	case strings.Contains(q, "item(") || strings.Contains(q, "$id"):
		return `{"data":{"item":{"id":"1","name":"Item 1","description":"A test item"}}}`
	case strings.Contains(q, "items"):
		return `{"data":{"items":[{"id":"1","name":"Item 1"},{"id":"2","name":"Item 2"},{"id":"3","name":"Item 3"}]}}`
	default:
		return `{"data":{"result":"ok"}}`
	}
}

// writeJSONResponse writes a JSON response with the given status code and body.
func writeJSONResponse(w http.ResponseWriter, statusCode int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(body))
}
