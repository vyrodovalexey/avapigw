package external

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestNewOPAClient_NilConfig tests that NewOPAClient returns an error when config is nil.
func TestNewOPAClient_NilConfig(t *testing.T) {
	t.Parallel()

	// Arrange & Act
	client, err := NewOPAClient(nil, 5*time.Second)

	// Assert
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "config is required")
}

// TestNewOPAClient_ValidConfig tests that NewOPAClient creates a client with valid config.
func TestNewOPAClient_ValidConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	config := &OPAConfig{
		URL:    "http://localhost:8181",
		Policy: "authz/allow",
	}

	// Act
	client, err := NewOPAClient(config, 5*time.Second)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify client can be closed
	err = client.Close()
	assert.NoError(t, err)
}

// TestNewOPAClient_WithOptions tests that NewOPAClient applies functional options.
func TestNewOPAClient_WithOptions(t *testing.T) {
	t.Parallel()

	// Arrange
	config := &OPAConfig{
		URL:    "http://localhost:8181",
		Policy: "authz/allow",
	}
	customHTTPClient := &http.Client{Timeout: 10 * time.Second}
	customLogger := observability.NopLogger()
	customMetrics := NewMetrics("test")

	// Act
	client, err := NewOPAClient(
		config,
		5*time.Second,
		WithOPAHTTPClient(customHTTPClient),
		WithOPALogger(customLogger),
		WithOPAMetrics(customMetrics),
	)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify the client was created with options applied
	opaClient, ok := client.(*opaClient)
	require.True(t, ok)
	assert.Equal(t, customHTTPClient, opaClient.httpClient)
	assert.Equal(t, customLogger, opaClient.logger)
	assert.Equal(t, customMetrics, opaClient.metrics)
}

// TestOPAClient_Authorize_Success_BoolResult tests successful authorization with boolean result.
func TestOPAClient_Authorize_Success_BoolResult(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, ContentTypeJSON, r.Header.Get(HeaderContentType))

		// Read and verify body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var reqBody map[string]interface{}
		err = json.Unmarshal(body, &reqBody)
		require.NoError(t, err)
		assert.Contains(t, reqBody, "input")

		// Return boolean result
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true, "decision_id": "test-decision-123"}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allow)
	assert.Equal(t, "test-decision-123", result.DecisionID)
}

// TestOPAClient_Authorize_Success_MapResult tests successful authorization with map result.
func TestOPAClient_Authorize_Success_MapResult(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"result": {
				"allow": true,
				"reason": "user has admin role"
			},
			"decision_id": "map-decision-456"
		}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "admin"},
		Resource: "/api/admin",
		Action:   "POST",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allow)
	assert.Equal(t, "user has admin role", result.Reason)
	assert.Equal(t, "map-decision-456", result.DecisionID)
}

// TestOPAClient_Authorize_Denied tests authorization denial.
func TestOPAClient_Authorize_Denied(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"result": {
				"allow": false,
				"reason": "insufficient permissions"
			},
			"decision_id": "denied-789"
		}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "guest"},
		Resource: "/api/admin",
		Action:   "DELETE",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allow)
	assert.Equal(t, "insufficient permissions", result.Reason)
	assert.Equal(t, "denied-789", result.DecisionID)
}

// TestOPAClient_Authorize_NetworkError tests handling of network errors.
func TestOPAClient_Authorize_NetworkError(t *testing.T) {
	t.Parallel()

	// Arrange - use an invalid URL that will cause a connection error
	config := &OPAConfig{
		URL:    "http://localhost:1", // Port 1 is unlikely to be listening
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 100*time.Millisecond)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to send request")
}

// TestOPAClient_Authorize_InvalidResponse tests handling of invalid JSON response.
func TestOPAClient_Authorize_InvalidResponse(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`invalid json`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// TestOPAClient_Authorize_NonOKStatus tests handling of non-200 HTTP status.
func TestOPAClient_Authorize_NonOKStatus(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "BadRequest",
			statusCode: http.StatusBadRequest,
			body:       `{"error": "invalid input"}`,
		},
		{
			name:       "InternalServerError",
			statusCode: http.StatusInternalServerError,
			body:       `{"error": "internal error"}`,
		},
		{
			name:       "ServiceUnavailable",
			statusCode: http.StatusServiceUnavailable,
			body:       `{"error": "service unavailable"}`,
		},
		{
			name:       "Unauthorized",
			statusCode: http.StatusUnauthorized,
			body:       `{"error": "unauthorized"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			config := &OPAConfig{
				URL:    server.URL,
				Policy: "authz/allow",
			}

			client, err := NewOPAClient(config, 5*time.Second)
			require.NoError(t, err)

			input := &OPAInput{
				Subject:  map[string]interface{}{"user": "alice"},
				Resource: "/api/users",
				Action:   "GET",
			}

			// Act
			result, err := client.Authorize(context.Background(), input)

			// Assert
			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "OPA returned status")
		})
	}
}

// TestOPAClient_Authorize_ContextCancellation tests handling of context cancellation.
func TestOPAClient_Authorize_ContextCancellation(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 10*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel the context after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// Act
	result, err := client.Authorize(ctx, input)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to send request")
}

// TestOPAClient_Authorize_Timeout tests handling of request timeout.
func TestOPAClient_Authorize_Timeout(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response that exceeds timeout
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	// Create client with very short timeout
	client, err := NewOPAClient(config, 50*time.Millisecond)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to send request")
}

// TestOPAClient_Close tests that Close returns no error.
func TestOPAClient_Close(t *testing.T) {
	t.Parallel()

	// Arrange
	config := &OPAConfig{
		URL:    "http://localhost:8181",
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	// Act
	err = client.Close()

	// Assert
	assert.NoError(t, err)

	// Verify Close can be called multiple times
	err = client.Close()
	assert.NoError(t, err)
}

// TestOPAClient_Authorize_WithCustomHeaders tests that custom headers are sent.
func TestOPAClient_Authorize_WithCustomHeaders(t *testing.T) {
	t.Parallel()

	// Arrange
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"Authorization":   "Bearer test-token",
		},
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allow)
	assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "Bearer test-token", receivedHeaders.Get("Authorization"))
}

// TestOPAClient_Authorize_WithoutPolicy tests URL construction without policy.
func TestOPAClient_Authorize_WithoutPolicy(t *testing.T) {
	t.Parallel()

	// Arrange
	var requestURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURL = r.URL.String()
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "", // No policy specified
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allow)
	// When no policy is specified, URL should be used as-is
	assert.Equal(t, "/", requestURL)
}

// TestOPAClient_Authorize_WithPolicy tests URL construction with policy.
func TestOPAClient_Authorize_WithPolicy(t *testing.T) {
	t.Parallel()

	// Arrange
	var requestURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURL = r.URL.String()
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allow)
	// When policy is specified, URL should include /v1/data/{policy}
	assert.Equal(t, "/v1/data/authz/allow", requestURL)
}

// TestOPAClient_Authorize_UnexpectedResultType tests handling of unexpected result type.
func TestOPAClient_Authorize_UnexpectedResultType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		response string
	}{
		{
			name:     "StringResult",
			response: `{"result": "unexpected string"}`,
		},
		{
			name:     "ArrayResult",
			response: `{"result": [1, 2, 3]}`,
		},
		{
			name:     "NumberResult",
			response: `{"result": 42}`,
		},
		{
			name:     "NullResult",
			response: `{"result": null}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()

			config := &OPAConfig{
				URL:    server.URL,
				Policy: "authz/allow",
			}

			client, err := NewOPAClient(config, 5*time.Second)
			require.NoError(t, err)

			input := &OPAInput{
				Subject:  map[string]interface{}{"user": "alice"},
				Resource: "/api/users",
				Action:   "GET",
			}

			// Act
			result, err := client.Authorize(context.Background(), input)

			// Assert
			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "unexpected result type")
		})
	}
}

// TestOPAClient_Authorize_MapResultWithoutAllow tests map result without allow field.
func TestOPAClient_Authorize_MapResultWithoutAllow(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		// Map result without "allow" field - should default to false
		_, _ = w.Write([]byte(`{"result": {"reason": "some reason"}}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allow) // Should default to false
	assert.Equal(t, "some reason", result.Reason)
}

// TestOPAClient_Authorize_ConcurrentRequests tests concurrent authorization requests.
func TestOPAClient_Authorize_ConcurrentRequests(t *testing.T) {
	t.Parallel()

	// Arrange
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "alice"},
		Resource: "/api/users",
		Action:   "GET",
	}

	// Act - send concurrent requests
	numRequests := 10
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			_, err := client.Authorize(context.Background(), input)
			results <- err
		}()
	}

	// Assert - all requests should succeed
	for i := 0; i < numRequests; i++ {
		err := <-results
		assert.NoError(t, err)
	}

	assert.Equal(t, int32(numRequests), requestCount.Load())
}

// TestOPAClient_Authorize_InputSerialization tests that input is properly serialized.
func TestOPAClient_Authorize_InputSerialization(t *testing.T) {
	t.Parallel()

	// Arrange
	var receivedInput map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var reqBody map[string]interface{}
		_ = json.Unmarshal(body, &reqBody)
		receivedInput = reqBody["input"].(map[string]interface{})

		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject: map[string]interface{}{
			"user":  "alice",
			"roles": []string{"admin", "user"},
		},
		Resource: "/api/users",
		Action:   "GET",
		Request: map[string]interface{}{
			"method": "GET",
			"path":   "/api/users",
		},
		Context: map[string]interface{}{
			"ip":        "192.168.1.1",
			"timestamp": "2024-01-01T00:00:00Z",
		},
	}

	// Act
	_, err = client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "/api/users", receivedInput["resource"])
	assert.Equal(t, "GET", receivedInput["action"])

	subject := receivedInput["subject"].(map[string]interface{})
	assert.Equal(t, "alice", subject["user"])

	request := receivedInput["request"].(map[string]interface{})
	assert.Equal(t, "GET", request["method"])

	ctx := receivedInput["context"].(map[string]interface{})
	assert.Equal(t, "192.168.1.1", ctx["ip"])
}

// TestOPAClient_Authorize_BoolResultFalse tests boolean false result.
func TestOPAClient_Authorize_BoolResultFalse(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": false, "decision_id": "bool-false-123"}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	input := &OPAInput{
		Subject:  map[string]interface{}{"user": "guest"},
		Resource: "/api/admin",
		Action:   "DELETE",
	}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allow)
	assert.Equal(t, "bool-false-123", result.DecisionID)
}

// TestOPAClient_Authorize_EmptyInput tests authorization with minimal input.
func TestOPAClient_Authorize_EmptyInput(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	// Empty input
	input := &OPAInput{}

	// Act
	result, err := client.Authorize(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allow)
}

// TestOPAClient_Authorize_NilInput tests authorization with nil input.
func TestOPAClient_Authorize_NilInput(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true}`))
	}))
	defer server.Close()

	config := &OPAConfig{
		URL:    server.URL,
		Policy: "authz/allow",
	}

	client, err := NewOPAClient(config, 5*time.Second)
	require.NoError(t, err)

	// Act
	result, err := client.Authorize(context.Background(), nil)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allow)
}

// TestOPAClientInterface tests that opaClient implements OPAClient interface.
func TestOPAClientInterface(t *testing.T) {
	t.Parallel()

	// This test verifies at compile time that opaClient implements OPAClient
	var _ OPAClient = (*opaClient)(nil)
}
