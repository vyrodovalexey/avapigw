//go:build integration
// +build integration

package integration

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

	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

/*
OPA Integration Tests

These tests verify the OPA client integration with a mock OPA server.
For tests with a real OPA server, see the E2E tests.

To run these tests:
  go test -tags=integration ./test/integration/... -run TestIntegration_OPA -v
*/

// TestIntegration_OPA_BasicAuthorization tests basic OPA authorization flow.
func TestIntegration_OPA_BasicAuthorization(t *testing.T) {
	t.Parallel()

	t.Run("allow request with valid user", func(t *testing.T) {
		// Arrange - create mock OPA server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request format
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			// Read and verify input
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			var reqBody map[string]interface{}
			err = json.Unmarshal(body, &reqBody)
			require.NoError(t, err)

			input, ok := reqBody["input"].(map[string]interface{})
			require.True(t, ok, "input should be present")

			// Check subject
			subject, ok := input["subject"].(map[string]interface{})
			require.True(t, ok)
			assert.Equal(t, "alice", subject["user"])

			// Return allow decision
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"result": {
					"allow": true,
					"reason": "user alice has access to /api/users"
				},
				"decision_id": "integration-test-001"
			}`))
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
		}

		client, err := external.NewOPAClient(config, 5*time.Second,
			external.WithOPALogger(observability.NopLogger()),
		)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "alice",
				"roles": []string{"user", "admin"},
			},
			Resource: "/api/users",
			Action:   "GET",
			Request: map[string]interface{}{
				"method": "GET",
				"path":   "/api/users",
			},
		}

		// Act
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := client.Authorize(ctx, input)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Allow)
		assert.Equal(t, "user alice has access to /api/users", result.Reason)
		assert.Equal(t, "integration-test-001", result.DecisionID)
	})

	t.Run("deny request with unauthorized user", func(t *testing.T) {
		// Arrange
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"result": {
					"allow": false,
					"reason": "user guest does not have admin role"
				},
				"decision_id": "integration-test-002"
			}`))
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
		}

		client, err := external.NewOPAClient(config, 5*time.Second)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "guest",
				"roles": []string{"guest"},
			},
			Resource: "/api/admin",
			Action:   "DELETE",
		}

		// Act
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := client.Authorize(ctx, input)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.Allow)
		assert.Equal(t, "user guest does not have admin role", result.Reason)
	})
}

// TestIntegration_OPA_PolicyEvaluation tests different policy evaluation scenarios.
func TestIntegration_OPA_PolicyEvaluation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		user           string
		roles          []string
		resource       string
		action         string
		expectedAllow  bool
		expectedReason string
	}{
		{
			name:           "admin can access admin endpoints",
			user:           "admin",
			roles:          []string{"admin"},
			resource:       "/api/admin/users",
			action:         "DELETE",
			expectedAllow:  true,
			expectedReason: "admin role has full access",
		},
		{
			name:           "user can read own profile",
			user:           "bob",
			roles:          []string{"user"},
			resource:       "/api/users/bob",
			action:         "GET",
			expectedAllow:  true,
			expectedReason: "user can access own profile",
		},
		{
			name:           "user cannot read other profile",
			user:           "bob",
			roles:          []string{"user"},
			resource:       "/api/users/alice",
			action:         "GET",
			expectedAllow:  false,
			expectedReason: "user cannot access other user's profile",
		},
		{
			name:           "guest cannot write",
			user:           "guest",
			roles:          []string{"guest"},
			resource:       "/api/items",
			action:         "POST",
			expectedAllow:  false,
			expectedReason: "guest role is read-only",
		},
		{
			name:           "guest can read public endpoints",
			user:           "guest",
			roles:          []string{"guest"},
			resource:       "/api/public/items",
			action:         "GET",
			expectedAllow:  true,
			expectedReason: "public endpoints are accessible to all",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange - create mock OPA server that evaluates based on input
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)

				response := map[string]interface{}{
					"result": map[string]interface{}{
						"allow":  tc.expectedAllow,
						"reason": tc.expectedReason,
					},
					"decision_id": "policy-eval-" + tc.name,
				}

				respBytes, _ := json.Marshal(response)
				_, _ = w.Write(respBytes)
			}))
			defer server.Close()

			config := &external.OPAConfig{
				URL:    server.URL,
				Policy: "authz/allow",
			}

			client, err := external.NewOPAClient(config, 5*time.Second)
			require.NoError(t, err)
			defer client.Close()

			input := &external.OPAInput{
				Subject: map[string]interface{}{
					"user":  tc.user,
					"roles": tc.roles,
				},
				Resource: tc.resource,
				Action:   tc.action,
			}

			// Act
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := client.Authorize(ctx, input)

			// Assert
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tc.expectedAllow, result.Allow)
			assert.Equal(t, tc.expectedReason, result.Reason)
		})
	}
}

// TestIntegration_OPA_CustomHeaders tests that custom headers are sent to OPA.
func TestIntegration_OPA_CustomHeaders(t *testing.T) {
	t.Parallel()

	t.Run("custom headers are forwarded to OPA", func(t *testing.T) {
		// Arrange
		var receivedHeaders http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": true}`))
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
			Headers: map[string]string{
				"X-API-Key":     "secret-api-key",
				"Authorization": "Bearer opa-token",
				"X-Request-ID":  "integration-test-123",
			},
		}

		client, err := external.NewOPAClient(config, 5*time.Second)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject:  map[string]interface{}{"user": "alice"},
			Resource: "/api/test",
			Action:   "GET",
		}

		// Act
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := client.Authorize(ctx, input)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Allow)

		// Verify headers were received
		assert.Equal(t, "secret-api-key", receivedHeaders.Get("X-API-Key"))
		assert.Equal(t, "Bearer opa-token", receivedHeaders.Get("Authorization"))
		assert.Equal(t, "integration-test-123", receivedHeaders.Get("X-Request-ID"))
	})
}

// TestIntegration_OPA_RetryBehavior tests retry behavior on transient failures.
func TestIntegration_OPA_RetryBehavior(t *testing.T) {
	t.Parallel()

	t.Run("retries on server error and succeeds", func(t *testing.T) {
		// Arrange
		var requestCount atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := requestCount.Add(1)

			// Fail first 2 requests, succeed on 3rd
			if count < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error": "service temporarily unavailable"}`))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": true, "decision_id": "retry-success"}`))
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
		}

		retryConfig := external.RetryConfig{
			MaxRetries:        3,
			InitialBackoff:    10 * time.Millisecond,
			MaxBackoff:        100 * time.Millisecond,
			BackoffMultiplier: 2.0,
		}

		client, err := external.NewOPAClient(config, 5*time.Second,
			external.WithOPARetryConfig(retryConfig),
			external.WithOPALogger(observability.NopLogger()),
		)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject:  map[string]interface{}{"user": "alice"},
			Resource: "/api/test",
			Action:   "GET",
		}

		// Act
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := client.Authorize(ctx, input)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Allow)
		assert.Equal(t, int32(3), requestCount.Load(), "should have made 3 requests")
	})

	t.Run("fails after max retries exceeded", func(t *testing.T) {
		// Arrange
		var requestCount atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error": "service unavailable"}`))
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
		}

		retryConfig := external.RetryConfig{
			MaxRetries:        2,
			InitialBackoff:    10 * time.Millisecond,
			MaxBackoff:        50 * time.Millisecond,
			BackoffMultiplier: 2.0,
		}

		client, err := external.NewOPAClient(config, 5*time.Second,
			external.WithOPARetryConfig(retryConfig),
			external.WithOPALogger(observability.NopLogger()),
		)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject:  map[string]interface{}{"user": "alice"},
			Resource: "/api/test",
			Action:   "GET",
		}

		// Act
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := client.Authorize(ctx, input)

		// Assert
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed after")
		// Initial request + 2 retries = 3 total requests
		assert.Equal(t, int32(3), requestCount.Load())
	})

	t.Run("does not retry on 4xx errors", func(t *testing.T) {
		// Arrange
		var requestCount atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "invalid input"}`))
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
		}

		retryConfig := external.RetryConfig{
			MaxRetries:        3,
			InitialBackoff:    10 * time.Millisecond,
			MaxBackoff:        50 * time.Millisecond,
			BackoffMultiplier: 2.0,
		}

		client, err := external.NewOPAClient(config, 5*time.Second,
			external.WithOPARetryConfig(retryConfig),
			external.WithOPALogger(observability.NopLogger()),
		)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject:  map[string]interface{}{"user": "alice"},
			Resource: "/api/test",
			Action:   "GET",
		}

		// Act
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := client.Authorize(ctx, input)

		// Assert
		require.Error(t, err)
		assert.Nil(t, result)
		// Should not retry on 4xx errors
		assert.Equal(t, int32(1), requestCount.Load())
	})
}

// TestIntegration_OPA_ConcurrentRequests tests concurrent authorization requests.
func TestIntegration_OPA_ConcurrentRequests(t *testing.T) {
	t.Parallel()

	t.Run("handles concurrent requests correctly", func(t *testing.T) {
		// Arrange
		var requestCount atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount.Add(1)

			// Simulate some processing time
			time.Sleep(10 * time.Millisecond)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": true}`))
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
		}

		client, err := external.NewOPAClient(config, 5*time.Second)
		require.NoError(t, err)
		defer client.Close()

		// Act - send 20 concurrent requests
		numRequests := 20
		results := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func(userID int) {
				input := &external.OPAInput{
					Subject: map[string]interface{}{
						"user": "user-" + string(rune('a'+userID%26)),
					},
					Resource: "/api/test",
					Action:   "GET",
				}

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				_, err := client.Authorize(ctx, input)
				results <- err
			}(i)
		}

		// Assert - all requests should succeed
		successCount := 0
		for i := 0; i < numRequests; i++ {
			err := <-results
			if err == nil {
				successCount++
			}
		}

		assert.Equal(t, numRequests, successCount, "all concurrent requests should succeed")
		assert.Equal(t, int32(numRequests), requestCount.Load())
	})
}

// TestIntegration_OPA_ContextCancellation tests context cancellation handling.
func TestIntegration_OPA_ContextCancellation(t *testing.T) {
	t.Parallel()

	t.Run("respects context cancellation", func(t *testing.T) {
		// Arrange
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate slow response
			time.Sleep(5 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
		}

		client, err := external.NewOPAClient(config, 10*time.Second)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject:  map[string]interface{}{"user": "alice"},
			Resource: "/api/test",
			Action:   "GET",
		}

		// Act - cancel context after 100ms
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		start := time.Now()
		result, err := client.Authorize(ctx, input)
		elapsed := time.Since(start)

		// Assert
		require.Error(t, err)
		assert.Nil(t, result)
		// Should fail quickly due to context cancellation
		assert.Less(t, elapsed, 1*time.Second, "should fail quickly due to context cancellation")
	})
}

// TestIntegration_OPA_InputSerialization tests that complex input is properly serialized.
func TestIntegration_OPA_InputSerialization(t *testing.T) {
	t.Parallel()

	t.Run("complex input is properly serialized", func(t *testing.T) {
		// Arrange
		var receivedInput map[string]interface{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var reqBody map[string]interface{}
			_ = json.Unmarshal(body, &reqBody)
			receivedInput = reqBody["input"].(map[string]interface{})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": true}`))
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
		}

		client, err := external.NewOPAClient(config, 5*time.Second)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "alice",
				"roles": []string{"admin", "user"},
				"attributes": map[string]interface{}{
					"department": "engineering",
					"level":      3,
				},
			},
			Resource: "/api/v1/users/123",
			Action:   "PUT",
			Request: map[string]interface{}{
				"method":  "PUT",
				"path":    "/api/v1/users/123",
				"headers": map[string]string{"Content-Type": "application/json"},
				"body": map[string]interface{}{
					"name":  "Alice Updated",
					"email": "alice@example.com",
				},
			},
			Context: map[string]interface{}{
				"ip":         "192.168.1.100",
				"user_agent": "Mozilla/5.0",
				"timestamp":  "2024-01-15T10:30:00Z",
				"request_id": "req-12345",
			},
		}

		// Act
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := client.Authorize(ctx, input)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Allow)

		// Verify input was properly serialized
		assert.Equal(t, "/api/v1/users/123", receivedInput["resource"])
		assert.Equal(t, "PUT", receivedInput["action"])

		subject := receivedInput["subject"].(map[string]interface{})
		assert.Equal(t, "alice", subject["user"])

		attrs := subject["attributes"].(map[string]interface{})
		assert.Equal(t, "engineering", attrs["department"])

		request := receivedInput["request"].(map[string]interface{})
		assert.Equal(t, "PUT", request["method"])

		ctx2 := receivedInput["context"].(map[string]interface{})
		assert.Equal(t, "192.168.1.100", ctx2["ip"])
	})
}

// TestIntegration_OPA_Metrics tests that metrics are recorded correctly.
func TestIntegration_OPA_Metrics(t *testing.T) {
	t.Parallel()

	t.Run("metrics are recorded for successful requests", func(t *testing.T) {
		// Arrange
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": true}`))
		}))
		defer server.Close()

		config := &external.OPAConfig{
			URL:    server.URL,
			Policy: "authz/allow",
		}

		metrics := external.NewMetrics("test_integration")

		client, err := external.NewOPAClient(config, 5*time.Second,
			external.WithOPAMetrics(metrics),
		)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject:  map[string]interface{}{"user": "alice"},
			Resource: "/api/test",
			Action:   "GET",
		}

		// Act
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := client.Authorize(ctx, input)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Allow)

		// Verify metrics were recorded (metrics are recorded internally)
		// The actual metric values would need to be verified through Prometheus registry
	})
}

// TestIntegration_OPA_BooleanResult tests handling of boolean result from OPA.
func TestIntegration_OPA_BooleanResult(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		response      string
		expectedAllow bool
	}{
		{
			name:          "boolean true",
			response:      `{"result": true, "decision_id": "bool-true"}`,
			expectedAllow: true,
		},
		{
			name:          "boolean false",
			response:      `{"result": false, "decision_id": "bool-false"}`,
			expectedAllow: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()

			config := &external.OPAConfig{
				URL:    server.URL,
				Policy: "authz/allow",
			}

			client, err := external.NewOPAClient(config, 5*time.Second)
			require.NoError(t, err)
			defer client.Close()

			input := &external.OPAInput{
				Subject:  map[string]interface{}{"user": "alice"},
				Resource: "/api/test",
				Action:   "GET",
			}

			// Act
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := client.Authorize(ctx, input)

			// Assert
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tc.expectedAllow, result.Allow)
		})
	}
}

// TestIntegration_OPA_URLConstruction tests URL construction with different policy paths.
func TestIntegration_OPA_URLConstruction(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		policy      string
		expectedURL string
	}{
		{
			name:        "with policy path",
			policy:      "authz/allow",
			expectedURL: "/v1/data/authz/allow",
		},
		{
			name:        "with nested policy path",
			policy:      "myapp/authz/api/allow",
			expectedURL: "/v1/data/myapp/authz/api/allow",
		},
		{
			name:        "without policy path",
			policy:      "",
			expectedURL: "/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			var requestURL string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestURL = r.URL.String()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"result": true}`))
			}))
			defer server.Close()

			config := &external.OPAConfig{
				URL:    server.URL,
				Policy: tc.policy,
			}

			client, err := external.NewOPAClient(config, 5*time.Second)
			require.NoError(t, err)
			defer client.Close()

			input := &external.OPAInput{
				Subject:  map[string]interface{}{"user": "alice"},
				Resource: "/api/test",
				Action:   "GET",
			}

			// Act
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			_, err = client.Authorize(ctx, input)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, tc.expectedURL, requestURL)
		})
	}
}

// TestIntegration_OPA_ErrorResponses tests handling of various error responses.
func TestIntegration_OPA_ErrorResponses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "bad request",
			statusCode: http.StatusBadRequest,
			body:       `{"error": "invalid input format"}`,
		},
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			body:       `{"error": "authentication required"}`,
		},
		{
			name:       "forbidden",
			statusCode: http.StatusForbidden,
			body:       `{"error": "access denied"}`,
		},
		{
			name:       "not found",
			statusCode: http.StatusNotFound,
			body:       `{"error": "policy not found"}`,
		},
		{
			name:       "internal server error",
			statusCode: http.StatusInternalServerError,
			body:       `{"error": "internal error"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			config := &external.OPAConfig{
				URL:    server.URL,
				Policy: "authz/allow",
			}

			// Disable retries for this test
			retryConfig := external.RetryConfig{
				MaxRetries:        0,
				InitialBackoff:    10 * time.Millisecond,
				MaxBackoff:        50 * time.Millisecond,
				BackoffMultiplier: 2.0,
			}

			client, err := external.NewOPAClient(config, 5*time.Second,
				external.WithOPARetryConfig(retryConfig),
				external.WithOPALogger(observability.NopLogger()),
			)
			require.NoError(t, err)
			defer client.Close()

			input := &external.OPAInput{
				Subject:  map[string]interface{}{"user": "alice"},
				Resource: "/api/test",
				Action:   "GET",
			}

			// Act
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := client.Authorize(ctx, input)

			// Assert
			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "OPA")
		})
	}
}
