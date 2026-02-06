//go:build e2e
// +build e2e

package e2e

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
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
OPA E2E Test Setup Instructions:

These tests verify OPA external authorization integration with the gateway.
Currently, the tests use a mock OPA server since the auth middleware integration
with the gateway is not yet complete.

To run these tests:
  go test -tags=e2e ./test/e2e/... -run TestE2E_OPA -v

For tests with a real OPA server:
1. Start OPA:
   docker run -d --name opa-test \
     -p 8181:8181 \
     openpolicyagent/opa:latest run --server

2. Load a policy:
   curl -X PUT http://localhost:8181/v1/policies/authz \
     -H "Content-Type: text/plain" \
     -d 'package authz
         default allow = false
         allow { input.subject.roles[_] == "admin" }'

3. Run tests:
   OPA_ADDR=http://127.0.0.1:8181 go test -tags=e2e ./test/e2e/... -run TestE2E_OPA -v
*/

// TestE2E_OPA_ExternalAuthorization tests OPA external authorization with a mock OPA server.
func TestE2E_OPA_ExternalAuthorization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create mock OPA server
	opaServer := createMockOPAServer(t)
	defer opaServer.Close()

	t.Run("OPA client authorizes requests correctly", func(t *testing.T) {
		// Create OPA client
		opaConfig := &external.OPAConfig{
			URL:    opaServer.URL,
			Policy: "authz/allow",
		}

		client, err := external.NewOPAClient(opaConfig, 5*time.Second,
			external.WithOPALogger(observability.NopLogger()),
		)
		require.NoError(t, err)
		defer client.Close()

		// Test admin access
		adminInput := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "admin",
				"roles": []string{"admin"},
			},
			Resource: "/api/admin/users",
			Action:   "DELETE",
		}

		result, err := client.Authorize(ctx, adminInput)
		require.NoError(t, err)
		assert.True(t, result.Allow, "admin should be allowed")

		// Test user access to own resource
		userInput := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "alice",
				"roles": []string{"user"},
			},
			Resource: "/api/users/alice",
			Action:   "GET",
		}

		result, err = client.Authorize(ctx, userInput)
		require.NoError(t, err)
		assert.True(t, result.Allow, "user should access own profile")

		// Test user access to other's resource
		otherInput := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "alice",
				"roles": []string{"user"},
			},
			Resource: "/api/users/bob",
			Action:   "GET",
		}

		result, err = client.Authorize(ctx, otherInput)
		require.NoError(t, err)
		assert.False(t, result.Allow, "user should not access other's profile")
	})
}

// TestE2E_OPA_FailOpen tests fail-open behavior when OPA is unavailable.
func TestE2E_OPA_FailOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("fail-open allows requests when OPA is unavailable", func(t *testing.T) {
		// Create OPA client pointing to non-existent server
		opaConfig := &external.OPAConfig{
			URL:    "http://localhost:1", // Non-existent server
			Policy: "authz/allow",
		}

		// Create external authz config with fail-open
		extConfig := &external.Config{
			Enabled:  true,
			Type:     "opa",
			OPA:      opaConfig,
			Timeout:  100 * time.Millisecond,
			FailOpen: true,
		}

		// Validate config
		err := extConfig.Validate()
		require.NoError(t, err)

		// Create OPA client with short timeout
		client, err := external.NewOPAClient(opaConfig, 100*time.Millisecond,
			external.WithOPARetryConfig(external.RetryConfig{
				MaxRetries:        0, // No retries for this test
				InitialBackoff:    10 * time.Millisecond,
				MaxBackoff:        50 * time.Millisecond,
				BackoffMultiplier: 2.0,
			}),
			external.WithOPALogger(observability.NopLogger()),
		)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "alice",
				"roles": []string{"user"},
			},
			Resource: "/api/test",
			Action:   "GET",
		}

		// OPA request should fail
		result, err := client.Authorize(ctx, input)
		require.Error(t, err, "should fail when OPA is unavailable")
		assert.Nil(t, result)

		// In a real gateway with fail-open, the request would be allowed
		// This test verifies the error is returned so the gateway can decide
		assert.Contains(t, err.Error(), "failed")
	})
}

// TestE2E_OPA_FailClosed tests fail-closed behavior when OPA is unavailable.
func TestE2E_OPA_FailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("fail-closed denies requests when OPA is unavailable", func(t *testing.T) {
		// Create OPA client pointing to non-existent server
		opaConfig := &external.OPAConfig{
			URL:    "http://localhost:1", // Non-existent server
			Policy: "authz/allow",
		}

		// Create external authz config with fail-closed (default)
		extConfig := &external.Config{
			Enabled:  true,
			Type:     "opa",
			OPA:      opaConfig,
			Timeout:  100 * time.Millisecond,
			FailOpen: false, // Fail-closed
		}

		// Validate config
		err := extConfig.Validate()
		require.NoError(t, err)

		// Create OPA client with short timeout
		client, err := external.NewOPAClient(opaConfig, 100*time.Millisecond,
			external.WithOPARetryConfig(external.RetryConfig{
				MaxRetries:        0, // No retries for this test
				InitialBackoff:    10 * time.Millisecond,
				MaxBackoff:        50 * time.Millisecond,
				BackoffMultiplier: 2.0,
			}),
			external.WithOPALogger(observability.NopLogger()),
		)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "alice",
				"roles": []string{"user"},
			},
			Resource: "/api/test",
			Action:   "GET",
		}

		// OPA request should fail
		result, err := client.Authorize(ctx, input)
		require.Error(t, err, "should fail when OPA is unavailable")
		assert.Nil(t, result)

		// In a real gateway with fail-closed, the request would be denied
		// This test verifies the error is returned so the gateway can decide
	})
}

// TestE2E_OPA_DecisionCaching tests OPA decision caching.
func TestE2E_OPA_DecisionCaching(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("decisions can be cached", func(t *testing.T) {
		// Track request count
		var requestCount atomic.Int32

		// Create mock OPA server
		opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount.Add(1)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"result": {"allow": true, "reason": "cached decision"},
				"decision_id": "cache-test"
			}`))
		}))
		defer opaServer.Close()

		// Create OPA client
		opaConfig := &external.OPAConfig{
			URL:    opaServer.URL,
			Policy: "authz/allow",
		}

		client, err := external.NewOPAClient(opaConfig, 5*time.Second)
		require.NoError(t, err)
		defer client.Close()

		input := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "alice",
				"roles": []string{"user"},
			},
			Resource: "/api/test",
			Action:   "GET",
		}

		// Make first request
		result1, err := client.Authorize(ctx, input)
		require.NoError(t, err)
		assert.True(t, result1.Allow)

		// Make second request with same input
		result2, err := client.Authorize(ctx, input)
		require.NoError(t, err)
		assert.True(t, result2.Allow)

		// Both requests should have been made (no caching in OPA client itself)
		// Caching would be implemented at a higher level (e.g., in the gateway middleware)
		assert.Equal(t, int32(2), requestCount.Load())
	})
}

// TestE2E_OPA_HighLoad tests OPA under high load.
func TestE2E_OPA_HighLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("handles high load correctly", func(t *testing.T) {
		// Track request count
		var requestCount atomic.Int32
		var successCount atomic.Int32

		// Create mock OPA server
		opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount.Add(1)

			// Simulate some processing time
			time.Sleep(5 * time.Millisecond)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": true}`))
		}))
		defer opaServer.Close()

		// Create OPA client
		opaConfig := &external.OPAConfig{
			URL:    opaServer.URL,
			Policy: "authz/allow",
		}

		client, err := external.NewOPAClient(opaConfig, 10*time.Second)
		require.NoError(t, err)
		defer client.Close()

		// Send 100 concurrent requests
		numRequests := 100
		done := make(chan struct{}, numRequests)

		for i := 0; i < numRequests; i++ {
			go func(userID int) {
				defer func() { done <- struct{}{} }()

				input := &external.OPAInput{
					Subject: map[string]interface{}{
						"user":  "user-" + string(rune('a'+userID%26)),
						"roles": []string{"user"},
					},
					Resource: "/api/test",
					Action:   "GET",
				}

				result, err := client.Authorize(ctx, input)
				if err == nil && result.Allow {
					successCount.Add(1)
				}
			}(i)
		}

		// Wait for all requests to complete
		for i := 0; i < numRequests; i++ {
			<-done
		}

		// All requests should succeed
		assert.Equal(t, int32(numRequests), requestCount.Load())
		assert.Equal(t, int32(numRequests), successCount.Load())
	})
}

// TestE2E_OPA_GatewayIntegration tests OPA with gateway configuration.
func TestE2E_OPA_GatewayIntegration(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create mock OPA server
	opaServer := createMockOPAServer(t)
	defer opaServer.Close()

	t.Run("gateway can be configured with OPA external authorization", func(t *testing.T) {
		// Load test gateway configuration
		cfg, err := helpers.LoadTestConfig("gateway-test.yaml")
		require.NoError(t, err)

		// Use a unique port for this test
		cfg.Spec.Listeners[0].Port = 18200

		// Start gateway using helper
		gi, err := helpers.StartGatewayWithConfig(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, gi)

		t.Cleanup(func() {
			_ = gi.Stop(ctx)
		})

		// Wait for gateway to be ready
		err = helpers.WaitForReady(gi.BaseURL+"/health", 10*time.Second)
		require.NoError(t, err)

		// Make a request through the gateway
		resp, err := http.Get(gi.BaseURL + "/api/v1/items")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Gateway should be running and accepting requests
		// Note: Full auth integration is not yet complete, so we just verify the gateway starts
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"Expected 200 or 502, got %d", resp.StatusCode)
	})
}

// TestE2E_OPA_PolicyDecisions tests various policy decision scenarios.
func TestE2E_OPA_PolicyDecisions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create mock OPA server with realistic policy behavior
	opaServer := createMockOPAServer(t)
	defer opaServer.Close()

	// Create OPA client
	opaConfig := &external.OPAConfig{
		URL:    opaServer.URL,
		Policy: "authz/allow",
	}

	client, err := external.NewOPAClient(opaConfig, 5*time.Second,
		external.WithOPALogger(observability.NopLogger()),
	)
	require.NoError(t, err)
	defer client.Close()

	testCases := []struct {
		name          string
		user          string
		roles         []string
		resource      string
		action        string
		expectedAllow bool
	}{
		{
			name:          "admin can delete users",
			user:          "admin",
			roles:         []string{"admin"},
			resource:      "/api/admin/users/123",
			action:        "DELETE",
			expectedAllow: true,
		},
		{
			name:          "admin can read all resources",
			user:          "admin",
			roles:         []string{"admin"},
			resource:      "/api/users/alice",
			action:        "GET",
			expectedAllow: true,
		},
		{
			name:          "user can read own profile",
			user:          "alice",
			roles:         []string{"user"},
			resource:      "/api/users/alice",
			action:        "GET",
			expectedAllow: true,
		},
		{
			name:          "user cannot read other profile",
			user:          "alice",
			roles:         []string{"user"},
			resource:      "/api/users/bob",
			action:        "GET",
			expectedAllow: false,
		},
		{
			name:          "user can create items",
			user:          "alice",
			roles:         []string{"user"},
			resource:      "/api/items",
			action:        "POST",
			expectedAllow: true,
		},
		{
			name:          "guest cannot create items",
			user:          "guest",
			roles:         []string{"guest"},
			resource:      "/api/items",
			action:        "POST",
			expectedAllow: false,
		},
		{
			name:          "guest can read public items",
			user:          "guest",
			roles:         []string{"guest"},
			resource:      "/api/public/items",
			action:        "GET",
			expectedAllow: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &external.OPAInput{
				Subject: map[string]interface{}{
					"user":  tc.user,
					"roles": tc.roles,
				},
				Resource: tc.resource,
				Action:   tc.action,
			}

			result, err := client.Authorize(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedAllow, result.Allow, "unexpected authorization result for %s", tc.name)
		})
	}
}

// TestE2E_OPA_RequestContext tests that request context is properly passed to OPA.
func TestE2E_OPA_RequestContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("request context is passed to OPA", func(t *testing.T) {
		var receivedInput map[string]interface{}

		// Create mock OPA server that captures input
		opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var reqBody map[string]interface{}
			_ = json.Unmarshal(body, &reqBody)
			receivedInput = reqBody["input"].(map[string]interface{})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": true}`))
		}))
		defer opaServer.Close()

		// Create OPA client
		opaConfig := &external.OPAConfig{
			URL:    opaServer.URL,
			Policy: "authz/allow",
		}

		client, err := external.NewOPAClient(opaConfig, 5*time.Second)
		require.NoError(t, err)
		defer client.Close()

		// Create input with full request context
		input := &external.OPAInput{
			Subject: map[string]interface{}{
				"user":  "alice",
				"roles": []string{"user", "developer"},
				"attributes": map[string]interface{}{
					"department": "engineering",
					"team":       "platform",
				},
			},
			Resource: "/api/v1/deployments/prod",
			Action:   "POST",
			Request: map[string]interface{}{
				"method": "POST",
				"path":   "/api/v1/deployments/prod",
				"headers": map[string]string{
					"Content-Type":    "application/json",
					"X-Request-ID":    "req-12345",
					"X-Forwarded-For": "192.168.1.100",
				},
				"body": map[string]interface{}{
					"image":    "myapp:v1.2.3",
					"replicas": 3,
				},
			},
			Context: map[string]interface{}{
				"client_ip":   "192.168.1.100",
				"user_agent":  "kubectl/v1.28.0",
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
				"environment": "production",
			},
		}

		// Make authorization request
		result, err := client.Authorize(ctx, input)
		require.NoError(t, err)
		assert.True(t, result.Allow)

		// Verify input was properly passed
		assert.Equal(t, "/api/v1/deployments/prod", receivedInput["resource"])
		assert.Equal(t, "POST", receivedInput["action"])

		subject := receivedInput["subject"].(map[string]interface{})
		assert.Equal(t, "alice", subject["user"])

		request := receivedInput["request"].(map[string]interface{})
		assert.Equal(t, "POST", request["method"])

		ctx2 := receivedInput["context"].(map[string]interface{})
		assert.Equal(t, "192.168.1.100", ctx2["client_ip"])
		assert.Equal(t, "production", ctx2["environment"])
	})
}

// createMockOPAServer creates a mock OPA server for testing.
func createMockOPAServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read input
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var reqBody map[string]interface{}
		if err := json.Unmarshal(body, &reqBody); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		input, ok := reqBody["input"].(map[string]interface{})
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Evaluate policy based on input
		allow, reason := evaluateMockPolicy(input)

		// Return decision
		response := map[string]interface{}{
			"result": map[string]interface{}{
				"allow":  allow,
				"reason": reason,
			},
			"decision_id": "mock-decision-" + time.Now().Format("20060102150405"),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		respBytes, _ := json.Marshal(response)
		_, _ = w.Write(respBytes)
	}))
}

// evaluateMockPolicy evaluates a mock policy based on input.
func evaluateMockPolicy(input map[string]interface{}) (bool, string) {
	subject, _ := input["subject"].(map[string]interface{})
	resource, _ := input["resource"].(string)
	action, _ := input["action"].(string)

	// Get user and roles
	user, _ := subject["user"].(string)
	rolesRaw, _ := subject["roles"].([]interface{})
	roles := make([]string, len(rolesRaw))
	for i, r := range rolesRaw {
		roles[i], _ = r.(string)
	}

	// Check if user has admin role
	hasAdmin := false
	hasUser := false
	hasGuest := false
	for _, role := range roles {
		if role == "admin" {
			hasAdmin = true
		}
		if role == "user" {
			hasUser = true
		}
		if role == "guest" {
			hasGuest = true
		}
	}

	// Admin can do anything
	if hasAdmin {
		return true, "admin role has full access"
	}

	// Public endpoints are accessible to all
	if len(resource) >= 11 && resource[:11] == "/api/public" {
		return true, "public endpoints are accessible to all"
	}

	// Guest can only read public endpoints
	if hasGuest && !hasUser {
		return false, "guest role is read-only for public endpoints"
	}

	// User can access own profile
	if hasUser && len(resource) >= 11 && resource[:11] == "/api/users/" {
		resourceUser := resource[11:]
		if resourceUser == user {
			return true, "user can access own profile"
		}
		return false, "user cannot access other user's profile"
	}

	// User can create/read items
	if hasUser && (resource == "/api/items" || len(resource) >= 11 && resource[:11] == "/api/items/") {
		if action == "GET" || action == "POST" || action == "PUT" {
			return true, "user can manage items"
		}
	}

	// Default deny
	return false, "access denied by default policy"
}
