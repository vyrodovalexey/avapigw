// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	// DefaultKeycloakAddr is the default Keycloak address for testing.
	DefaultKeycloakAddr = "http://127.0.0.1:8090"
	// DefaultKeycloakAdminUser is the default admin username.
	DefaultKeycloakAdminUser = "admin"
	// DefaultKeycloakAdminPassword is the default admin password.
	DefaultKeycloakAdminPassword = "admin"
	// DefaultKeycloakRealm is the default test realm.
	DefaultKeycloakRealm = "gateway-test"
	// DefaultKeycloakClientID is the default client ID.
	DefaultKeycloakClientID = "gateway"
	// DefaultKeycloakClientSecret is the default client secret.
	DefaultKeycloakClientSecret = "gateway-secret"
)

// GetKeycloakAddr returns the Keycloak address from environment or default.
func GetKeycloakAddr() string {
	if addr := os.Getenv("KEYCLOAK_ADDR"); addr != "" {
		return addr
	}
	return DefaultKeycloakAddr
}

// GetKeycloakAdminUser returns the Keycloak admin user from environment or default.
func GetKeycloakAdminUser() string {
	if user := os.Getenv("KEYCLOAK_ADMIN_USER"); user != "" {
		return user
	}
	return DefaultKeycloakAdminUser
}

// GetKeycloakAdminPassword returns the Keycloak admin password from environment or default.
func GetKeycloakAdminPassword() string {
	if pass := os.Getenv("KEYCLOAK_ADMIN_PASSWORD"); pass != "" {
		return pass
	}
	return DefaultKeycloakAdminPassword
}

// GetKeycloakRealm returns the Keycloak realm from environment or default.
func GetKeycloakRealm() string {
	if realm := os.Getenv("KEYCLOAK_REALM"); realm != "" {
		return realm
	}
	return DefaultKeycloakRealm
}

// GetKeycloakClientID returns the Keycloak client ID from environment or default.
func GetKeycloakClientID() string {
	if clientID := os.Getenv("KEYCLOAK_CLIENT_ID"); clientID != "" {
		return clientID
	}
	return DefaultKeycloakClientID
}

// GetKeycloakClientSecret returns the Keycloak client secret from environment or default.
func GetKeycloakClientSecret() string {
	if secret := os.Getenv("KEYCLOAK_CLIENT_SECRET"); secret != "" {
		return secret
	}
	return DefaultKeycloakClientSecret
}

// KeycloakTestConfig holds Keycloak test configuration.
type KeycloakTestConfig struct {
	Address      string
	AdminUser    string
	AdminPass    string
	Realm        string
	ClientID     string
	ClientSecret string
}

// GetKeycloakTestConfig returns Keycloak test configuration from environment.
func GetKeycloakTestConfig() KeycloakTestConfig {
	return KeycloakTestConfig{
		Address:      GetKeycloakAddr(),
		AdminUser:    GetKeycloakAdminUser(),
		AdminPass:    GetKeycloakAdminPassword(),
		Realm:        GetKeycloakRealm(),
		ClientID:     GetKeycloakClientID(),
		ClientSecret: GetKeycloakClientSecret(),
	}
}

// IsKeycloakAvailable checks if Keycloak is available.
func IsKeycloakAvailable() bool {
	client := &http.Client{Timeout: 5 * time.Second}

	// Try the primary health endpoint first
	resp, err := client.Get(GetKeycloakAddr() + "/health/ready")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}

	// Fallback: try the realm endpoint (works on all Keycloak versions)
	resp, err = client.Get(GetKeycloakAddr() + "/realms/master")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// SkipIfKeycloakUnavailable skips the test if Keycloak is not available.
func SkipIfKeycloakUnavailable(t *testing.T) {
	if !IsKeycloakAvailable() {
		t.Skip("Keycloak not available at", GetKeycloakAddr(), "- skipping test")
	}
}

// keycloakAdminTransport is an http.RoundTripper that adds X-Forwarded-Proto: https
// to admin and master realm requests. Keycloak 24+ enforces HTTPS on the master
// realm by default, even in dev mode. This header tells Keycloak the request was
// forwarded from an HTTPS proxy, satisfying the SSL requirement.
// Non-admin requests (e.g., token requests on test realms with sslRequired=none)
// are sent without the header to avoid issuer URL mismatch in tokens.
type keycloakAdminTransport struct {
	base http.RoundTripper
}

func (t *keycloakAdminTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	path := req.URL.Path
	needsForwarded := strings.Contains(path, "/admin/") ||
		strings.Contains(path, "/realms/master/")
	if needsForwarded {
		req = req.Clone(req.Context())
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	return t.base.RoundTrip(req)
}

// KeycloakClient provides methods to interact with Keycloak for testing.
type KeycloakClient struct {
	baseURL    string
	adminToken string
	httpClient *http.Client
}

// NewKeycloakClient creates a new Keycloak client for testing.
func NewKeycloakClient(baseURL string) *KeycloakClient {
	return &KeycloakClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &keycloakAdminTransport{
				base: http.DefaultTransport,
			},
		},
	}
}

// AdminLogin authenticates as admin and stores the token.
func (c *KeycloakClient) AdminLogin(ctx context.Context, username, password string) error {
	tokenURL := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", c.baseURL)

	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("grant_type", "password")
	data.Set("client_id", "admin-cli")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin login failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	c.adminToken = tokenResp.AccessToken
	return nil
}

// CreateRealm creates a new realm.
func (c *KeycloakClient) CreateRealm(ctx context.Context, realmName string) error {
	realmURL := fmt.Sprintf("%s/admin/realms", c.baseURL)

	realmData := map[string]interface{}{
		"realm":       realmName,
		"enabled":     true,
		"sslRequired": "none",
	}

	body, err := json.Marshal(realmData)
	if err != nil {
		return fmt.Errorf("failed to marshal realm data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, realmURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 201 Created or 409 Conflict (already exists) are acceptable
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create realm: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}

// CreateClient creates a new client in a realm.
func (c *KeycloakClient) CreateClient(ctx context.Context, realmName string, clientConfig map[string]interface{}) error {
	clientURL := fmt.Sprintf("%s/admin/realms/%s/clients", c.baseURL, realmName)

	body, err := json.Marshal(clientConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal client config: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, clientURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 201 Created or 409 Conflict (already exists) are acceptable
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create client: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}

// CreateUser creates a new user in a realm.
func (c *KeycloakClient) CreateUser(ctx context.Context, realmName string, userConfig map[string]interface{}) error {
	userURL := fmt.Sprintf("%s/admin/realms/%s/users", c.baseURL, realmName)

	body, err := json.Marshal(userConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal user config: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, userURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 201 Created or 409 Conflict (already exists) are acceptable
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create user: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}

// CreateRealmRole creates a realm role.
func (c *KeycloakClient) CreateRealmRole(ctx context.Context, realmName, roleName string) error {
	roleURL := fmt.Sprintf("%s/admin/realms/%s/roles", c.baseURL, realmName)

	roleData := map[string]interface{}{
		"name": roleName,
	}

	body, err := json.Marshal(roleData)
	if err != nil {
		return fmt.Errorf("failed to marshal role data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, roleURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 201 Created or 409 Conflict (already exists) are acceptable
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create role: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}

// GetUserToken gets an access token for a user using password grant.
func (c *KeycloakClient) GetUserToken(ctx context.Context, realmName, clientID, clientSecret, username, password string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, realmName)

	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// GetClientCredentialsToken gets an access token using client credentials grant.
func (c *KeycloakClient) GetClientCredentialsToken(ctx context.Context, realmName, clientID, clientSecret string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, realmName)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// GetJWKSURL returns the JWKS URL for a realm.
func (c *KeycloakClient) GetJWKSURL(realmName string) string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.baseURL, realmName)
}

// GetIssuerURL returns the issuer URL for a realm.
func (c *KeycloakClient) GetIssuerURL(realmName string) string {
	return fmt.Sprintf("%s/realms/%s", c.baseURL, realmName)
}

// DeleteRealm deletes a realm.
func (c *KeycloakClient) DeleteRealm(ctx context.Context, realmName string) error {
	realmURL := fmt.Sprintf("%s/admin/realms/%s", c.baseURL, realmName)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, realmURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 204 No Content or 404 Not Found are acceptable
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete realm: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}

// TokenResponse represents an OAuth token response.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

// KeycloakTestSetup contains Keycloak test setup information.
type KeycloakTestSetup struct {
	Client       *KeycloakClient
	Config       KeycloakTestConfig
	Realm        string
	ClientID     string
	ClientSecret string
	TestUsers    map[string]TestUser
	cleanupFn    func()
}

// TestUser represents a test user.
type TestUser struct {
	Username string
	Password string
	Roles    []string
	Groups   []string
}

// SetupKeycloakForTesting sets up Keycloak for integration testing.
func SetupKeycloakForTesting(t *testing.T) *KeycloakTestSetup {
	SkipIfKeycloakUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := GetKeycloakTestConfig()
	client := NewKeycloakClient(cfg.Address)

	// Login as admin
	if err := client.AdminLogin(ctx, cfg.AdminUser, cfg.AdminPass); err != nil {
		t.Fatalf("Failed to login as admin: %v", err)
	}

	// Create test realm
	if err := client.CreateRealm(ctx, cfg.Realm); err != nil {
		t.Logf("Warning: Failed to create realm (may already exist): %v", err)
	}

	// Create test client
	clientConfig := map[string]interface{}{
		"clientId":                  cfg.ClientID,
		"enabled":                   true,
		"publicClient":              false,
		"secret":                    cfg.ClientSecret,
		"directAccessGrantsEnabled": true,
		"standardFlowEnabled":       true,
		"serviceAccountsEnabled":    true,
	}
	if err := client.CreateClient(ctx, cfg.Realm, clientConfig); err != nil {
		t.Logf("Warning: Failed to create client (may already exist): %v", err)
	}

	// Create realm roles
	roles := []string{"user", "admin", "reader", "writer"}
	for _, role := range roles {
		if err := client.CreateRealmRole(ctx, cfg.Realm, role); err != nil {
			t.Logf("Warning: Failed to create role %s (may already exist): %v", role, err)
		}
	}

	// Create test users
	testUsers := map[string]TestUser{
		"testuser": {
			Username: "testuser",
			Password: "testpass",
			Roles:    []string{"user"},
		},
		"adminuser": {
			Username: "adminuser",
			Password: "adminpass",
			Roles:    []string{"admin", "user"},
		},
		"reader": {
			Username: "reader",
			Password: "readerpass",
			Roles:    []string{"reader"},
		},
	}

	for _, user := range testUsers {
		userConfig := map[string]interface{}{
			"username":        user.Username,
			"enabled":         true,
			"emailVerified":   true,
			"email":           user.Username + "@test.local",
			"firstName":       user.Username,
			"lastName":        "TestUser",
			"requiredActions": []string{},
			"credentials":     []map[string]interface{}{{"type": "password", "value": user.Password, "temporary": false}},
		}
		if err := client.CreateUser(ctx, cfg.Realm, userConfig); err != nil {
			t.Logf("Warning: Failed to create user %s (may already exist): %v", user.Username, err)
		}
	}

	setup := &KeycloakTestSetup{
		Client:       client,
		Config:       cfg,
		Realm:        cfg.Realm,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TestUsers:    testUsers,
	}

	return setup
}

// Cleanup cleans up Keycloak test resources.
func (s *KeycloakTestSetup) Cleanup() {
	if s.cleanupFn != nil {
		s.cleanupFn()
	}
}

// GetUserToken gets a token for a test user.
func (s *KeycloakTestSetup) GetUserToken(ctx context.Context, username string) (*TokenResponse, error) {
	user, ok := s.TestUsers[username]
	if !ok {
		return nil, fmt.Errorf("unknown test user: %s", username)
	}
	return s.Client.GetUserToken(ctx, s.Realm, s.ClientID, s.ClientSecret, user.Username, user.Password)
}

// GetJWKSURL returns the JWKS URL for the test realm.
func (s *KeycloakTestSetup) GetJWKSURL() string {
	return s.Client.GetJWKSURL(s.Realm)
}

// GetIssuerURL returns the issuer URL for the test realm.
func (s *KeycloakTestSetup) GetIssuerURL() string {
	return s.Client.GetIssuerURL(s.Realm)
}

/*
Keycloak Setup Instructions for Testing:

1. Start Keycloak:
   docker run -d --name keycloak-test \
     -p 8090:8080 \
     -e KEYCLOAK_ADMIN=admin \
     -e KEYCLOAK_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:26.5 start-dev

2. Wait for Keycloak to be ready (may take 30-60 seconds):
   curl -s http://localhost:8090/health/ready

3. The test setup will automatically:
   - Create a test realm (gateway-test)
   - Create a test client (gateway)
   - Create test users (testuser, adminuser, reader)
   - Create realm roles (user, admin, reader, writer)

4. Run tests:
   KEYCLOAK_ADDR=http://127.0.0.1:8090 go test -tags=integration ./test/integration/...

Manual Setup (if needed):

# Get admin token
ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8090/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

# Create test realm
curl -X POST "http://localhost:8090/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"realm": "gateway-test", "enabled": true}'

# Create client
curl -X POST "http://localhost:8090/admin/realms/gateway-test/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "gateway",
    "enabled": true,
    "publicClient": false,
    "secret": "gateway-secret",
    "directAccessGrantsEnabled": true,
    "standardFlowEnabled": true,
    "serviceAccountsEnabled": true
  }'

# Create test user
curl -X POST "http://localhost:8090/admin/realms/gateway-test/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "enabled": true,
    "credentials": [{"type": "password", "value": "testpass", "temporary": false}]
  }'
*/
