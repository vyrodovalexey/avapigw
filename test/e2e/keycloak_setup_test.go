//go:build e2e
// +build e2e

/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// ============================================================================
// Keycloak Data Structures
// ============================================================================

// ClientRepresentation represents a Keycloak OAuth2 client
type ClientRepresentation struct {
	ID                        string   `json:"id,omitempty"`
	ClientID                  string   `json:"clientId"`
	Name                      string   `json:"name,omitempty"`
	Description               string   `json:"description,omitempty"`
	Enabled                   bool     `json:"enabled"`
	ClientAuthenticatorType   string   `json:"clientAuthenticatorType,omitempty"`
	Secret                    string   `json:"secret,omitempty"`
	ServiceAccountsEnabled    bool     `json:"serviceAccountsEnabled"`
	StandardFlowEnabled       bool     `json:"standardFlowEnabled"`
	DirectAccessGrantsEnabled bool     `json:"directAccessGrantsEnabled"`
	PublicClient              bool     `json:"publicClient"`
	Protocol                  string   `json:"protocol,omitempty"`
	RedirectUris              []string `json:"redirectUris,omitempty"`
	WebOrigins                []string `json:"webOrigins,omitempty"`
}

// UserRepresentation represents a Keycloak user
type UserRepresentation struct {
	ID            string              `json:"id,omitempty"`
	Username      string              `json:"username"`
	Email         string              `json:"email,omitempty"`
	FirstName     string              `json:"firstName,omitempty"`
	LastName      string              `json:"lastName,omitempty"`
	Enabled       bool                `json:"enabled"`
	EmailVerified bool                `json:"emailVerified"`
	Attributes    map[string][]string `json:"attributes,omitempty"`
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

// RealmRepresentation represents a Keycloak realm
type RealmRepresentation struct {
	ID          string `json:"id,omitempty"`
	Realm       string `json:"realm"`
	DisplayName string `json:"displayName,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// RoleRepresentation represents a Keycloak role
type RoleRepresentation struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Composite   bool   `json:"composite,omitempty"`
}

// CredentialRepresentation represents user credentials
type CredentialRepresentation struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

// JWKSResponse represents a JWKS response
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg,omitempty"`
	Use string   `json:"use,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	X5c []string `json:"x5c,omitempty"`
	X5t string   `json:"x5t,omitempty"`
}

// ============================================================================
// Keycloak Admin Client
// ============================================================================

// KeycloakAdminClient provides methods to interact with Keycloak Admin REST API
type KeycloakAdminClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client

	// Token caching
	mu          sync.RWMutex
	accessToken string
	tokenExpiry time.Time
}

// NewKeycloakAdminClient creates a new Keycloak admin client
func NewKeycloakAdminClient(baseURL, username, password string) *KeycloakAdminClient {
	return &KeycloakAdminClient{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetAdminToken obtains an admin access token from Keycloak
func (c *KeycloakAdminClient) GetAdminToken() (string, error) {
	// Check if we have a valid cached token
	c.mu.RLock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		token := c.accessToken
		c.mu.RUnlock()
		return token, nil
	}
	c.mu.RUnlock()

	// Get a new token
	tokenURL := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", c.baseURL)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", "admin-cli")
	data.Set("username", c.username)
	data.Set("password", c.password)

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get admin token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get admin token: status %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	// Cache the token with a buffer before expiry
	c.mu.Lock()
	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-30) * time.Second)
	c.mu.Unlock()

	return tokenResp.AccessToken, nil
}

// doRequest performs an authenticated HTTP request to Keycloak Admin API
func (c *KeycloakAdminClient) doRequest(method, path string, body interface{}) (*http.Response, error) {
	token, err := c.GetAdminToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	fullURL := fmt.Sprintf("%s%s", c.baseURL, path)

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, fullURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.httpClient.Do(req)
}

// CreateRealm creates a new realm in Keycloak
func (c *KeycloakAdminClient) CreateRealm(realmName string) error {
	realm := RealmRepresentation{
		Realm:       realmName,
		DisplayName: realmName,
		Enabled:     true,
	}

	resp, err := c.doRequest(http.MethodPost, "/admin/realms", realm)
	if err != nil {
		return fmt.Errorf("failed to create realm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		// Realm already exists
		return nil
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create realm: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteRealm deletes a realm from Keycloak
func (c *KeycloakAdminClient) DeleteRealm(realmName string) error {
	path := fmt.Sprintf("/admin/realms/%s", realmName)

	resp, err := c.doRequest(http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete realm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Realm doesn't exist
		return nil
	}

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete realm: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RealmExists checks if a realm exists in Keycloak
func (c *KeycloakAdminClient) RealmExists(realmName string) (bool, error) {
	path := fmt.Sprintf("/admin/realms/%s", realmName)

	resp, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return false, fmt.Errorf("failed to check realm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("failed to check realm: status %d, body: %s", resp.StatusCode, string(body))
	}

	return true, nil
}

// CreateClient creates an OAuth2 client in a realm
func (c *KeycloakAdminClient) CreateClient(realmName string, client ClientRepresentation) error {
	path := fmt.Sprintf("/admin/realms/%s/clients", realmName)

	resp, err := c.doRequest(http.MethodPost, path, client)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		// Client already exists
		return nil
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create client: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetClientByClientID retrieves a client by its clientId
func (c *KeycloakAdminClient) GetClientByClientID(realmName, clientID string) (*ClientRepresentation, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients?clientId=%s", realmName, url.QueryEscape(clientID))

	resp, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get client: status %d, body: %s", resp.StatusCode, string(body))
	}

	var clients []ClientRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, fmt.Errorf("failed to decode clients response: %w", err)
	}

	if len(clients) == 0 {
		return nil, nil
	}

	return &clients[0], nil
}

// GetClientSecret retrieves the client secret for a client
func (c *KeycloakAdminClient) GetClientSecret(realmName, clientID string) (string, error) {
	// First, get the client's internal ID
	client, err := c.GetClientByClientID(realmName, clientID)
	if err != nil {
		return "", fmt.Errorf("failed to get client: %w", err)
	}
	if client == nil {
		return "", fmt.Errorf("client %s not found", clientID)
	}

	path := fmt.Sprintf("/admin/realms/%s/clients/%s/client-secret", realmName, client.ID)

	resp, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get client secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get client secret: status %d, body: %s", resp.StatusCode, string(body))
	}

	var secretResp struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return "", fmt.Errorf("failed to decode client secret response: %w", err)
	}

	return secretResp.Value, nil
}

// CreateUser creates a user in a realm
func (c *KeycloakAdminClient) CreateUser(realmName string, user UserRepresentation) (string, error) {
	path := fmt.Sprintf("/admin/realms/%s/users", realmName)

	resp, err := c.doRequest(http.MethodPost, path, user)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		// User already exists, get the existing user ID
		existingUser, err := c.GetUserByUsername(realmName, user.Username)
		if err != nil {
			return "", fmt.Errorf("user exists but failed to get user ID: %w", err)
		}
		if existingUser != nil {
			return existingUser.ID, nil
		}
		return "", fmt.Errorf("user exists but could not retrieve ID")
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create user: status %d, body: %s", resp.StatusCode, string(body))
	}

	// Extract user ID from Location header
	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("no Location header in response")
	}

	// Location format: .../users/{id}
	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid Location header format")
	}

	return parts[len(parts)-1], nil
}

// GetUserByUsername retrieves a user by username
func (c *KeycloakAdminClient) GetUserByUsername(realmName, username string) (*UserRepresentation, error) {
	path := fmt.Sprintf("/admin/realms/%s/users?username=%s&exact=true", realmName, url.QueryEscape(username))

	resp, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user: status %d, body: %s", resp.StatusCode, string(body))
	}

	var users []UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode users response: %w", err)
	}

	if len(users) == 0 {
		return nil, nil
	}

	return &users[0], nil
}

// SetUserPassword sets the password for a user
func (c *KeycloakAdminClient) SetUserPassword(realmName, userID, password string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/reset-password", realmName, userID)

	credential := CredentialRepresentation{
		Type:      "password",
		Value:     password,
		Temporary: false,
	}

	resp, err := c.doRequest(http.MethodPut, path, credential)
	if err != nil {
		return fmt.Errorf("failed to set user password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to set user password: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// CreateRole creates a realm role
func (c *KeycloakAdminClient) CreateRole(realmName, roleName string) error {
	path := fmt.Sprintf("/admin/realms/%s/roles", realmName)

	role := RoleRepresentation{
		Name:        roleName,
		Description: fmt.Sprintf("Test role: %s", roleName),
	}

	resp, err := c.doRequest(http.MethodPost, path, role)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		// Role already exists
		return nil
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create role: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetRole retrieves a realm role by name
func (c *KeycloakAdminClient) GetRole(realmName, roleName string) (*RoleRepresentation, error) {
	path := fmt.Sprintf("/admin/realms/%s/roles/%s", realmName, url.PathEscape(roleName))

	resp, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get role: status %d, body: %s", resp.StatusCode, string(body))
	}

	var role RoleRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&role); err != nil {
		return nil, fmt.Errorf("failed to decode role response: %w", err)
	}

	return &role, nil
}

// AssignRoleToUser assigns a realm role to a user
func (c *KeycloakAdminClient) AssignRoleToUser(realmName, userID, roleName string) error {
	// First, get the role
	role, err := c.GetRole(realmName, roleName)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}
	if role == nil {
		return fmt.Errorf("role %s not found", roleName)
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/realm", realmName, userID)

	roles := []RoleRepresentation{*role}

	resp, err := c.doRequest(http.MethodPost, path, roles)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to assign role: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetToken obtains an access token using client credentials flow
func (c *KeycloakAdminClient) GetToken(realmName, clientID, clientSecret string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, realmName)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get token: status %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// GetTokenWithPassword obtains an access token using resource owner password credentials flow
func (c *KeycloakAdminClient) GetTokenWithPassword(realmName, clientID, username, password string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, realmName)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	data.Set("username", username)
	data.Set("password", password)

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get token: status %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// GetJWKS retrieves the JWKS from Keycloak
func (c *KeycloakAdminClient) GetJWKS(realmName string) (*JWKSResponse, error) {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.baseURL, realmName)

	resp, err := c.httpClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get JWKS: status %d, body: %s", resp.StatusCode, string(body))
	}

	var jwks JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS response: %w", err)
	}

	return &jwks, nil
}

// ============================================================================
// Global Variables for Keycloak Tests
// ============================================================================

var (
	keycloakClient   *KeycloakAdminClient
	testClientSecret string
)

// ============================================================================
// Keycloak Setup Test Suite
// ============================================================================

var _ = Describe("Keycloak Setup", Ordered, func() {
	BeforeAll(func() {
		if testConfig.ShouldSkipKeycloakTests() {
			Skip("Keycloak tests are skipped (SKIP_KEYCLOAK_TESTS=true)")
		}

		// Initialize Keycloak admin client
		keycloakClient = NewKeycloakAdminClient(
			testConfig.KeycloakURL,
			testConfig.KeycloakAdmin,
			testConfig.KeycloakPassword,
		)

		GinkgoWriter.Printf("Keycloak client initialized for %s\n", testConfig.KeycloakURL)
	})

	Context("Keycloak Connectivity", func() {
		It("should verify Keycloak is accessible", func() {
			// Try to get admin token to verify connectivity
			token, err := keycloakClient.GetAdminToken()
			Expect(err).NotTo(HaveOccurred(), "Should be able to get admin token")
			Expect(token).NotTo(BeEmpty(), "Admin token should not be empty")

			GinkgoWriter.Printf("Successfully obtained admin token from Keycloak\n")
		})
	})

	Context("Create Test Realm", func() {
		It("should check if realm already exists", func() {
			exists, err := keycloakClient.RealmExists(testConfig.KeycloakRealm)
			Expect(err).NotTo(HaveOccurred(), "Should be able to check realm existence")

			if exists {
				GinkgoWriter.Printf("Realm '%s' already exists\n", testConfig.KeycloakRealm)
			} else {
				GinkgoWriter.Printf("Realm '%s' does not exist, will create\n", testConfig.KeycloakRealm)
			}
		})

		It("should create realm if not exists", func() {
			err := keycloakClient.CreateRealm(testConfig.KeycloakRealm)
			Expect(err).NotTo(HaveOccurred(), "Should be able to create realm")

			GinkgoWriter.Printf("Realm '%s' created or already exists\n", testConfig.KeycloakRealm)
		})

		It("should verify realm is accessible", func() {
			exists, err := keycloakClient.RealmExists(testConfig.KeycloakRealm)
			Expect(err).NotTo(HaveOccurred(), "Should be able to check realm existence")
			Expect(exists).To(BeTrue(), "Realm should exist")

			GinkgoWriter.Printf("Realm '%s' is accessible\n", testConfig.KeycloakRealm)
		})
	})

	Context("Create OAuth2 Client for Client Credentials Flow", func() {
		It("should create confidential client", func() {
			client := ClientRepresentation{
				ClientID:                  testConfig.KeycloakClientID,
				Name:                      "AVAPIGW Test Client",
				Description:               "OAuth2 client for AVAPIGW E2E tests",
				Enabled:                   true,
				ClientAuthenticatorType:   "client-secret",
				ServiceAccountsEnabled:    true,
				StandardFlowEnabled:       false,
				DirectAccessGrantsEnabled: false,
				PublicClient:              false,
				Protocol:                  "openid-connect",
			}

			err := keycloakClient.CreateClient(testConfig.KeycloakRealm, client)
			Expect(err).NotTo(HaveOccurred(), "Should be able to create client")

			GinkgoWriter.Printf("Created confidential client '%s'\n", testConfig.KeycloakClientID)
		})

		It("should retrieve and store client secret", func() {
			secret, err := keycloakClient.GetClientSecret(testConfig.KeycloakRealm, testConfig.KeycloakClientID)
			Expect(err).NotTo(HaveOccurred(), "Should be able to get client secret")
			Expect(secret).NotTo(BeEmpty(), "Client secret should not be empty")

			testClientSecret = secret
			GinkgoWriter.Printf("Retrieved client secret for '%s'\n", testConfig.KeycloakClientID)
		})
	})

	Context("Create OAuth2 Client for Authorization Code Flow", func() {
		It("should create public client", func() {
			client := ClientRepresentation{
				ClientID:                  "avapigw-test-public",
				Name:                      "AVAPIGW Test Public Client",
				Description:               "Public OAuth2 client for AVAPIGW E2E tests",
				Enabled:                   true,
				StandardFlowEnabled:       true,
				DirectAccessGrantsEnabled: true,
				PublicClient:              true,
				Protocol:                  "openid-connect",
				RedirectUris:              []string{"http://localhost:8080/*", "http://localhost:3000/*"},
				WebOrigins:                []string{"http://localhost:8080", "http://localhost:3000"},
			}

			err := keycloakClient.CreateClient(testConfig.KeycloakRealm, client)
			Expect(err).NotTo(HaveOccurred(), "Should be able to create public client")

			GinkgoWriter.Printf("Created public client 'avapigw-test-public'\n")
		})
	})

	Context("Create Test Roles", func() {
		It("should create api-user role", func() {
			err := keycloakClient.CreateRole(testConfig.KeycloakRealm, "api-user")
			Expect(err).NotTo(HaveOccurred(), "Should be able to create api-user role")

			GinkgoWriter.Printf("Created role 'api-user'\n")
		})

		It("should create api-admin role", func() {
			err := keycloakClient.CreateRole(testConfig.KeycloakRealm, "api-admin")
			Expect(err).NotTo(HaveOccurred(), "Should be able to create api-admin role")

			GinkgoWriter.Printf("Created role 'api-admin'\n")
		})

		It("should verify roles exist", func() {
			apiUserRole, err := keycloakClient.GetRole(testConfig.KeycloakRealm, "api-user")
			Expect(err).NotTo(HaveOccurred())
			Expect(apiUserRole).NotTo(BeNil(), "api-user role should exist")

			apiAdminRole, err := keycloakClient.GetRole(testConfig.KeycloakRealm, "api-admin")
			Expect(err).NotTo(HaveOccurred())
			Expect(apiAdminRole).NotTo(BeNil(), "api-admin role should exist")

			GinkgoWriter.Printf("Verified roles 'api-user' and 'api-admin' exist\n")
		})
	})

	Context("Create Test Users", func() {
		var testUserID string
		var adminUserID string

		It("should create testuser", func() {
			user := UserRepresentation{
				Username:      "testuser",
				Email:         "testuser@example.com",
				FirstName:     "Test",
				LastName:      "User",
				Enabled:       true,
				EmailVerified: true,
			}

			var err error
			testUserID, err = keycloakClient.CreateUser(testConfig.KeycloakRealm, user)
			Expect(err).NotTo(HaveOccurred(), "Should be able to create testuser")
			Expect(testUserID).NotTo(BeEmpty(), "User ID should not be empty")

			GinkgoWriter.Printf("Created user 'testuser' with ID: %s\n", testUserID)
		})

		It("should set testuser password", func() {
			err := keycloakClient.SetUserPassword(testConfig.KeycloakRealm, testUserID, "testpassword")
			Expect(err).NotTo(HaveOccurred(), "Should be able to set testuser password")

			GinkgoWriter.Printf("Set password for 'testuser'\n")
		})

		It("should assign api-user role to testuser", func() {
			err := keycloakClient.AssignRoleToUser(testConfig.KeycloakRealm, testUserID, "api-user")
			Expect(err).NotTo(HaveOccurred(), "Should be able to assign api-user role")

			GinkgoWriter.Printf("Assigned 'api-user' role to 'testuser'\n")
		})

		It("should create admin-user", func() {
			user := UserRepresentation{
				Username:      "admin-user",
				Email:         "admin@example.com",
				FirstName:     "Admin",
				LastName:      "User",
				Enabled:       true,
				EmailVerified: true,
			}

			var err error
			adminUserID, err = keycloakClient.CreateUser(testConfig.KeycloakRealm, user)
			Expect(err).NotTo(HaveOccurred(), "Should be able to create admin-user")
			Expect(adminUserID).NotTo(BeEmpty(), "User ID should not be empty")

			GinkgoWriter.Printf("Created user 'admin-user' with ID: %s\n", adminUserID)
		})

		It("should set admin-user password", func() {
			err := keycloakClient.SetUserPassword(testConfig.KeycloakRealm, adminUserID, "adminpassword")
			Expect(err).NotTo(HaveOccurred(), "Should be able to set admin-user password")

			GinkgoWriter.Printf("Set password for 'admin-user'\n")
		})

		It("should assign api-admin role to admin-user", func() {
			err := keycloakClient.AssignRoleToUser(testConfig.KeycloakRealm, adminUserID, "api-admin")
			Expect(err).NotTo(HaveOccurred(), "Should be able to assign api-admin role")

			GinkgoWriter.Printf("Assigned 'api-admin' role to 'admin-user'\n")
		})
	})

	Context("Verify Token Endpoint", func() {
		It("should obtain token using client credentials flow", func() {
			Expect(testClientSecret).NotTo(BeEmpty(), "Client secret should be available")

			tokenResp, err := keycloakClient.GetToken(
				testConfig.KeycloakRealm,
				testConfig.KeycloakClientID,
				testClientSecret,
			)
			Expect(err).NotTo(HaveOccurred(), "Should be able to get token")
			Expect(tokenResp).NotTo(BeNil())
			Expect(tokenResp.AccessToken).NotTo(BeEmpty(), "Access token should not be empty")
			Expect(tokenResp.TokenType).To(Equal("Bearer"), "Token type should be Bearer")
			Expect(tokenResp.ExpiresIn).To(BeNumerically(">", 0), "Token should have positive expiry")

			GinkgoWriter.Printf("Successfully obtained token via client credentials flow\n")
			GinkgoWriter.Printf("Token type: %s, Expires in: %d seconds\n", tokenResp.TokenType, tokenResp.ExpiresIn)
		})

		It("should obtain token using password grant for testuser", func() {
			tokenResp, err := keycloakClient.GetTokenWithPassword(
				testConfig.KeycloakRealm,
				"avapigw-test-public",
				"testuser",
				"testpassword",
			)
			Expect(err).NotTo(HaveOccurred(), "Should be able to get token for testuser")
			Expect(tokenResp).NotTo(BeNil())
			Expect(tokenResp.AccessToken).NotTo(BeEmpty(), "Access token should not be empty")

			GinkgoWriter.Printf("Successfully obtained token for 'testuser' via password grant\n")
		})

		It("should obtain token using password grant for admin-user", func() {
			tokenResp, err := keycloakClient.GetTokenWithPassword(
				testConfig.KeycloakRealm,
				"avapigw-test-public",
				"admin-user",
				"adminpassword",
			)
			Expect(err).NotTo(HaveOccurred(), "Should be able to get token for admin-user")
			Expect(tokenResp).NotTo(BeNil())
			Expect(tokenResp.AccessToken).NotTo(BeEmpty(), "Access token should not be empty")

			GinkgoWriter.Printf("Successfully obtained token for 'admin-user' via password grant\n")
		})
	})

	Context("Verify JWKS Endpoint", func() {
		It("should fetch JWKS from Keycloak", func() {
			jwks, err := keycloakClient.GetJWKS(testConfig.KeycloakRealm)
			Expect(err).NotTo(HaveOccurred(), "Should be able to fetch JWKS")
			Expect(jwks).NotTo(BeNil())
			Expect(jwks.Keys).NotTo(BeEmpty(), "JWKS should contain keys")

			GinkgoWriter.Printf("Successfully fetched JWKS with %d keys\n", len(jwks.Keys))
		})

		It("should verify JWKS keys have correct format", func() {
			jwks, err := keycloakClient.GetJWKS(testConfig.KeycloakRealm)
			Expect(err).NotTo(HaveOccurred())

			for i, key := range jwks.Keys {
				Expect(key.Kid).NotTo(BeEmpty(), "Key %d should have kid", i)
				Expect(key.Kty).NotTo(BeEmpty(), "Key %d should have kty", i)

				GinkgoWriter.Printf("Key %d: kid=%s, kty=%s, alg=%s, use=%s\n",
					i, key.Kid, key.Kty, key.Alg, key.Use)

				// RSA keys should have n and e
				if key.Kty == "RSA" {
					Expect(key.N).NotTo(BeEmpty(), "RSA key %d should have n", i)
					Expect(key.E).NotTo(BeEmpty(), "RSA key %d should have e", i)
				}
			}
		})

		It("should verify JWKS endpoint URL is correct", func() {
			expectedURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs",
				testConfig.KeycloakURL, testConfig.KeycloakRealm)

			// Verify the URL matches what testConfig provides
			Expect(testConfig.GetKeycloakJWKSURL()).To(Equal(expectedURL))

			GinkgoWriter.Printf("JWKS URL: %s\n", expectedURL)
		})
	})

	AfterAll(func() {
		GinkgoWriter.Printf("Keycloak setup completed successfully\n")
		GinkgoWriter.Printf("Realm: %s\n", testConfig.KeycloakRealm)
		GinkgoWriter.Printf("Client ID: %s\n", testConfig.KeycloakClientID)
		GinkgoWriter.Printf("Token URL: %s\n", testConfig.GetKeycloakTokenURL())
		GinkgoWriter.Printf("JWKS URL: %s\n", testConfig.GetKeycloakJWKSURL())
	})
})
