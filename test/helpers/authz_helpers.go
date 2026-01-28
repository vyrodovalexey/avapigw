// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/authz"
	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
)

// TestAuthzConfig creates a test authorization configuration.
func TestAuthzConfig() *authz.Config {
	return &authz.Config{
		Enabled:       true,
		DefaultPolicy: authz.PolicyDeny,
		Cache: &authz.CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 10000,
			Type:    "memory",
		},
	}
}

// TestAuthzConfigWithRBAC creates a test authorization configuration with RBAC.
func TestAuthzConfigWithRBAC(policies []rbac.Policy) *authz.Config {
	cfg := TestAuthzConfig()
	cfg.RBAC = &rbac.Config{
		Enabled:  true,
		Policies: policies,
		ClaimMapping: &rbac.ClaimMapping{
			Roles:       "roles",
			Permissions: "permissions",
			Groups:      "groups",
		},
	}
	return cfg
}

// TestAuthzConfigWithABAC creates a test authorization configuration with ABAC.
func TestAuthzConfigWithABAC(policies []abac.Policy) *authz.Config {
	cfg := TestAuthzConfig()
	cfg.ABAC = &abac.Config{
		Enabled:  true,
		Engine:   "cel",
		Policies: policies,
	}
	return cfg
}

// TestRBACConfig creates a test RBAC configuration.
func TestRBACConfig() *rbac.Config {
	return &rbac.Config{
		Enabled: true,
		ClaimMapping: &rbac.ClaimMapping{
			Roles:       "roles",
			Permissions: "permissions",
			Groups:      "groups",
		},
		Policies: []rbac.Policy{
			{
				Name:      "admin-all",
				Roles:     []string{"admin"},
				Resources: []string{"*"},
				Actions:   []string{"*"},
				Effect:    rbac.EffectAllow,
				Priority:  100,
			},
			{
				Name:      "user-read",
				Roles:     []string{"user"},
				Resources: []string{"/api/*"},
				Actions:   []string{"GET"},
				Effect:    rbac.EffectAllow,
				Priority:  50,
			},
		},
	}
}

// TestABACConfig creates a test ABAC configuration.
func TestABACConfig() *abac.Config {
	return &abac.Config{
		Enabled: true,
		Engine:  "cel",
		Policies: []abac.Policy{
			{
				Name:       "admin-access",
				Expression: `"admin" in subject.roles`,
				Effect:     abac.EffectAllow,
				Priority:   100,
			},
			{
				Name:       "user-read-own",
				Expression: `subject.id == request.user_id && action == "GET"`,
				Effect:     abac.EffectAllow,
				Priority:   50,
			},
		},
	}
}

// TestExternalConfig creates a test external authorization configuration.
func TestExternalConfig(opaURL string) *external.Config {
	return &external.Config{
		Enabled:  true,
		Timeout:  10 * time.Second,
		FailOpen: false,
		OPA: &external.OPAConfig{
			URL:    opaURL,
			Policy: "authz/allow",
		},
	}
}

// CreateTestRBACPolicy creates a test RBAC policy.
func CreateTestRBACPolicy(name string, roles, resources, actions []string, effect rbac.PolicyEffect) rbac.Policy {
	return rbac.Policy{
		Name:      name,
		Roles:     roles,
		Resources: resources,
		Actions:   actions,
		Effect:    effect,
	}
}

// CreateTestRBACPolicyWithPriority creates a test RBAC policy with priority.
func CreateTestRBACPolicyWithPriority(name string, roles, resources, actions []string, effect rbac.PolicyEffect, priority int) rbac.Policy {
	policy := CreateTestRBACPolicy(name, roles, resources, actions, effect)
	policy.Priority = priority
	return policy
}

// CreateTestRBACPolicyWithConditions creates a test RBAC policy with conditions.
func CreateTestRBACPolicyWithConditions(name string, roles, resources, actions []string, effect rbac.PolicyEffect, conditions []rbac.Condition) rbac.Policy {
	policy := CreateTestRBACPolicy(name, roles, resources, actions, effect)
	policy.Conditions = conditions
	return policy
}

// CreateTestABACPolicy creates a test ABAC policy.
func CreateTestABACPolicy(name, expression string, effect abac.PolicyEffect) abac.Policy {
	return abac.Policy{
		Name:       name,
		Expression: expression,
		Effect:     effect,
	}
}

// CreateTestABACPolicyWithScope creates a test ABAC policy with resource/action scope.
func CreateTestABACPolicyWithScope(name, expression string, effect abac.PolicyEffect, resources, actions []string) abac.Policy {
	return abac.Policy{
		Name:       name,
		Expression: expression,
		Effect:     effect,
		Resources:  resources,
		Actions:    actions,
	}
}

// CreateTestAuthzRequest creates a test authorization request.
func CreateTestAuthzRequest(identity *auth.Identity, resource, action string) *authz.Request {
	return &authz.Request{
		Identity: identity,
		Resource: resource,
		Action:   action,
		Context:  make(map[string]interface{}),
	}
}

// CreateTestAuthzRequestWithContext creates a test authorization request with context.
func CreateTestAuthzRequestWithContext(identity *auth.Identity, resource, action string, ctx map[string]interface{}) *authz.Request {
	return &authz.Request{
		Identity: identity,
		Resource: resource,
		Action:   action,
		Context:  ctx,
	}
}

// CreateTestRBACRequest creates a test RBAC request.
func CreateTestRBACRequest(subject string, roles []string, resource, action string) *rbac.Request {
	return &rbac.Request{
		Subject:  subject,
		Roles:    roles,
		Resource: resource,
		Action:   action,
		Context:  make(map[string]interface{}),
	}
}

// CreateTestABACRequest creates a test ABAC request.
func CreateTestABACRequest(subject map[string]interface{}, resource, action string) *abac.Request {
	return &abac.Request{
		Subject:      subject,
		Resource:     resource,
		Action:       action,
		RequestAttrs: make(map[string]interface{}),
		Environment:  make(map[string]interface{}),
	}
}

// StandardRBACPolicies returns a set of standard RBAC policies for testing.
func StandardRBACPolicies() []rbac.Policy {
	return []rbac.Policy{
		{
			Name:      "admin-full-access",
			Roles:     []string{"admin"},
			Resources: []string{"*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectAllow,
			Priority:  100,
		},
		{
			Name:      "user-api-read",
			Roles:     []string{"user"},
			Resources: []string{"/api/*"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
			Priority:  50,
		},
		{
			Name:      "user-api-write",
			Roles:     []string{"user"},
			Resources: []string{"/api/users/*"},
			Actions:   []string{"POST", "PUT", "PATCH"},
			Effect:    rbac.EffectAllow,
			Priority:  50,
		},
		{
			Name:      "reader-read-only",
			Roles:     []string{"reader"},
			Resources: []string{"/api/*"},
			Actions:   []string{"GET"},
			Effect:    rbac.EffectAllow,
			Priority:  40,
		},
		{
			Name:      "writer-write-access",
			Roles:     []string{"writer"},
			Resources: []string{"/api/*"},
			Actions:   []string{"POST", "PUT", "PATCH", "DELETE"},
			Effect:    rbac.EffectAllow,
			Priority:  40,
		},
		{
			Name:      "deny-admin-endpoints",
			Roles:     []string{"user", "reader", "writer"},
			Resources: []string{"/admin/*"},
			Actions:   []string{"*"},
			Effect:    rbac.EffectDeny,
			Priority:  200,
		},
	}
}

// StandardABACPolicies returns a set of standard ABAC policies for testing.
func StandardABACPolicies() []abac.Policy {
	return []abac.Policy{
		{
			Name:       "admin-full-access",
			Expression: `"admin" in subject.roles`,
			Effect:     abac.EffectAllow,
			Priority:   100,
		},
		{
			Name:       "user-own-resources",
			Expression: `subject.id == request.owner_id`,
			Effect:     abac.EffectAllow,
			Priority:   80,
		},
		{
			Name:       "tenant-isolation",
			Expression: `subject.tenant_id == request.tenant_id`,
			Effect:     abac.EffectAllow,
			Priority:   90,
		},
		{
			Name:       "time-based-access",
			Expression: `now.getHours() >= 9 && now.getHours() < 17`,
			Effect:     abac.EffectAllow,
			Priority:   50,
			Resources:  []string{"/api/business/*"},
		},
		{
			Name:       "ip-based-access",
			Expression: `ip_in_range(request.client_ip, "10.0.0.0/8")`,
			Effect:     abac.EffectAllow,
			Priority:   60,
			Resources:  []string{"/api/internal/*"},
		},
	}
}

// RoleHierarchy returns a standard role hierarchy for testing.
func RoleHierarchy() map[string][]string {
	return map[string][]string{
		"admin":      {"user", "reader", "writer"},
		"user":       {"reader"},
		"supervisor": {"user"},
	}
}

// AuthzTestSetup contains authorization test setup information.
type AuthzTestSetup struct {
	RBACPolicies  []rbac.Policy
	ABACPolicies  []abac.Policy
	RoleHierarchy map[string][]string
	TestUsers     map[string]*auth.Identity
}

// SetupAuthzForTesting sets up authorization resources for testing.
func SetupAuthzForTesting(t *testing.T) *AuthzTestSetup {
	testUsers := map[string]*auth.Identity{
		"admin": {
			Subject:  "admin-user",
			AuthType: auth.AuthTypeJWT,
			Roles:    []string{"admin"},
			Groups:   []string{"administrators"},
			TenantID: "tenant-1",
		},
		"user": {
			Subject:  "regular-user",
			AuthType: auth.AuthTypeJWT,
			Roles:    []string{"user"},
			Groups:   []string{"users"},
			TenantID: "tenant-1",
		},
		"reader": {
			Subject:  "reader-user",
			AuthType: auth.AuthTypeJWT,
			Roles:    []string{"reader"},
			Groups:   []string{"readers"},
			TenantID: "tenant-1",
		},
		"writer": {
			Subject:  "writer-user",
			AuthType: auth.AuthTypeJWT,
			Roles:    []string{"writer"},
			Groups:   []string{"writers"},
			TenantID: "tenant-1",
		},
		"multi-role": {
			Subject:  "multi-role-user",
			AuthType: auth.AuthTypeJWT,
			Roles:    []string{"user", "writer"},
			Groups:   []string{"users", "writers"},
			TenantID: "tenant-1",
		},
		"other-tenant": {
			Subject:  "other-tenant-user",
			AuthType: auth.AuthTypeJWT,
			Roles:    []string{"user"},
			Groups:   []string{"users"},
			TenantID: "tenant-2",
		},
	}

	return &AuthzTestSetup{
		RBACPolicies:  StandardRBACPolicies(),
		ABACPolicies:  StandardABACPolicies(),
		RoleHierarchy: RoleHierarchy(),
		TestUsers:     testUsers,
	}
}

// GetTestUser returns a test user identity by name.
func (s *AuthzTestSetup) GetTestUser(name string) *auth.Identity {
	return s.TestUsers[name]
}

// CELExpressions contains common CEL expressions for testing.
var CELExpressions = struct {
	AdminAccess      string
	UserOwnResources string
	TenantIsolation  string
	RoleCheck        string
	ScopeCheck       string
	TimeBasedAccess  string
	IPBasedAccess    string
	AttributeCheck   string
	ComplexCondition string
}{
	AdminAccess:      `"admin" in subject.roles`,
	UserOwnResources: `subject.id == request.owner_id`,
	TenantIsolation:  `subject.tenant_id == request.tenant_id`,
	RoleCheck:        `"user" in subject.roles || "admin" in subject.roles`,
	ScopeCheck:       `"read" in subject.scopes`,
	TimeBasedAccess:  `now.getHours() >= 9 && now.getHours() < 17`,
	IPBasedAccess:    `ip_in_range(request.client_ip, "10.0.0.0/8")`,
	AttributeCheck:   `subject.email.endsWith("@company.com")`,
	ComplexCondition: `("admin" in subject.roles) || (subject.tenant_id == request.tenant_id && "user" in subject.roles)`,
}
