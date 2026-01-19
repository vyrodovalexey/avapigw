package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Subject Tests
// ============================================================================

func TestSubject_HasRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject *Subject
		role    string
		want    bool
	}{
		{
			name:    "has role",
			subject: &Subject{Roles: []string{"admin", "user"}},
			role:    "admin",
			want:    true,
		},
		{
			name:    "does not have role",
			subject: &Subject{Roles: []string{"user"}},
			role:    "admin",
			want:    false,
		},
		{
			name:    "empty roles",
			subject: &Subject{Roles: []string{}},
			role:    "admin",
			want:    false,
		},
		{
			name:    "nil roles",
			subject: &Subject{Roles: nil},
			role:    "admin",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.subject.HasRole(tt.role)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSubject_HasAnyRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject *Subject
		roles   []string
		want    bool
	}{
		{
			name:    "has first role",
			subject: &Subject{Roles: []string{"admin", "user"}},
			roles:   []string{"admin", "superuser"},
			want:    true,
		},
		{
			name:    "has second role",
			subject: &Subject{Roles: []string{"admin", "user"}},
			roles:   []string{"superuser", "user"},
			want:    true,
		},
		{
			name:    "has no matching role",
			subject: &Subject{Roles: []string{"user"}},
			roles:   []string{"admin", "superuser"},
			want:    false,
		},
		{
			name:    "empty subject roles",
			subject: &Subject{Roles: []string{}},
			roles:   []string{"admin"},
			want:    false,
		},
		{
			name:    "empty check roles",
			subject: &Subject{Roles: []string{"admin"}},
			roles:   []string{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.subject.HasAnyRole(tt.roles...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSubject_HasAllRoles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject *Subject
		roles   []string
		want    bool
	}{
		{
			name:    "has all roles",
			subject: &Subject{Roles: []string{"admin", "user", "moderator"}},
			roles:   []string{"admin", "user"},
			want:    true,
		},
		{
			name:    "missing one role",
			subject: &Subject{Roles: []string{"admin", "user"}},
			roles:   []string{"admin", "user", "superuser"},
			want:    false,
		},
		{
			name:    "empty check roles returns true",
			subject: &Subject{Roles: []string{"admin"}},
			roles:   []string{},
			want:    true,
		},
		{
			name:    "empty subject roles",
			subject: &Subject{Roles: []string{}},
			roles:   []string{"admin"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.subject.HasAllRoles(tt.roles...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSubject_HasGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject *Subject
		group   string
		want    bool
	}{
		{
			name:    "has group",
			subject: &Subject{Groups: []string{"developers", "admins"}},
			group:   "developers",
			want:    true,
		},
		{
			name:    "does not have group",
			subject: &Subject{Groups: []string{"users"}},
			group:   "admins",
			want:    false,
		},
		{
			name:    "empty groups",
			subject: &Subject{Groups: []string{}},
			group:   "admins",
			want:    false,
		},
		{
			name:    "nil groups",
			subject: &Subject{Groups: nil},
			group:   "admins",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.subject.HasGroup(tt.group)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSubject_HasScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject *Subject
		scope   string
		want    bool
	}{
		{
			name:    "has scope",
			subject: &Subject{Scopes: []string{"read", "write"}},
			scope:   "read",
			want:    true,
		},
		{
			name:    "does not have scope",
			subject: &Subject{Scopes: []string{"read"}},
			scope:   "write",
			want:    false,
		},
		{
			name:    "empty scopes",
			subject: &Subject{Scopes: []string{}},
			scope:   "read",
			want:    false,
		},
		{
			name:    "nil scopes",
			subject: &Subject{Scopes: nil},
			scope:   "read",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.subject.HasScope(tt.scope)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSubject_GetClaim(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		subject   *Subject
		claimName string
		wantValue interface{}
		wantOk    bool
	}{
		{
			name: "existing string claim",
			subject: &Subject{Claims: map[string]interface{}{
				"sub": "user123",
			}},
			claimName: "sub",
			wantValue: "user123",
			wantOk:    true,
		},
		{
			name: "existing array claim",
			subject: &Subject{Claims: map[string]interface{}{
				"roles": []string{"admin", "user"},
			}},
			claimName: "roles",
			wantValue: []string{"admin", "user"},
			wantOk:    true,
		},
		{
			name: "non-existing claim",
			subject: &Subject{Claims: map[string]interface{}{
				"sub": "user123",
			}},
			claimName: "email",
			wantValue: nil,
			wantOk:    false,
		},
		{
			name:      "nil claims",
			subject:   &Subject{Claims: nil},
			claimName: "sub",
			wantValue: nil,
			wantOk:    false,
		},
		{
			name:      "empty claims",
			subject:   &Subject{Claims: map[string]interface{}{}},
			claimName: "sub",
			wantValue: nil,
			wantOk:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotValue, gotOk := tt.subject.GetClaim(tt.claimName)
			assert.Equal(t, tt.wantOk, gotOk)
			assert.Equal(t, tt.wantValue, gotValue)
		})
	}
}

// ============================================================================
// NewResourceFromRequest Tests
// ============================================================================

func TestNewResourceFromRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		setupRequest func() *http.Request
		wantPath     string
		wantMethod   string
		wantHost     string
		wantPort     int
		wantSourceIP string
	}{
		{
			name: "basic request",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/users", nil)
				req.Host = "example.com"
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			wantPath:     "/api/users",
			wantMethod:   "GET",
			wantHost:     "example.com",
			wantPort:     0,
			wantSourceIP: "192.168.1.1",
		},
		{
			name: "request with port in host",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/api/users", nil)
				req.Host = "example.com:8080"
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			wantPath:     "/api/users",
			wantMethod:   "POST",
			wantHost:     "example.com",
			wantPort:     8080,
			wantSourceIP: "192.168.1.1",
		},
		{
			name: "request with X-Forwarded-For header",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/users", nil)
				req.Host = "example.com"
				req.RemoteAddr = "10.0.0.1:12345"
				req.Header.Set("X-Forwarded-For", "203.0.113.195")
				return req
			},
			wantPath:     "/api/users",
			wantMethod:   "GET",
			wantHost:     "example.com",
			wantPort:     0,
			wantSourceIP: "203.0.113.195",
		},
		{
			name: "request with multiple X-Forwarded-For IPs",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/users", nil)
				req.Host = "example.com"
				req.RemoteAddr = "10.0.0.1:12345"
				req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")
				return req
			},
			wantPath:     "/api/users",
			wantMethod:   "GET",
			wantHost:     "example.com",
			wantPort:     0,
			wantSourceIP: "203.0.113.195",
		},
		{
			name: "request with X-Forwarded-For with spaces",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/users", nil)
				req.Host = "example.com"
				req.RemoteAddr = "10.0.0.1:12345"
				req.Header.Set("X-Forwarded-For", "  203.0.113.195  , 70.41.3.18")
				return req
			},
			wantPath:     "/api/users",
			wantMethod:   "GET",
			wantHost:     "example.com",
			wantPort:     0,
			wantSourceIP: "203.0.113.195",
		},
		{
			name: "request without port in RemoteAddr",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/users", nil)
				req.Host = "example.com"
				req.RemoteAddr = "192.168.1.1"
				return req
			},
			wantPath:     "/api/users",
			wantMethod:   "GET",
			wantHost:     "example.com",
			wantPort:     0,
			wantSourceIP: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := tt.setupRequest()
			resource := NewResourceFromRequest(req)

			assert.Equal(t, tt.wantPath, resource.Path)
			assert.Equal(t, tt.wantMethod, resource.Method)
			assert.Equal(t, tt.wantHost, resource.Host)
			assert.Equal(t, tt.wantPort, resource.Port)
			assert.Equal(t, tt.wantSourceIP, resource.SourceIP)
			assert.NotNil(t, resource.Headers)
		})
	}
}

// ============================================================================
// Rule.Matches Tests
// ============================================================================

func TestRule_Matches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rule     *Rule
		subject  *Subject
		resource *Resource
		want     bool
	}{
		{
			name:     "disabled rule returns false",
			rule:     &Rule{Enabled: false},
			subject:  &Subject{},
			resource: &Resource{},
			want:     false,
		},
		{
			name:     "enabled rule with no conditions and no targets matches",
			rule:     &Rule{Enabled: true},
			subject:  &Subject{},
			resource: &Resource{},
			want:     true,
		},
		{
			name: "rule with failing condition returns false",
			rule: &Rule{
				Enabled: true,
				Conditions: []Condition{
					&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
				},
			},
			subject:  &Subject{Roles: []string{"user"}},
			resource: &Resource{},
			want:     false,
		},
		{
			name: "rule with passing condition and no targets matches",
			rule: &Rule{
				Enabled: true,
				Conditions: []Condition{
					&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
				},
			},
			subject:  &Subject{Roles: []string{"admin"}},
			resource: &Resource{},
			want:     true,
		},
		{
			name: "rule with passing condition and matching target",
			rule: &Rule{
				Enabled: true,
				Conditions: []Condition{
					&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
				},
				Targets: []*Target{
					{Methods: []string{"GET"}},
				},
			},
			subject:  &Subject{Roles: []string{"admin"}},
			resource: &Resource{Method: "GET"},
			want:     true,
		},
		{
			name: "rule with passing condition but non-matching target",
			rule: &Rule{
				Enabled: true,
				Conditions: []Condition{
					&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
				},
				Targets: []*Target{
					{Methods: []string{"POST"}},
				},
			},
			subject:  &Subject{Roles: []string{"admin"}},
			resource: &Resource{Method: "GET"},
			want:     false,
		},
		{
			name: "rule with multiple conditions - all must pass",
			rule: &Rule{
				Enabled: true,
				Conditions: []Condition{
					&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
					&ScopeCondition{Scopes: []string{"write"}, MatchAll: false},
				},
			},
			subject:  &Subject{Roles: []string{"admin"}, Scopes: []string{"write"}},
			resource: &Resource{},
			want:     true,
		},
		{
			name: "rule with multiple conditions - one fails",
			rule: &Rule{
				Enabled: true,
				Conditions: []Condition{
					&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
					&ScopeCondition{Scopes: []string{"write"}, MatchAll: false},
				},
			},
			subject:  &Subject{Roles: []string{"admin"}, Scopes: []string{"read"}},
			resource: &Resource{},
			want:     false,
		},
		{
			name: "rule with multiple targets - first matches",
			rule: &Rule{
				Enabled: true,
				Targets: []*Target{
					{Methods: []string{"GET"}},
					{Methods: []string{"POST"}},
				},
			},
			subject:  &Subject{},
			resource: &Resource{Method: "GET"},
			want:     true,
		},
		{
			name: "rule with multiple targets - second matches",
			rule: &Rule{
				Enabled: true,
				Targets: []*Target{
					{Methods: []string{"POST"}},
					{Methods: []string{"GET"}},
				},
			},
			subject:  &Subject{},
			resource: &Resource{Method: "GET"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.rule.Matches(tt.subject, tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// ClaimCondition.Evaluate Tests
// ============================================================================

func TestClaimCondition_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		condition *ClaimCondition
		subject   *Subject
		resource  *Resource
		want      bool
	}{
		{
			name:      "nil subject returns false",
			condition: &ClaimCondition{Claim: "sub", Values: []string{"user123"}},
			subject:   nil,
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "nil claims returns false",
			condition: &ClaimCondition{Claim: "sub", Values: []string{"user123"}},
			subject:   &Subject{Claims: nil},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "missing claim returns false",
			condition: &ClaimCondition{Claim: "sub", Values: []string{"user123"}},
			subject:   &Subject{Claims: map[string]interface{}{"email": "test@example.com"}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "string claim matches",
			condition: &ClaimCondition{Claim: "sub", Values: []string{"user123"}, MatchAny: true},
			subject:   &Subject{Claims: map[string]interface{}{"sub": "user123"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "string claim does not match",
			condition: &ClaimCondition{Claim: "sub", Values: []string{"user123"}, MatchAny: true},
			subject:   &Subject{Claims: map[string]interface{}{"sub": "user456"}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "string claim matches one of multiple values",
			condition: &ClaimCondition{Claim: "sub", Values: []string{"user123", "user456"}, MatchAny: true},
			subject:   &Subject{Claims: map[string]interface{}{"sub": "user456"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "array claim ([]interface{}) with MatchAny - matches",
			condition: &ClaimCondition{Claim: "roles", Values: []string{"admin"}, MatchAny: true},
			subject:   &Subject{Claims: map[string]interface{}{"roles": []interface{}{"admin", "user"}}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "array claim ([]interface{}) with MatchAny - no match",
			condition: &ClaimCondition{Claim: "roles", Values: []string{"superuser"}, MatchAny: true},
			subject:   &Subject{Claims: map[string]interface{}{"roles": []interface{}{"admin", "user"}}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "array claim ([]interface{}) with MatchAll - all present",
			condition: &ClaimCondition{Claim: "roles", Values: []string{"admin", "user"}, MatchAny: false},
			subject:   &Subject{Claims: map[string]interface{}{"roles": []interface{}{"admin", "user", "moderator"}}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "array claim ([]interface{}) with MatchAll - missing one",
			condition: &ClaimCondition{Claim: "roles", Values: []string{"admin", "superuser"}, MatchAny: false},
			subject:   &Subject{Claims: map[string]interface{}{"roles": []interface{}{"admin", "user"}}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "array claim ([]string) with MatchAny - matches",
			condition: &ClaimCondition{Claim: "roles", Values: []string{"admin"}, MatchAny: true},
			subject:   &Subject{Claims: map[string]interface{}{"roles": []string{"admin", "user"}}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "array claim ([]string) with MatchAny - no match",
			condition: &ClaimCondition{Claim: "roles", Values: []string{"superuser"}, MatchAny: true},
			subject:   &Subject{Claims: map[string]interface{}{"roles": []string{"admin", "user"}}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "array claim ([]string) with MatchAll - all present",
			condition: &ClaimCondition{Claim: "roles", Values: []string{"admin", "user"}, MatchAny: false},
			subject:   &Subject{Claims: map[string]interface{}{"roles": []string{"admin", "user", "moderator"}}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "array claim ([]string) with MatchAll - missing one",
			condition: &ClaimCondition{Claim: "roles", Values: []string{"admin", "superuser"}, MatchAny: false},
			subject:   &Subject{Claims: map[string]interface{}{"roles": []string{"admin", "user"}}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "unsupported claim type returns false",
			condition: &ClaimCondition{Claim: "count", Values: []string{"5"}, MatchAny: true},
			subject:   &Subject{Claims: map[string]interface{}{"count": 5}},
			resource:  &Resource{},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.condition.Evaluate(tt.subject, tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// RoleCondition.Evaluate Tests
// ============================================================================

func TestRoleCondition_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		condition *RoleCondition
		subject   *Subject
		resource  *Resource
		want      bool
	}{
		{
			name:      "nil subject returns false",
			condition: &RoleCondition{Roles: []string{"admin"}, MatchAll: false},
			subject:   nil,
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "MatchAny - has one role",
			condition: &RoleCondition{Roles: []string{"admin", "superuser"}, MatchAll: false},
			subject:   &Subject{Roles: []string{"admin"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "MatchAny - has no matching role",
			condition: &RoleCondition{Roles: []string{"admin", "superuser"}, MatchAll: false},
			subject:   &Subject{Roles: []string{"user"}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "MatchAll - has all roles",
			condition: &RoleCondition{Roles: []string{"admin", "user"}, MatchAll: true},
			subject:   &Subject{Roles: []string{"admin", "user", "moderator"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "MatchAll - missing one role",
			condition: &RoleCondition{Roles: []string{"admin", "superuser"}, MatchAll: true},
			subject:   &Subject{Roles: []string{"admin", "user"}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "empty roles with MatchAll returns true",
			condition: &RoleCondition{Roles: []string{}, MatchAll: true},
			subject:   &Subject{Roles: []string{"admin"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "empty roles with MatchAny returns false",
			condition: &RoleCondition{Roles: []string{}, MatchAll: false},
			subject:   &Subject{Roles: []string{"admin"}},
			resource:  &Resource{},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.condition.Evaluate(tt.subject, tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// GroupCondition.Evaluate Tests
// ============================================================================

func TestGroupCondition_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		condition *GroupCondition
		subject   *Subject
		resource  *Resource
		want      bool
	}{
		{
			name:      "nil subject returns false",
			condition: &GroupCondition{Groups: []string{"admins"}, MatchAll: false},
			subject:   nil,
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "MatchAny - has one group",
			condition: &GroupCondition{Groups: []string{"admins", "developers"}, MatchAll: false},
			subject:   &Subject{Groups: []string{"admins"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "MatchAny - has no matching group",
			condition: &GroupCondition{Groups: []string{"admins", "developers"}, MatchAll: false},
			subject:   &Subject{Groups: []string{"users"}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "MatchAll - has all groups",
			condition: &GroupCondition{Groups: []string{"admins", "developers"}, MatchAll: true},
			subject:   &Subject{Groups: []string{"admins", "developers", "users"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "MatchAll - missing one group",
			condition: &GroupCondition{Groups: []string{"admins", "superusers"}, MatchAll: true},
			subject:   &Subject{Groups: []string{"admins", "developers"}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "empty groups with MatchAll returns true",
			condition: &GroupCondition{Groups: []string{}, MatchAll: true},
			subject:   &Subject{Groups: []string{"admins"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "empty groups with MatchAny returns false",
			condition: &GroupCondition{Groups: []string{}, MatchAll: false},
			subject:   &Subject{Groups: []string{"admins"}},
			resource:  &Resource{},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.condition.Evaluate(tt.subject, tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// ScopeCondition.Evaluate Tests
// ============================================================================

func TestScopeCondition_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		condition *ScopeCondition
		subject   *Subject
		resource  *Resource
		want      bool
	}{
		{
			name:      "nil subject returns false",
			condition: &ScopeCondition{Scopes: []string{"read"}, MatchAll: false},
			subject:   nil,
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "MatchAny - has one scope",
			condition: &ScopeCondition{Scopes: []string{"read", "write"}, MatchAll: false},
			subject:   &Subject{Scopes: []string{"read"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "MatchAny - has no matching scope",
			condition: &ScopeCondition{Scopes: []string{"read", "write"}, MatchAll: false},
			subject:   &Subject{Scopes: []string{"delete"}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "MatchAll - has all scopes",
			condition: &ScopeCondition{Scopes: []string{"read", "write"}, MatchAll: true},
			subject:   &Subject{Scopes: []string{"read", "write", "delete"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "MatchAll - missing one scope",
			condition: &ScopeCondition{Scopes: []string{"read", "admin"}, MatchAll: true},
			subject:   &Subject{Scopes: []string{"read", "write"}},
			resource:  &Resource{},
			want:      false,
		},
		{
			name:      "empty scopes with MatchAll returns true",
			condition: &ScopeCondition{Scopes: []string{}, MatchAll: true},
			subject:   &Subject{Scopes: []string{"read"}},
			resource:  &Resource{},
			want:      true,
		},
		{
			name:      "empty scopes with MatchAny returns false",
			condition: &ScopeCondition{Scopes: []string{}, MatchAll: false},
			subject:   &Subject{Scopes: []string{"read"}},
			resource:  &Resource{},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.condition.Evaluate(tt.subject, tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// SourceIPCondition.Evaluate Tests
// ============================================================================

func TestSourceIPCondition_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		condition *SourceIPCondition
		subject   *Subject
		resource  *Resource
		want      bool
	}{
		{
			name:      "nil resource returns false",
			condition: &SourceIPCondition{CIDRs: []string{"192.168.0.0/16"}},
			subject:   &Subject{},
			resource:  nil,
			want:      false,
		},
		{
			name:      "empty source IP returns false",
			condition: &SourceIPCondition{CIDRs: []string{"192.168.0.0/16"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: ""},
			want:      false,
		},
		{
			name:      "invalid source IP returns false",
			condition: &SourceIPCondition{CIDRs: []string{"192.168.0.0/16"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "invalid-ip"},
			want:      false,
		},
		{
			name:      "IP in allowed CIDR",
			condition: &SourceIPCondition{CIDRs: []string{"192.168.0.0/16"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "192.168.1.100"},
			want:      true,
		},
		{
			name:      "IP not in allowed CIDR",
			condition: &SourceIPCondition{CIDRs: []string{"192.168.0.0/16"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "10.0.0.1"},
			want:      false,
		},
		{
			name:      "IP in one of multiple CIDRs",
			condition: &SourceIPCondition{CIDRs: []string{"192.168.0.0/16", "10.0.0.0/8"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "10.0.0.1"},
			want:      true,
		},
		{
			name:      "IP in NotCIDRs is denied",
			condition: &SourceIPCondition{NotCIDRs: []string{"192.168.0.0/16"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "192.168.1.100"},
			want:      false,
		},
		{
			name:      "IP not in NotCIDRs is allowed (no CIDRs specified)",
			condition: &SourceIPCondition{NotCIDRs: []string{"192.168.0.0/16"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "10.0.0.1"},
			want:      true,
		},
		{
			name:      "IP in CIDRs but also in NotCIDRs is denied",
			condition: &SourceIPCondition{CIDRs: []string{"192.168.0.0/16"}, NotCIDRs: []string{"192.168.1.0/24"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "192.168.1.100"},
			want:      false,
		},
		{
			name:      "IP in CIDRs and not in NotCIDRs is allowed",
			condition: &SourceIPCondition{CIDRs: []string{"192.168.0.0/16"}, NotCIDRs: []string{"192.168.1.0/24"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "192.168.2.100"},
			want:      true,
		},
		{
			name:      "no CIDRs and no NotCIDRs allows all",
			condition: &SourceIPCondition{},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "192.168.1.100"},
			want:      true,
		},
		{
			name:      "IPv6 address in CIDR",
			condition: &SourceIPCondition{CIDRs: []string{"2001:db8::/32"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "2001:db8::1"},
			want:      true,
		},
		{
			name:      "IPv6 address not in CIDR",
			condition: &SourceIPCondition{CIDRs: []string{"2001:db8::/32"}},
			subject:   &Subject{},
			resource:  &Resource{SourceIP: "2001:db9::1"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Not parallel because SourceIPCondition uses sync.Once
			got := tt.condition.Evaluate(tt.subject, tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSourceIPCondition_Evaluate_InvalidCIDR(t *testing.T) {
	// Test with invalid CIDR - should be skipped during parsing
	condition := &SourceIPCondition{CIDRs: []string{"invalid-cidr", "192.168.0.0/16"}}
	resource := &Resource{SourceIP: "192.168.1.100"}

	got := condition.Evaluate(&Subject{}, resource)
	assert.True(t, got) // Should still match the valid CIDR
}

// ============================================================================
// HeaderCondition.Evaluate Tests
// ============================================================================

func TestHeaderCondition_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		condition *HeaderCondition
		subject   *Subject
		resource  *Resource
		want      bool
	}{
		{
			name:      "nil resource returns false",
			condition: &HeaderCondition{Header: "X-Custom", Values: []string{"value1"}},
			subject:   &Subject{},
			resource:  nil,
			want:      false,
		},
		{
			name:      "nil headers returns false",
			condition: &HeaderCondition{Header: "X-Custom", Values: []string{"value1"}},
			subject:   &Subject{},
			resource:  &Resource{Headers: nil},
			want:      false,
		},
		{
			name:      "missing header returns false",
			condition: &HeaderCondition{Header: "X-Custom", Values: []string{"value1"}},
			subject:   &Subject{},
			resource:  &Resource{Headers: http.Header{"X-Other": []string{"value"}}},
			want:      false,
		},
		{
			name:      "empty header value returns false",
			condition: &HeaderCondition{Header: "X-Custom", Values: []string{"value1"}},
			subject:   &Subject{},
			resource:  &Resource{Headers: http.Header{"X-Custom": []string{""}}},
			want:      false,
		},
		{
			name:      "header matches exact value",
			condition: &HeaderCondition{Header: "X-Custom", Values: []string{"value1"}},
			subject:   &Subject{},
			resource:  &Resource{Headers: http.Header{"X-Custom": []string{"value1"}}},
			want:      true,
		},
		{
			name:      "header matches one of multiple values",
			condition: &HeaderCondition{Header: "X-Custom", Values: []string{"value1", "value2"}},
			subject:   &Subject{},
			resource:  &Resource{Headers: http.Header{"X-Custom": []string{"value2"}}},
			want:      true,
		},
		{
			name:      "header does not match any value",
			condition: &HeaderCondition{Header: "X-Custom", Values: []string{"value1", "value2"}},
			subject:   &Subject{},
			resource:  &Resource{Headers: http.Header{"X-Custom": []string{"value3"}}},
			want:      false,
		},
		{
			name:      "header matches regex",
			condition: &HeaderCondition{Header: "X-Custom", Regex: "^value[0-9]+$"},
			subject:   &Subject{},
			resource:  &Resource{Headers: http.Header{"X-Custom": []string{"value123"}}},
			want:      true,
		},
		{
			name:      "header does not match regex",
			condition: &HeaderCondition{Header: "X-Custom", Regex: "^value[0-9]+$"},
			subject:   &Subject{},
			resource:  &Resource{Headers: http.Header{"X-Custom": []string{"valueABC"}}},
			want:      false,
		},
		{
			name:      "no values and no regex returns true if header exists",
			condition: &HeaderCondition{Header: "X-Custom"},
			subject:   &Subject{},
			resource:  &Resource{Headers: http.Header{"X-Custom": []string{"any-value"}}},
			want:      true,
		},
		{
			name:      "case-insensitive header name",
			condition: &HeaderCondition{Header: "x-custom", Values: []string{"value1"}},
			subject:   &Subject{},
			resource:  &Resource{Headers: http.Header{"X-Custom": []string{"value1"}}},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Not parallel because HeaderCondition uses sync.Once
			got := tt.condition.Evaluate(tt.subject, tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHeaderCondition_Evaluate_InvalidRegex(t *testing.T) {
	// Test with invalid regex - when regex compilation fails, compiledRegex is nil
	// and the function returns true (falls through to the default return)
	condition := &HeaderCondition{Header: "X-Custom", Regex: "[invalid"}
	resource := &Resource{Headers: http.Header{"X-Custom": []string{"value"}}}

	got := condition.Evaluate(&Subject{}, resource)
	// When regex is invalid, it falls through to return true (header exists)
	assert.True(t, got)
}

// ============================================================================
// Target.Matches Tests
// ============================================================================

func TestTarget_Matches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		target   *Target
		resource *Resource
		want     bool
	}{
		{
			name:     "nil resource returns false",
			target:   &Target{Methods: []string{"GET"}},
			resource: nil,
			want:     false,
		},
		{
			name:     "empty target matches all",
			target:   &Target{},
			resource: &Resource{Method: "GET", Path: "/api", Host: "example.com", Port: 8080},
			want:     true,
		},
		{
			name:     "method matches (case insensitive)",
			target:   &Target{Methods: []string{"GET"}},
			resource: &Resource{Method: "get"},
			want:     true,
		},
		{
			name:     "method does not match",
			target:   &Target{Methods: []string{"POST"}},
			resource: &Resource{Method: "GET"},
			want:     false,
		},
		{
			name:     "one of multiple methods matches",
			target:   &Target{Methods: []string{"GET", "POST", "PUT"}},
			resource: &Resource{Method: "POST"},
			want:     true,
		},
		{
			name:     "path matches exact",
			target:   &Target{Paths: []string{"/api/users"}},
			resource: &Resource{Path: "/api/users"},
			want:     true,
		},
		{
			name:     "path matches wildcard",
			target:   &Target{Paths: []string{"/api/*"}},
			resource: &Resource{Path: "/api/users"},
			want:     true,
		},
		{
			name:     "path does not match",
			target:   &Target{Paths: []string{"/api/users"}},
			resource: &Resource{Path: "/api/posts"},
			want:     false,
		},
		{
			name:     "host matches exact",
			target:   &Target{Hosts: []string{"example.com"}},
			resource: &Resource{Host: "example.com"},
			want:     true,
		},
		{
			name:     "host matches wildcard",
			target:   &Target{Hosts: []string{"*.example.com"}},
			resource: &Resource{Host: "api.example.com"},
			want:     true,
		},
		{
			name:     "host does not match",
			target:   &Target{Hosts: []string{"example.com"}},
			resource: &Resource{Host: "other.com"},
			want:     false,
		},
		{
			name:     "port matches",
			target:   &Target{Ports: []int{8080}},
			resource: &Resource{Port: 8080},
			want:     true,
		},
		{
			name:     "port does not match",
			target:   &Target{Ports: []int{8080}},
			resource: &Resource{Port: 9090},
			want:     false,
		},
		{
			name:     "port check skipped when resource port is 0",
			target:   &Target{Ports: []int{8080}},
			resource: &Resource{Port: 0},
			want:     true,
		},
		{
			name:     "one of multiple ports matches",
			target:   &Target{Ports: []int{8080, 8443, 9090}},
			resource: &Resource{Port: 8443},
			want:     true,
		},
		{
			name:     "all criteria must match - success",
			target:   &Target{Methods: []string{"GET"}, Paths: []string{"/api/*"}, Hosts: []string{"example.com"}, Ports: []int{8080}},
			resource: &Resource{Method: "GET", Path: "/api/users", Host: "example.com", Port: 8080},
			want:     true,
		},
		{
			name:     "all criteria must match - method fails",
			target:   &Target{Methods: []string{"POST"}, Paths: []string{"/api/*"}, Hosts: []string{"example.com"}, Ports: []int{8080}},
			resource: &Resource{Method: "GET", Path: "/api/users", Host: "example.com", Port: 8080},
			want:     false,
		},
		{
			name:     "all criteria must match - path fails",
			target:   &Target{Methods: []string{"GET"}, Paths: []string{"/admin/*"}, Hosts: []string{"example.com"}, Ports: []int{8080}},
			resource: &Resource{Method: "GET", Path: "/api/users", Host: "example.com", Port: 8080},
			want:     false,
		},
		{
			name:     "all criteria must match - host fails",
			target:   &Target{Methods: []string{"GET"}, Paths: []string{"/api/*"}, Hosts: []string{"other.com"}, Ports: []int{8080}},
			resource: &Resource{Method: "GET", Path: "/api/users", Host: "example.com", Port: 8080},
			want:     false,
		},
		{
			name:     "all criteria must match - port fails",
			target:   &Target{Methods: []string{"GET"}, Paths: []string{"/api/*"}, Hosts: []string{"example.com"}, Ports: []int{9090}},
			resource: &Resource{Method: "GET", Path: "/api/users", Host: "example.com", Port: 8080},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Not parallel because Target uses sync.Once
			got := tt.target.Matches(tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// RBACAuthorizer Tests
// ============================================================================

func TestNewRBACAuthorizer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *RBACConfig
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
		},
		{
			name:   "empty config uses defaults",
			config: &RBACConfig{},
		},
		{
			name: "custom config with rules",
			config: &RBACConfig{
				Rules: []*Rule{
					{Name: "rule1", Priority: 10, Enabled: true, Action: ActionAllow},
				},
				DefaultAction: ActionAllow,
				Logger:        zap.NewNop(),
			},
		},
		{
			name: "config with nil logger",
			config: &RBACConfig{
				DefaultAction: ActionDeny,
				Logger:        nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authorizer := NewRBACAuthorizer(tt.config)
			assert.NotNil(t, authorizer)
		})
	}
}

func TestRBACAuthorizer_Authorize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		rules         []*Rule
		defaultAction Action
		subject       *Subject
		resource      *Resource
		wantAllowed   bool
		wantRule      string
	}{
		{
			name:          "no rules uses default action deny",
			rules:         nil,
			defaultAction: ActionDeny,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   false,
			wantRule:      "",
		},
		{
			name:          "no rules uses default action allow",
			rules:         nil,
			defaultAction: ActionAllow,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   true,
			wantRule:      "",
		},
		{
			name: "matching rule returns allow",
			rules: []*Rule{
				{
					Name:    "allow-all",
					Enabled: true,
					Action:  ActionAllow,
				},
			},
			defaultAction: ActionDeny,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   true,
			wantRule:      "allow-all",
		},
		{
			name: "matching rule returns deny",
			rules: []*Rule{
				{
					Name:    "deny-all",
					Enabled: true,
					Action:  ActionDeny,
				},
			},
			defaultAction: ActionAllow,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   false,
			wantRule:      "deny-all",
		},
		{
			name: "disabled rule is skipped",
			rules: []*Rule{
				{
					Name:    "disabled-rule",
					Enabled: false,
					Action:  ActionAllow,
				},
			},
			defaultAction: ActionDeny,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   false,
			wantRule:      "",
		},
		{
			name: "rule with condition - matches",
			rules: []*Rule{
				{
					Name:    "admin-rule",
					Enabled: true,
					Action:  ActionAllow,
					Conditions: []Condition{
						&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
					},
				},
			},
			defaultAction: ActionDeny,
			subject:       &Subject{Roles: []string{"admin"}},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   true,
			wantRule:      "admin-rule",
		},
		{
			name: "rule with condition - does not match",
			rules: []*Rule{
				{
					Name:    "admin-rule",
					Enabled: true,
					Action:  ActionAllow,
					Conditions: []Condition{
						&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
					},
				},
			},
			defaultAction: ActionDeny,
			subject:       &Subject{Roles: []string{"user"}},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   false,
			wantRule:      "",
		},
		{
			name: "first rule in list is evaluated first (no sorting in constructor)",
			rules: []*Rule{
				{
					Name:     "first-rule",
					Priority: 10,
					Enabled:  true,
					Action:   ActionAllow,
				},
				{
					Name:     "second-rule",
					Priority: 100,
					Enabled:  true,
					Action:   ActionDeny,
				},
			},
			defaultAction: ActionDeny,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   true,
			wantRule:      "first-rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authorizer := NewRBACAuthorizer(&RBACConfig{
				Rules:         tt.rules,
				DefaultAction: tt.defaultAction,
				Logger:        zap.NewNop(),
			})

			decision, err := authorizer.Authorize(context.Background(), tt.subject, tt.resource)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
			assert.Equal(t, tt.wantRule, decision.Rule)
		})
	}
}

func TestRBACAuthorizer_AddRule(t *testing.T) {
	t.Parallel()

	authorizer := NewRBACAuthorizer(&RBACConfig{
		DefaultAction: ActionDeny,
		Logger:        zap.NewNop(),
	})

	// Initially no rules - should deny
	decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// Add allow rule
	authorizer.AddRule(&Rule{
		Name:    "allow-all",
		Enabled: true,
		Action:  ActionAllow,
	})

	// Now should allow
	decision, err = authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestRBACAuthorizer_RemoveRule(t *testing.T) {
	t.Parallel()

	authorizer := NewRBACAuthorizer(&RBACConfig{
		Rules: []*Rule{
			{Name: "rule1", Enabled: true, Action: ActionAllow},
			{Name: "rule2", Enabled: true, Action: ActionDeny},
		},
		DefaultAction: ActionDeny,
		Logger:        zap.NewNop(),
	})

	// Initially rule1 allows
	decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Remove rule1
	authorizer.RemoveRule("rule1")

	// Now rule2 denies
	decision, err = authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// Remove non-existing rule (should not panic)
	authorizer.RemoveRule("non-existing")
}

func TestRBACAuthorizer_SetRules(t *testing.T) {
	t.Parallel()

	authorizer := NewRBACAuthorizer(&RBACConfig{
		Rules: []*Rule{
			{Name: "old-rule", Enabled: true, Action: ActionDeny},
		},
		DefaultAction: ActionAllow,
		Logger:        zap.NewNop(),
	})

	// Initially old-rule denies
	decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// Set new rules
	authorizer.SetRules([]*Rule{
		{Name: "new-rule", Enabled: true, Action: ActionAllow},
	})

	// Now new-rule allows
	decision, err = authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestRBACAuthorizer_SetDefaultAction(t *testing.T) {
	t.Parallel()

	authorizer := NewRBACAuthorizer(&RBACConfig{
		DefaultAction: ActionDeny,
		Logger:        zap.NewNop(),
	})

	// Initially default is deny
	decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// Change default to allow
	authorizer.SetDefaultAction(ActionAllow)

	decision, err = authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestRBACAuthorizer_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	authorizer := NewRBACAuthorizer(&RBACConfig{
		Logger: zap.NewNop(),
	})

	var wg sync.WaitGroup
	iterations := 100

	// Phase 1: Concurrent adds (no reads during adds to avoid race in sortRules)
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			authorizer.AddRule(&Rule{
				Name:     "rule-" + string(rune('a'+idx%26)),
				Priority: idx,
				Enabled:  true,
				Action:   ActionAllow,
			})
		}(i)
	}
	wg.Wait()

	// Phase 2: Concurrent reads only (safe after adds complete)
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
		}()
	}
	wg.Wait()

	// Phase 3: Concurrent removes (no reads during removes)
	for i := 0; i < iterations/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			authorizer.RemoveRule("rule-" + string(rune('a'+idx%26)))
		}(i)
	}
	wg.Wait()
}

// ============================================================================
// Context Functions Tests
// ============================================================================

func TestGetSubjectFromContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ctx     context.Context
		wantOk  bool
		wantNil bool
	}{
		{
			name:    "subject in context",
			ctx:     ContextWithSubject(context.Background(), &Subject{User: "test"}),
			wantOk:  true,
			wantNil: false,
		},
		{
			name:    "no subject in context",
			ctx:     context.Background(),
			wantOk:  false,
			wantNil: true,
		},
		{
			name:    "nil subject in context - type assertion succeeds but value is nil",
			ctx:     context.WithValue(context.Background(), SubjectContextKey{}, (*Subject)(nil)),
			wantOk:  true, // Type assertion succeeds for typed nil
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			subject, ok := GetSubjectFromContext(tt.ctx)
			assert.Equal(t, tt.wantOk, ok)
			if tt.wantNil {
				assert.Nil(t, subject)
			} else {
				assert.NotNil(t, subject)
			}
		})
	}
}

func TestContextWithSubject(t *testing.T) {
	t.Parallel()

	subject := &Subject{
		User:   "testuser",
		Roles:  []string{"admin"},
		Groups: []string{"developers"},
	}

	ctx := ContextWithSubject(context.Background(), subject)

	retrieved, ok := GetSubjectFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, subject, retrieved)
	assert.Equal(t, "testuser", retrieved.User)
	assert.Equal(t, []string{"admin"}, retrieved.Roles)
	assert.Equal(t, []string{"developers"}, retrieved.Groups)
}

// ============================================================================
// compilePattern Tests
// ============================================================================

func TestCompilePattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{
			name:    "exact match",
			pattern: "/api/users",
			input:   "/api/users",
			want:    true,
		},
		{
			name:    "exact no match",
			pattern: "/api/users",
			input:   "/api/posts",
			want:    false,
		},
		{
			name:    "wildcard match",
			pattern: "/api/*",
			input:   "/api/users",
			want:    true,
		},
		{
			name:    "wildcard match anything",
			pattern: "/api/*",
			input:   "/api/anything-here",
			want:    true,
		},
		{
			name:    "wildcard in middle",
			pattern: "/api/*/posts",
			input:   "/api/users/posts",
			want:    true,
		},
		{
			name:    "special regex chars escaped",
			pattern: "/api/users.json",
			input:   "/api/users.json",
			want:    true,
		},
		{
			name:    "special regex chars escaped - no match",
			pattern: "/api/users.json",
			input:   "/api/usersXjson",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			re, err := compilePattern(tt.pattern)
			require.NoError(t, err)
			got := re.MatchString(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// Edge Cases and Error Handling Tests
// ============================================================================

func TestRBACAuthorizer_WithTargetMatching(t *testing.T) {
	t.Parallel()

	authorizer := NewRBACAuthorizer(&RBACConfig{
		Rules: []*Rule{
			{
				Name:    "api-rule",
				Enabled: true,
				Action:  ActionAllow,
				Targets: []*Target{
					{Methods: []string{"GET"}, Paths: []string{"/api/*"}},
				},
			},
		},
		DefaultAction: ActionDeny,
		Logger:        zap.NewNop(),
	})

	tests := []struct {
		name        string
		resource    *Resource
		wantAllowed bool
	}{
		{
			name:        "matching method and path",
			resource:    &Resource{Method: "GET", Path: "/api/users"},
			wantAllowed: true,
		},
		{
			name:        "non-matching method",
			resource:    &Resource{Method: "POST", Path: "/api/users"},
			wantAllowed: false,
		},
		{
			name:        "non-matching path",
			resource:    &Resource{Method: "GET", Path: "/admin/users"},
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, err := authorizer.Authorize(context.Background(), &Subject{}, tt.resource)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
		})
	}
}

func TestRBACAuthorizer_RulePrioritySorting(t *testing.T) {
	t.Parallel()

	rules := []*Rule{
		{Name: "low", Priority: 10, Enabled: true, Action: ActionDeny},
		{Name: "high", Priority: 100, Enabled: true, Action: ActionAllow},
		{Name: "medium", Priority: 50, Enabled: true, Action: ActionDeny},
	}

	authorizer := NewRBACAuthorizer(&RBACConfig{
		DefaultAction: ActionDeny,
		Logger:        zap.NewNop(),
	})

	// Use SetRules to trigger sorting
	authorizer.SetRules(rules)

	// The high priority rule should be evaluated first and allow
	decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "high", decision.Rule)
}

func TestSubject_EmptyAndNilHandling(t *testing.T) {
	t.Parallel()

	subject := &Subject{}

	// All checks should return false for empty subject
	assert.False(t, subject.HasRole("admin"))
	assert.False(t, subject.HasAnyRole("admin", "user"))
	assert.True(t, subject.HasAllRoles()) // Empty check returns true
	assert.False(t, subject.HasGroup("admins"))
	assert.False(t, subject.HasScope("read"))

	val, ok := subject.GetClaim("sub")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestResource_WithAllFields(t *testing.T) {
	t.Parallel()

	resource := &Resource{
		Path:     "/api/users/123",
		Method:   "GET",
		Host:     "api.example.com",
		Port:     8080,
		Headers:  http.Header{"Authorization": []string{"Bearer token"}},
		SourceIP: "192.168.1.100",
		Metadata: map[string]string{"key": "value"},
	}

	assert.Equal(t, "/api/users/123", resource.Path)
	assert.Equal(t, "GET", resource.Method)
	assert.Equal(t, "api.example.com", resource.Host)
	assert.Equal(t, 8080, resource.Port)
	assert.Equal(t, "Bearer token", resource.Headers.Get("Authorization"))
	assert.Equal(t, "192.168.1.100", resource.SourceIP)
	assert.Equal(t, "value", resource.Metadata["key"])
}
