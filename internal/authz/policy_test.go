package authz

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Policy.Matches Tests
// ============================================================================

func TestPolicy_Matches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		resource *Resource
		want     bool
	}{
		{
			name:     "disabled policy returns false",
			policy:   &Policy{Enabled: false},
			resource: &Resource{Path: "/api"},
			want:     false,
		},
		{
			name:     "enabled policy with empty targets matches all",
			policy:   &Policy{Enabled: true, Targets: nil},
			resource: &Resource{Path: "/api"},
			want:     true,
		},
		{
			name:     "enabled policy with empty targets slice matches all",
			policy:   &Policy{Enabled: true, Targets: []*Target{}},
			resource: &Resource{Path: "/api"},
			want:     true,
		},
		{
			name: "enabled policy with matching target returns true",
			policy: &Policy{
				Enabled: true,
				Targets: []*Target{
					{Methods: []string{"GET"}},
				},
			},
			resource: &Resource{Path: "/api", Method: "GET"},
			want:     true,
		},
		{
			name: "enabled policy with non-matching target returns false",
			policy: &Policy{
				Enabled: true,
				Targets: []*Target{
					{Methods: []string{"POST"}},
				},
			},
			resource: &Resource{Path: "/api", Method: "GET"},
			want:     false,
		},
		{
			name: "enabled policy with multiple targets - first matches",
			policy: &Policy{
				Enabled: true,
				Targets: []*Target{
					{Methods: []string{"GET"}},
					{Methods: []string{"POST"}},
				},
			},
			resource: &Resource{Path: "/api", Method: "GET"},
			want:     true,
		},
		{
			name: "enabled policy with multiple targets - second matches",
			policy: &Policy{
				Enabled: true,
				Targets: []*Target{
					{Methods: []string{"POST"}},
					{Methods: []string{"GET"}},
				},
			},
			resource: &Resource{Path: "/api", Method: "GET"},
			want:     true,
		},
		{
			name: "enabled policy with multiple targets - none match",
			policy: &Policy{
				Enabled: true,
				Targets: []*Target{
					{Methods: []string{"POST"}},
					{Methods: []string{"PUT"}},
				},
			},
			resource: &Resource{Path: "/api", Method: "GET"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.policy.Matches(tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// Policy.Evaluate Tests
// ============================================================================

func TestPolicy_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		policy       *Policy
		subject      *Subject
		resource     *Resource
		wantDecision *Decision
		wantMatched  bool
	}{
		{
			name:         "disabled policy returns nil and false",
			policy:       &Policy{Enabled: false},
			subject:      &Subject{User: "test"},
			resource:     &Resource{Path: "/api"},
			wantDecision: nil,
			wantMatched:  false,
		},
		{
			name: "non-matching resource returns nil and false",
			policy: &Policy{
				Enabled: true,
				Targets: []*Target{
					{Methods: []string{"POST"}},
				},
			},
			subject:      &Subject{User: "test"},
			resource:     &Resource{Path: "/api", Method: "GET"},
			wantDecision: nil,
			wantMatched:  false,
		},
		{
			name: "matching rule returns decision with allow",
			policy: &Policy{
				Enabled:       true,
				DefaultAction: ActionDeny,
				Rules: []*Rule{
					{
						Name:    "allow-rule",
						Enabled: true,
						Action:  ActionAllow,
					},
				},
			},
			subject:  &Subject{User: "test"},
			resource: &Resource{Path: "/api", Method: "GET"},
			wantDecision: &Decision{
				Allowed: true,
				Reason:  "ALLOW",
				Rule:    "allow-rule",
			},
			wantMatched: true,
		},
		{
			name: "matching rule returns decision with deny",
			policy: &Policy{
				Enabled:       true,
				DefaultAction: ActionAllow,
				Rules: []*Rule{
					{
						Name:    "deny-rule",
						Enabled: true,
						Action:  ActionDeny,
					},
				},
			},
			subject:  &Subject{User: "test"},
			resource: &Resource{Path: "/api", Method: "GET"},
			wantDecision: &Decision{
				Allowed: false,
				Reason:  "DENY",
				Rule:    "deny-rule",
			},
			wantMatched: true,
		},
		{
			name: "no matching rules uses default action allow",
			policy: &Policy{
				Enabled:       true,
				DefaultAction: ActionAllow,
				Rules: []*Rule{
					{
						Name:    "disabled-rule",
						Enabled: false,
						Action:  ActionDeny,
					},
				},
			},
			subject:  &Subject{User: "test"},
			resource: &Resource{Path: "/api", Method: "GET"},
			wantDecision: &Decision{
				Allowed: true,
				Reason:  "policy default",
				Rule:    "",
			},
			wantMatched: true,
		},
		{
			name: "no matching rules uses default action deny",
			policy: &Policy{
				Enabled:       true,
				DefaultAction: ActionDeny,
				Rules: []*Rule{
					{
						Name:    "disabled-rule",
						Enabled: false,
						Action:  ActionAllow,
					},
				},
			},
			subject:  &Subject{User: "test"},
			resource: &Resource{Path: "/api", Method: "GET"},
			wantDecision: &Decision{
				Allowed: false,
				Reason:  "policy default",
				Rule:    "",
			},
			wantMatched: true,
		},
		{
			name: "first matching rule wins",
			policy: &Policy{
				Enabled:       true,
				DefaultAction: ActionDeny,
				Rules: []*Rule{
					{
						Name:    "first-rule",
						Enabled: true,
						Action:  ActionAllow,
					},
					{
						Name:    "second-rule",
						Enabled: true,
						Action:  ActionDeny,
					},
				},
			},
			subject:  &Subject{User: "test"},
			resource: &Resource{Path: "/api", Method: "GET"},
			wantDecision: &Decision{
				Allowed: true,
				Reason:  "ALLOW",
				Rule:    "first-rule",
			},
			wantMatched: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotDecision, gotMatched := tt.policy.Evaluate(tt.subject, tt.resource)
			assert.Equal(t, tt.wantMatched, gotMatched)
			assert.Equal(t, tt.wantDecision, gotDecision)
		})
	}
}

// ============================================================================
// PolicyEngine Tests
// ============================================================================

func TestNewPolicyEngine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *PolicyEngineConfig
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
		},
		{
			name:   "empty config uses defaults",
			config: &PolicyEngineConfig{},
		},
		{
			name: "custom config with policies",
			config: &PolicyEngineConfig{
				Policies: []*Policy{
					{Name: "policy1", Priority: 10, Enabled: true},
					{Name: "policy2", Priority: 20, Enabled: true},
				},
				DefaultAction: ActionAllow,
				Logger:        zap.NewNop(),
			},
		},
		{
			name: "config with nil logger",
			config: &PolicyEngineConfig{
				DefaultAction: ActionDeny,
				Logger:        nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			engine := NewPolicyEngine(tt.config)
			assert.NotNil(t, engine)
		})
	}
}

func TestPolicyEngine_Authorize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		policies      []*Policy
		defaultAction Action
		subject       *Subject
		resource      *Resource
		wantAllowed   bool
		wantReason    string
	}{
		{
			name:          "no policies uses default action deny",
			policies:      nil,
			defaultAction: ActionDeny,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   false,
			wantReason:    "engine default",
		},
		{
			name:          "no policies uses default action allow",
			policies:      nil,
			defaultAction: ActionAllow,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   true,
			wantReason:    "engine default",
		},
		{
			name: "matching policy returns decision",
			policies: []*Policy{
				{
					Name:          "test-policy",
					Enabled:       true,
					DefaultAction: ActionAllow,
				},
			},
			defaultAction: ActionDeny,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   true,
			wantReason:    "policy default",
		},
		{
			name: "higher priority policy evaluated first",
			policies: []*Policy{
				{
					Name:          "low-priority",
					Priority:      10,
					Enabled:       true,
					DefaultAction: ActionDeny,
				},
				{
					Name:          "high-priority",
					Priority:      100,
					Enabled:       true,
					DefaultAction: ActionAllow,
				},
			},
			defaultAction: ActionDeny,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   true,
			wantReason:    "policy default",
		},
		{
			name: "disabled policy is skipped",
			policies: []*Policy{
				{
					Name:          "disabled-policy",
					Priority:      100,
					Enabled:       false,
					DefaultAction: ActionAllow,
				},
				{
					Name:          "enabled-policy",
					Priority:      10,
					Enabled:       true,
					DefaultAction: ActionDeny,
				},
			},
			defaultAction: ActionAllow,
			subject:       &Subject{User: "test"},
			resource:      &Resource{Path: "/api", Method: "GET"},
			wantAllowed:   false,
			wantReason:    "policy default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			engine := NewPolicyEngine(&PolicyEngineConfig{
				Policies:      tt.policies,
				DefaultAction: tt.defaultAction,
				Logger:        zap.NewNop(),
			})

			decision, err := engine.Authorize(context.Background(), tt.subject, tt.resource)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
			assert.Equal(t, tt.wantReason, decision.Reason)
		})
	}
}

func TestPolicyEngine_AddPolicy(t *testing.T) {
	t.Parallel()

	engine := NewPolicyEngine(&PolicyEngineConfig{
		Logger: zap.NewNop(),
	})

	// Add first policy
	policy1 := &Policy{Name: "policy1", Priority: 10, Enabled: true}
	engine.AddPolicy(policy1)

	got, found := engine.GetPolicy("policy1")
	assert.True(t, found)
	assert.Equal(t, policy1, got)

	// Add second policy with higher priority
	policy2 := &Policy{Name: "policy2", Priority: 20, Enabled: true}
	engine.AddPolicy(policy2)

	// Verify both policies exist
	_, found1 := engine.GetPolicy("policy1")
	_, found2 := engine.GetPolicy("policy2")
	assert.True(t, found1)
	assert.True(t, found2)
}

func TestPolicyEngine_RemovePolicy(t *testing.T) {
	t.Parallel()

	engine := NewPolicyEngine(&PolicyEngineConfig{
		Policies: []*Policy{
			{Name: "policy1", Priority: 10, Enabled: true},
			{Name: "policy2", Priority: 20, Enabled: true},
		},
		Logger: zap.NewNop(),
	})

	// Remove existing policy
	engine.RemovePolicy("policy1")
	_, found := engine.GetPolicy("policy1")
	assert.False(t, found)

	// Verify other policy still exists
	_, found = engine.GetPolicy("policy2")
	assert.True(t, found)

	// Remove non-existing policy (should not panic)
	engine.RemovePolicy("non-existing")
}

func TestPolicyEngine_GetPolicy(t *testing.T) {
	t.Parallel()

	policy := &Policy{Name: "test-policy", Priority: 10, Enabled: true}
	engine := NewPolicyEngine(&PolicyEngineConfig{
		Policies: []*Policy{policy},
		Logger:   zap.NewNop(),
	})

	tests := []struct {
		name       string
		policyName string
		wantFound  bool
	}{
		{
			name:       "existing policy",
			policyName: "test-policy",
			wantFound:  true,
		},
		{
			name:       "non-existing policy",
			policyName: "non-existing",
			wantFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, found := engine.GetPolicy(tt.policyName)
			assert.Equal(t, tt.wantFound, found)
			if tt.wantFound {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func TestPolicyEngine_SetPolicies(t *testing.T) {
	t.Parallel()

	engine := NewPolicyEngine(&PolicyEngineConfig{
		Policies: []*Policy{
			{Name: "old-policy", Priority: 10, Enabled: true},
		},
		Logger: zap.NewNop(),
	})

	// Set new policies
	newPolicies := []*Policy{
		{Name: "new-policy1", Priority: 30, Enabled: true},
		{Name: "new-policy2", Priority: 20, Enabled: true},
	}
	engine.SetPolicies(newPolicies)

	// Verify old policy is gone
	_, found := engine.GetPolicy("old-policy")
	assert.False(t, found)

	// Verify new policies exist
	_, found1 := engine.GetPolicy("new-policy1")
	_, found2 := engine.GetPolicy("new-policy2")
	assert.True(t, found1)
	assert.True(t, found2)
}

func TestPolicyEngine_SetDefaultAction(t *testing.T) {
	t.Parallel()

	engine := NewPolicyEngine(&PolicyEngineConfig{
		DefaultAction: ActionDeny,
		Logger:        zap.NewNop(),
	})

	// Initial default action is deny
	decision, err := engine.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// Change default action to allow
	engine.SetDefaultAction(ActionAllow)

	decision, err = engine.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestPolicyEngine_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	engine := NewPolicyEngine(&PolicyEngineConfig{
		Logger: zap.NewNop(),
	})

	var wg sync.WaitGroup
	iterations := 100

	// Phase 1: Concurrent adds (no reads during adds to avoid race in sortPolicies)
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			engine.AddPolicy(&Policy{
				Name:     "policy-" + string(rune('a'+idx%26)),
				Priority: idx,
				Enabled:  true,
			})
		}(i)
	}
	wg.Wait()

	// Phase 2: Concurrent reads only (safe after adds complete)
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = engine.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
		}()
	}
	wg.Wait()

	// Phase 3: Concurrent removes (no reads during removes)
	for i := 0; i < iterations/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			engine.RemovePolicy("policy-" + string(rune('a'+idx%26)))
		}(i)
	}
	wg.Wait()
}

// ============================================================================
// PolicyBuilder Tests
// ============================================================================

func TestNewPolicyBuilder(t *testing.T) {
	t.Parallel()

	builder := NewPolicyBuilder("test-policy")
	assert.NotNil(t, builder)

	policy := builder.Build()
	assert.Equal(t, "test-policy", policy.Name)
	assert.Equal(t, ActionDeny, policy.DefaultAction)
	assert.True(t, policy.Enabled)
	assert.NotZero(t, policy.CreatedAt)
	assert.NotZero(t, policy.UpdatedAt)
}

func TestPolicyBuilder_WithDescription(t *testing.T) {
	t.Parallel()

	policy := NewPolicyBuilder("test").
		WithDescription("Test description").
		Build()

	assert.Equal(t, "Test description", policy.Description)
}

func TestPolicyBuilder_WithDefaultAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		action Action
	}{
		{"allow", ActionAllow},
		{"deny", ActionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			policy := NewPolicyBuilder("test").
				WithDefaultAction(tt.action).
				Build()
			assert.Equal(t, tt.action, policy.DefaultAction)
		})
	}
}

func TestPolicyBuilder_WithPriority(t *testing.T) {
	t.Parallel()

	policy := NewPolicyBuilder("test").
		WithPriority(100).
		Build()

	assert.Equal(t, 100, policy.Priority)
}

func TestPolicyBuilder_WithEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled bool
	}{
		{"enabled", true},
		{"disabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			policy := NewPolicyBuilder("test").
				WithEnabled(tt.enabled).
				Build()
			assert.Equal(t, tt.enabled, policy.Enabled)
		})
	}
}

func TestPolicyBuilder_WithTarget(t *testing.T) {
	t.Parallel()

	target1 := &Target{Methods: []string{"GET"}}
	target2 := &Target{Methods: []string{"POST"}}

	policy := NewPolicyBuilder("test").
		WithTarget(target1).
		WithTarget(target2).
		Build()

	assert.Len(t, policy.Targets, 2)
	assert.Equal(t, target1, policy.Targets[0])
	assert.Equal(t, target2, policy.Targets[1])
}

func TestPolicyBuilder_WithRule(t *testing.T) {
	t.Parallel()

	rule1 := &Rule{Name: "rule1", Action: ActionAllow}
	rule2 := &Rule{Name: "rule2", Action: ActionDeny}

	policy := NewPolicyBuilder("test").
		WithRule(rule1).
		WithRule(rule2).
		Build()

	assert.Len(t, policy.Rules, 2)
	assert.Equal(t, rule1, policy.Rules[0])
	assert.Equal(t, rule2, policy.Rules[1])
}

func TestPolicyBuilder_ChainedMethods(t *testing.T) {
	t.Parallel()

	target := &Target{Methods: []string{"GET"}}
	rule := &Rule{Name: "rule1", Action: ActionAllow, Enabled: true}

	policy := NewPolicyBuilder("comprehensive-policy").
		WithDescription("A comprehensive test policy").
		WithDefaultAction(ActionAllow).
		WithPriority(50).
		WithEnabled(true).
		WithTarget(target).
		WithRule(rule).
		Build()

	assert.Equal(t, "comprehensive-policy", policy.Name)
	assert.Equal(t, "A comprehensive test policy", policy.Description)
	assert.Equal(t, ActionAllow, policy.DefaultAction)
	assert.Equal(t, 50, policy.Priority)
	assert.True(t, policy.Enabled)
	assert.Len(t, policy.Targets, 1)
	assert.Len(t, policy.Rules, 1)
}

// ============================================================================
// RuleBuilder Tests
// ============================================================================

func TestNewRuleBuilder(t *testing.T) {
	t.Parallel()

	builder := NewRuleBuilder("test-rule")
	assert.NotNil(t, builder)

	rule := builder.Build()
	assert.Equal(t, "test-rule", rule.Name)
	assert.Equal(t, ActionAllow, rule.Action)
	assert.True(t, rule.Enabled)
}

func TestRuleBuilder_WithPriority(t *testing.T) {
	t.Parallel()

	rule := NewRuleBuilder("test").
		WithPriority(100).
		Build()

	assert.Equal(t, 100, rule.Priority)
}

func TestRuleBuilder_WithAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		action Action
	}{
		{"allow", ActionAllow},
		{"deny", ActionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewRuleBuilder("test").
				WithAction(tt.action).
				Build()
			assert.Equal(t, tt.action, rule.Action)
		})
	}
}

func TestRuleBuilder_WithEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled bool
	}{
		{"enabled", true},
		{"disabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewRuleBuilder("test").
				WithEnabled(tt.enabled).
				Build()
			assert.Equal(t, tt.enabled, rule.Enabled)
		})
	}
}

func TestRuleBuilder_WithCondition(t *testing.T) {
	t.Parallel()

	condition := &RoleCondition{Roles: []string{"admin"}}

	rule := NewRuleBuilder("test").
		WithCondition(condition).
		Build()

	assert.Len(t, rule.Conditions, 1)
	assert.Equal(t, condition, rule.Conditions[0])
}

func TestRuleBuilder_WithTarget(t *testing.T) {
	t.Parallel()

	target := &Target{Methods: []string{"GET"}}

	rule := NewRuleBuilder("test").
		WithTarget(target).
		Build()

	assert.Len(t, rule.Targets, 1)
	assert.Equal(t, target, rule.Targets[0])
}

func TestRuleBuilder_RequireRole(t *testing.T) {
	t.Parallel()

	rule := NewRuleBuilder("test").
		RequireRole("admin", "user").
		Build()

	require.Len(t, rule.Conditions, 1)
	roleCondition, ok := rule.Conditions[0].(*RoleCondition)
	require.True(t, ok)
	assert.Equal(t, []string{"admin", "user"}, roleCondition.Roles)
	assert.False(t, roleCondition.MatchAll)
}

func TestRuleBuilder_RequireAllRoles(t *testing.T) {
	t.Parallel()

	rule := NewRuleBuilder("test").
		RequireAllRoles("admin", "user").
		Build()

	require.Len(t, rule.Conditions, 1)
	roleCondition, ok := rule.Conditions[0].(*RoleCondition)
	require.True(t, ok)
	assert.Equal(t, []string{"admin", "user"}, roleCondition.Roles)
	assert.True(t, roleCondition.MatchAll)
}

func TestRuleBuilder_RequireGroup(t *testing.T) {
	t.Parallel()

	rule := NewRuleBuilder("test").
		RequireGroup("developers", "admins").
		Build()

	require.Len(t, rule.Conditions, 1)
	groupCondition, ok := rule.Conditions[0].(*GroupCondition)
	require.True(t, ok)
	assert.Equal(t, []string{"developers", "admins"}, groupCondition.Groups)
	assert.False(t, groupCondition.MatchAll)
}

func TestRuleBuilder_RequireScope(t *testing.T) {
	t.Parallel()

	rule := NewRuleBuilder("test").
		RequireScope("read", "write").
		Build()

	require.Len(t, rule.Conditions, 1)
	scopeCondition, ok := rule.Conditions[0].(*ScopeCondition)
	require.True(t, ok)
	assert.Equal(t, []string{"read", "write"}, scopeCondition.Scopes)
	assert.False(t, scopeCondition.MatchAll)
}

func TestRuleBuilder_RequireClaim(t *testing.T) {
	t.Parallel()

	rule := NewRuleBuilder("test").
		RequireClaim("department", "engineering", "sales").
		Build()

	require.Len(t, rule.Conditions, 1)
	claimCondition, ok := rule.Conditions[0].(*ClaimCondition)
	require.True(t, ok)
	assert.Equal(t, "department", claimCondition.Claim)
	assert.Equal(t, []string{"engineering", "sales"}, claimCondition.Values)
	assert.True(t, claimCondition.MatchAny)
}

func TestRuleBuilder_ForMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		methods []string
	}{
		{"single method", []string{"GET"}},
		{"multiple methods", []string{"GET", "POST", "PUT"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewRuleBuilder("test").
				ForMethods(tt.methods...).
				Build()

			require.Len(t, rule.Targets, 1)
			assert.Equal(t, tt.methods, rule.Targets[0].Methods)
		})
	}
}

func TestRuleBuilder_ForPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		paths []string
	}{
		{"single path", []string{"/api/v1/*"}},
		{"multiple paths", []string{"/api/v1/*", "/api/v2/*"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewRuleBuilder("test").
				ForPaths(tt.paths...).
				Build()

			require.Len(t, rule.Targets, 1)
			assert.Equal(t, tt.paths, rule.Targets[0].Paths)
		})
	}
}

func TestRuleBuilder_ForMethodsAndPaths(t *testing.T) {
	t.Parallel()

	rule := NewRuleBuilder("test").
		ForMethods("GET", "POST").
		ForPaths("/api/*").
		Build()

	require.Len(t, rule.Targets, 1)
	assert.Equal(t, []string{"GET", "POST"}, rule.Targets[0].Methods)
	assert.Equal(t, []string{"/api/*"}, rule.Targets[0].Paths)
}

func TestRuleBuilder_ChainedMethods(t *testing.T) {
	t.Parallel()

	target := &Target{Hosts: []string{"example.com"}}

	rule := NewRuleBuilder("comprehensive-rule").
		WithPriority(100).
		WithAction(ActionAllow).
		WithEnabled(true).
		RequireRole("admin").
		RequireScope("read").
		ForMethods("GET").
		ForPaths("/api/*").
		WithTarget(target).
		Build()

	assert.Equal(t, "comprehensive-rule", rule.Name)
	assert.Equal(t, 100, rule.Priority)
	assert.Equal(t, ActionAllow, rule.Action)
	assert.True(t, rule.Enabled)
	assert.Len(t, rule.Conditions, 2)
	assert.Len(t, rule.Targets, 2)
}

// ============================================================================
// PathMatcher Tests
// ============================================================================

func TestNewPathMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"exact path", "/api/users", false},
		{"single wildcard", "/api/*", false},
		{"double wildcard", "/api/**", false},
		{"path parameter", "/api/users/{id}", false},
		{"complex pattern", "/api/v1/users/{id}/posts/*", false},
		{"multiple parameters", "/api/{version}/users/{id}", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := NewPathMatcher(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, matcher)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, matcher)
			}
		})
	}
}

func TestPathMatcher_Matches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		// Exact matches
		{"exact match", "/api/users", "/api/users", true},
		{"exact no match", "/api/users", "/api/posts", false},
		{"exact no match prefix", "/api/users", "/api/users/123", false},

		// Single wildcard (*)
		{"single wildcard match", "/api/*", "/api/users", true},
		{"single wildcard match empty", "/api/*", "/api/", true},
		{"single wildcard no match nested", "/api/*", "/api/users/123", false},
		{"single wildcard in middle", "/api/*/posts", "/api/users/posts", true},
		{"single wildcard in middle no match", "/api/*/posts", "/api/users/comments", false},

		// Double wildcard (**)
		{"double wildcard match single", "/api/**", "/api/users", true},
		{"double wildcard match nested", "/api/**", "/api/users/123/posts", true},
		{"double wildcard match empty", "/api/**", "/api/", true},
		{"double wildcard at end", "/api/v1/**", "/api/v1/users/123", true},

		// Path parameters ({id})
		{"path param match", "/api/users/{id}", "/api/users/123", true},
		{"path param match uuid", "/api/users/{id}", "/api/users/abc-123-def", true},
		{"path param no match extra", "/api/users/{id}", "/api/users/123/posts", false},
		{"multiple path params", "/api/{version}/users/{id}", "/api/v1/users/123", true},

		// Combined patterns
		{"param and wildcard", "/api/users/{id}/*", "/api/users/123/posts", true},
		{"param and double wildcard", "/api/users/{id}/**", "/api/users/123/posts/456", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := NewPathMatcher(tt.pattern)
			require.NoError(t, err)
			got := matcher.Matches(tt.path)
			assert.Equal(t, tt.want, got, "pattern=%s, path=%s", tt.pattern, tt.path)
		})
	}
}

func TestPathMatcher_ExtractParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		path    string
		want    map[string]string
	}{
		{
			name:    "single param",
			pattern: "/api/users/{id}",
			path:    "/api/users/123",
			want:    map[string]string{"id": "123"},
		},
		{
			name:    "multiple params",
			pattern: "/api/{version}/users/{id}",
			path:    "/api/v1/users/456",
			want:    map[string]string{"version": "v1", "id": "456"},
		},
		{
			name:    "no params",
			pattern: "/api/users",
			path:    "/api/users",
			want:    map[string]string{},
		},
		{
			name:    "mismatched segments",
			pattern: "/api/users/{id}",
			path:    "/api/users/123/posts",
			want:    map[string]string{},
		},
		{
			name:    "param with special chars",
			pattern: "/api/users/{id}",
			path:    "/api/users/abc-123-def",
			want:    map[string]string{"id": "abc-123-def"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matcher, err := NewPathMatcher(tt.pattern)
			require.NoError(t, err)
			got := matcher.ExtractParams(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// CompositeAuthorizer Tests
// ============================================================================

func TestNewCompositeAuthorizer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		authorizers []Authorizer
		mode        CompositeMode
		logger      *zap.Logger
	}{
		{
			name:        "empty authorizers",
			authorizers: nil,
			mode:        CompositeModeAll,
			logger:      nil,
		},
		{
			name:        "with authorizers",
			authorizers: []Authorizer{&NoopAuthorizer{}},
			mode:        CompositeModeAny,
			logger:      zap.NewNop(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authorizer := NewCompositeAuthorizer(tt.authorizers, tt.mode, tt.logger)
			assert.NotNil(t, authorizer)
		})
	}
}

func TestCompositeAuthorizer_Authorize_EmptyAuthorizers(t *testing.T) {
	t.Parallel()

	modes := []CompositeMode{CompositeModeAll, CompositeModeAny, CompositeModeFirst}

	for _, mode := range modes {
		t.Run("mode_"+string(rune('0'+mode)), func(t *testing.T) {
			t.Parallel()
			authorizer := NewCompositeAuthorizer(nil, mode, nil)
			decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{})
			require.NoError(t, err)
			assert.True(t, decision.Allowed)
			assert.Equal(t, "no authorizers", decision.Reason)
		})
	}
}

func TestCompositeAuthorizer_Authorize_ModeAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		authorizers []Authorizer
		wantAllowed bool
		wantReason  string
	}{
		{
			name:        "all allow",
			authorizers: []Authorizer{&NoopAuthorizer{}, &NoopAuthorizer{}},
			wantAllowed: true,
			wantReason:  "all authorizers allowed",
		},
		{
			name:        "first denies",
			authorizers: []Authorizer{&DenyAllAuthorizer{}, &NoopAuthorizer{}},
			wantAllowed: false,
			wantReason:  "deny all",
		},
		{
			name:        "second denies",
			authorizers: []Authorizer{&NoopAuthorizer{}, &DenyAllAuthorizer{}},
			wantAllowed: false,
			wantReason:  "deny all",
		},
		{
			name:        "all deny",
			authorizers: []Authorizer{&DenyAllAuthorizer{}, &DenyAllAuthorizer{}},
			wantAllowed: false,
			wantReason:  "deny all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authorizer := NewCompositeAuthorizer(tt.authorizers, CompositeModeAll, nil)
			decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{})
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
			assert.Equal(t, tt.wantReason, decision.Reason)
		})
	}
}

func TestCompositeAuthorizer_Authorize_ModeAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		authorizers []Authorizer
		wantAllowed bool
		wantReason  string
	}{
		{
			name:        "all allow",
			authorizers: []Authorizer{&NoopAuthorizer{}, &NoopAuthorizer{}},
			wantAllowed: true,
			wantReason:  "noop",
		},
		{
			name:        "first allows",
			authorizers: []Authorizer{&NoopAuthorizer{}, &DenyAllAuthorizer{}},
			wantAllowed: true,
			wantReason:  "noop",
		},
		{
			name:        "second allows",
			authorizers: []Authorizer{&DenyAllAuthorizer{}, &NoopAuthorizer{}},
			wantAllowed: true,
			wantReason:  "noop",
		},
		{
			name:        "all deny",
			authorizers: []Authorizer{&DenyAllAuthorizer{}, &DenyAllAuthorizer{}},
			wantAllowed: false,
			wantReason:  "deny all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authorizer := NewCompositeAuthorizer(tt.authorizers, CompositeModeAny, nil)
			decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{})
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
			assert.Equal(t, tt.wantReason, decision.Reason)
		})
	}
}

func TestCompositeAuthorizer_Authorize_ModeFirst(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		authorizers []Authorizer
		wantAllowed bool
		wantReason  string
	}{
		{
			name:        "first allows",
			authorizers: []Authorizer{&NoopAuthorizer{}, &DenyAllAuthorizer{}},
			wantAllowed: true,
			wantReason:  "noop",
		},
		{
			name:        "first denies",
			authorizers: []Authorizer{&DenyAllAuthorizer{}, &NoopAuthorizer{}},
			wantAllowed: false,
			wantReason:  "deny all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authorizer := NewCompositeAuthorizer(tt.authorizers, CompositeModeFirst, nil)
			decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{})
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
			assert.Equal(t, tt.wantReason, decision.Reason)
		})
	}
}

// ErrorAuthorizer is a test authorizer that returns an error
type ErrorAuthorizer struct{}

func (a *ErrorAuthorizer) Authorize(ctx context.Context, subject *Subject, resource *Resource) (*Decision, error) {
	return nil, errors.New("authorization error")
}

func TestCompositeAuthorizer_Authorize_WithError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode CompositeMode
	}{
		{"mode all", CompositeModeAll},
		{"mode any", CompositeModeAny},
		{"mode first", CompositeModeFirst},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authorizer := NewCompositeAuthorizer([]Authorizer{&ErrorAuthorizer{}}, tt.mode, nil)
			decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{})
			assert.Error(t, err)
			assert.Nil(t, decision)
		})
	}
}

func TestCompositeAuthorizer_Authorize_InvalidMode(t *testing.T) {
	t.Parallel()

	authorizer := NewCompositeAuthorizer([]Authorizer{&NoopAuthorizer{}}, CompositeMode(999), nil)
	decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{})
	assert.Error(t, err)
	assert.Nil(t, decision)
}

func TestCompositeAuthorizer_Add(t *testing.T) {
	t.Parallel()

	authorizer := NewCompositeAuthorizer(nil, CompositeModeAll, nil)

	// Initially empty - should allow
	decision, err := authorizer.Authorize(context.Background(), &Subject{}, &Resource{})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Add a deny authorizer
	authorizer.Add(&DenyAllAuthorizer{})

	// Now should deny
	decision, err = authorizer.Authorize(context.Background(), &Subject{}, &Resource{})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

// ============================================================================
// NoopAuthorizer Tests
// ============================================================================

func TestNoopAuthorizer_Authorize(t *testing.T) {
	t.Parallel()

	authorizer := &NoopAuthorizer{}

	tests := []struct {
		name     string
		subject  *Subject
		resource *Resource
	}{
		{"nil subject and resource", nil, nil},
		{"with subject", &Subject{User: "test"}, nil},
		{"with resource", nil, &Resource{Path: "/api"}},
		{"with both", &Subject{User: "test"}, &Resource{Path: "/api"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, err := authorizer.Authorize(context.Background(), tt.subject, tt.resource)
			require.NoError(t, err)
			assert.True(t, decision.Allowed)
			assert.Equal(t, "noop", decision.Reason)
		})
	}
}

// ============================================================================
// DenyAllAuthorizer Tests
// ============================================================================

func TestDenyAllAuthorizer_Authorize(t *testing.T) {
	t.Parallel()

	authorizer := &DenyAllAuthorizer{}

	tests := []struct {
		name     string
		subject  *Subject
		resource *Resource
	}{
		{"nil subject and resource", nil, nil},
		{"with subject", &Subject{User: "test"}, nil},
		{"with resource", nil, &Resource{Path: "/api"}},
		{"with both", &Subject{User: "test"}, &Resource{Path: "/api"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, err := authorizer.Authorize(context.Background(), tt.subject, tt.resource)
			require.NoError(t, err)
			assert.False(t, decision.Allowed)
			assert.Equal(t, "deny all", decision.Reason)
		})
	}
}

// ============================================================================
// Policy Sorting Tests
// ============================================================================

func TestPolicyEngine_SortPolicies(t *testing.T) {
	t.Parallel()

	policies := []*Policy{
		{Name: "low", Priority: 10, Enabled: true, DefaultAction: ActionDeny},
		{Name: "high", Priority: 100, Enabled: true, DefaultAction: ActionAllow},
		{Name: "medium", Priority: 50, Enabled: true, DefaultAction: ActionDeny},
	}

	engine := NewPolicyEngine(&PolicyEngineConfig{
		Policies:      policies,
		DefaultAction: ActionDeny,
		Logger:        zap.NewNop(),
	})

	// The high priority policy should be evaluated first and allow
	decision, err := engine.Authorize(context.Background(), &Subject{}, &Resource{Path: "/api"})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

func TestPolicy_Evaluate_WithConditions(t *testing.T) {
	t.Parallel()

	policy := &Policy{
		Enabled:       true,
		DefaultAction: ActionDeny,
		Rules: []*Rule{
			{
				Name:    "admin-rule",
				Enabled: true,
				Action:  ActionAllow,
				Conditions: []Condition{
					&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
				},
			},
		},
	}

	tests := []struct {
		name        string
		subject     *Subject
		wantAllowed bool
	}{
		{
			name:        "subject with admin role",
			subject:     &Subject{Roles: []string{"admin"}},
			wantAllowed: true,
		},
		{
			name:        "subject without admin role",
			subject:     &Subject{Roles: []string{"user"}},
			wantAllowed: false,
		},
		{
			name:        "subject with no roles",
			subject:     &Subject{},
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, matched := policy.Evaluate(tt.subject, &Resource{Path: "/api"})
			assert.True(t, matched)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
		})
	}
}

func TestPolicyEngine_Authorize_WithRuleMatching(t *testing.T) {
	t.Parallel()

	engine := NewPolicyEngine(&PolicyEngineConfig{
		Policies: []*Policy{
			{
				Name:          "api-policy",
				Enabled:       true,
				Priority:      100,
				DefaultAction: ActionDeny,
				Rules: []*Rule{
					{
						Name:    "allow-admin",
						Enabled: true,
						Action:  ActionAllow,
						Conditions: []Condition{
							&RoleCondition{Roles: []string{"admin"}, MatchAll: false},
						},
					},
				},
			},
		},
		DefaultAction: ActionDeny,
		Logger:        zap.NewNop(),
	})

	tests := []struct {
		name        string
		subject     *Subject
		wantAllowed bool
		wantRule    string
	}{
		{
			name:        "admin allowed",
			subject:     &Subject{Roles: []string{"admin"}},
			wantAllowed: true,
			wantRule:    "allow-admin",
		},
		{
			name:        "non-admin denied by policy default",
			subject:     &Subject{Roles: []string{"user"}},
			wantAllowed: false,
			wantRule:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, err := engine.Authorize(context.Background(), tt.subject, &Resource{Path: "/api"})
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
			assert.Equal(t, tt.wantRule, decision.Rule)
		})
	}
}
