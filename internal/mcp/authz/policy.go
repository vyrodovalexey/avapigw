package authz

import "context"

// PolicyEngine is the deny-by-default authorization policy keyed on
// (principal, upstream, primitive, method) (HUB-310). It is independent of
// upstream-supplied annotations, which are untrusted input.
type PolicyEngine interface {
	// Decide returns whether the request is allowed and a human-readable
	// reason for the decision (used in audit logs).
	Decide(ctx context.Context, principal, upstream, primitive, method string) (allow bool, reason string)
}

// AllowAllPolicy permits every request. It is the default when the policy
// engine is not enabled, so authorization remains additive/opt-in.
type AllowAllPolicy struct{}

// Decide always allows. The parameters are unused because this policy applies
// no restrictions; it exists so a nil-safe default engine is always present.
func (AllowAllPolicy) Decide(
	_ context.Context, _, _, _, _ string,
) (allow bool, reason string) {
	return true, "policy disabled"
}

// PolicyRule matches a request tuple. Empty fields are wildcards. A request is
// allowed when it matches at least one rule (deny-by-default otherwise).
type PolicyRule struct {
	// Principal matches the authenticated subject ("" = any).
	Principal string
	// Upstream matches the upstream id ("" = any).
	Upstream string
	// Primitive matches the de-namespaced primitive name ("" = any).
	Primitive string
	// Method matches the MCP method ("" = any).
	Method string
}

// matches reports whether the rule matches the request tuple.
func (r PolicyRule) matches(principal, upstream, primitive, method string) bool {
	if r.Principal != "" && r.Principal != principal {
		return false
	}
	if r.Upstream != "" && r.Upstream != upstream {
		return false
	}
	if r.Primitive != "" && r.Primitive != primitive {
		return false
	}
	if r.Method != "" && r.Method != method {
		return false
	}
	return true
}

// DenyByDefaultPolicy allows a request only when it matches an explicit allow
// rule; every unmatched request is denied (HUB-310).
type DenyByDefaultPolicy struct {
	allow []PolicyRule
}

// NewDenyByDefaultPolicy constructs a deny-by-default engine from allow rules.
// With no rules every request is denied.
func NewDenyByDefaultPolicy(allow []PolicyRule) *DenyByDefaultPolicy {
	return &DenyByDefaultPolicy{allow: allow}
}

// Decide allows the request only when it matches an allow rule.
func (p *DenyByDefaultPolicy) Decide(
	_ context.Context, principal, upstream, primitive, method string,
) (allow bool, reason string) {
	for _, rule := range p.allow {
		if rule.matches(principal, upstream, primitive, method) {
			return true, "matched allow rule"
		}
	}
	return false, "no allow rule matched (deny by default)"
}
