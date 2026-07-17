// Package webhook contains regression tests ensuring admission validation is
// no stricter than the data plane: mTLS without caFile (vault-managed CA) is
// admitted with a warning, and ABAC CEL expressions are compiled against the
// gateway's runtime CEL environment.
package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// newValidAPIRouteBase returns a minimal valid APIRoute for validator tests.
func newValidAPIRouteBase(name string) *avapigwv1alpha1.APIRoute {
	return &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/" + name}},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080},
					Weight:      100,
				},
			},
		},
	}
}

// hasWarningContaining reports whether any warning contains the substring.
func hasWarningContaining(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// TestWarnMTLSMissingCAFile exercises the mTLS caFile warning helper.
func TestWarnMTLSMissingCAFile(t *testing.T) {
	tests := []struct {
		name        string
		auth        *avapigwv1alpha1.AuthenticationConfig
		wantWarning bool
	}{
		{"nil auth", nil, false},
		{"nil mtls", &avapigwv1alpha1.AuthenticationConfig{Enabled: true}, false},
		{
			"mtls disabled",
			&avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				MTLS:    &avapigwv1alpha1.MTLSAuthConfig{Enabled: false},
			},
			false,
		},
		{
			"mtls with caFile",
			&avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				MTLS:    &avapigwv1alpha1.MTLSAuthConfig{Enabled: true, CAFile: "/certs/ca.crt"},
			},
			false,
		},
		{
			"mtls without caFile warns",
			&avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				MTLS:    &avapigwv1alpha1.MTLSAuthConfig{Enabled: true},
			},
			true,
		},
		{
			"mtls vault-managed style (enabled + extractIdentity) warns",
			&avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				MTLS: &avapigwv1alpha1.MTLSAuthConfig{
					Enabled:         true,
					ExtractIdentity: "cn",
				},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := warnMTLSMissingCAFile(tt.auth)
			if tt.wantWarning && len(warnings) == 0 {
				t.Error("warnMTLSMissingCAFile() expected a warning, got none")
			}
			if !tt.wantWarning && len(warnings) > 0 {
				t.Errorf("warnMTLSMissingCAFile() expected no warning, got %v", warnings)
			}
		})
	}
}

// TestAPIRouteValidator_MTLSWithoutCAFile_AdmittedWithWarning is the
// regression test for the previously-rejected valid CR pattern
// {enabled, extractIdentity} with a vault-managed CA.
func TestAPIRouteValidator_MTLSWithoutCAFile_AdmittedWithWarning(t *testing.T) {
	validator := &APIRouteValidator{}

	route := newValidAPIRouteBase("mtls-vault-ca")
	route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
		Enabled: true,
		MTLS: &avapigwv1alpha1.MTLSAuthConfig{
			Enabled:         true,
			ExtractIdentity: "cn",
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Fatalf("ValidateCreate() must admit mtls without caFile (vault-managed CA), got error: %v", err)
	}
	if !hasWarningContaining(warnings, "caFile") {
		t.Errorf("ValidateCreate() must warn about the missing caFile, warnings = %v", warnings)
	}

	// Update path behaves identically.
	warnings, err = validator.ValidateUpdate(context.Background(), route, route)
	if err != nil {
		t.Fatalf("ValidateUpdate() must admit mtls without caFile, got error: %v", err)
	}
	if !hasWarningContaining(warnings, "caFile") {
		t.Errorf("ValidateUpdate() must warn about the missing caFile, warnings = %v", warnings)
	}
}

// TestAPIRouteValidator_MTLSBareEnabled_AdmittedWithWarning verifies the
// minimal {enabled: true} mTLS config is admitted (validated sensibly via the
// warning) rather than rejected.
func TestAPIRouteValidator_MTLSBareEnabled_AdmittedWithWarning(t *testing.T) {
	validator := &APIRouteValidator{}

	route := newValidAPIRouteBase("mtls-bare")
	route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
		Enabled: true,
		MTLS:    &avapigwv1alpha1.MTLSAuthConfig{Enabled: true},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Fatalf("ValidateCreate() must admit bare-enabled mtls, got error: %v", err)
	}
	if !hasWarningContaining(warnings, "caFile") {
		t.Errorf("ValidateCreate() must warn about the missing caFile, warnings = %v", warnings)
	}
}

// TestAPIRouteValidator_MTLSInvalidExtractIdentity_StillRejected verifies the
// remaining hard mTLS validation is intact.
func TestAPIRouteValidator_MTLSInvalidExtractIdentity_StillRejected(t *testing.T) {
	validator := &APIRouteValidator{}

	route := newValidAPIRouteBase("mtls-bad-extract")
	route.Spec.Authentication = &avapigwv1alpha1.AuthenticationConfig{
		Enabled: true,
		MTLS: &avapigwv1alpha1.MTLSAuthConfig{
			Enabled:         true,
			ExtractIdentity: "spiffe",
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() must reject an invalid extractIdentity value")
	}
}

// TestAPIRouteValidator_ABACSubjectExpression_Admitted is the regression test
// for CEL environment parity: expressions referencing 'subject' (declared at
// gateway runtime) were previously rejected with "undeclared reference".
func TestAPIRouteValidator_ABACSubjectExpression_Admitted(t *testing.T) {
	validator := &APIRouteValidator{}

	route := newValidAPIRouteBase("abac-subject")
	route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
		Enabled:       true,
		DefaultPolicy: "deny",
		ABAC: &avapigwv1alpha1.ABACConfig{
			Enabled: true,
			Policies: []avapigwv1alpha1.ABACPolicyConfig{
				{
					Name:       "subject-admin",
					Expression: "subject.roles.exists(r, r == 'admin')",
					Effect:     "allow",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Fatalf("ValidateCreate() must admit runtime-valid 'subject' CEL expression, got: %v", err)
	}
}

// TestAPIRouteValidator_ABACInvalidExpression_StillRejected verifies that
// genuinely invalid CEL (syntax error / undeclared variable) is still rejected.
func TestAPIRouteValidator_ABACInvalidExpression_StillRejected(t *testing.T) {
	validator := &APIRouteValidator{}

	tests := []struct {
		name string
		expr string
	}{
		{"syntax error", "subject.role =="},
		{"undeclared variable", "bogus_variable == 'x'"},
		{"identity not declared at runtime", "identity.role == 'admin'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := newValidAPIRouteBase("abac-invalid")
			route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				ABAC: &avapigwv1alpha1.ABACConfig{
					Enabled: true,
					Policies: []avapigwv1alpha1.ABACPolicyConfig{
						{Name: "bad", Expression: tt.expr, Effect: "allow"},
					},
				},
			}

			_, err := validator.ValidateCreate(context.Background(), route)
			if err == nil {
				t.Errorf("ValidateCreate() must reject invalid CEL expression %q", tt.expr)
			}
		})
	}
}

// TestValidateCELExpression_RuntimeEnvParity compiles a set of expressions
// straight through the shared helper to pin the webhook/runtime environment
// contract.
func TestValidateCELExpression_RuntimeEnvParity(t *testing.T) {
	valid := []string{
		"subject.name == 'alice'",
		"request.method == 'GET'",
		"resource == 'orders'",
		"action == 'read'",
		"environment.env == 'prod'",
		"now < timestamp('2100-01-01T00:00:00Z')",
		"ip_in_range('10.1.2.3', '10.0.0.0/8')",
		"has_role('admin')",
	}
	for _, expr := range valid {
		if err := validateCELExpression(expr); err != nil {
			t.Errorf("validateCELExpression(%q) must be valid, got: %v", expr, err)
		}
	}

	invalid := []string{
		"identity.name == 'alice'", // runtime variable is 'subject'
		"resource.owner == 'me'",   // resource is a string at runtime
		"subject.name ==",          // syntax error
	}
	for _, expr := range invalid {
		if err := validateCELExpression(expr); err == nil {
			t.Errorf("validateCELExpression(%q) must be rejected", expr)
		}
	}
}
