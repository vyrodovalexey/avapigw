// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"strings"
	"testing"
)

// ============================================================================
// ValidationError Tests
// ============================================================================

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ValidationError
		contains []string
	}{
		{
			name: "basic error",
			err: &ValidationError{
				Field:   "spec.hosts[0].port",
				Message: "must be between 1 and 65535",
			},
			contains: []string{"spec.hosts[0].port", "must be between 1 and 65535"},
		},
		{
			name: "error with value",
			err: &ValidationError{
				Field:   "spec.timeout",
				Message: "invalid duration format",
				Value:   "invalid",
			},
			contains: []string{"spec.timeout", "invalid duration format", "got: invalid"},
		},
		{
			name: "error with suggestion",
			err: &ValidationError{
				Field:      "spec.hosts",
				Message:    "is required",
				Suggestion: "Please provide at least one host",
			},
			contains: []string{"spec.hosts", "is required", "Please provide at least one host"},
		},
		{
			name: "error with all fields",
			err: &ValidationError{
				Field:      "spec.port",
				Message:    "must be between 1 and 65535",
				Value:      70000,
				Suggestion: "Use a port number in the valid range",
			},
			contains: []string{"spec.port", "must be between 1 and 65535", "got: 70000", "Use a port number"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("Error() = %q, should contain %q", result, substr)
				}
			}
		})
	}
}

// ============================================================================
// ValidationErrors Collection Tests
// ============================================================================

func TestNewValidationErrors(t *testing.T) {
	errs := NewValidationErrors()
	if errs == nil {
		t.Fatal("NewValidationErrors() returned nil")
	}
	if errs.HasErrors() {
		t.Error("NewValidationErrors() should return empty collection")
	}
	if errs.Count() != 0 {
		t.Errorf("NewValidationErrors() Count() = %d, want 0", errs.Count())
	}
}

func TestValidationErrors_Add(t *testing.T) {
	errs := NewValidationErrors()
	errs.Add("spec.hosts", "is required")

	if !errs.HasErrors() {
		t.Error("HasErrors() should return true after Add()")
	}
	if errs.Count() != 1 {
		t.Errorf("Count() = %d, want 1", errs.Count())
	}

	errors := errs.Errors()
	if len(errors) != 1 {
		t.Fatalf("Errors() returned %d errors, want 1", len(errors))
	}
	if errors[0].Field != "spec.hosts" {
		t.Errorf("Field = %q, want %q", errors[0].Field, "spec.hosts")
	}
	if errors[0].Message != "is required" {
		t.Errorf("Message = %q, want %q", errors[0].Message, "is required")
	}
}

func TestValidationErrors_AddWithValue(t *testing.T) {
	errs := NewValidationErrors()
	errs.AddWithValue("spec.port", "must be positive", -1)

	if errs.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", errs.Count())
	}

	errors := errs.Errors()
	if errors[0].Value != -1 {
		t.Errorf("Value = %v, want %v", errors[0].Value, -1)
	}
}

func TestValidationErrors_AddWithSuggestion(t *testing.T) {
	errs := NewValidationErrors()
	errs.AddWithSuggestion("spec.timeout", "invalid format", "Use format like '30s' or '5m'")

	if errs.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", errs.Count())
	}

	errors := errs.Errors()
	if errors[0].Suggestion != "Use format like '30s' or '5m'" {
		t.Errorf("Suggestion = %q, want %q", errors[0].Suggestion, "Use format like '30s' or '5m'")
	}
}

func TestValidationErrors_AddFull(t *testing.T) {
	errs := NewValidationErrors()
	errs.AddFull("spec.weight", "must be between 0 and 100", 150, "Use a value in the range [0, 100]")

	if errs.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", errs.Count())
	}

	errors := errs.Errors()
	if errors[0].Field != "spec.weight" {
		t.Errorf("Field = %q, want %q", errors[0].Field, "spec.weight")
	}
	if errors[0].Message != "must be between 0 and 100" {
		t.Errorf("Message = %q, want %q", errors[0].Message, "must be between 0 and 100")
	}
	if errors[0].Value != 150 {
		t.Errorf("Value = %v, want %v", errors[0].Value, 150)
	}
	if errors[0].Suggestion != "Use a value in the range [0, 100]" {
		t.Errorf("Suggestion = %q, want %q", errors[0].Suggestion, "Use a value in the range [0, 100]")
	}
}

func TestValidationErrors_AddError(t *testing.T) {
	errs := NewValidationErrors()
	err := &ValidationError{
		Field:   "spec.hosts[0].address",
		Message: "is required",
	}
	errs.AddError(err)

	if errs.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", errs.Count())
	}

	errors := errs.Errors()
	if errors[0] != err {
		t.Error("AddError() should add the exact error instance")
	}
}

func TestValidationErrors_Error_Empty(t *testing.T) {
	errs := NewValidationErrors()
	result := errs.Error()
	if result != "" {
		t.Errorf("Error() on empty collection = %q, want empty string", result)
	}
}

func TestValidationErrors_Error_SingleError(t *testing.T) {
	errs := NewValidationErrors()
	errs.Add("spec.hosts", "is required")

	result := errs.Error()
	if !strings.Contains(result, "spec.hosts") {
		t.Errorf("Error() = %q, should contain field name", result)
	}
	if !strings.Contains(result, "is required") {
		t.Errorf("Error() = %q, should contain message", result)
	}
}

func TestValidationErrors_Error_MultipleErrors(t *testing.T) {
	errs := NewValidationErrors()
	errs.Add("spec.hosts", "is required")
	errs.Add("spec.port", "must be positive")
	errs.Add("spec.timeout", "invalid format")

	result := errs.Error()
	if !strings.Contains(result, "3 errors") {
		t.Errorf("Error() = %q, should mention error count", result)
	}
	if !strings.Contains(result, "spec.hosts") {
		t.Errorf("Error() = %q, should contain first field", result)
	}
	if !strings.Contains(result, "spec.port") {
		t.Errorf("Error() = %q, should contain second field", result)
	}
	if !strings.Contains(result, "spec.timeout") {
		t.Errorf("Error() = %q, should contain third field", result)
	}
}

func TestValidationErrors_ToError_NoErrors(t *testing.T) {
	errs := NewValidationErrors()
	result := errs.ToError()
	if result != nil {
		t.Errorf("ToError() on empty collection = %v, want nil", result)
	}
}

func TestValidationErrors_ToError_WithErrors(t *testing.T) {
	errs := NewValidationErrors()
	errs.Add("spec.hosts", "is required")

	result := errs.ToError()
	if result == nil {
		t.Fatal("ToError() with errors should not return nil")
	}
	if result != errs {
		t.Error("ToError() should return the ValidationErrors instance")
	}
}

// ============================================================================
// FieldPath Tests
// ============================================================================

func TestNewFieldPath(t *testing.T) {
	tests := []struct {
		name string
		root []string
		want string
	}{
		{
			name: "empty root",
			root: nil,
			want: "",
		},
		{
			name: "single root",
			root: []string{"spec"},
			want: "spec",
		},
		{
			name: "multiple roots",
			root: []string{"spec", "hosts"},
			want: "spec.hosts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := NewFieldPath(tt.root...)
			result := fp.String()
			if result != tt.want {
				t.Errorf("NewFieldPath(%v).String() = %q, want %q", tt.root, result, tt.want)
			}
		})
	}
}

func TestFieldPath_Child(t *testing.T) {
	tests := []struct {
		name  string
		root  []string
		child string
		want  string
	}{
		{
			name:  "child from empty",
			root:  nil,
			child: "spec",
			want:  "spec",
		},
		{
			name:  "child from single",
			root:  []string{"spec"},
			child: "hosts",
			want:  "spec.hosts",
		},
		{
			name:  "child from multiple",
			root:  []string{"spec", "hosts"},
			child: "address",
			want:  "spec.hosts.address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := NewFieldPath(tt.root...)
			result := fp.Child(tt.child).String()
			if result != tt.want {
				t.Errorf("Child(%q).String() = %q, want %q", tt.child, result, tt.want)
			}
		})
	}
}

func TestFieldPath_Index(t *testing.T) {
	tests := []struct {
		name  string
		root  []string
		index int
		want  string
	}{
		{
			name:  "index from empty",
			root:  nil,
			index: 0,
			want:  "[0]",
		},
		{
			name:  "index from single",
			root:  []string{"hosts"},
			index: 0,
			want:  "hosts[0]",
		},
		{
			name:  "index from multiple",
			root:  []string{"spec", "hosts"},
			index: 2,
			want:  "spec.hosts[2]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := NewFieldPath(tt.root...)
			result := fp.Index(tt.index).String()
			if result != tt.want {
				t.Errorf("Index(%d).String() = %q, want %q", tt.index, result, tt.want)
			}
		})
	}
}

func TestFieldPath_Key(t *testing.T) {
	tests := []struct {
		name string
		root []string
		key  string
		want string
	}{
		{
			name: "key from empty",
			root: nil,
			key:  "mykey",
			want: `["mykey"]`,
		},
		{
			name: "key from single",
			root: []string{"metadata"},
			key:  "name",
			want: `metadata["name"]`,
		},
		{
			name: "key from multiple",
			root: []string{"spec", "labels"},
			key:  "app",
			want: `spec.labels["app"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := NewFieldPath(tt.root...)
			result := fp.Key(tt.key).String()
			if result != tt.want {
				t.Errorf("Key(%q).String() = %q, want %q", tt.key, result, tt.want)
			}
		})
	}
}

func TestFieldPath_Chaining(t *testing.T) {
	fp := NewFieldPath("spec").Child("hosts").Index(0).Child("port")
	result := fp.String()
	want := "spec.hosts[0].port"
	if result != want {
		t.Errorf("Chained path = %q, want %q", result, want)
	}
}

func TestFieldPath_Immutability(t *testing.T) {
	fp1 := NewFieldPath("spec")
	fp2 := fp1.Child("hosts")
	fp3 := fp1.Child("timeout")

	if fp1.String() != "spec" {
		t.Errorf("Original path modified: %q", fp1.String())
	}
	if fp2.String() != "spec.hosts" {
		t.Errorf("First child path wrong: %q", fp2.String())
	}
	if fp3.String() != "spec.timeout" {
		t.Errorf("Second child path wrong: %q", fp3.String())
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestNewRequiredError(t *testing.T) {
	err := NewRequiredError("spec.hosts")

	if err.Field != "spec.hosts" {
		t.Errorf("Field = %q, want %q", err.Field, "spec.hosts")
	}
	if err.Message != ErrRequired {
		t.Errorf("Message = %q, want %q", err.Message, ErrRequired)
	}
	if err.Suggestion == "" {
		t.Error("Suggestion should not be empty")
	}
}

func TestNewRangeError(t *testing.T) {
	err := NewRangeError("spec.port", 70000, 1, 65535)

	if err.Field != "spec.port" {
		t.Errorf("Field = %q, want %q", err.Field, "spec.port")
	}
	if err.Value != 70000 {
		t.Errorf("Value = %v, want %v", err.Value, 70000)
	}
	if !strings.Contains(err.Message, "1") || !strings.Contains(err.Message, "65535") {
		t.Errorf("Message = %q, should contain range values", err.Message)
	}
	if !strings.Contains(err.Suggestion, "1") || !strings.Contains(err.Suggestion, "65535") {
		t.Errorf("Suggestion = %q, should contain range values", err.Suggestion)
	}
}

func TestNewEnumError(t *testing.T) {
	validValues := []string{"GET", "POST", "PUT", "DELETE"}
	err := NewEnumError("spec.method", "INVALID", validValues)

	if err.Field != "spec.method" {
		t.Errorf("Field = %q, want %q", err.Field, "spec.method")
	}
	if err.Value != "INVALID" {
		t.Errorf("Value = %v, want %v", err.Value, "INVALID")
	}
	for _, v := range validValues {
		if !strings.Contains(err.Message, v) {
			t.Errorf("Message = %q, should contain %q", err.Message, v)
		}
	}
}

func TestNewFormatError(t *testing.T) {
	err := NewFormatError("spec.timeout", "invalid", "30s, 5m, 1h")

	if err.Field != "spec.timeout" {
		t.Errorf("Field = %q, want %q", err.Field, "spec.timeout")
	}
	if err.Value != "invalid" {
		t.Errorf("Value = %v, want %v", err.Value, "invalid")
	}
	if !strings.Contains(err.Message, "30s, 5m, 1h") {
		t.Errorf("Message = %q, should contain expected format", err.Message)
	}
}

func TestNewConflictError(t *testing.T) {
	err := NewConflictError("spec.redirect", "spec.route")

	if err.Field != "spec.redirect" {
		t.Errorf("Field = %q, want %q", err.Field, "spec.redirect")
	}
	if !strings.Contains(err.Message, "spec.route") {
		t.Errorf("Message = %q, should contain conflicting field", err.Message)
	}
	if !strings.Contains(err.Suggestion, "spec.redirect") || !strings.Contains(err.Suggestion, "spec.route") {
		t.Errorf("Suggestion = %q, should contain both fields", err.Suggestion)
	}
}

func TestNewDependencyError(t *testing.T) {
	err := NewDependencyError("spec.tls.certFile", "spec.tls.keyFile")

	if err.Field != "spec.tls.certFile" {
		t.Errorf("Field = %q, want %q", err.Field, "spec.tls.certFile")
	}
	if !strings.Contains(err.Message, "spec.tls.keyFile") {
		t.Errorf("Message = %q, should contain dependency field", err.Message)
	}
	if !strings.Contains(err.Suggestion, "spec.tls.keyFile") {
		t.Errorf("Suggestion = %q, should contain dependency field", err.Suggestion)
	}
}

// ============================================================================
// Error Constants Tests
// ============================================================================

func TestErrorConstants(t *testing.T) {
	// Verify error constants are non-empty
	constants := map[string]string{
		"ErrRequired":          ErrRequired,
		"ErrMustBePositive":    ErrMustBePositive,
		"ErrMustBeNonNegative": ErrMustBeNonNegative,
		"ErrInvalidFormat":     ErrInvalidFormat,
		"ErrOutOfRange":        ErrOutOfRange,
		"ErrInvalidValue":      ErrInvalidValue,
		"ErrMutuallyExclusive": ErrMutuallyExclusive,
		"ErrConflict":          ErrConflict,
	}

	for name, value := range constants {
		if value == "" {
			t.Errorf("%s should not be empty", name)
		}
	}
}

// ============================================================================
// Table-Driven Tests
// ============================================================================

func TestValidationErrors_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*ValidationErrors)
		wantCount  int
		wantErrors bool
	}{
		{
			name:       "empty collection",
			setup:      func(v *ValidationErrors) {},
			wantCount:  0,
			wantErrors: false,
		},
		{
			name: "single error",
			setup: func(v *ValidationErrors) {
				v.Add("field1", "error1")
			},
			wantCount:  1,
			wantErrors: true,
		},
		{
			name: "multiple errors",
			setup: func(v *ValidationErrors) {
				v.Add("field1", "error1")
				v.AddWithValue("field2", "error2", 123)
				v.AddWithSuggestion("field3", "error3", "suggestion")
			},
			wantCount:  3,
			wantErrors: true,
		},
		{
			name: "mixed error types",
			setup: func(v *ValidationErrors) {
				v.Add("field1", "error1")
				v.AddError(NewRequiredError("field2"))
				v.AddFull("field3", "error3", "value", "suggestion")
			},
			wantCount:  3,
			wantErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := NewValidationErrors()
			tt.setup(errs)

			if errs.Count() != tt.wantCount {
				t.Errorf("Count() = %d, want %d", errs.Count(), tt.wantCount)
			}
			if errs.HasErrors() != tt.wantErrors {
				t.Errorf("HasErrors() = %v, want %v", errs.HasErrors(), tt.wantErrors)
			}
		})
	}
}
