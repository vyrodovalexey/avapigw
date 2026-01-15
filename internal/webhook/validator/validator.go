// Package validator provides validation logic for CRD webhooks.
package validator

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Validator interface for all CRD validators
type Validator interface {
	// ValidateSyntax performs syntax validation on the object
	ValidateSyntax(obj interface{}) error

	// ValidateSemantics performs semantic validation on the object
	ValidateSemantics(obj interface{}) error

	// CheckDuplicates checks for duplicate resources across namespaces
	CheckDuplicates(ctx context.Context, client client.Client, obj interface{}) error

	// ValidateReferences validates cross-resource references
	ValidateReferences(ctx context.Context, client client.Client, obj interface{}) error
}

// BaseValidator provides common validation functionality
type BaseValidator struct {
	Client client.Client
}

// NewBaseValidator creates a new BaseValidator
func NewBaseValidator(c client.Client) *BaseValidator {
	return &BaseValidator{
		Client: c,
	}
}
