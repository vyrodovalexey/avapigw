package openapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ValidationError represents a structured validation error.
type ValidationError struct {
	// Field is the field that failed validation (e.g., "body.name", "query.limit").
	Field string

	// Message is a human-readable error message.
	Message string

	// ErrorType categorizes the error (e.g., "body", "params", "headers", "security").
	ErrorType string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors struct {
	Errors []ValidationError
}

// Error implements the error interface.
func (e *ValidationErrors) Error() string {
	if len(e.Errors) == 0 {
		return "no validation errors"
	}
	if len(e.Errors) == 1 {
		return e.Errors[0].Error()
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d validation errors: ", len(e.Errors))
	for i, err := range e.Errors {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(err.Error())
	}
	return sb.String()
}

// Option is a functional option for configuring a Validator.
type Option func(*Validator)

// WithLoader sets the spec loader for the validator.
func WithLoader(loader Loader) Option {
	return func(v *Validator) {
		v.loader = loader
	}
}

// WithSpecFile sets the OpenAPI spec file path.
func WithSpecFile(path string) Option {
	return func(v *Validator) {
		v.specFile = path
	}
}

// WithSpecURL sets the OpenAPI spec URL.
func WithSpecURL(specURL string) Option {
	return func(v *Validator) {
		v.specURL = specURL
	}
}

// WithFailOnError sets whether to reject requests that fail validation.
func WithFailOnError(failOnError bool) Option {
	return func(v *Validator) {
		v.failOnError = failOnError
	}
}

// WithValidateBody enables or disables request body validation.
func WithValidateBody(validate bool) Option {
	return func(v *Validator) {
		v.validateBody = validate
	}
}

// WithValidateParams enables or disables request parameter validation.
func WithValidateParams(validate bool) Option {
	return func(v *Validator) {
		v.validateParams = validate
	}
}

// WithValidateHeaders enables or disables request header validation.
func WithValidateHeaders(validate bool) Option {
	return func(v *Validator) {
		v.validateHeaders = validate
	}
}

// WithValidateSecurity enables or disables security requirement validation.
func WithValidateSecurity(validate bool) Option {
	return func(v *Validator) {
		v.validateSecurity = validate
	}
}

// WithLogger sets the logger for the validator.
func WithLogger(logger observability.Logger) Option {
	return func(v *Validator) {
		v.logger = logger
	}
}

// WithMetrics sets the metrics collector for the validator.
func WithMetrics(metrics *Metrics) Option {
	return func(v *Validator) {
		v.metrics = metrics
	}
}

// Validator validates HTTP requests against an OpenAPI specification.
type Validator struct {
	loader           Loader
	specFile         string
	specURL          string
	failOnError      bool
	validateBody     bool
	validateParams   bool
	validateHeaders  bool
	validateSecurity bool
	logger           observability.Logger
	metrics          *Metrics
	doc              *openapi3.T
	router           routers.Router
}

// NewValidator creates a new Validator with the given options.
// It loads the OpenAPI spec and prepares the router for request matching.
func NewValidator(opts ...Option) (*Validator, error) {
	v := &Validator{
		failOnError:    true,
		validateBody:   true,
		validateParams: true,
		// Headers and security validation are off by default.
	}

	for _, opt := range opts {
		opt(v)
	}

	if v.logger == nil {
		v.logger = observability.NopLogger()
	}

	if v.loader == nil {
		v.loader = NewSpecLoader()
	}

	if err := v.loadSpec(); err != nil {
		return nil, err
	}

	return v, nil
}

// NewValidatorFromConfig creates a Validator from an OpenAPIValidationConfig.
func NewValidatorFromConfig(
	cfg *config.OpenAPIValidationConfig,
	logger observability.Logger,
	metrics *Metrics,
) (*Validator, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil //nolint:nilnil // nil validator means validation is disabled
	}

	opts := []Option{
		WithFailOnError(cfg.GetEffectiveFailOnError()),
		WithValidateBody(cfg.GetEffectiveValidateRequestBody()),
		WithValidateParams(cfg.GetEffectiveValidateRequestParams()),
		WithValidateHeaders(cfg.GetEffectiveValidateRequestHeaders()),
		WithValidateSecurity(cfg.GetEffectiveValidateSecurity()),
	}

	if logger != nil {
		opts = append(opts, WithLogger(logger))
	}

	if metrics != nil {
		opts = append(opts, WithMetrics(metrics))
	}

	if cfg.SpecFile != "" {
		opts = append(opts, WithSpecFile(cfg.SpecFile))
	}

	if cfg.SpecURL != "" {
		opts = append(opts, WithSpecURL(cfg.SpecURL))
	}

	return NewValidator(opts...)
}

// loadSpec loads the OpenAPI specification from the configured source.
func (v *Validator) loadSpec() error {
	ctx := context.Background()

	var err error
	switch {
	case v.specFile != "":
		v.doc, err = v.loader.LoadFromFile(ctx, v.specFile)
	case v.specURL != "":
		v.doc, err = v.loader.LoadFromURL(ctx, v.specURL)
	default:
		return errors.New("either specFile or specURL must be configured")
	}

	if err != nil {
		return fmt.Errorf("failed to load OpenAPI spec: %w", err)
	}

	v.router, err = gorillamux.NewRouter(v.doc)
	if err != nil {
		return fmt.Errorf("failed to create OpenAPI router: %w", err)
	}

	return nil
}

// Reload invalidates the cached spec and reloads it.
// This supports hot-reload when spec files change.
func (v *Validator) Reload() error {
	key := v.specFile
	if key == "" {
		key = v.specURL
	}
	v.loader.Invalidate(key)
	return v.loadSpec()
}

// ValidateRequest validates an HTTP request against the OpenAPI specification.
// Returns nil if the request is valid or if the request path is not defined in the spec.
func (v *Validator) ValidateRequest(ctx context.Context, req *http.Request) error {
	if v.router == nil || v.doc == nil {
		return nil
	}

	route, pathParams, findErr := v.router.FindRoute(req)
	if findErr != nil {
		// Route not found in spec — skip validation for unmatched routes.
		// This is intentional: we only validate paths defined in the spec.
		v.logger.Debug("request path not found in OpenAPI spec, skipping validation",
			observability.String("path", req.URL.Path),
			observability.String("method", req.Method),
			observability.String("reason", findErr.Error()),
		)
		return nil
	}

	input := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
		Options:    v.buildFilterOptions(),
	}

	if err := openapi3filter.ValidateRequest(ctx, input); err != nil {
		return v.convertValidationError(err)
	}

	return nil
}

// FailOnError returns whether the validator is configured to reject invalid requests.
func (v *Validator) FailOnError() bool {
	return v.failOnError
}

// buildFilterOptions creates openapi3filter options based on validator configuration.
func (v *Validator) buildFilterOptions() *openapi3filter.Options {
	opts := &openapi3filter.Options{}

	if !v.validateBody {
		opts.ExcludeRequestBody = true
	}

	if !v.validateParams {
		opts.ExcludeRequestQueryParams = true
	}

	if !v.validateSecurity {
		opts.AuthenticationFunc = openapi3filter.NoopAuthenticationFunc
	}

	return opts
}

// convertValidationError converts an openapi3filter error into structured ValidationErrors.
func (v *Validator) convertValidationError(err error) *ValidationErrors {
	var validationErrs ValidationErrors

	var requestErr *openapi3filter.RequestError
	if errors.As(err, &requestErr) {
		field := ""
		if requestErr.Parameter != nil {
			field = requestErr.Parameter.Name
		}
		validationErrs.Errors = append(validationErrs.Errors, ValidationError{
			Field:     field,
			Message:   requestErr.Error(),
			ErrorType: classifyRequestError(requestErr),
		})
		return &validationErrs
	}

	var securityErr *openapi3filter.SecurityRequirementsError
	if errors.As(err, &securityErr) {
		validationErrs.Errors = append(validationErrs.Errors, ValidationError{
			Message:   securityErr.Error(),
			ErrorType: "security",
		})
		return &validationErrs
	}

	// Fallback for other error types.
	validationErrs.Errors = append(validationErrs.Errors, ValidationError{
		Message:   err.Error(),
		ErrorType: "unknown",
	})
	return &validationErrs
}

// classifyRequestError determines the error type from a RequestError.
func classifyRequestError(err *openapi3filter.RequestError) string {
	if err.Parameter != nil {
		switch err.Parameter.In {
		case "query", "path":
			return "params"
		case "header":
			return "headers"
		}
	}
	return "body"
}
