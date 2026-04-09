package openapi

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// validationErrorResponse is the JSON response body for validation errors.
type validationErrorResponse struct {
	Error   string             `json:"error"`
	Details []validationDetail `json:"details,omitempty"`
}

// validationDetail is a single validation error detail.
type validationDetail struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
	Type    string `json:"type,omitempty"`
}

// Middleware creates an HTTP middleware that validates requests against an OpenAPI spec.
// If validator is nil, the middleware is a no-op passthrough.
func Middleware(validator *Validator) func(http.Handler) http.Handler {
	if validator == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			routeLabel := r.URL.Path

			err := validator.ValidateRequest(r.Context(), r)
			durationSec := time.Since(start).Seconds()

			if err != nil {
				handleValidationError(validator, w, r, err, routeLabel, durationSec)
				return
			}

			if validator.metrics != nil {
				validator.metrics.RecordSuccess(routeLabel, durationSec)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// MiddlewareFromConfig creates an OpenAPI validation middleware from configuration.
// Returns a no-op middleware if validation is not enabled or configuration is invalid.
func MiddlewareFromConfig(
	cfg *config.OpenAPIValidationConfig,
	logger observability.Logger,
) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	if logger == nil {
		logger = observability.NopLogger()
	}

	validator, err := NewValidatorFromConfig(cfg, logger, nil)
	if err != nil {
		logger.Error("failed to create OpenAPI validator, skipping validation",
			observability.Error(err),
		)
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return Middleware(validator)
}

// handleValidationError handles a validation error by either rejecting the request
// or logging the error and allowing the request through, depending on configuration.
func handleValidationError(
	validator *Validator,
	w http.ResponseWriter,
	r *http.Request,
	err error,
	routeLabel string,
	durationSec float64,
) {
	var valErrs *ValidationErrors
	var errorType string

	//nolint:errorlint // type assertion is intentional for structured error handling
	if ve, ok := err.(*ValidationErrors); ok {
		valErrs = ve
		if len(ve.Errors) > 0 {
			errorType = ve.Errors[0].ErrorType
		}
	} else {
		errorType = "unknown"
	}

	if validator.metrics != nil {
		validator.metrics.RecordFailure(routeLabel, errorType, durationSec)
	}

	if validator.failOnError {
		validator.logger.Warn("OpenAPI request validation failed",
			observability.String("path", r.URL.Path),
			observability.String("method", r.Method),
			observability.String("error", err.Error()),
		)
		writeValidationErrorResponse(w, valErrs, err)
		return
	}

	// Log-only mode: log the error but allow the request through.
	validator.logger.Debug("OpenAPI request validation error (non-blocking)",
		observability.String("path", r.URL.Path),
		observability.String("method", r.Method),
		observability.String("error", err.Error()),
	)
}

// writeValidationErrorResponse writes a 400 Bad Request response with validation error details.
func writeValidationErrorResponse(w http.ResponseWriter, valErrs *ValidationErrors, fallbackErr error) {
	resp := validationErrorResponse{
		Error: "request validation failed",
	}

	if valErrs != nil {
		for _, ve := range valErrs.Errors {
			resp.Details = append(resp.Details, validationDetail{
				Field:   ve.Field,
				Message: ve.Message,
				Type:    ve.ErrorType,
			})
		}
	} else {
		resp.Details = append(resp.Details, validationDetail{
			Message: fallbackErr.Error(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	body, err := json.Marshal(resp)
	if err != nil {
		// Fallback to plain text if JSON marshaling fails.
		_, _ = io.WriteString(w, `{"error":"request validation failed"}`)
		return
	}
	_, _ = w.Write(body)
}
