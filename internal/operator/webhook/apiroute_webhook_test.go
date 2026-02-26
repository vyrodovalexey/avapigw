// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"testing"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestAPIRouteValidator_ValidateCreate_ValidRoute(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1",
					},
					Methods: []string{"GET", "POST"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend-service",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidURIRegex(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Regex: "[invalid(regex",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid regex")
	}
}

func TestAPIRouteValidator_ValidateCreate_MultipleURIMatchers(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Exact:  "/api/v1",
						Prefix: "/api",
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for multiple URI matchers")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidHTTPMethod(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					Methods: []string{"INVALID_METHOD"},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid HTTP method")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidHeaderRegex(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					Headers: []avapigwv1alpha1.HeaderMatch{
						{
							Name:  "X-Custom",
							Regex: "[invalid(regex",
						},
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid header regex")
	}
}

func TestAPIRouteValidator_ValidateCreate_MissingHeaderName(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					Headers: []avapigwv1alpha1.HeaderMatch{
						{
							Name:  "",
							Exact: "value",
						},
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing header name")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidQueryParamRegex(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					QueryParams: []avapigwv1alpha1.QueryParamMatch{
						{
							Name:  "param",
							Regex: "[invalid(regex",
						},
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid query param regex")
	}
}

func TestAPIRouteValidator_ValidateCreate_MissingQueryParamName(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					QueryParams: []avapigwv1alpha1.QueryParamMatch{
						{
							Name:  "",
							Exact: "value",
						},
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing query param name")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidDestinationPort(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 0,
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid port")
	}
}

func TestAPIRouteValidator_ValidateCreate_MissingDestinationHost(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "",
						Port: 8080,
					},
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing host")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidWeight(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 150,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid weight")
	}
}

func TestAPIRouteValidator_ValidateCreate_WeightSumNot100(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend1",
						Port: 8080,
					},
					Weight: 30,
				},
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend2",
						Port: 8080,
					},
					Weight: 30,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for weight sum not 100")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidTimeout(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Timeout: avapigwv1alpha1.Duration("invalid"),
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid timeout")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidRetryAttempts(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Retries: &avapigwv1alpha1.RetryPolicy{
				Attempts: 0,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid retry attempts")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidRetryOn(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Retries: &avapigwv1alpha1.RetryPolicy{
				Attempts: 3,
				RetryOn:  "invalid-condition",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid retryOn")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidRedirectCode(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Redirect: &avapigwv1alpha1.RedirectConfig{
				Code: 200,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid redirect code")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidRedirectScheme(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Redirect: &avapigwv1alpha1.RedirectConfig{
				Scheme: "ftp",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid redirect scheme")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidDirectResponseStatus(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			DirectResponse: &avapigwv1alpha1.DirectResponseConfig{
				Status: 50,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid direct response status")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidFaultDelayPercentage(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Fault: &avapigwv1alpha1.FaultInjection{
				Delay: &avapigwv1alpha1.FaultDelay{
					FixedDelay: avapigwv1alpha1.Duration("100ms"),
					Percentage: 150,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid fault delay percentage")
	}
}

func TestAPIRouteValidator_ValidateCreate_MissingFaultDelay(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Fault: &avapigwv1alpha1.FaultInjection{
				Delay: &avapigwv1alpha1.FaultDelay{
					FixedDelay: avapigwv1alpha1.Duration(""),
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing fault delay")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidFaultAbortStatus(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Fault: &avapigwv1alpha1.FaultInjection{
				Abort: &avapigwv1alpha1.FaultAbort{
					HTTPStatus: 50,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid fault abort status")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidRateLimit(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			RateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 0,
				Burst:             100,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid rate limit")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidCacheTTL(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Cache: &avapigwv1alpha1.CacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("invalid"),
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid cache TTL")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidCORSMethod(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			CORS: &avapigwv1alpha1.CORSConfig{
				AllowMethods: []string{"INVALID"},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid CORS method")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidMaxSessions(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			MaxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 0,
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid max sessions")
	}
}

func TestAPIRouteValidator_ValidateCreate_InvalidTLSVersion(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				MinVersion: "TLS10",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for invalid TLS version")
	}
}

func TestAPIRouteValidator_ValidateCreate_TLSVersionMismatch(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				MinVersion: "TLS13",
				MaxVersion: "TLS12",
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for TLS version mismatch")
	}
}

func TestAPIRouteValidator_ValidateCreate_WarningRedirectAndRoute(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Redirect: &avapigwv1alpha1.RedirectConfig{
				URI:  "/new-path",
				Code: 301,
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Error("ValidateCreate() should return warning for redirect and route")
	}
}

func TestAPIRouteValidator_ValidateCreate_WarningDirectResponseAndRoute(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			DirectResponse: &avapigwv1alpha1.DirectResponseConfig{
				Status: 200,
				Body:   "OK",
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Error("ValidateCreate() should return warning for direct response and route")
	}
}

func TestAPIRouteValidator_ValidateUpdate(t *testing.T) {
	validator := &APIRouteValidator{}
	oldRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
	}
	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	warnings, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	if err != nil {
		t.Errorf("ValidateUpdate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateUpdate() warnings = %v, want empty", warnings)
	}
}

func TestAPIRouteValidator_ValidateDelete(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
	}

	warnings, err := validator.ValidateDelete(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateDelete() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() warnings = %v, want empty", warnings)
	}
}

func TestAPIRouteValidator_ValidateCreate_ValidRetryPolicy(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Retries: &avapigwv1alpha1.RetryPolicy{
				Attempts:      3,
				PerTryTimeout: avapigwv1alpha1.Duration("10s"),
				RetryOn:       "5xx,reset,connect-failure",
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestAPIRouteValidator_ValidateCreate_ValidRedirect(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Redirect: &avapigwv1alpha1.RedirectConfig{
				URI:    "/new-path",
				Code:   301,
				Scheme: "https",
				Host:   "example.com",
				Port:   443,
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestAPIRouteValidator_ValidateCreate_ValidFaultInjection(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Fault: &avapigwv1alpha1.FaultInjection{
				Delay: &avapigwv1alpha1.FaultDelay{
					FixedDelay: avapigwv1alpha1.Duration("100ms"),
					Percentage: 10,
				},
				Abort: &avapigwv1alpha1.FaultAbort{
					HTTPStatus: 503,
					Percentage: 5,
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestAPIRouteValidator_ValidateCreate_ValidTLS(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				CertFile:   "/certs/tls.crt",
				KeyFile:    "/certs/tls.key",
				MinVersion: "TLS12",
				MaxVersion: "TLS13",
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestAPIRouteValidator_ValidateCreate_ValidVaultTLS(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				Vault: &avapigwv1alpha1.VaultTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "api-route",
					CommonName: "api.example.com",
				},
			},
		},
	}

	warnings, err := validator.ValidateCreate(context.Background(), route)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want empty", warnings)
	}
}

func TestAPIRouteValidator_ValidateCreate_MissingVaultPKIMount(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				Vault: &avapigwv1alpha1.VaultTLSConfig{
					Enabled:  true,
					PKIMount: "",
					Role:     "api-route",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing Vault PKI mount")
	}
}

func TestAPIRouteValidator_ValidateCreate_MissingVaultRole(t *testing.T) {
	validator := &APIRouteValidator{}
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			TLS: &avapigwv1alpha1.RouteTLSConfig{
				Vault: &avapigwv1alpha1.VaultTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "",
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for missing Vault role")
	}
}

func TestAPIRouteValidator_ValidateCreate_CrossConflictWithGraphQL(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingGraphQLRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-graphql-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Prefix: "/api"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingGraphQLRoute).
		Build()

	validator := &APIRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-api-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	_, err := validator.ValidateCreate(context.Background(), route)
	if err == nil {
		t.Error("ValidateCreate() should return error for cross-CRD conflict with GraphQLRoute")
	}
}

func TestAPIRouteValidator_ValidateUpdate_CrossConflictWithGraphQL(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	existingGraphQLRoute := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-graphql-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{
					Path: &avapigwv1alpha1.StringMatch{Prefix: "/api"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingGraphQLRoute).
		Build()

	validator := &APIRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	oldRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-api-route",
			Namespace: "default",
		},
	}
	newRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-api-route",
			Namespace: "default",
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	_, err := validator.ValidateUpdate(context.Background(), oldRoute, newRoute)
	if err == nil {
		t.Error("ValidateUpdate() should return error for cross-CRD conflict with GraphQLRoute")
	}
}
