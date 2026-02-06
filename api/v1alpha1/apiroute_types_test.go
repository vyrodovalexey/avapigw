// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAPIRoute_TypeMeta(t *testing.T) {
	route := &APIRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "APIRoute",
		},
	}

	if route.APIVersion != "avapigw.io/v1alpha1" {
		t.Errorf("APIVersion = %v, want avapigw.io/v1alpha1", route.APIVersion)
	}
	if route.Kind != "APIRoute" {
		t.Errorf("Kind = %v, want APIRoute", route.Kind)
	}
}

func TestAPIRoute_ObjectMeta(t *testing.T) {
	route := &APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "test-namespace",
		},
	}

	if route.Name != "test-route" {
		t.Errorf("Name = %v, want test-route", route.Name)
	}
	if route.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want test-namespace", route.Namespace)
	}
}

func TestAPIRouteSpec_Match(t *testing.T) {
	spec := APIRouteSpec{
		Match: []RouteMatch{
			{
				URI: &URIMatch{
					Exact: "/api/v1/users",
				},
				Methods: []string{"GET", "POST"},
			},
		},
	}

	if len(spec.Match) != 1 {
		t.Fatalf("Match length = %v, want 1", len(spec.Match))
	}
	if spec.Match[0].URI.Exact != "/api/v1/users" {
		t.Errorf("Match[0].URI.Exact = %v, want /api/v1/users", spec.Match[0].URI.Exact)
	}
	if len(spec.Match[0].Methods) != 2 {
		t.Errorf("Match[0].Methods length = %v, want 2", len(spec.Match[0].Methods))
	}
}

func TestAPIRouteSpec_Route(t *testing.T) {
	spec := APIRouteSpec{
		Route: []RouteDestination{
			{
				Destination: Destination{
					Host: "backend-service",
					Port: 8080,
				},
				Weight: 70,
			},
			{
				Destination: Destination{
					Host: "backend-service-canary",
					Port: 8080,
				},
				Weight: 30,
			},
		},
	}

	if len(spec.Route) != 2 {
		t.Fatalf("Route length = %v, want 2", len(spec.Route))
	}
	if spec.Route[0].Destination.Host != "backend-service" {
		t.Errorf("Route[0].Destination.Host = %v, want backend-service", spec.Route[0].Destination.Host)
	}
	if spec.Route[0].Weight != 70 {
		t.Errorf("Route[0].Weight = %v, want 70", spec.Route[0].Weight)
	}
	if spec.Route[1].Weight != 30 {
		t.Errorf("Route[1].Weight = %v, want 30", spec.Route[1].Weight)
	}
}

func TestAPIRouteSpec_Timeout(t *testing.T) {
	spec := APIRouteSpec{
		Timeout: Duration("30s"),
	}

	if spec.Timeout != Duration("30s") {
		t.Errorf("Timeout = %v, want 30s", spec.Timeout)
	}
}

func TestAPIRouteSpec_Retries(t *testing.T) {
	spec := APIRouteSpec{
		Retries: &RetryPolicy{
			Attempts:      3,
			PerTryTimeout: Duration("10s"),
			RetryOn:       "5xx,reset,connect-failure",
		},
	}

	if spec.Retries == nil {
		t.Fatal("Retries should not be nil")
	}
	if spec.Retries.Attempts != 3 {
		t.Errorf("Retries.Attempts = %v, want 3", spec.Retries.Attempts)
	}
	if spec.Retries.PerTryTimeout != Duration("10s") {
		t.Errorf("Retries.PerTryTimeout = %v, want 10s", spec.Retries.PerTryTimeout)
	}
}

func TestAPIRouteSpec_Redirect(t *testing.T) {
	spec := APIRouteSpec{
		Redirect: &RedirectConfig{
			URI:    "/new-path",
			Code:   301,
			Scheme: "https",
			Host:   "example.com",
			Port:   443,
		},
	}

	if spec.Redirect == nil {
		t.Fatal("Redirect should not be nil")
	}
	if spec.Redirect.URI != "/new-path" {
		t.Errorf("Redirect.URI = %v, want /new-path", spec.Redirect.URI)
	}
	if spec.Redirect.Code != 301 {
		t.Errorf("Redirect.Code = %v, want 301", spec.Redirect.Code)
	}
}

func TestAPIRouteSpec_Rewrite(t *testing.T) {
	spec := APIRouteSpec{
		Rewrite: &RewriteConfig{
			URI:       "/internal/users",
			Authority: "internal.example.com",
		},
	}

	if spec.Rewrite == nil {
		t.Fatal("Rewrite should not be nil")
	}
	if spec.Rewrite.URI != "/internal/users" {
		t.Errorf("Rewrite.URI = %v, want /internal/users", spec.Rewrite.URI)
	}
	if spec.Rewrite.Authority != "internal.example.com" {
		t.Errorf("Rewrite.Authority = %v, want internal.example.com", spec.Rewrite.Authority)
	}
}

func TestAPIRouteSpec_DirectResponse(t *testing.T) {
	spec := APIRouteSpec{
		DirectResponse: &DirectResponseConfig{
			Status: 200,
			Body:   `{"status":"ok"}`,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
	}

	if spec.DirectResponse == nil {
		t.Fatal("DirectResponse should not be nil")
	}
	if spec.DirectResponse.Status != 200 {
		t.Errorf("DirectResponse.Status = %v, want 200", spec.DirectResponse.Status)
	}
	if spec.DirectResponse.Body != `{"status":"ok"}` {
		t.Errorf("DirectResponse.Body = %v, want {\"status\":\"ok\"}", spec.DirectResponse.Body)
	}
}

func TestAPIRouteSpec_Headers(t *testing.T) {
	spec := APIRouteSpec{
		Headers: &HeaderManipulation{
			Request: &HeaderOperation{
				Set: map[string]string{"X-Gateway": "avapigw"},
			},
			Response: &HeaderOperation{
				Set: map[string]string{"X-Response-Time": "{{.ResponseTime}}"},
			},
		},
	}

	if spec.Headers == nil {
		t.Fatal("Headers should not be nil")
	}
	if spec.Headers.Request == nil {
		t.Fatal("Headers.Request should not be nil")
	}
	if spec.Headers.Request.Set["X-Gateway"] != "avapigw" {
		t.Errorf("Headers.Request.Set[X-Gateway] = %v, want avapigw", spec.Headers.Request.Set["X-Gateway"])
	}
}

func TestAPIRouteSpec_Mirror(t *testing.T) {
	spec := APIRouteSpec{
		Mirror: &MirrorConfig{
			Destination: Destination{
				Host: "mirror-service",
				Port: 8080,
			},
			Percentage: 10,
		},
	}

	if spec.Mirror == nil {
		t.Fatal("Mirror should not be nil")
	}
	if spec.Mirror.Destination.Host != "mirror-service" {
		t.Errorf("Mirror.Destination.Host = %v, want mirror-service", spec.Mirror.Destination.Host)
	}
	if spec.Mirror.Percentage != 10 {
		t.Errorf("Mirror.Percentage = %v, want 10", spec.Mirror.Percentage)
	}
}

func TestAPIRouteSpec_Fault(t *testing.T) {
	spec := APIRouteSpec{
		Fault: &FaultInjection{
			Delay: &FaultDelay{
				FixedDelay: Duration("100ms"),
				Percentage: 10,
			},
			Abort: &FaultAbort{
				HTTPStatus: 503,
				Percentage: 5,
			},
		},
	}

	if spec.Fault == nil {
		t.Fatal("Fault should not be nil")
	}
	if spec.Fault.Delay == nil {
		t.Fatal("Fault.Delay should not be nil")
	}
	if spec.Fault.Delay.FixedDelay != Duration("100ms") {
		t.Errorf("Fault.Delay.FixedDelay = %v, want 100ms", spec.Fault.Delay.FixedDelay)
	}
	if spec.Fault.Abort.HTTPStatus != 503 {
		t.Errorf("Fault.Abort.HTTPStatus = %v, want 503", spec.Fault.Abort.HTTPStatus)
	}
}

func TestAPIRouteSpec_RateLimit(t *testing.T) {
	spec := APIRouteSpec{
		RateLimit: &RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
			PerClient:         true,
		},
	}

	if spec.RateLimit == nil {
		t.Fatal("RateLimit should not be nil")
	}
	if !spec.RateLimit.Enabled {
		t.Error("RateLimit.Enabled should be true")
	}
	if spec.RateLimit.RequestsPerSecond != 100 {
		t.Errorf("RateLimit.RequestsPerSecond = %v, want 100", spec.RateLimit.RequestsPerSecond)
	}
}

func TestAPIRouteSpec_Transform(t *testing.T) {
	spec := APIRouteSpec{
		Transform: &TransformConfig{
			Request: &RequestTransform{
				Template: `{"wrapped": {{.Body}}}`,
			},
			Response: &ResponseTransform{
				AllowFields: []string{"id", "name"},
				DenyFields:  []string{"password"},
				FieldMappings: map[string]string{
					"created_at": "createdAt",
				},
			},
		},
	}

	if spec.Transform == nil {
		t.Fatal("Transform should not be nil")
	}
	if spec.Transform.Request == nil {
		t.Fatal("Transform.Request should not be nil")
	}
	if spec.Transform.Request.Template != `{"wrapped": {{.Body}}}` {
		t.Errorf("Transform.Request.Template = %v, want {\"wrapped\": {{.Body}}}", spec.Transform.Request.Template)
	}
	if len(spec.Transform.Response.AllowFields) != 2 {
		t.Errorf("Transform.Response.AllowFields length = %v, want 2", len(spec.Transform.Response.AllowFields))
	}
}

func TestAPIRouteSpec_Cache(t *testing.T) {
	spec := APIRouteSpec{
		Cache: &CacheConfig{
			Enabled:              true,
			TTL:                  Duration("5m"),
			KeyComponents:        []string{"path", "query"},
			StaleWhileRevalidate: Duration("1m"),
		},
	}

	if spec.Cache == nil {
		t.Fatal("Cache should not be nil")
	}
	if !spec.Cache.Enabled {
		t.Error("Cache.Enabled should be true")
	}
	if spec.Cache.TTL != Duration("5m") {
		t.Errorf("Cache.TTL = %v, want 5m", spec.Cache.TTL)
	}
}

func TestAPIRouteSpec_Encoding(t *testing.T) {
	spec := APIRouteSpec{
		Encoding: &EncodingConfig{
			Request: &EncodingSettings{
				ContentType: "application/json",
			},
			Response: &EncodingSettings{
				ContentType: "application/json",
			},
		},
	}

	if spec.Encoding == nil {
		t.Fatal("Encoding should not be nil")
	}
	if spec.Encoding.Request.ContentType != "application/json" {
		t.Errorf("Encoding.Request.ContentType = %v, want application/json", spec.Encoding.Request.ContentType)
	}
}

func TestAPIRouteSpec_RequestLimits(t *testing.T) {
	spec := APIRouteSpec{
		RequestLimits: &RequestLimitsConfig{
			MaxBodySize:   10485760,
			MaxHeaderSize: 1048576,
		},
	}

	if spec.RequestLimits == nil {
		t.Fatal("RequestLimits should not be nil")
	}
	if spec.RequestLimits.MaxBodySize != 10485760 {
		t.Errorf("RequestLimits.MaxBodySize = %v, want 10485760", spec.RequestLimits.MaxBodySize)
	}
}

func TestAPIRouteSpec_CORS(t *testing.T) {
	spec := APIRouteSpec{
		CORS: &CORSConfig{
			AllowOrigins:     []string{"https://example.com"},
			AllowMethods:     []string{"GET", "POST"},
			AllowCredentials: true,
		},
	}

	if spec.CORS == nil {
		t.Fatal("CORS should not be nil")
	}
	if len(spec.CORS.AllowOrigins) != 1 {
		t.Errorf("CORS.AllowOrigins length = %v, want 1", len(spec.CORS.AllowOrigins))
	}
}

func TestAPIRouteSpec_Security(t *testing.T) {
	spec := APIRouteSpec{
		Security: &SecurityConfig{
			Enabled: true,
			Headers: &SecurityHeadersConfig{
				Enabled:       true,
				XFrameOptions: "DENY",
			},
		},
	}

	if spec.Security == nil {
		t.Fatal("Security should not be nil")
	}
	if !spec.Security.Enabled {
		t.Error("Security.Enabled should be true")
	}
}

func TestAPIRouteSpec_MaxSessions(t *testing.T) {
	spec := APIRouteSpec{
		MaxSessions: &MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1000,
			QueueSize:     100,
			QueueTimeout:  Duration("10s"),
		},
	}

	if spec.MaxSessions == nil {
		t.Fatal("MaxSessions should not be nil")
	}
	if !spec.MaxSessions.Enabled {
		t.Error("MaxSessions.Enabled should be true")
	}
	if spec.MaxSessions.MaxConcurrent != 1000 {
		t.Errorf("MaxSessions.MaxConcurrent = %v, want 1000", spec.MaxSessions.MaxConcurrent)
	}
}

func TestAPIRouteSpec_TLS(t *testing.T) {
	spec := APIRouteSpec{
		TLS: &RouteTLSConfig{
			CertFile:   "/certs/tls.crt",
			KeyFile:    "/certs/tls.key",
			SNIHosts:   []string{"api.example.com"},
			MinVersion: "TLS12",
		},
	}

	if spec.TLS == nil {
		t.Fatal("TLS should not be nil")
	}
	if spec.TLS.CertFile != "/certs/tls.crt" {
		t.Errorf("TLS.CertFile = %v, want /certs/tls.crt", spec.TLS.CertFile)
	}
}

func TestAPIRouteStatus_Conditions(t *testing.T) {
	status := APIRouteStatus{
		Conditions: []Condition{
			{
				Type:               ConditionReady,
				Status:             metav1.ConditionTrue,
				Reason:             ReasonReconciled,
				Message:            "Route successfully applied",
				LastTransitionTime: metav1.Now(),
			},
			{
				Type:               ConditionValid,
				Status:             metav1.ConditionTrue,
				Reason:             ReasonValidationPassed,
				Message:            "Configuration is valid",
				LastTransitionTime: metav1.Now(),
			},
		},
		ObservedGeneration: 1,
	}

	if len(status.Conditions) != 2 {
		t.Fatalf("Conditions length = %v, want 2", len(status.Conditions))
	}
	if status.Conditions[0].Type != ConditionReady {
		t.Errorf("Conditions[0].Type = %v, want Ready", status.Conditions[0].Type)
	}
	if status.ObservedGeneration != 1 {
		t.Errorf("ObservedGeneration = %v, want 1", status.ObservedGeneration)
	}
}

func TestAPIRouteStatus_AppliedGateways(t *testing.T) {
	status := APIRouteStatus{
		AppliedGateways: []AppliedGateway{
			{
				Name:        "gateway-1",
				Namespace:   "avapigw-system",
				LastApplied: metav1.Now(),
			},
		},
	}

	if len(status.AppliedGateways) != 1 {
		t.Fatalf("AppliedGateways length = %v, want 1", len(status.AppliedGateways))
	}
	if status.AppliedGateways[0].Name != "gateway-1" {
		t.Errorf("AppliedGateways[0].Name = %v, want gateway-1", status.AppliedGateways[0].Name)
	}
}

func TestAPIRouteList_Items(t *testing.T) {
	list := &APIRouteList{
		Items: []APIRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-1",
					Namespace: "default",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route-2",
					Namespace: "default",
				},
			},
		},
	}

	if len(list.Items) != 2 {
		t.Fatalf("Items length = %v, want 2", len(list.Items))
	}
	if list.Items[0].Name != "route-1" {
		t.Errorf("Items[0].Name = %v, want route-1", list.Items[0].Name)
	}
}

func TestRouteMatch_URIMatch(t *testing.T) {
	tests := []struct {
		name  string
		match URIMatch
	}{
		{
			name: "exact match",
			match: URIMatch{
				Exact: "/api/v1/users",
			},
		},
		{
			name: "prefix match",
			match: URIMatch{
				Prefix: "/api/v1",
			},
		},
		{
			name: "regex match",
			match: URIMatch{
				Regex: "^/api/v[0-9]+/.*",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := RouteMatch{
				URI: &tt.match,
			}
			if rm.URI == nil {
				t.Error("URI should not be nil")
			}
		})
	}
}

func TestRouteMatch_Headers(t *testing.T) {
	present := true
	rm := RouteMatch{
		Headers: []HeaderMatch{
			{
				Name:    "Authorization",
				Present: &present,
			},
			{
				Name:  "X-Custom-Header",
				Exact: "custom-value",
			},
		},
	}

	if len(rm.Headers) != 2 {
		t.Fatalf("Headers length = %v, want 2", len(rm.Headers))
	}
	if rm.Headers[0].Name != "Authorization" {
		t.Errorf("Headers[0].Name = %v, want Authorization", rm.Headers[0].Name)
	}
	if rm.Headers[0].Present == nil || !*rm.Headers[0].Present {
		t.Error("Headers[0].Present should be true")
	}
}

func TestRouteMatch_QueryParams(t *testing.T) {
	present := true
	rm := RouteMatch{
		QueryParams: []QueryParamMatch{
			{
				Name:  "version",
				Exact: "v1",
			},
			{
				Name:    "debug",
				Present: &present,
			},
		},
	}

	if len(rm.QueryParams) != 2 {
		t.Fatalf("QueryParams length = %v, want 2", len(rm.QueryParams))
	}
	if rm.QueryParams[0].Name != "version" {
		t.Errorf("QueryParams[0].Name = %v, want version", rm.QueryParams[0].Name)
	}
	if rm.QueryParams[0].Exact != "v1" {
		t.Errorf("QueryParams[0].Exact = %v, want v1", rm.QueryParams[0].Exact)
	}
}

func TestQueryParamMatch_Fields(t *testing.T) {
	present := true
	qpm := QueryParamMatch{
		Name:    "filter",
		Exact:   "active",
		Regex:   "^[a-z]+$",
		Present: &present,
	}

	if qpm.Name != "filter" {
		t.Errorf("Name = %v, want filter", qpm.Name)
	}
	if qpm.Exact != "active" {
		t.Errorf("Exact = %v, want active", qpm.Exact)
	}
	if qpm.Regex != "^[a-z]+$" {
		t.Errorf("Regex = %v, want ^[a-z]+$", qpm.Regex)
	}
	if qpm.Present == nil || !*qpm.Present {
		t.Error("Present should be true")
	}
}

func TestRedirectConfig_AllFields(t *testing.T) {
	rc := RedirectConfig{
		URI:        "/new-path",
		Code:       301,
		Scheme:     "https",
		Host:       "example.com",
		Port:       443,
		StripQuery: true,
	}

	if rc.URI != "/new-path" {
		t.Errorf("URI = %v, want /new-path", rc.URI)
	}
	if rc.Code != 301 {
		t.Errorf("Code = %v, want 301", rc.Code)
	}
	if rc.Scheme != "https" {
		t.Errorf("Scheme = %v, want https", rc.Scheme)
	}
	if rc.Host != "example.com" {
		t.Errorf("Host = %v, want example.com", rc.Host)
	}
	if rc.Port != 443 {
		t.Errorf("Port = %v, want 443", rc.Port)
	}
	if !rc.StripQuery {
		t.Error("StripQuery should be true")
	}
}

func TestFaultInjection_DelayOnly(t *testing.T) {
	fi := FaultInjection{
		Delay: &FaultDelay{
			FixedDelay: Duration("500ms"),
			Percentage: 50,
		},
	}

	if fi.Delay == nil {
		t.Fatal("Delay should not be nil")
	}
	if fi.Abort != nil {
		t.Error("Abort should be nil")
	}
	if fi.Delay.FixedDelay != Duration("500ms") {
		t.Errorf("Delay.FixedDelay = %v, want 500ms", fi.Delay.FixedDelay)
	}
	if fi.Delay.Percentage != 50 {
		t.Errorf("Delay.Percentage = %v, want 50", fi.Delay.Percentage)
	}
}

func TestFaultInjection_AbortOnly(t *testing.T) {
	fi := FaultInjection{
		Abort: &FaultAbort{
			HTTPStatus: 500,
			Percentage: 25,
		},
	}

	if fi.Abort == nil {
		t.Fatal("Abort should not be nil")
	}
	if fi.Delay != nil {
		t.Error("Delay should be nil")
	}
	if fi.Abort.HTTPStatus != 500 {
		t.Errorf("Abort.HTTPStatus = %v, want 500", fi.Abort.HTTPStatus)
	}
	if fi.Abort.Percentage != 25 {
		t.Errorf("Abort.Percentage = %v, want 25", fi.Abort.Percentage)
	}
}

func TestTransformConfig_RequestOnly(t *testing.T) {
	tc := TransformConfig{
		Request: &RequestTransform{
			Template: `{"data": {{.Body}}}`,
		},
	}

	if tc.Request == nil {
		t.Fatal("Request should not be nil")
	}
	if tc.Response != nil {
		t.Error("Response should be nil")
	}
	if tc.Request.Template != `{"data": {{.Body}}}` {
		t.Errorf("Request.Template = %v, want {\"data\": {{.Body}}}", tc.Request.Template)
	}
}

func TestTransformConfig_ResponseOnly(t *testing.T) {
	tc := TransformConfig{
		Response: &ResponseTransform{
			AllowFields: []string{"id", "name", "email"},
			DenyFields:  []string{"password", "secret"},
			FieldMappings: map[string]string{
				"user_id":    "userId",
				"created_at": "createdAt",
			},
		},
	}

	if tc.Response == nil {
		t.Fatal("Response should not be nil")
	}
	if tc.Request != nil {
		t.Error("Request should be nil")
	}
	if len(tc.Response.AllowFields) != 3 {
		t.Errorf("Response.AllowFields length = %v, want 3", len(tc.Response.AllowFields))
	}
	if len(tc.Response.DenyFields) != 2 {
		t.Errorf("Response.DenyFields length = %v, want 2", len(tc.Response.DenyFields))
	}
	if len(tc.Response.FieldMappings) != 2 {
		t.Errorf("Response.FieldMappings length = %v, want 2", len(tc.Response.FieldMappings))
	}
}

func TestCacheConfig_AllFields(t *testing.T) {
	cc := CacheConfig{
		Enabled:              true,
		TTL:                  Duration("10m"),
		KeyComponents:        []string{"path", "query", "headers"},
		StaleWhileRevalidate: Duration("2m"),
	}

	if !cc.Enabled {
		t.Error("Enabled should be true")
	}
	if cc.TTL != Duration("10m") {
		t.Errorf("TTL = %v, want 10m", cc.TTL)
	}
	if len(cc.KeyComponents) != 3 {
		t.Errorf("KeyComponents length = %v, want 3", len(cc.KeyComponents))
	}
	if cc.StaleWhileRevalidate != Duration("2m") {
		t.Errorf("StaleWhileRevalidate = %v, want 2m", cc.StaleWhileRevalidate)
	}
}

func TestEncodingConfig_AllFields(t *testing.T) {
	ec := EncodingConfig{
		Request: &EncodingSettings{
			ContentType: "application/json",
		},
		Response: &EncodingSettings{
			ContentType: "application/xml",
		},
	}

	if ec.Request == nil {
		t.Fatal("Request should not be nil")
	}
	if ec.Response == nil {
		t.Fatal("Response should not be nil")
	}
	if ec.Request.ContentType != "application/json" {
		t.Errorf("Request.ContentType = %v, want application/json", ec.Request.ContentType)
	}
	if ec.Response.ContentType != "application/xml" {
		t.Errorf("Response.ContentType = %v, want application/xml", ec.Response.ContentType)
	}
}

func TestAPIRoute_FullSpec(t *testing.T) {
	route := &APIRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "APIRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-route",
			Namespace: "default",
		},
		Spec: APIRouteSpec{
			Match: []RouteMatch{
				{
					URI: &URIMatch{
						Prefix: "/api/v1",
					},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
			Timeout: Duration("30s"),
			Retries: &RetryPolicy{
				Attempts:      3,
				PerTryTimeout: Duration("10s"),
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
			},
			CORS: &CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{"GET", "POST"},
			},
		},
		Status: APIRouteStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					LastTransitionTime: metav1.Now(),
				},
			},
			ObservedGeneration: 1,
		},
	}

	// Verify all fields are set correctly
	if route.Name != "full-route" {
		t.Errorf("Name = %v, want full-route", route.Name)
	}
	if len(route.Spec.Match) != 1 {
		t.Errorf("Spec.Match length = %v, want 1", len(route.Spec.Match))
	}
	if len(route.Spec.Route) != 1 {
		t.Errorf("Spec.Route length = %v, want 1", len(route.Spec.Route))
	}
	if route.Spec.Timeout != Duration("30s") {
		t.Errorf("Spec.Timeout = %v, want 30s", route.Spec.Timeout)
	}
	if len(route.Status.Conditions) != 1 {
		t.Errorf("Status.Conditions length = %v, want 1", len(route.Status.Conditions))
	}
}

// Tests for APIRoute with Authentication configuration

func TestAPIRouteSpec_Authentication(t *testing.T) {
	tests := []struct {
		name string
		spec APIRouteSpec
	}{
		{
			name: "JWT authentication",
			spec: APIRouteSpec{
				Authentication: &AuthenticationConfig{
					Enabled: true,
					JWT: &JWTAuthConfig{
						Enabled:   true,
						Issuer:    "https://issuer.example.com",
						JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
						Algorithm: "RS256",
						Audience:  []string{"api"},
						ClaimMapping: &ClaimMappingConfig{
							Roles:  "roles",
							Groups: "groups",
						},
					},
				},
			},
		},
		{
			name: "API key authentication",
			spec: APIRouteSpec{
				Authentication: &AuthenticationConfig{
					Enabled: true,
					APIKey: &APIKeyAuthConfig{
						Enabled:       true,
						Header:        "X-API-Key",
						HashAlgorithm: "sha256",
						VaultPath:     "secret/data/api-keys",
					},
				},
			},
		},
		{
			name: "mTLS authentication",
			spec: APIRouteSpec{
				Authentication: &AuthenticationConfig{
					Enabled: true,
					MTLS: &MTLSAuthConfig{
						Enabled:         true,
						CAFile:          "/certs/ca.crt",
						ExtractIdentity: "cn",
						AllowedCNs:      []string{"client1", "client2"},
					},
				},
			},
		},
		{
			name: "OIDC authentication",
			spec: APIRouteSpec{
				Authentication: &AuthenticationConfig{
					Enabled: true,
					OIDC: &OIDCAuthConfig{
						Enabled: true,
						Providers: []OIDCProviderConfig{
							{
								Name:         "keycloak",
								IssuerURL:    "https://keycloak.example.com/realms/myrealm",
								ClientID:     "my-client",
								ClientSecret: "my-secret",
								Scopes:       []string{"openid", "profile"},
							},
						},
					},
				},
			},
		},
		{
			name: "allow anonymous with skip paths",
			spec: APIRouteSpec{
				Authentication: &AuthenticationConfig{
					Enabled:        true,
					AllowAnonymous: true,
					SkipPaths:      []string{"/health", "/metrics"},
					JWT: &JWTAuthConfig{
						Enabled: true,
						JWKSURL: "https://issuer.example.com/.well-known/jwks.json",
					},
				},
			},
		},
		{
			name: "multiple authentication methods",
			spec: APIRouteSpec{
				Authentication: &AuthenticationConfig{
					Enabled: true,
					JWT: &JWTAuthConfig{
						Enabled: true,
						JWKSURL: "https://issuer.example.com/.well-known/jwks.json",
					},
					APIKey: &APIKeyAuthConfig{
						Enabled: true,
						Header:  "X-API-Key",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.Authentication == nil {
				t.Fatal("Authentication should not be nil")
			}
			if !tt.spec.Authentication.Enabled {
				t.Error("Authentication.Enabled should be true")
			}
		})
	}
}

func TestAPIRouteSpec_Authentication_JWT_AllFields(t *testing.T) {
	spec := APIRouteSpec{
		Authentication: &AuthenticationConfig{
			Enabled: true,
			JWT: &JWTAuthConfig{
				Enabled:   true,
				Issuer:    "https://issuer.example.com",
				Audience:  []string{"api", "web"},
				JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
				Secret:    "my-secret",
				PublicKey: "-----BEGIN PUBLIC KEY-----\n...",
				Algorithm: "RS256",
				ClaimMapping: &ClaimMappingConfig{
					Roles:       "roles",
					Permissions: "permissions",
					Groups:      "groups",
					Scopes:      "scope",
					Email:       "email",
					Name:        "name",
				},
			},
		},
	}

	jwt := spec.Authentication.JWT
	if jwt == nil {
		t.Fatal("JWT should not be nil")
	}
	if jwt.Issuer != "https://issuer.example.com" {
		t.Errorf("JWT.Issuer = %v, want https://issuer.example.com", jwt.Issuer)
	}
	if len(jwt.Audience) != 2 {
		t.Errorf("JWT.Audience length = %v, want 2", len(jwt.Audience))
	}
	if jwt.Algorithm != "RS256" {
		t.Errorf("JWT.Algorithm = %v, want RS256", jwt.Algorithm)
	}
	if jwt.ClaimMapping == nil {
		t.Fatal("JWT.ClaimMapping should not be nil")
	}
	if jwt.ClaimMapping.Roles != "roles" {
		t.Errorf("JWT.ClaimMapping.Roles = %v, want roles", jwt.ClaimMapping.Roles)
	}
}

func TestAPIRouteSpec_Authentication_OIDC_MultipleProviders(t *testing.T) {
	spec := APIRouteSpec{
		Authentication: &AuthenticationConfig{
			Enabled: true,
			OIDC: &OIDCAuthConfig{
				Enabled: true,
				Providers: []OIDCProviderConfig{
					{
						Name:         "keycloak",
						IssuerURL:    "https://keycloak.example.com/realms/myrealm",
						ClientID:     "keycloak-client",
						ClientSecret: "keycloak-secret",
						Scopes:       []string{"openid", "profile"},
					},
					{
						Name:      "google",
						IssuerURL: "https://accounts.google.com",
						ClientID:  "google-client",
						ClientSecretRef: &SecretKeySelector{
							Name: "google-secret",
							Key:  "client-secret",
						},
						Scopes: []string{"openid", "email"},
					},
					{
						Name:      "azure",
						IssuerURL: "https://login.microsoftonline.com/tenant/v2.0",
						ClientID:  "azure-client",
						Scopes:    []string{"openid", "profile", "email"},
					},
				},
			},
		},
	}

	oidc := spec.Authentication.OIDC
	if oidc == nil {
		t.Fatal("OIDC should not be nil")
	}
	if len(oidc.Providers) != 3 {
		t.Fatalf("OIDC.Providers length = %v, want 3", len(oidc.Providers))
	}
	if oidc.Providers[0].Name != "keycloak" {
		t.Errorf("OIDC.Providers[0].Name = %v, want keycloak", oidc.Providers[0].Name)
	}
	if oidc.Providers[1].ClientSecretRef == nil {
		t.Error("OIDC.Providers[1].ClientSecretRef should not be nil")
	}
}

// Tests for APIRoute with Authorization configuration

func TestAPIRouteSpec_Authorization(t *testing.T) {
	tests := []struct {
		name string
		spec APIRouteSpec
	}{
		{
			name: "RBAC authorization",
			spec: APIRouteSpec{
				Authorization: &AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					RBAC: &RBACConfig{
						Enabled: true,
						Policies: []RBACPolicyConfig{
							{
								Name:      "admin-policy",
								Roles:     []string{"admin"},
								Resources: []string{"*"},
								Actions:   []string{"*"},
								Effect:    "allow",
							},
						},
					},
				},
			},
		},
		{
			name: "ABAC authorization",
			spec: APIRouteSpec{
				Authorization: &AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					ABAC: &ABACConfig{
						Enabled: true,
						Policies: []ABACPolicyConfig{
							{
								Name:       "owner-policy",
								Expression: "request.user == resource.owner",
								Effect:     "allow",
							},
						},
					},
				},
			},
		},
		{
			name: "External OPA authorization",
			spec: APIRouteSpec{
				Authorization: &AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					External: &ExternalAuthzConfig{
						Enabled: true,
						OPA: &OPAAuthzConfig{
							URL:    "http://opa:8181/v1/data/authz/allow",
							Policy: "authz/allow",
						},
						Timeout:  Duration("5s"),
						FailOpen: false,
					},
				},
			},
		},
		{
			name: "authorization with cache",
			spec: APIRouteSpec{
				Authorization: &AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					RBAC: &RBACConfig{
						Enabled: true,
					},
					Cache: &AuthzCacheConfig{
						Enabled: true,
						TTL:     Duration("5m"),
						MaxSize: 1000,
						Type:    "memory",
					},
				},
			},
		},
		{
			name: "authorization with skip paths",
			spec: APIRouteSpec{
				Authorization: &AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					SkipPaths:     []string{"/health", "/metrics", "/public/*"},
					RBAC: &RBACConfig{
						Enabled: true,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.Authorization == nil {
				t.Fatal("Authorization should not be nil")
			}
			if !tt.spec.Authorization.Enabled {
				t.Error("Authorization.Enabled should be true")
			}
		})
	}
}

func TestAPIRouteSpec_Authorization_RBAC_AllFields(t *testing.T) {
	spec := APIRouteSpec{
		Authorization: &AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &RBACConfig{
				Enabled: true,
				Policies: []RBACPolicyConfig{
					{
						Name:      "admin-policy",
						Roles:     []string{"admin", "superadmin"},
						Resources: []string{"/api/*", "/admin/*"},
						Actions:   []string{"GET", "POST", "PUT", "DELETE"},
						Effect:    "allow",
						Priority:  100,
					},
					{
						Name:      "user-policy",
						Roles:     []string{"user"},
						Resources: []string{"/api/users/*"},
						Actions:   []string{"GET"},
						Effect:    "allow",
						Priority:  50,
					},
				},
				RoleHierarchy: map[string][]string{
					"superadmin": {"admin", "user"},
					"admin":      {"user"},
				},
			},
		},
	}

	rbac := spec.Authorization.RBAC
	if rbac == nil {
		t.Fatal("RBAC should not be nil")
	}
	if len(rbac.Policies) != 2 {
		t.Fatalf("RBAC.Policies length = %v, want 2", len(rbac.Policies))
	}
	if rbac.Policies[0].Priority != 100 {
		t.Errorf("RBAC.Policies[0].Priority = %v, want 100", rbac.Policies[0].Priority)
	}
	if len(rbac.RoleHierarchy) != 2 {
		t.Errorf("RBAC.RoleHierarchy length = %v, want 2", len(rbac.RoleHierarchy))
	}
}

func TestAPIRouteSpec_Authorization_ABAC_AllFields(t *testing.T) {
	spec := APIRouteSpec{
		Authorization: &AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			ABAC: &ABACConfig{
				Enabled: true,
				Policies: []ABACPolicyConfig{
					{
						Name:       "owner-policy",
						Expression: "request.user == resource.owner",
						Resources:  []string{"/api/documents/*"},
						Actions:    []string{"GET", "PUT", "DELETE"},
						Effect:     "allow",
						Priority:   100,
					},
					{
						Name:       "department-policy",
						Expression: "request.user.department == resource.department",
						Resources:  []string{"/api/reports/*"},
						Actions:    []string{"GET"},
						Effect:     "allow",
						Priority:   50,
					},
				},
			},
		},
	}

	abac := spec.Authorization.ABAC
	if abac == nil {
		t.Fatal("ABAC should not be nil")
	}
	if len(abac.Policies) != 2 {
		t.Fatalf("ABAC.Policies length = %v, want 2", len(abac.Policies))
	}
	if abac.Policies[0].Expression != "request.user == resource.owner" {
		t.Errorf("ABAC.Policies[0].Expression = %v, want request.user == resource.owner", abac.Policies[0].Expression)
	}
}

// Tests for APIRoute with combined Authentication + Authorization

func TestAPIRouteSpec_AuthenticationAndAuthorization(t *testing.T) {
	spec := APIRouteSpec{
		Match: []RouteMatch{
			{
				URI: &URIMatch{
					Prefix: "/api/v1",
				},
			},
		},
		Route: []RouteDestination{
			{
				Destination: Destination{
					Host: "backend",
					Port: 8080,
				},
			},
		},
		Authentication: &AuthenticationConfig{
			Enabled: true,
			JWT: &JWTAuthConfig{
				Enabled:   true,
				JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
				Algorithm: "RS256",
				ClaimMapping: &ClaimMappingConfig{
					Roles: "roles",
				},
			},
			SkipPaths: []string{"/api/v1/health"},
		},
		Authorization: &AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &RBACConfig{
				Enabled: true,
				Policies: []RBACPolicyConfig{
					{
						Name:      "admin-policy",
						Roles:     []string{"admin"},
						Resources: []string{"*"},
						Actions:   []string{"*"},
						Effect:    "allow",
					},
					{
						Name:      "user-read-policy",
						Roles:     []string{"user"},
						Resources: []string{"/api/v1/users/*"},
						Actions:   []string{"GET"},
						Effect:    "allow",
					},
				},
			},
			Cache: &AuthzCacheConfig{
				Enabled: true,
				TTL:     Duration("5m"),
				MaxSize: 1000,
				Type:    "memory",
			},
			SkipPaths: []string{"/api/v1/health", "/api/v1/public/*"},
		},
	}

	if spec.Authentication == nil {
		t.Fatal("Authentication should not be nil")
	}
	if spec.Authorization == nil {
		t.Fatal("Authorization should not be nil")
	}
	if !spec.Authentication.Enabled {
		t.Error("Authentication.Enabled should be true")
	}
	if !spec.Authorization.Enabled {
		t.Error("Authorization.Enabled should be true")
	}
	if spec.Authentication.JWT == nil {
		t.Error("Authentication.JWT should not be nil")
	}
	if spec.Authorization.RBAC == nil {
		t.Error("Authorization.RBAC should not be nil")
	}
	if spec.Authorization.Cache == nil {
		t.Error("Authorization.Cache should not be nil")
	}
}

func TestAPIRoute_FullSpecWithAuthenticationAndAuthorization(t *testing.T) {
	route := &APIRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "APIRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secure-route",
			Namespace: "default",
		},
		Spec: APIRouteSpec{
			Match: []RouteMatch{
				{
					URI: &URIMatch{
						Prefix: "/api/v1",
					},
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
			Timeout: Duration("30s"),
			Authentication: &AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled:   true,
					Issuer:    "https://issuer.example.com",
					JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
					Algorithm: "RS256",
				},
			},
			Authorization: &AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				RBAC: &RBACConfig{
					Enabled: true,
					Policies: []RBACPolicyConfig{
						{
							Name:   "admin-policy",
							Roles:  []string{"admin"},
							Effect: "allow",
						},
					},
				},
			},
		},
		Status: APIRouteStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					LastTransitionTime: metav1.Now(),
				},
			},
			ObservedGeneration: 1,
		},
	}

	if route.Name != "secure-route" {
		t.Errorf("Name = %v, want secure-route", route.Name)
	}
	if route.Spec.Authentication == nil {
		t.Error("Spec.Authentication should not be nil")
	}
	if route.Spec.Authorization == nil {
		t.Error("Spec.Authorization should not be nil")
	}
}
