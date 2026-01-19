package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// AuthPolicy CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ap
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".spec.targetRef.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// AuthPolicy is the Schema for the authpolicies API.
// AuthPolicy defines authentication and authorization configuration for a target resource.
type AuthPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthPolicySpec   `json:"spec,omitempty"`
	Status AuthPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AuthPolicyList contains a list of AuthPolicy
type AuthPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthPolicy `json:"items"`
}

// AuthPolicySpec defines the desired state of AuthPolicy
type AuthPolicySpec struct {
	// TargetRef identifies the target resource to apply authentication to.
	// +kubebuilder:validation:Required
	TargetRef TargetRef `json:"targetRef"`

	// Authentication defines authentication configuration.
	// +optional
	Authentication *AuthenticationConfig `json:"authentication,omitempty"`

	// Authorization defines authorization configuration.
	// +optional
	Authorization *AuthorizationConfig `json:"authorization,omitempty"`

	// SecurityHeaders defines security headers configuration.
	// +optional
	SecurityHeaders *SecurityHeadersConfig `json:"securityHeaders,omitempty"`
}

// ============================================================================
// Authentication Configuration
// ============================================================================

// AuthenticationConfig defines authentication configuration
type AuthenticationConfig struct {
	// JWT defines JWT authentication configuration.
	// +optional
	JWT *JWTAuthConfig `json:"jwt,omitempty"`

	// APIKey defines API key authentication configuration.
	// +optional
	APIKey *APIKeyAuthConfig `json:"apiKey,omitempty"`

	// Basic defines basic authentication configuration.
	// +optional
	Basic *BasicAuthConfig `json:"basic,omitempty"`

	// OAuth2 defines OAuth2 client credentials configuration.
	// +optional
	OAuth2 *OAuth2Config `json:"oauth2,omitempty"`
}

// JWTAuthConfig defines JWT authentication configuration
type JWTAuthConfig struct {
	// Enabled indicates whether JWT authentication is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Issuer is the expected issuer of the JWT.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	Issuer *string `json:"issuer,omitempty"`

	// Audiences is the list of expected audiences.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Audiences []string `json:"audiences,omitempty"`

	// JWKSUri is the URI to fetch the JWKS from.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	JWKSUri *string `json:"jwksUri,omitempty"`

	// JWKSCacheDuration is the duration to cache the JWKS.
	// +kubebuilder:default="1h"
	// +optional
	JWKSCacheDuration *Duration `json:"jwksCacheDuration,omitempty"`

	// JWKS references a Secret containing the JWKS.
	// +optional
	JWKS *SecretObjectReference `json:"jwks,omitempty"`

	// TokenLocation defines where to find the JWT token.
	// +optional
	TokenLocation *TokenLocationConfig `json:"tokenLocation,omitempty"`

	// ClaimsToHeaders defines claims to extract and add as headers.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	ClaimsToHeaders []ClaimToHeader `json:"claimsToHeaders,omitempty"`

	// RequiredClaims defines claims that must be present in the JWT.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	RequiredClaims []RequiredClaim `json:"requiredClaims,omitempty"`

	// ForwardOriginalToken indicates whether to forward the original token.
	// +kubebuilder:default=false
	// +optional
	ForwardOriginalToken *bool `json:"forwardOriginalToken,omitempty"`
}

// TokenLocationConfig defines where to find the token
type TokenLocationConfig struct {
	// Header is the name of the header containing the token.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:default="Authorization"
	// +optional
	Header *string `json:"header,omitempty"`

	// Prefix is the prefix to strip from the header value.
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:default="Bearer "
	// +optional
	Prefix *string `json:"prefix,omitempty"`

	// Cookie is the name of the cookie containing the token.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +optional
	Cookie *string `json:"cookie,omitempty"`

	// QueryParam is the name of the query parameter containing the token.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +optional
	QueryParam *string `json:"queryParam,omitempty"`
}

// ClaimToHeader defines a claim to extract and add as a header
type ClaimToHeader struct {
	// Claim is the name of the JWT claim.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Claim string `json:"claim"`

	// Header is the name of the header to add.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Header string `json:"header"`
}

// RequiredClaim defines a required JWT claim
type RequiredClaim struct {
	// Name is the name of the claim.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Name string `json:"name"`

	// Values is the list of allowed values for the claim.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Values []string `json:"values,omitempty"`
}

// APIKeyAuthConfig defines API key authentication configuration
type APIKeyAuthConfig struct {
	// Enabled indicates whether API key authentication is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Location defines where to find the API key.
	// +optional
	Location *APIKeyLocationConfig `json:"location,omitempty"`

	// Validation defines how to validate the API key.
	// +optional
	Validation *APIKeyValidationConfig `json:"validation,omitempty"`
}

// APIKeyLocationConfig defines where to find the API key
type APIKeyLocationConfig struct {
	// Header is the name of the header containing the API key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:default="X-API-Key"
	// +optional
	Header *string `json:"header,omitempty"`

	// QueryParam is the name of the query parameter containing the API key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +optional
	QueryParam *string `json:"queryParam,omitempty"`
}

// APIKeyValidationConfig defines how to validate the API key
type APIKeyValidationConfig struct {
	// Type is the type of validation.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Secret;External
	Type APIKeyValidationType `json:"type"`

	// SecretRef references a Secret containing valid API keys.
	// Required when Type is Secret.
	// +optional
	SecretRef *SecretObjectReference `json:"secretRef,omitempty"`

	// External defines external validation configuration.
	// Required when Type is External.
	// +optional
	External *ExternalValidationConfig `json:"external,omitempty"`
}

// APIKeyValidationType defines the type of API key validation
// +kubebuilder:validation:Enum=Secret;External
type APIKeyValidationType string

const (
	// APIKeyValidationSecret validates against a Secret
	APIKeyValidationSecret APIKeyValidationType = "Secret"
	// APIKeyValidationExternal validates against an external service
	APIKeyValidationExternal APIKeyValidationType = "External"
)

// ExternalValidationConfig defines external validation configuration
type ExternalValidationConfig struct {
	// URL is the URL of the external validation service.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	URL string `json:"url"`

	// Timeout is the timeout for the validation request.
	// +kubebuilder:validation:Pattern=`^([0-9]+(ms|s))+$`
	// +kubebuilder:default="5s"
	// +optional
	Timeout *string `json:"timeout,omitempty"`

	// Headers defines headers to include in the validation request.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Headers []HTTPHeader `json:"headers,omitempty"`
}

// BasicAuthConfig defines basic authentication configuration
type BasicAuthConfig struct {
	// Enabled indicates whether basic authentication is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// SecretRef references a Secret containing username:password pairs.
	// +optional
	SecretRef *SecretObjectReference `json:"secretRef,omitempty"`

	// Realm is the authentication realm.
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:default="Restricted"
	// +optional
	Realm *string `json:"realm,omitempty"`
}

// OAuth2Config defines OAuth2 client credentials configuration
type OAuth2Config struct {
	// Enabled indicates whether OAuth2 is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// TokenEndpoint is the OAuth2 token endpoint.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	TokenEndpoint *string `json:"tokenEndpoint,omitempty"`

	// ClientID is the OAuth2 client ID.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +optional
	ClientID *string `json:"clientId,omitempty"`

	// ClientSecretRef references a Secret containing the client secret.
	// +optional
	ClientSecretRef *SecretObjectReference `json:"clientSecretRef,omitempty"`

	// Scopes is the list of OAuth2 scopes.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Scopes []string `json:"scopes,omitempty"`
}

// ============================================================================
// Authorization Configuration
// ============================================================================

// AuthorizationConfig defines authorization configuration
type AuthorizationConfig struct {
	// Rules defines authorization rules.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	Rules []AuthorizationRule `json:"rules,omitempty"`

	// DefaultAction is the default action when no rules match.
	// +kubebuilder:validation:Enum=ALLOW;DENY
	// +kubebuilder:default=DENY
	// +optional
	DefaultAction *AuthorizationAction `json:"defaultAction,omitempty"`
}

// AuthorizationAction defines the authorization action
// +kubebuilder:validation:Enum=ALLOW;DENY
type AuthorizationAction string

const (
	// AuthorizationActionAllow allows the request
	AuthorizationActionAllow AuthorizationAction = "ALLOW"
	// AuthorizationActionDeny denies the request
	AuthorizationActionDeny AuthorizationAction = "DENY"
)

// AuthorizationRule defines an authorization rule
type AuthorizationRule struct {
	// Name is the name of the rule.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// When defines conditions that must be met for the rule to apply.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	When []AuthorizationCondition `json:"when,omitempty"`

	// To defines the operations this rule applies to.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	To []AuthorizationTarget `json:"to,omitempty"`

	// Action is the action to take when the rule matches.
	// +kubebuilder:validation:Enum=ALLOW;DENY
	// +kubebuilder:default=ALLOW
	// +optional
	Action *AuthorizationAction `json:"action,omitempty"`
}

// AuthorizationCondition defines a condition for authorization
type AuthorizationCondition struct {
	// Claim is the name of the JWT claim to match.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Claim *string `json:"claim,omitempty"`

	// Values is the list of values to match.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Values []string `json:"values,omitempty"`

	// MatchPath enables dynamic matching against path parameters.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	MatchPath *string `json:"matchPath,omitempty"`

	// Header is the name of the header to match.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Header *string `json:"header,omitempty"`

	// SourceIP defines source IP matching.
	// +optional
	SourceIP *SourceIPMatch `json:"sourceIP,omitempty"`
}

// SourceIPMatch defines source IP matching
type SourceIPMatch struct {
	// CIDRs is the list of CIDR ranges to match.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	CIDRs []string `json:"cidrs,omitempty"`

	// NotCIDRs is the list of CIDR ranges to not match.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	NotCIDRs []string `json:"notCidrs,omitempty"`
}

// AuthorizationTarget defines the target of an authorization rule
type AuthorizationTarget struct {
	// Operation defines the operation to match.
	// +optional
	Operation *OperationMatch `json:"operation,omitempty"`
}

// OperationMatch defines an operation to match
type OperationMatch struct {
	// Methods is the list of HTTP methods to match.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Methods []string `json:"methods,omitempty"`

	// Paths is the list of paths to match.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Paths []string `json:"paths,omitempty"`

	// Hosts is the list of hosts to match.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Hosts []string `json:"hosts,omitempty"`

	// Ports is the list of ports to match.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Ports []int32 `json:"ports,omitempty"`
}

// ============================================================================
// Security Headers Configuration
// ============================================================================

// SecurityHeadersConfig defines security headers configuration
type SecurityHeadersConfig struct {
	// CORS defines CORS configuration.
	// +optional
	CORS *CORSConfig `json:"cors,omitempty"`

	// HSTS defines HSTS configuration.
	// +optional
	HSTS *HSTSConfig `json:"hsts,omitempty"`

	// ContentSecurityPolicy is the Content-Security-Policy header value.
	// +kubebuilder:validation:MaxLength=4096
	// +optional
	ContentSecurityPolicy *string `json:"contentSecurityPolicy,omitempty"`

	// XFrameOptions is the X-Frame-Options header value.
	// +kubebuilder:validation:Enum=DENY;SAMEORIGIN
	// +optional
	XFrameOptions *string `json:"xFrameOptions,omitempty"`

	// XContentTypeOptions is the X-Content-Type-Options header value.
	// +kubebuilder:validation:Enum=nosniff
	// +optional
	XContentTypeOptions *string `json:"xContentTypeOptions,omitempty"`

	// XXSSProtection is the X-XSS-Protection header value.
	// +kubebuilder:validation:MaxLength=256
	// +optional
	XXSSProtection *string `json:"xXSSProtection,omitempty"`

	// ReferrerPolicy is the Referrer-Policy header value.
	//nolint:lll // kubebuilder validation enum cannot be shortened
	//+kubebuilder:validation:Enum=no-referrer;no-referrer-when-downgrade;origin;origin-when-cross-origin;same-origin;strict-origin;strict-origin-when-cross-origin;unsafe-url
	// +optional
	ReferrerPolicy *string `json:"referrerPolicy,omitempty"`

	// PermissionsPolicy is the Permissions-Policy header value.
	// +kubebuilder:validation:MaxLength=4096
	// +optional
	PermissionsPolicy *string `json:"permissionsPolicy,omitempty"`
}

// CORSConfig defines CORS configuration
type CORSConfig struct {
	// Enabled indicates whether CORS is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// AllowOrigins defines allowed origins.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	AllowOrigins []CORSOrigin `json:"allowOrigins,omitempty"`

	// AllowMethods defines allowed HTTP methods.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	AllowMethods []string `json:"allowMethods,omitempty"`

	// AllowHeaders defines allowed headers.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	AllowHeaders []string `json:"allowHeaders,omitempty"`

	// ExposeHeaders defines headers to expose.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	ExposeHeaders []string `json:"exposeHeaders,omitempty"`

	// MaxAge is the max age for preflight requests.
	// +optional
	MaxAge *Duration `json:"maxAge,omitempty"`

	// AllowCredentials indicates whether credentials are allowed.
	// +kubebuilder:default=false
	// +optional
	AllowCredentials *bool `json:"allowCredentials,omitempty"`
}

// CORSOrigin defines a CORS origin
type CORSOrigin struct {
	// Exact is an exact origin match.
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	Exact *string `json:"exact,omitempty"`

	// Prefix is a prefix origin match.
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	Prefix *string `json:"prefix,omitempty"`

	// Regex is a regex origin match.
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	Regex *string `json:"regex,omitempty"`
}

// HSTSConfig defines HSTS configuration
type HSTSConfig struct {
	// Enabled indicates whether HSTS is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// MaxAge is the max age in seconds.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=63072000
	// +kubebuilder:default=31536000
	// +optional
	MaxAge *int32 `json:"maxAge,omitempty"`

	// IncludeSubDomains indicates whether to include subdomains.
	// +kubebuilder:default=true
	// +optional
	IncludeSubDomains *bool `json:"includeSubDomains,omitempty"`

	// Preload indicates whether to enable HSTS preload.
	// +kubebuilder:default=false
	// +optional
	Preload *bool `json:"preload,omitempty"`
}

// ============================================================================
// AuthPolicy Status
// ============================================================================

// AuthPolicyStatus defines the observed state of AuthPolicy
type AuthPolicyStatus struct {
	Status `json:",inline"`
}

// GetTargetRef returns the target reference for the policy.
// This implements the PolicyWithTargetRef interface.
func (p *AuthPolicy) GetTargetRef() TargetRef {
	return p.Spec.TargetRef
}

// GetPolicies returns the list of AuthPolicy items.
// This implements the PolicyList interface for watch handlers.
func (l *AuthPolicyList) GetPolicies() []*AuthPolicy {
	policies := make([]*AuthPolicy, len(l.Items))
	for i := range l.Items {
		policies[i] = &l.Items[i]
	}
	return policies
}

func init() {
	SchemeBuilder.Register(&AuthPolicy{}, &AuthPolicyList{})
}
