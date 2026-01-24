package auth

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"
)

// Credentials represents extracted credentials.
type Credentials struct {
	// Type is the credential type.
	Type CredentialType

	// Value is the credential value.
	Value string

	// Source is where the credential was extracted from.
	Source string
}

// CredentialType represents the type of credential.
type CredentialType string

// Credential types.
const (
	CredentialTypeJWT    CredentialType = "jwt"
	CredentialTypeAPIKey CredentialType = "apikey"
	CredentialTypeBasic  CredentialType = "basic"
)

// Extractor extracts credentials from requests.
type Extractor interface {
	// ExtractJWT extracts a JWT token from the request.
	ExtractJWT(r *http.Request) (*Credentials, error)

	// ExtractAPIKey extracts an API key from the request.
	ExtractAPIKey(r *http.Request) (*Credentials, error)

	// ExtractJWTFromGRPC extracts a JWT token from gRPC metadata.
	ExtractJWTFromGRPC(ctx context.Context) (*Credentials, error)

	// ExtractAPIKeyFromGRPC extracts an API key from gRPC metadata.
	ExtractAPIKeyFromGRPC(ctx context.Context) (*Credentials, error)
}

// extractor implements the Extractor interface.
type extractor struct {
	config *ExtractionConfig
}

// NewExtractor creates a new credential extractor.
func NewExtractor(config *ExtractionConfig) Extractor {
	if config == nil {
		config = &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
			},
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-API-Key"},
			},
		}
	}
	return &extractor{config: config}
}

// ExtractJWT extracts a JWT token from the request.
func (e *extractor) ExtractJWT(r *http.Request) (*Credentials, error) {
	for _, source := range e.config.JWT {
		value := e.extractFromHTTP(r, source)
		if value != "" {
			return &Credentials{
				Type:   CredentialTypeJWT,
				Value:  value,
				Source: string(source.Type) + ":" + source.Name,
			}, nil
		}
	}
	return nil, ErrNoCredentials
}

// ExtractAPIKey extracts an API key from the request.
func (e *extractor) ExtractAPIKey(r *http.Request) (*Credentials, error) {
	for _, source := range e.config.APIKey {
		value := e.extractFromHTTP(r, source)
		if value != "" {
			return &Credentials{
				Type:   CredentialTypeAPIKey,
				Value:  value,
				Source: string(source.Type) + ":" + source.Name,
			}, nil
		}
	}
	return nil, ErrNoCredentials
}

// ExtractJWTFromGRPC extracts a JWT token from gRPC metadata.
func (e *extractor) ExtractJWTFromGRPC(ctx context.Context) (*Credentials, error) {
	for _, source := range e.config.JWT {
		if source.Type != ExtractionTypeMetadata && source.Type != ExtractionTypeHeader {
			continue
		}
		value := e.extractFromGRPC(ctx, source)
		if value != "" {
			return &Credentials{
				Type:   CredentialTypeJWT,
				Value:  value,
				Source: "metadata:" + source.Name,
			}, nil
		}
	}
	return nil, ErrNoCredentials
}

// ExtractAPIKeyFromGRPC extracts an API key from gRPC metadata.
func (e *extractor) ExtractAPIKeyFromGRPC(ctx context.Context) (*Credentials, error) {
	for _, source := range e.config.APIKey {
		if source.Type != ExtractionTypeMetadata && source.Type != ExtractionTypeHeader {
			continue
		}
		value := e.extractFromGRPC(ctx, source)
		if value != "" {
			return &Credentials{
				Type:   CredentialTypeAPIKey,
				Value:  value,
				Source: "metadata:" + source.Name,
			}, nil
		}
	}
	return nil, ErrNoCredentials
}

// extractFromHTTP extracts a value from an HTTP request.
func (e *extractor) extractFromHTTP(r *http.Request, source ExtractionSource) string {
	var value string

	switch source.Type {
	case ExtractionTypeHeader:
		value = r.Header.Get(source.Name)
	case ExtractionTypeCookie:
		if cookie, err := r.Cookie(source.Name); err == nil {
			value = cookie.Value
		}
	case ExtractionTypeQuery:
		value = r.URL.Query().Get(source.Name)
	}

	if value == "" {
		return ""
	}

	// Strip prefix if configured
	if source.Prefix != "" {
		if strings.HasPrefix(value, source.Prefix) {
			value = strings.TrimPrefix(value, source.Prefix)
		} else {
			return ""
		}
	}

	return strings.TrimSpace(value)
}

// extractFromGRPC extracts a value from gRPC metadata.
func (e *extractor) extractFromGRPC(ctx context.Context, source ExtractionSource) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	// Try the exact name first
	values := md.Get(source.Name)
	if len(values) == 0 {
		// Try lowercase (gRPC metadata keys are lowercase)
		values = md.Get(strings.ToLower(source.Name))
	}

	if len(values) == 0 {
		return ""
	}

	value := values[0]

	// Strip prefix if configured
	if source.Prefix != "" {
		if strings.HasPrefix(value, source.Prefix) {
			value = strings.TrimPrefix(value, source.Prefix)
		} else {
			return ""
		}
	}

	return strings.TrimSpace(value)
}

// ExtractBearerToken extracts a bearer token from the Authorization header.
func ExtractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}

	return strings.TrimSpace(auth[len(prefix):])
}

// ExtractBearerTokenFromGRPC extracts a bearer token from gRPC metadata.
func ExtractBearerTokenFromGRPC(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return ""
	}

	auth := values[0]
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}

	return strings.TrimSpace(auth[len(prefix):])
}

// Ensure extractor implements Extractor.
var _ Extractor = (*extractor)(nil)
