// Package auth provides authentication functionality for the API Gateway.
package auth

// HTTP header constants for authentication.
const (
	// HeaderAuthorization is the Authorization header name.
	HeaderAuthorization = "Authorization"

	// HeaderWWWAuthenticate is the WWW-Authenticate header name.
	HeaderWWWAuthenticate = "WWW-Authenticate"

	// HeaderXAPIKey is the X-Api-Key header name.
	HeaderXAPIKey = "X-Api-Key"

	// HeaderXAuthToken is the X-Auth-Token header name.
	HeaderXAuthToken = "X-Auth-Token"

	// HeaderProxyAuthorization is the Proxy-Authorization header name.
	HeaderProxyAuthorization = "Proxy-Authorization"

	// HeaderContentType is the Content-Type header name.
	HeaderContentType = "Content-Type"

	// HeaderCookie is the Cookie header name.
	HeaderCookie = "Cookie"

	// HeaderSetCookie is the Set-Cookie header name.
	HeaderSetCookie = "Set-Cookie"
)

// Content type constants.
const (
	// ContentTypeJSON is the JSON content type.
	ContentTypeJSON = "application/json"
)

// Authentication scheme constants.
const (
	// AuthSchemeBearer is the Bearer authentication scheme prefix.
	AuthSchemeBearer = "Bearer "

	// AuthSchemeBasic is the Basic authentication scheme prefix.
	AuthSchemeBasic = "Basic "

	// AuthSchemeAPIKey is the ApiKey authentication scheme prefix.
	AuthSchemeAPIKey = "ApiKey "
)
