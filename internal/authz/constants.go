// Package authz provides authorization functionality for the API Gateway.
package authz

// HTTP header constants for authorization.
const (
	// HeaderContentType is the Content-Type header name.
	HeaderContentType = "Content-Type"

	// HeaderAuthorization is the Authorization header name.
	HeaderAuthorization = "Authorization"

	// HeaderCookie is the Cookie header name.
	HeaderCookie = "Cookie"

	// HeaderSetCookie is the Set-Cookie header name.
	HeaderSetCookie = "Set-Cookie"

	// HeaderXAPIKey is the X-Api-Key header name.
	HeaderXAPIKey = "X-Api-Key"

	// HeaderXAuthToken is the X-Auth-Token header name.
	HeaderXAuthToken = "X-Auth-Token"

	// HeaderProxyAuthorization is the Proxy-Authorization header name.
	HeaderProxyAuthorization = "Proxy-Authorization"

	// HeaderXForwardedFor is the X-Forwarded-For header name.
	HeaderXForwardedFor = "X-Forwarded-For"

	// HeaderXRealIP is the X-Real-IP header name.
	HeaderXRealIP = "X-Real-IP"
)

// Content type constants.
const (
	// ContentTypeJSON is the JSON content type.
	ContentTypeJSON = "application/json"
)
