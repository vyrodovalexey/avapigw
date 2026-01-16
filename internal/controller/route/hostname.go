// Package route provides shared utilities for route controllers.
package route

import (
	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// HostnameMatches checks if route hostnames match the listener hostname.
// Returns true if:
//   - Listener has no hostname (matches all)
//   - Route has no hostnames (matches all listeners)
//   - Any route hostname matches the listener hostname (including wildcards)
func HostnameMatches(routeHostnames []avapigwv1alpha1.Hostname, listenerHostname *avapigwv1alpha1.Hostname) bool {
	// If listener has no hostname, it matches all
	if listenerHostname == nil {
		return true
	}

	// If route has no hostnames, it matches all listeners
	if len(routeHostnames) == 0 {
		return true
	}

	listenerHost := string(*listenerHostname)
	for _, routeHostname := range routeHostnames {
		routeHost := string(routeHostname)
		if HostnameMatch(routeHost, listenerHost) {
			return true
		}
	}

	return false
}

// HostnameMatch checks if two hostnames match (supporting wildcards).
// Wildcard matching rules:
//   - Exact match: "example.com" matches "example.com"
//   - Listener wildcard: "*.example.com" matches "api.example.com"
//   - Route wildcard: "*.example.com" matches "api.example.com"
//   - Both wildcards: "*.example.com" matches "*.example.com" (same suffix)
func HostnameMatch(routeHost, listenerHost string) bool {
	// Exact match
	if routeHost == listenerHost {
		return true
	}

	// Wildcard matching
	if listenerHost != "" && listenerHost[0] == '*' {
		// Listener has wildcard, e.g., *.example.com
		suffix := listenerHost[1:] // .example.com
		if routeHost != "" && routeHost[0] == '*' {
			// Both have wildcards
			return routeHost[1:] == suffix
		}
		// Route is specific, check if it matches the wildcard
		if len(routeHost) > len(suffix) {
			return routeHost[len(routeHost)-len(suffix):] == suffix
		}
	}

	if routeHost != "" && routeHost[0] == '*' {
		// Route has wildcard, e.g., *.example.com
		suffix := routeHost[1:] // .example.com
		// Listener is specific, check if it matches the wildcard
		if len(listenerHost) > len(suffix) {
			return listenerHost[len(listenerHost)-len(suffix):] == suffix
		}
	}

	return false
}
