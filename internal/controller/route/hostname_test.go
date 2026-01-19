package route

import (
	"testing"

	"github.com/stretchr/testify/assert"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

func ptrString(s string) *string {
	return &s
}

func TestHostnameMatches(t *testing.T) {
	tests := []struct {
		name             string
		routeHostnames   []avapigwv1alpha1.Hostname
		listenerHostname *avapigwv1alpha1.Hostname
		wantMatch        bool
	}{
		{
			name:             "nil listener hostname matches all",
			routeHostnames:   []avapigwv1alpha1.Hostname{"example.com"},
			listenerHostname: nil,
			wantMatch:        true,
		},
		{
			name:             "empty route hostnames matches all",
			routeHostnames:   []avapigwv1alpha1.Hostname{},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com")),
			wantMatch:        true,
		},
		{
			name:             "exact match",
			routeHostnames:   []avapigwv1alpha1.Hostname{"example.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com")),
			wantMatch:        true,
		},
		{
			name:             "no match",
			routeHostnames:   []avapigwv1alpha1.Hostname{"example.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("other.com")),
			wantMatch:        false,
		},
		{
			name:             "multiple route hostnames - one matches",
			routeHostnames:   []avapigwv1alpha1.Hostname{"foo.com", "example.com", "bar.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com")),
			wantMatch:        true,
		},
		{
			name:             "multiple route hostnames - none match",
			routeHostnames:   []avapigwv1alpha1.Hostname{"foo.com", "bar.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("example.com")),
			wantMatch:        false,
		},
		{
			name:             "wildcard listener matches subdomain",
			routeHostnames:   []avapigwv1alpha1.Hostname{"api.example.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("*.example.com")),
			wantMatch:        true,
		},
		{
			name:             "wildcard route matches subdomain",
			routeHostnames:   []avapigwv1alpha1.Hostname{"*.example.com"},
			listenerHostname: (*avapigwv1alpha1.Hostname)(ptrString("api.example.com")),
			wantMatch:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HostnameMatches(tt.routeHostnames, tt.listenerHostname)
			assert.Equal(t, tt.wantMatch, result)
		})
	}
}

func TestHostnameMatch(t *testing.T) {
	tests := []struct {
		name         string
		routeHost    string
		listenerHost string
		wantMatch    bool
	}{
		{
			name:         "exact match",
			routeHost:    "example.com",
			listenerHost: "example.com",
			wantMatch:    true,
		},
		{
			name:         "no match - different hosts",
			routeHost:    "example.com",
			listenerHost: "other.com",
			wantMatch:    false,
		},
		{
			name:         "listener wildcard matches route subdomain",
			routeHost:    "api.example.com",
			listenerHost: "*.example.com",
			wantMatch:    true,
		},
		{
			name:         "listener wildcard does not match different domain",
			routeHost:    "api.other.com",
			listenerHost: "*.example.com",
			wantMatch:    false,
		},
		{
			name:         "route wildcard matches listener subdomain",
			routeHost:    "*.example.com",
			listenerHost: "api.example.com",
			wantMatch:    true,
		},
		{
			name:         "both wildcards - same suffix",
			routeHost:    "*.example.com",
			listenerHost: "*.example.com",
			wantMatch:    true,
		},
		{
			name:         "both wildcards - different suffix",
			routeHost:    "*.example.com",
			listenerHost: "*.other.com",
			wantMatch:    false,
		},
		{
			name:         "empty strings",
			routeHost:    "",
			listenerHost: "",
			wantMatch:    true,
		},
		{
			name:         "wildcard listener with short route host",
			routeHost:    "a.com",
			listenerHost: "*.example.com",
			wantMatch:    false,
		},
		{
			name:         "wildcard route with short listener host",
			routeHost:    "*.example.com",
			listenerHost: "a.com",
			wantMatch:    false,
		},
		{
			name:         "deep subdomain matches wildcard",
			routeHost:    "deep.sub.example.com",
			listenerHost: "*.example.com",
			wantMatch:    true,
		},
		{
			name:         "wildcard route matches deep subdomain",
			routeHost:    "*.example.com",
			listenerHost: "deep.sub.example.com",
			wantMatch:    true,
		},
		{
			name:         "single character wildcard suffix",
			routeHost:    "a.b",
			listenerHost: "*.b",
			wantMatch:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HostnameMatch(tt.routeHost, tt.listenerHost)
			assert.Equal(t, tt.wantMatch, result)
		})
	}
}
