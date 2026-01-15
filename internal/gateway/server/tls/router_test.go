// Package tls provides the TLS server implementation for the API Gateway.
package tls

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestNewRouter(t *testing.T) {
	tests := []struct {
		name   string
		logger *zap.Logger
	}{
		{
			name:   "with logger",
			logger: zaptest.NewLogger(t),
		},
		{
			name:   "with nop logger",
			logger: zap.NewNop(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(tt.logger)

			require.NotNil(t, router)
			assert.NotNil(t, router.routes)
			assert.NotNil(t, router.hostnameIndex)
			assert.NotNil(t, router.wildcardRoutes)
			assert.Equal(t, tt.logger, router.logger)
			assert.Empty(t, router.routes)
			assert.Empty(t, router.hostnameIndex)
			assert.Empty(t, router.wildcardRoutes)
		})
	}
}

func TestRouter_Match(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		setupRoutes   []*TLSRoute
		sni           string
		expectedRoute string
		expectError   bool
		errorContains string
	}{
		{
			name: "exact match",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			sni:           "example.com",
			expectedRoute: "route1",
			expectError:   false,
		},
		{
			name: "exact match case insensitive",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"Example.COM"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			sni:           "example.com",
			expectedRoute: "route1",
			expectError:   false,
		},
		{
			name: "wildcard match",
			setupRoutes: []*TLSRoute{
				{
					Name:      "wildcard-route",
					Hostnames: []string{"*.example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			sni:           "api.example.com",
			expectedRoute: "wildcard-route",
			expectError:   false,
		},
		{
			name: "wildcard match subdomain",
			setupRoutes: []*TLSRoute{
				{
					Name:      "wildcard-route",
					Hostnames: []string{"*.example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			sni:           "www.example.com",
			expectedRoute: "wildcard-route",
			expectError:   false,
		},
		{
			name: "exact match takes precedence over wildcard",
			setupRoutes: []*TLSRoute{
				{
					Name:      "wildcard-route",
					Hostnames: []string{"*.example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
				{
					Name:      "exact-route",
					Hostnames: []string{"api.example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend2", Port: 443},
					},
				},
			},
			sni:           "api.example.com",
			expectedRoute: "exact-route",
			expectError:   false,
		},
		{
			name:          "empty SNI",
			setupRoutes:   []*TLSRoute{},
			sni:           "",
			expectedRoute: "",
			expectError:   true,
			errorContains: "empty SNI",
		},
		{
			name: "not found",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			sni:           "other.com",
			expectedRoute: "",
			expectError:   true,
			errorContains: "no route found",
		},
		{
			name: "wildcard does not match multi-level subdomain",
			setupRoutes: []*TLSRoute{
				{
					Name:      "wildcard-route",
					Hostnames: []string{"*.example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			sni:           "sub.api.example.com",
			expectedRoute: "",
			expectError:   true,
			errorContains: "no route found",
		},
		{
			name: "multiple hostnames in route",
			setupRoutes: []*TLSRoute{
				{
					Name:      "multi-host-route",
					Hostnames: []string{"example.com", "example.org", "example.net"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			sni:           "example.org",
			expectedRoute: "multi-host-route",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			// Setup routes
			for _, route := range tt.setupRoutes {
				err := router.AddRoute(route)
				require.NoError(t, err)
			}

			// Test match
			route, err := router.Match(tt.sni)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, route)
			} else {
				require.NoError(t, err)
				require.NotNil(t, route)
				assert.Equal(t, tt.expectedRoute, route.Name)
			}
		})
	}
}

func TestRouter_AddRoute(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		existingRoute *TLSRoute
		newRoute      *TLSRoute
		expectError   bool
		errorContains string
	}{
		{
			name:          "add new route",
			existingRoute: nil,
			newRoute: &TLSRoute{
				Name:      "route1",
				Hostnames: []string{"example.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			expectError: false,
		},
		{
			name: "add duplicate route",
			existingRoute: &TLSRoute{
				Name:      "route1",
				Hostnames: []string{"example.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			newRoute: &TLSRoute{
				Name:      "route1",
				Hostnames: []string{"other.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend2", Port: 443},
				},
			},
			expectError:   true,
			errorContains: "already exists",
		},
		{
			name:          "add route with wildcard hostname",
			existingRoute: nil,
			newRoute: &TLSRoute{
				Name:      "wildcard-route",
				Hostnames: []string{"*.example.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			expectError: false,
		},
		{
			name:          "add route with mixed hostnames",
			existingRoute: nil,
			newRoute: &TLSRoute{
				Name:      "mixed-route",
				Hostnames: []string{"example.com", "*.example.org"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			// Add existing route if specified
			if tt.existingRoute != nil {
				err := router.AddRoute(tt.existingRoute)
				require.NoError(t, err)
			}

			// Add new route
			err := router.AddRoute(tt.newRoute)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				// Verify route was added
				route := router.GetRoute(tt.newRoute.Name)
				require.NotNil(t, route)
				assert.Equal(t, tt.newRoute.Name, route.Name)
			}
		})
	}
}

func TestRouter_RemoveRoute(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		setupRoutes   []*TLSRoute
		removeRoute   string
		expectError   bool
		errorContains string
	}{
		{
			name: "remove existing route",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			removeRoute: "route1",
			expectError: false,
		},
		{
			name:          "remove non-existent route",
			setupRoutes:   []*TLSRoute{},
			removeRoute:   "non-existent",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name: "remove route with wildcard hostname",
			setupRoutes: []*TLSRoute{
				{
					Name:      "wildcard-route",
					Hostnames: []string{"*.example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			removeRoute: "wildcard-route",
			expectError: false,
		},
		{
			name: "remove route with mixed hostnames",
			setupRoutes: []*TLSRoute{
				{
					Name:      "mixed-route",
					Hostnames: []string{"example.com", "*.example.org"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			removeRoute: "mixed-route",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			// Setup routes
			for _, route := range tt.setupRoutes {
				err := router.AddRoute(route)
				require.NoError(t, err)
			}

			// Remove route
			err := router.RemoveRoute(tt.removeRoute)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				// Verify route was removed
				route := router.GetRoute(tt.removeRoute)
				assert.Nil(t, route)
			}
		})
	}
}

func TestRouter_UpdateRoute(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		existingRoute *TLSRoute
		updateRoute   *TLSRoute
		expectError   bool
		errorContains string
	}{
		{
			name: "update existing route",
			existingRoute: &TLSRoute{
				Name:      "route1",
				Hostnames: []string{"example.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			updateRoute: &TLSRoute{
				Name:      "route1",
				Hostnames: []string{"updated.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend2", Port: 8443},
				},
			},
			expectError: false,
		},
		{
			name:          "update non-existent route",
			existingRoute: nil,
			updateRoute: &TLSRoute{
				Name:      "non-existent",
				Hostnames: []string{"example.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			expectError:   true,
			errorContains: "not found",
		},
		{
			name: "update route from exact to wildcard",
			existingRoute: &TLSRoute{
				Name:      "route1",
				Hostnames: []string{"example.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			updateRoute: &TLSRoute{
				Name:      "route1",
				Hostnames: []string{"*.example.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			expectError: false,
		},
		{
			name: "update route from wildcard to exact",
			existingRoute: &TLSRoute{
				Name:      "route1",
				Hostnames: []string{"*.example.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			updateRoute: &TLSRoute{
				Name:      "route1",
				Hostnames: []string{"example.com"},
				BackendRefs: []TLSBackendRef{
					{Name: "backend1", Port: 443},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			// Add existing route if specified
			if tt.existingRoute != nil {
				err := router.AddRoute(tt.existingRoute)
				require.NoError(t, err)
			}

			// Update route
			err := router.UpdateRoute(tt.updateRoute)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				// Verify route was updated
				route := router.GetRoute(tt.updateRoute.Name)
				require.NotNil(t, route)
				assert.Equal(t, tt.updateRoute.Hostnames, route.Hostnames)
			}
		})
	}
}

func TestRouter_GetRoute(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		setupRoutes []*TLSRoute
		getRoute    string
		expectNil   bool
	}{
		{
			name: "get existing route",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
					BackendRefs: []TLSBackendRef{
						{Name: "backend1", Port: 443},
					},
				},
			},
			getRoute:  "route1",
			expectNil: false,
		},
		{
			name:        "get non-existent route",
			setupRoutes: []*TLSRoute{},
			getRoute:    "non-existent",
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			// Setup routes
			for _, route := range tt.setupRoutes {
				err := router.AddRoute(route)
				require.NoError(t, err)
			}

			// Get route
			route := router.GetRoute(tt.getRoute)

			if tt.expectNil {
				assert.Nil(t, route)
			} else {
				require.NotNil(t, route)
				assert.Equal(t, tt.getRoute, route.Name)
			}
		})
	}
}

func TestRouter_ListRoutes(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		setupRoutes   []*TLSRoute
		expectedCount int
	}{
		{
			name:          "empty router",
			setupRoutes:   []*TLSRoute{},
			expectedCount: 0,
		},
		{
			name: "single route",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
				},
			},
			expectedCount: 1,
		},
		{
			name: "multiple routes",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
				},
				{
					Name:      "route2",
					Hostnames: []string{"example.org"},
				},
				{
					Name:      "route3",
					Hostnames: []string{"example.net"},
				},
			},
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			// Setup routes
			for _, route := range tt.setupRoutes {
				err := router.AddRoute(route)
				require.NoError(t, err)
			}

			// List routes
			names := router.ListRoutes()

			assert.Len(t, names, tt.expectedCount)
		})
	}
}

func TestRouter_GetAllRoutes(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		setupRoutes   []*TLSRoute
		expectedCount int
	}{
		{
			name:          "empty router",
			setupRoutes:   []*TLSRoute{},
			expectedCount: 0,
		},
		{
			name: "single route",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
				},
			},
			expectedCount: 1,
		},
		{
			name: "multiple routes",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
				},
				{
					Name:      "route2",
					Hostnames: []string{"example.org"},
				},
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			// Setup routes
			for _, route := range tt.setupRoutes {
				err := router.AddRoute(route)
				require.NoError(t, err)
			}

			// Get all routes
			routes := router.GetAllRoutes()

			assert.Len(t, routes, tt.expectedCount)
		})
	}
}

func TestRouter_Clear(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		setupRoutes []*TLSRoute
	}{
		{
			name:        "clear empty router",
			setupRoutes: []*TLSRoute{},
		},
		{
			name: "clear router with routes",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
				},
				{
					Name:      "route2",
					Hostnames: []string{"*.example.org"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			// Setup routes
			for _, route := range tt.setupRoutes {
				err := router.AddRoute(route)
				require.NoError(t, err)
			}

			// Clear router
			router.Clear()

			// Verify router is empty
			assert.Empty(t, router.ListRoutes())
			assert.Empty(t, router.GetAllRoutes())
		})
	}
}

func TestRouter_GetRouteForHostname(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		setupRoutes   []*TLSRoute
		hostname      string
		expectedRoute string
		expectNil     bool
	}{
		{
			name: "get route for exact hostname",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
				},
			},
			hostname:      "example.com",
			expectedRoute: "route1",
			expectNil:     false,
		},
		{
			name: "get route for wildcard hostname",
			setupRoutes: []*TLSRoute{
				{
					Name:      "wildcard-route",
					Hostnames: []string{"*.example.com"},
				},
			},
			hostname:      "api.example.com",
			expectedRoute: "wildcard-route",
			expectNil:     false,
		},
		{
			name: "no route for hostname",
			setupRoutes: []*TLSRoute{
				{
					Name:      "route1",
					Hostnames: []string{"example.com"},
				},
			},
			hostname:  "other.com",
			expectNil: true,
		},
		{
			name:        "empty hostname",
			setupRoutes: []*TLSRoute{},
			hostname:    "",
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(logger)

			// Setup routes
			for _, route := range tt.setupRoutes {
				err := router.AddRoute(route)
				require.NoError(t, err)
			}

			// Get route for hostname
			route := router.GetRouteForHostname(tt.hostname)

			if tt.expectNil {
				assert.Nil(t, route)
			} else {
				require.NotNil(t, route)
				assert.Equal(t, tt.expectedRoute, route.Name)
			}
		})
	}
}

func TestCompileWildcardPattern(t *testing.T) {
	tests := []struct {
		name           string
		pattern        string
		testHostname   string
		shouldMatch    bool
		expectNilRegex bool
	}{
		{
			name:         "simple wildcard",
			pattern:      "*.example.com",
			testHostname: "api.example.com",
			shouldMatch:  true,
		},
		{
			name:         "wildcard does not match base domain",
			pattern:      "*.example.com",
			testHostname: "example.com",
			shouldMatch:  false,
		},
		{
			name:         "wildcard does not match multi-level subdomain",
			pattern:      "*.example.com",
			testHostname: "sub.api.example.com",
			shouldMatch:  false,
		},
		{
			name:         "wildcard matches single subdomain",
			pattern:      "*.example.com",
			testHostname: "www.example.com",
			shouldMatch:  true,
		},
		{
			name:         "wildcard with longer domain",
			pattern:      "*.sub.example.com",
			testHostname: "api.sub.example.com",
			shouldMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex := compileWildcardPattern(tt.pattern)

			if tt.expectNilRegex {
				assert.Nil(t, regex)
				return
			}

			require.NotNil(t, regex)
			assert.Equal(t, tt.shouldMatch, regex.MatchString(tt.testHostname))
		})
	}
}

func TestRouter_Concurrency(t *testing.T) {
	logger := zap.NewNop()
	router := NewRouter(logger)

	// Number of concurrent operations
	numOps := 100
	var wg sync.WaitGroup

	// Add routes concurrently
	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func(idx int) {
			defer wg.Done()
			route := &TLSRoute{
				Name:      "route-" + string(rune('a'+idx%26)) + "-" + string(rune('0'+idx/26)),
				Hostnames: []string{"host-" + string(rune('a'+idx%26)) + ".example.com"},
			}
			_ = router.AddRoute(route)
		}(i)
	}
	wg.Wait()

	// Match routes concurrently
	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func(idx int) {
			defer wg.Done()
			hostname := "host-" + string(rune('a'+idx%26)) + ".example.com"
			_, _ = router.Match(hostname)
		}(i)
	}
	wg.Wait()

	// List routes concurrently
	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func() {
			defer wg.Done()
			_ = router.ListRoutes()
		}()
	}
	wg.Wait()

	// Get all routes concurrently
	wg.Add(numOps)
	for i := 0; i < numOps; i++ {
		go func() {
			defer wg.Done()
			_ = router.GetAllRoutes()
		}()
	}
	wg.Wait()

	// Clear should work after concurrent operations
	router.Clear()
	assert.Empty(t, router.ListRoutes())
}

func TestRouter_WildcardPriority(t *testing.T) {
	logger := zap.NewNop()
	router := NewRouter(logger)

	// Add routes with different priorities
	routes := []*TLSRoute{
		{
			Name:      "low-priority",
			Hostnames: []string{"*.example.com"},
			Priority:  1,
		},
		{
			Name:      "high-priority",
			Hostnames: []string{"*.api.example.com"},
			Priority:  10,
		},
	}

	for _, route := range routes {
		err := router.AddRoute(route)
		require.NoError(t, err)
	}

	// Test that more specific pattern matches
	route, err := router.Match("test.api.example.com")
	require.NoError(t, err)
	assert.Equal(t, "high-priority", route.Name)
}
