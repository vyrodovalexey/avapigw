// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"context"
	"fmt"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	graphqlproxy "github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GraphQLGatewayInstance represents a running gateway serving the embedded
// GraphQL endpoint (router + proxy wired into the gateway's gin engine).
type GraphQLGatewayInstance struct {
	Gateway *gateway.Gateway
	Config  *config.GatewayConfig
	Router  *graphqlrouter.Router
	Proxy   *graphqlproxy.Proxy
	BaseURL string
}

// StartGraphQLGatewayWithConfig starts a gateway with the embedded GraphQL
// pipeline built from cfg.Spec.GraphQLRoutes and cfg.Spec.GraphQLBackends.
// The /graphql endpoint (or spec.graphql.path) serves queries, CORS
// preflights, and graphql-ws subscription upgrades, honoring
// spec.websocket.allowedOrigins. Works with both HTTP and HTTPS listeners.
func StartGraphQLGatewayWithConfig(
	ctx context.Context, cfg *config.GatewayConfig,
) (*GraphQLGatewayInstance, error) {
	logger := observability.NopLogger()

	rt := graphqlrouter.New(graphqlrouter.WithRouterLogger(logger))
	if err := rt.LoadRoutes(cfg.Spec.GraphQLRoutes); err != nil {
		return nil, fmt.Errorf("failed to load GraphQL routes: %w", err)
	}

	px := graphqlproxy.New(
		graphqlproxy.WithLogger(logger),
		graphqlproxy.WithTimeout(30*time.Second),
	)
	px.UpdateBackends(cfg.Spec.GraphQLBackends)

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithGraphQLRouter(rt),
		gateway.WithGraphQLProxy(px),
	)
	if err != nil {
		px.Close()
		return nil, fmt.Errorf("failed to create GraphQL gateway: %w", err)
	}

	if err := gw.Start(ctx); err != nil {
		px.Close()
		return nil, fmt.Errorf("failed to start GraphQL gateway: %w", err)
	}

	port := 8080
	scheme := "http"
	if len(cfg.Spec.Listeners) > 0 {
		port = cfg.Spec.Listeners[0].Port
		if cfg.Spec.Listeners[0].Protocol == config.ProtocolHTTPS {
			scheme = "https"
		}
	}

	return &GraphQLGatewayInstance{
		Gateway: gw,
		Config:  cfg,
		Router:  rt,
		Proxy:   px,
		BaseURL: fmt.Sprintf("%s://127.0.0.1:%d", scheme, port),
	}, nil
}

// Stop stops the GraphQL gateway instance and closes the proxy.
func (gi *GraphQLGatewayInstance) Stop(ctx context.Context) error {
	var err error
	if gi.Gateway != nil {
		err = gi.Gateway.Stop(ctx)
	}
	if gi.Proxy != nil {
		gi.Proxy.Close()
	}
	return err
}

// BuildGraphQLGatewayConfig builds a gateway config with a single listener
// (HTTP, or HTTPS when certs is non-nil) and one GraphQL route to the given
// backend. Optional allowed origins install the subscription CSWSH policy.
func BuildGraphQLGatewayConfig(
	port int,
	certs *TestCertificates,
	backendHost string,
	backendPort int,
	allowedOrigins []string,
) *config.GatewayConfig {
	listener := config.Listener{
		Name:     "http",
		Port:     port,
		Protocol: config.ProtocolHTTP,
		Bind:     "127.0.0.1",
	}
	if certs != nil {
		listener.Name = "https"
		listener.Protocol = config.ProtocolHTTPS
		listener.TLS = &config.ListenerTLSConfig{
			Mode:       "SIMPLE",
			MinVersion: "TLS12",
			CertFile:   certs.ServerCertPath(),
			KeyFile:    certs.ServerKeyPath(),
		}
	}

	cfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "graphql-ws-test-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{listener},
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "graphql-ws-route",
					Match: []config.GraphQLRouteMatch{
						{Path: &config.StringMatch{Exact: "/graphql"}},
					},
					Route: []config.RouteDestination{
						{
							Destination: config.Destination{
								Host: backendHost,
								Port: backendPort,
							},
							Weight: 100,
						},
					},
					Timeout: config.Duration(30 * time.Second),
				},
			},
			GraphQLBackends: []config.GraphQLBackend{
				{
					Name: backendHost,
					Hosts: []config.BackendHost{
						{Address: backendHost, Port: backendPort},
					},
				},
			},
		},
	}
	if len(allowedOrigins) > 0 {
		cfg.Spec.WebSocket = &config.WebSocketConfig{AllowedOrigins: allowedOrigins}
	}
	return cfg
}
