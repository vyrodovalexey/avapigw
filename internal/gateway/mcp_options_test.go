package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/meta"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/mcp/namespace"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestNewMCPHandler_AllOptions exercises every With* option setter so the
// wiring surface is covered. Optional components are passed as nil where a nil
// value is the documented additive default.
func TestNewMCPHandler_AllOptions(t *testing.T) {
	t.Parallel()

	mapper, err := namespace.NewDefaultMapper(".")
	require.NoError(t, err)

	h, err := NewMCPHandler(
		WithMCPHandlerLogger(observability.NopLogger()),
		WithMCPHandlerBackendRegistry(&fakeBackendRegistry{}),
		WithMCPHandlerHub(&fakeHub{}),
		WithMCPHandlerMapper(mapper),
		WithMCPHandlerMetrics(mcpmetrics.GetMetrics()),
		WithMCPHandlerRouteMiddleware(nil),
		WithMCPHandlerConfig(nil, nil, &config.MCPConfig{}),
		WithMCPHandlerClientInfo(meta.Info{Name: "client"}),
		WithMCPHandlerServerInfo(meta.Info{Name: "server"}),
		WithMCPHandlerAggregator(nil),
		WithMCPHandlerCache(nil),
		WithMCPHandlerAuthorizer(nil),
		WithMCPHandlerMRTRCoordinator(nil),
		WithMCPHandlerSubscriptionManager(nil),
		WithMCPHandlerAuditLogger(nil),
		WithMCPHandlerDryRun(false),
		WithMCPHandlerLimits(10, 20),
		WithMCPHandlerEra(nil, nil),
	)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, "client", h.hubClientInfo.Name)
	assert.Equal(t, "server", h.hubServerInfo.Name)
	assert.NotNil(t, h.limiter)
}

// TestWithMCPHandlerLogger_NilIgnored verifies a nil logger does not overwrite
// the default.
func TestWithMCPHandlerLogger_NilIgnored(t *testing.T) {
	t.Parallel()

	h, err := NewMCPHandler(WithMCPHandlerLogger(nil))
	require.NoError(t, err)
	assert.NotNil(t, h.logger)
}

// TestWithMCPHandlerAuditLogger_NilIgnored verifies a nil audit logger leaves
// the field unset (auditing disabled/additive).
func TestWithMCPHandlerAuditLogger_NilIgnored(t *testing.T) {
	t.Parallel()

	h, err := NewMCPHandler(WithMCPHandlerAuditLogger(nil))
	require.NoError(t, err)
	assert.Nil(t, h.auditLogger)
}
