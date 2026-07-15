package openapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestGetSharedMetrics_Singleton verifies the shared instance is created
// once and reused.
func TestGetSharedMetrics_Singleton(t *testing.T) {
	first := GetSharedMetrics()
	second := GetSharedMetrics()
	require.NotNil(t, first)
	assert.Same(t, first, second, "shared metrics must be a singleton")

	// InitSharedMetrics after initialization is a no-op returning the same.
	third := InitSharedMetrics(prometheus.NewRegistry())
	assert.Same(t, first, third)
}

// TestMiddlewareFromConfig_RecordsSharedMetrics is the regression test for
// the unrecorded validation metrics: the config-built middleware (the route
// middleware path) must increment gateway_openapi_validation_requests_total.
func TestMiddlewareFromConfig_RecordsSharedMetrics(t *testing.T) {
	shared := GetSharedMetrics()
	before := testutil.CollectAndCount(shared.requestsTotal)

	spec := `openapi: 3.0.0
info:
  title: t
  version: "1"
paths:
  /items:
    get:
      responses:
        "200":
          description: ok
`
	cfg := &config.OpenAPIValidationConfig{
		Enabled:    true,
		SpecInline: spec,
	}

	mw := MiddlewareFromConfig(cfg, observability.NopLogger())
	require.NotNil(t, mw)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/items", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	after := testutil.CollectAndCount(shared.requestsTotal)
	assert.Greater(t, after, before,
		"config-built validation middleware must record into the shared metrics")
}

// TestNewMetrics_DuplicateRegistrationAdoptsExisting verifies duplicate
// registration against the same registry reuses the registered collectors
// instead of panicking.
func TestNewMetrics_DuplicateRegistrationAdoptsExisting(t *testing.T) {
	reg := prometheus.NewRegistry()

	first := NewMetrics(reg)
	require.NotPanics(t, func() {
		second := NewMetrics(reg)
		second.RecordSuccess("/dup", 0.001)
	})

	// The second instance's recording landed on the registered series.
	count := testutil.CollectAndCount(first.requestsTotal)
	assert.Positive(t, count)
}

// TestMiddlewareFromConfig_InvalidSpecStillNoop verifies broken specs keep
// the passthrough behavior with shared metrics wiring in place.
func TestMiddlewareFromConfig_InvalidSpecStillNoop(t *testing.T) {
	cfg := &config.OpenAPIValidationConfig{
		Enabled:    true,
		SpecInline: strings.Repeat("not yaml: [", 3),
	}

	mw := MiddlewareFromConfig(cfg, observability.NopLogger())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}
