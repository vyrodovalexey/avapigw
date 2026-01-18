package controller

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// GatewayIndexKey Tests
// ============================================================================

func TestGatewayIndexKey(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		gwName    string
		want      string
	}{
		{
			name:      "simple key",
			namespace: "default",
			gwName:    "my-gateway",
			want:      "default/my-gateway",
		},
		{
			name:      "different namespace",
			namespace: "production",
			gwName:    "prod-gateway",
			want:      "production/prod-gateway",
		},
		{
			name:      "empty namespace",
			namespace: "",
			gwName:    "gateway",
			want:      "/gateway",
		},
		{
			name:      "empty name",
			namespace: "default",
			gwName:    "",
			want:      "default/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GatewayIndexKey(tt.namespace, tt.gwName)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// BackendIndexKey Tests
// ============================================================================

func TestBackendIndexKey(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		backendName string
		want        string
	}{
		{
			name:        "simple key",
			namespace:   "default",
			backendName: "my-backend",
			want:        "default/my-backend",
		},
		{
			name:        "different namespace",
			namespace:   "staging",
			backendName: "staging-backend",
			want:        "staging/staging-backend",
		},
		{
			name:        "empty namespace",
			namespace:   "",
			backendName: "backend",
			want:        "/backend",
		},
		{
			name:        "empty name",
			namespace:   "default",
			backendName: "",
			want:        "default/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BackendIndexKey(tt.namespace, tt.backendName)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// extractGatewayRefs Tests
// ============================================================================

func TestExtractGatewayRefs(t *testing.T) {
	tests := []struct {
		name           string
		routeNamespace string
		parentRefs     []avapigwv1alpha1.ParentRef
		want           []string
	}{
		{
			name:           "empty parent refs",
			routeNamespace: "default",
			parentRefs:     []avapigwv1alpha1.ParentRef{},
			want:           []string{},
		},
		{
			name:           "single parent ref without namespace",
			routeNamespace: "default",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "gateway-1"},
			},
			want: []string{"default/gateway-1"},
		},
		{
			name:           "single parent ref with namespace",
			routeNamespace: "default",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "gateway-1", Namespace: ptrString("other-ns")},
			},
			want: []string{"other-ns/gateway-1"},
		},
		{
			name:           "multiple parent refs",
			routeNamespace: "default",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "gateway-1"},
				{Name: "gateway-2", Namespace: ptrString("prod")},
				{Name: "gateway-3"},
			},
			want: []string{"default/gateway-1", "prod/gateway-2", "default/gateway-3"},
		},
		{
			name:           "parent ref with section name (ignored for indexing)",
			routeNamespace: "default",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "gateway-1", SectionName: ptrString("http")},
			},
			want: []string{"default/gateway-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractGatewayRefs(tt.routeNamespace, tt.parentRefs)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// extractBackendRefs Tests
// ============================================================================

func TestExtractBackendRefs(t *testing.T) {
	tests := []struct {
		name           string
		routeNamespace string
		rules          []avapigwv1alpha1.HTTPRouteRule
		want           []string
	}{
		{
			name:           "empty rules",
			routeNamespace: "default",
			rules:          []avapigwv1alpha1.HTTPRouteRule{},
			want:           nil,
		},
		{
			name:           "rule with no backend refs",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{BackendRefs: []avapigwv1alpha1.HTTPBackendRef{}},
			},
			want: nil,
		},
		{
			name:           "Service backend (not indexed)",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "my-service"}},
					},
				},
			},
			want: nil, // Services are not indexed, only Backend kind
		},
		{
			name:           "Backend kind without namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-backend",
							Kind: ptrString("Backend"),
						}},
					},
				},
			},
			want: []string{"default/my-backend"},
		},
		{
			name:           "Backend kind with namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "my-backend",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("other-ns"),
						}},
					},
				},
			},
			want: []string{"other-ns/my-backend"},
		},
		{
			name:           "multiple rules with mixed backends",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "service-1"}}, // Service, not indexed
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "backend-1",
							Kind: ptrString("Backend"),
						}},
					},
				},
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "backend-2",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("prod"),
						}},
					},
				},
			},
			want: []string{"default/backend-1", "prod/backend-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHTTPBackendRefs(tt.routeNamespace, tt.rules)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Index Field Constants Tests
// ============================================================================

func TestIndexFieldConstants(t *testing.T) {
	// Verify constants are defined correctly
	assert.Equal(t, ".spec.parentRefs.gateway", HTTPRouteGatewayIndexField)
	assert.Equal(t, ".spec.parentRefs.gateway", GRPCRouteGatewayIndexField)
	assert.Equal(t, ".spec.parentRefs.gateway", TCPRouteGatewayIndexField)
	assert.Equal(t, ".spec.parentRefs.gateway", TLSRouteGatewayIndexField)
	assert.Equal(t, ".spec.rules.backendRefs.backend", HTTPRouteBackendIndexField)
}

// ============================================================================
// extractGRPCBackendRefs Tests
// ============================================================================

func TestExtractGRPCBackendRefs(t *testing.T) {
	tests := []struct {
		name           string
		routeNamespace string
		rules          []avapigwv1alpha1.GRPCRouteRule
		want           []string
	}{
		{
			name:           "empty rules",
			routeNamespace: "default",
			rules:          []avapigwv1alpha1.GRPCRouteRule{},
			want:           nil,
		},
		{
			name:           "rule with no backend refs",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.GRPCRouteRule{
				{BackendRefs: []avapigwv1alpha1.GRPCBackendRef{}},
			},
			want: nil,
		},
		{
			name:           "Service backend (not indexed)",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.GRPCRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "my-service"}},
					},
				},
			},
			want: nil, // Services are not indexed, only Backend kind
		},
		{
			name:           "Backend kind without namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.GRPCRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-backend",
							Kind: ptrString("Backend"),
						}},
					},
				},
			},
			want: []string{"default/my-backend"},
		},
		{
			name:           "Backend kind with namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.GRPCRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "my-backend",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("other-ns"),
						}},
					},
				},
			},
			want: []string{"other-ns/my-backend"},
		},
		{
			name:           "multiple rules with mixed backends",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.GRPCRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "service-1"}}, // Service, not indexed
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "backend-1",
							Kind: ptrString("Backend"),
						}},
					},
				},
				{
					BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "backend-2",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("prod"),
						}},
					},
				},
			},
			want: []string{"default/backend-1", "prod/backend-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractGRPCBackendRefs(tt.routeNamespace, tt.rules)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// extractTCPBackendRefs Tests
// ============================================================================

func TestExtractTCPBackendRefs(t *testing.T) {
	tests := []struct {
		name           string
		routeNamespace string
		rules          []avapigwv1alpha1.TCPRouteRule
		want           []string
	}{
		{
			name:           "empty rules",
			routeNamespace: "default",
			rules:          []avapigwv1alpha1.TCPRouteRule{},
			want:           nil,
		},
		{
			name:           "rule with no backend refs",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TCPRouteRule{
				{BackendRefs: []avapigwv1alpha1.TCPBackendRef{}},
			},
			want: nil,
		},
		{
			name:           "Service backend (not indexed)",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TCPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "my-service"}},
					},
				},
			},
			want: nil, // Services are not indexed, only Backend kind
		},
		{
			name:           "Backend kind without namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TCPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-backend",
							Kind: ptrString("Backend"),
						}},
					},
				},
			},
			want: []string{"default/my-backend"},
		},
		{
			name:           "Backend kind with namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TCPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "my-backend",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("other-ns"),
						}},
					},
				},
			},
			want: []string{"other-ns/my-backend"},
		},
		{
			name:           "multiple rules with mixed backends",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TCPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "service-1"}}, // Service, not indexed
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "backend-1",
							Kind: ptrString("Backend"),
						}},
					},
				},
				{
					BackendRefs: []avapigwv1alpha1.TCPBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "backend-2",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("prod"),
						}},
					},
				},
			},
			want: []string{"default/backend-1", "prod/backend-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTCPBackendRefs(tt.routeNamespace, tt.rules)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// extractTLSBackendRefs Tests
// ============================================================================

func TestExtractTLSBackendRefs(t *testing.T) {
	tests := []struct {
		name           string
		routeNamespace string
		rules          []avapigwv1alpha1.TLSRouteRule
		want           []string
	}{
		{
			name:           "empty rules",
			routeNamespace: "default",
			rules:          []avapigwv1alpha1.TLSRouteRule{},
			want:           nil,
		},
		{
			name:           "rule with no backend refs",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TLSRouteRule{
				{BackendRefs: []avapigwv1alpha1.TLSBackendRef{}},
			},
			want: nil,
		},
		{
			name:           "Service backend (not indexed)",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TLSRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TLSBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "my-service"}},
					},
				},
			},
			want: nil, // Services are not indexed, only Backend kind
		},
		{
			name:           "Backend kind without namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TLSRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TLSBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "my-backend",
							Kind: ptrString("Backend"),
						}},
					},
				},
			},
			want: []string{"default/my-backend"},
		},
		{
			name:           "Backend kind with namespace",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TLSRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TLSBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "my-backend",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("other-ns"),
						}},
					},
				},
			},
			want: []string{"other-ns/my-backend"},
		},
		{
			name:           "multiple rules with mixed backends",
			routeNamespace: "default",
			rules: []avapigwv1alpha1.TLSRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.TLSBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{Name: "service-1"}}, // Service, not indexed
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name: "backend-1",
							Kind: ptrString("Backend"),
						}},
					},
				},
				{
					BackendRefs: []avapigwv1alpha1.TLSBackendRef{
						{BackendRef: avapigwv1alpha1.BackendRef{
							Name:      "backend-2",
							Kind:      ptrString("Backend"),
							Namespace: ptrString("prod"),
						}},
					},
				},
			},
			want: []string{"default/backend-1", "prod/backend-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTLSBackendRefs(tt.routeNamespace, tt.rules)
			assert.Equal(t, tt.want, result)
		})
	}
}

// ============================================================================
// Mock FieldIndexer for testing SetupIndexers
// ============================================================================

// mockFieldIndexer implements client.FieldIndexer for testing
type mockFieldIndexer struct {
	indexedFields map[string]bool
	shouldFail    bool
	failOnField   string
}

func newMockFieldIndexer() *mockFieldIndexer {
	return &mockFieldIndexer{
		indexedFields: make(map[string]bool),
	}
}

func (m *mockFieldIndexer) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	if m.shouldFail && (m.failOnField == "" || m.failOnField == field) {
		return fmt.Errorf("mock indexer error for field: %s", field)
	}
	m.indexedFields[field] = true
	return nil
}

// mockManager implements manager.Manager for testing SetupIndexers
type mockManager struct {
	fieldIndexer *mockFieldIndexer
}

func newMockManager() *mockManager {
	return &mockManager{
		fieldIndexer: newMockFieldIndexer(),
	}
}

func (m *mockManager) GetFieldIndexer() client.FieldIndexer {
	return m.fieldIndexer
}

// Implement other manager.Manager methods as no-ops
func (m *mockManager) Add(manager.Runnable) error  { return nil }
func (m *mockManager) Elected() <-chan struct{}    { return nil }
func (m *mockManager) SetFields(interface{}) error { return nil }
func (m *mockManager) AddMetricsServerExtraHandler(path string, handler http.Handler) error {
	return nil
}
func (m *mockManager) AddHealthzCheck(name string, check healthz.Checker) error { return nil }
func (m *mockManager) AddReadyzCheck(name string, check healthz.Checker) error  { return nil }
func (m *mockManager) Start(ctx context.Context) error                          { return nil }
func (m *mockManager) GetConfig() *rest.Config                                  { return nil }
func (m *mockManager) GetScheme() *runtime.Scheme                               { return nil }
func (m *mockManager) GetClient() client.Client                                 { return nil }
func (m *mockManager) GetAPIReader() client.Reader                              { return nil }
func (m *mockManager) GetEventRecorderFor(name string) record.EventRecorder     { return nil }
func (m *mockManager) GetRESTMapper() meta.RESTMapper                           { return nil }
func (m *mockManager) GetCache() cache.Cache                                    { return nil }
func (m *mockManager) GetWebhookServer() webhook.Server                         { return nil }
func (m *mockManager) GetLogger() logr.Logger                                   { return logr.Discard() }
func (m *mockManager) GetControllerOptions() config.Controller                  { return config.Controller{} }
func (m *mockManager) GetHTTPClient() *http.Client                              { return nil }

// ============================================================================
// SetupIndexers Tests
// ============================================================================

func TestSetupIndexers(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*mockManager)
		wantErr     bool
		errContains string
	}{
		{
			name:      "successfully sets up all indexers",
			setupMock: func(m *mockManager) {},
			wantErr:   false,
		},
		{
			name: "fails when gateway indexer fails",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = HTTPRouteGatewayIndexField
			},
			wantErr:     true,
			errContains: "mock indexer error",
		},
		{
			name: "fails when backend indexer fails",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = HTTPRouteBackendIndexField
			},
			wantErr:     true,
			errContains: "mock indexer error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newMockManager()
			tt.setupMock(mgr)

			err := SetupIndexers(context.Background(), mgr)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				// Verify all expected fields were indexed
				assert.True(t, mgr.fieldIndexer.indexedFields[HTTPRouteGatewayIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[GRPCRouteGatewayIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[TCPRouteGatewayIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[TLSRouteGatewayIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[HTTPRouteBackendIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[GRPCRouteBackendIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[TCPRouteBackendIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[TLSRouteBackendIndexField])
			}
		})
	}
}

// ============================================================================
// setupGatewayIndexers Tests
// ============================================================================

func TestSetupGatewayIndexers(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*mockManager)
		wantErr     bool
		errContains string
	}{
		{
			name:      "successfully sets up gateway indexers",
			setupMock: func(m *mockManager) {},
			wantErr:   false,
		},
		{
			name: "fails on HTTPRoute indexer",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = HTTPRouteGatewayIndexField
			},
			wantErr:     true,
			errContains: HTTPRouteGatewayIndexField,
		},
		{
			name: "fails on GRPCRoute indexer",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = GRPCRouteGatewayIndexField
			},
			wantErr:     true,
			errContains: GRPCRouteGatewayIndexField,
		},
		{
			name: "fails on TCPRoute indexer",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = TCPRouteGatewayIndexField
			},
			wantErr:     true,
			errContains: TCPRouteGatewayIndexField,
		},
		{
			name: "fails on TLSRoute indexer",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = TLSRouteGatewayIndexField
			},
			wantErr:     true,
			errContains: TLSRouteGatewayIndexField,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newMockManager()
			tt.setupMock(mgr)

			err := setupGatewayIndexers(context.Background(), mgr)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.True(t, mgr.fieldIndexer.indexedFields[HTTPRouteGatewayIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[GRPCRouteGatewayIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[TCPRouteGatewayIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[TLSRouteGatewayIndexField])
			}
		})
	}
}

// ============================================================================
// setupBackendIndexers Tests
// ============================================================================

func TestSetupBackendIndexers(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*mockManager)
		wantErr     bool
		errContains string
	}{
		{
			name:      "successfully sets up backend indexers",
			setupMock: func(m *mockManager) {},
			wantErr:   false,
		},
		{
			name: "fails on HTTPRoute backend indexer",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = HTTPRouteBackendIndexField
			},
			wantErr:     true,
			errContains: HTTPRouteBackendIndexField,
		},
		{
			name: "fails on GRPCRoute backend indexer",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = GRPCRouteBackendIndexField
			},
			wantErr:     true,
			errContains: GRPCRouteBackendIndexField,
		},
		{
			name: "fails on TCPRoute backend indexer",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = TCPRouteBackendIndexField
			},
			wantErr:     true,
			errContains: TCPRouteBackendIndexField,
		},
		{
			name: "fails on TLSRoute backend indexer",
			setupMock: func(m *mockManager) {
				m.fieldIndexer.shouldFail = true
				m.fieldIndexer.failOnField = TLSRouteBackendIndexField
			},
			wantErr:     true,
			errContains: TLSRouteBackendIndexField,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newMockManager()
			tt.setupMock(mgr)

			err := setupBackendIndexers(context.Background(), mgr)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.True(t, mgr.fieldIndexer.indexedFields[HTTPRouteBackendIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[GRPCRouteBackendIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[TCPRouteBackendIndexField])
				assert.True(t, mgr.fieldIndexer.indexedFields[TLSRouteBackendIndexField])
			}
		})
	}
}

// ============================================================================
// Tests for Index Functions with Closure Invocation
// ============================================================================

// mockFieldIndexerWithCapture captures the index functions for testing
type mockFieldIndexerWithCapture struct {
	// Use type+field as key since different types can have the same field name
	indexFuncs map[string]func(client.Object) []string
}

func newMockFieldIndexerWithCapture() *mockFieldIndexerWithCapture {
	return &mockFieldIndexerWithCapture{
		indexFuncs: make(map[string]func(client.Object) []string),
	}
}

func (m *mockFieldIndexerWithCapture) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	// Use type name + field as key since different types can have the same field name
	typeName := fmt.Sprintf("%T", obj)
	key := typeName + ":" + field
	m.indexFuncs[key] = extractValue
	return nil
}

func (m *mockFieldIndexerWithCapture) getIndexFunc(typeName, field string) func(client.Object) []string {
	key := typeName + ":" + field
	return m.indexFuncs[key]
}

// mockManagerWithCapture implements manager.Manager and captures index functions
type mockManagerWithCapture struct {
	fieldIndexer *mockFieldIndexerWithCapture
}

func newMockManagerWithCapture() *mockManagerWithCapture {
	return &mockManagerWithCapture{
		fieldIndexer: newMockFieldIndexerWithCapture(),
	}
}

func (m *mockManagerWithCapture) GetFieldIndexer() client.FieldIndexer {
	return m.fieldIndexer
}

// Implement other manager.Manager methods as no-ops
func (m *mockManagerWithCapture) Add(manager.Runnable) error  { return nil }
func (m *mockManagerWithCapture) Elected() <-chan struct{}    { return nil }
func (m *mockManagerWithCapture) SetFields(interface{}) error { return nil }
func (m *mockManagerWithCapture) AddMetricsServerExtraHandler(path string, handler http.Handler) error {
	return nil
}
func (m *mockManagerWithCapture) AddHealthzCheck(name string, check healthz.Checker) error {
	return nil
}
func (m *mockManagerWithCapture) AddReadyzCheck(name string, check healthz.Checker) error { return nil }
func (m *mockManagerWithCapture) Start(ctx context.Context) error                         { return nil }
func (m *mockManagerWithCapture) GetConfig() *rest.Config                                 { return nil }
func (m *mockManagerWithCapture) GetScheme() *runtime.Scheme                              { return nil }
func (m *mockManagerWithCapture) GetClient() client.Client                                { return nil }
func (m *mockManagerWithCapture) GetAPIReader() client.Reader                             { return nil }
func (m *mockManagerWithCapture) GetEventRecorderFor(name string) record.EventRecorder    { return nil }
func (m *mockManagerWithCapture) GetRESTMapper() meta.RESTMapper                          { return nil }
func (m *mockManagerWithCapture) GetCache() cache.Cache                                   { return nil }
func (m *mockManagerWithCapture) GetWebhookServer() webhook.Server                        { return nil }
func (m *mockManagerWithCapture) GetLogger() logr.Logger                                  { return logr.Discard() }
func (m *mockManagerWithCapture) GetControllerOptions() config.Controller                 { return config.Controller{} }
func (m *mockManagerWithCapture) GetHTTPClient() *http.Client                             { return nil }

func TestSetupGatewayIndexers_IndexFunctionExecution(t *testing.T) {
	mgr := newMockManagerWithCapture()

	err := setupGatewayIndexers(context.Background(), mgr)
	assert.NoError(t, err)

	// Test HTTPRoute index function
	t.Run("HTTPRoute gateway index function", func(t *testing.T) {
		indexFunc := mgr.fieldIndexer.getIndexFunc("*v1alpha1.HTTPRoute", HTTPRouteGatewayIndexField)
		assert.NotNil(t, indexFunc)

		route := &avapigwv1alpha1.HTTPRoute{}
		route.Namespace = "default"
		route.Spec.ParentRefs = []avapigwv1alpha1.ParentRef{
			{Name: "gateway-1"},
			{Name: "gateway-2", Namespace: ptrString("other-ns")},
		}

		result := indexFunc(route)
		assert.Equal(t, []string{"default/gateway-1", "other-ns/gateway-2"}, result)
	})

	// Test GRPCRoute index function
	t.Run("GRPCRoute gateway index function", func(t *testing.T) {
		indexFunc := mgr.fieldIndexer.getIndexFunc("*v1alpha1.GRPCRoute", GRPCRouteGatewayIndexField)
		assert.NotNil(t, indexFunc)

		route := &avapigwv1alpha1.GRPCRoute{}
		route.Namespace = "default"
		route.Spec.ParentRefs = []avapigwv1alpha1.ParentRef{
			{Name: "grpc-gateway"},
		}

		result := indexFunc(route)
		assert.Equal(t, []string{"default/grpc-gateway"}, result)
	})

	// Test TCPRoute index function
	t.Run("TCPRoute gateway index function", func(t *testing.T) {
		indexFunc := mgr.fieldIndexer.getIndexFunc("*v1alpha1.TCPRoute", TCPRouteGatewayIndexField)
		assert.NotNil(t, indexFunc)

		route := &avapigwv1alpha1.TCPRoute{}
		route.Namespace = "tcp-ns"
		route.Spec.ParentRefs = []avapigwv1alpha1.ParentRef{
			{Name: "tcp-gateway"},
		}

		result := indexFunc(route)
		assert.Equal(t, []string{"tcp-ns/tcp-gateway"}, result)
	})

	// Test TLSRoute index function
	t.Run("TLSRoute gateway index function", func(t *testing.T) {
		indexFunc := mgr.fieldIndexer.getIndexFunc("*v1alpha1.TLSRoute", TLSRouteGatewayIndexField)
		assert.NotNil(t, indexFunc)

		route := &avapigwv1alpha1.TLSRoute{}
		route.Namespace = "tls-ns"
		route.Spec.ParentRefs = []avapigwv1alpha1.ParentRef{
			{Name: "tls-gateway"},
		}

		result := indexFunc(route)
		assert.Equal(t, []string{"tls-ns/tls-gateway"}, result)
	})
}

func TestSetupBackendIndexers_IndexFunctionExecution(t *testing.T) {
	mgr := newMockManagerWithCapture()

	err := setupBackendIndexers(context.Background(), mgr)
	assert.NoError(t, err)

	// Test HTTPRoute backend index function
	t.Run("HTTPRoute backend index function", func(t *testing.T) {
		indexFunc := mgr.fieldIndexer.getIndexFunc("*v1alpha1.HTTPRoute", HTTPRouteBackendIndexField)
		assert.NotNil(t, indexFunc)

		route := &avapigwv1alpha1.HTTPRoute{}
		route.Namespace = "default"
		route.Spec.Rules = []avapigwv1alpha1.HTTPRouteRule{
			{
				BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
					{BackendRef: avapigwv1alpha1.BackendRef{
						Name: "my-backend",
						Kind: ptrString("Backend"),
					}},
				},
			},
		}

		result := indexFunc(route)
		assert.Equal(t, []string{"default/my-backend"}, result)
	})

	// Test GRPCRoute backend index function
	t.Run("GRPCRoute backend index function", func(t *testing.T) {
		indexFunc := mgr.fieldIndexer.getIndexFunc("*v1alpha1.GRPCRoute", GRPCRouteBackendIndexField)
		assert.NotNil(t, indexFunc)

		route := &avapigwv1alpha1.GRPCRoute{}
		route.Namespace = "grpc-ns"
		route.Spec.Rules = []avapigwv1alpha1.GRPCRouteRule{
			{
				BackendRefs: []avapigwv1alpha1.GRPCBackendRef{
					{BackendRef: avapigwv1alpha1.BackendRef{
						Name: "grpc-backend",
						Kind: ptrString("Backend"),
					}},
				},
			},
		}

		result := indexFunc(route)
		assert.Equal(t, []string{"grpc-ns/grpc-backend"}, result)
	})

	// Test TCPRoute backend index function
	t.Run("TCPRoute backend index function", func(t *testing.T) {
		indexFunc := mgr.fieldIndexer.getIndexFunc("*v1alpha1.TCPRoute", TCPRouteBackendIndexField)
		assert.NotNil(t, indexFunc)

		route := &avapigwv1alpha1.TCPRoute{}
		route.Namespace = "tcp-ns"
		route.Spec.Rules = []avapigwv1alpha1.TCPRouteRule{
			{
				BackendRefs: []avapigwv1alpha1.TCPBackendRef{
					{BackendRef: avapigwv1alpha1.BackendRef{
						Name: "tcp-backend",
						Kind: ptrString("Backend"),
					}},
				},
			},
		}

		result := indexFunc(route)
		assert.Equal(t, []string{"tcp-ns/tcp-backend"}, result)
	})

	// Test TLSRoute backend index function
	t.Run("TLSRoute backend index function", func(t *testing.T) {
		indexFunc := mgr.fieldIndexer.getIndexFunc("*v1alpha1.TLSRoute", TLSRouteBackendIndexField)
		assert.NotNil(t, indexFunc)

		route := &avapigwv1alpha1.TLSRoute{}
		route.Namespace = "tls-ns"
		route.Spec.Rules = []avapigwv1alpha1.TLSRouteRule{
			{
				BackendRefs: []avapigwv1alpha1.TLSBackendRef{
					{BackendRef: avapigwv1alpha1.BackendRef{
						Name: "tls-backend",
						Kind: ptrString("Backend"),
					}},
				},
			},
		}

		result := indexFunc(route)
		assert.Equal(t, []string{"tls-ns/tls-backend"}, result)
	})
}
