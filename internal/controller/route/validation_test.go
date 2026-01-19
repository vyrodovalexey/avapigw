package route

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	require.NoError(t, corev1.AddToScheme(scheme))
	return scheme
}

// mockRoute implements RouteWithParentRefs for testing.
type mockRoute struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	parentRefs []avapigwv1alpha1.ParentRef
	hostnames  []avapigwv1alpha1.Hostname
}

func (m *mockRoute) GetParentRefs() []avapigwv1alpha1.ParentRef {
	return m.parentRefs
}

func (m *mockRoute) GetHostnames() []avapigwv1alpha1.Hostname {
	return m.hostnames
}

func (m *mockRoute) GetObjectKind() schema.ObjectKind {
	return &m.TypeMeta
}

func (m *mockRoute) DeepCopyObject() runtime.Object {
	return &mockRoute{
		TypeMeta:   m.TypeMeta,
		ObjectMeta: *m.ObjectMeta.DeepCopy(),
		parentRefs: m.parentRefs,
		hostnames:  m.hostnames,
	}
}

func TestParentRefValidator_ValidateParentRefs(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name           string
		objects        []client.Object
		route          *mockRoute
		matcher        ListenerMatcher
		wantErr        bool
		wantStatuses   int
		validateStatus func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus)
	}{
		{
			name:    "gateway not found",
			objects: []client.Object{},
			route: &mockRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				parentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "missing-gateway"},
				},
			},
			matcher:      &HTTPListenerMatcher{},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionFalse, statuses[0].Conditions[0].Status)
				assert.Equal(t, string(avapigwv1alpha1.ReasonNoMatchingParent), statuses[0].Conditions[0].Reason)
			},
		},
		{
			name: "gateway found with matching HTTP listener",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						},
					},
				},
			},
			route: &mockRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				parentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway"},
				},
			},
			matcher:      &HTTPListenerMatcher{},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionTrue, statuses[0].Conditions[0].Status)
				assert.Equal(t, string(avapigwv1alpha1.ReasonAccepted), statuses[0].Conditions[0].Reason)
			},
		},
		{
			name: "gateway with non-matching protocol (TCP for HTTP route)",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "tcp", Port: 9000, Protocol: avapigwv1alpha1.ProtocolTCP},
						},
					},
				},
			},
			route: &mockRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				parentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway"},
				},
			},
			matcher:      &HTTPListenerMatcher{},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionFalse, statuses[0].Conditions[0].Status)
				assert.Equal(t, string(avapigwv1alpha1.ReasonNotAllowedByListeners), statuses[0].Conditions[0].Reason)
			},
		},
		{
			name: "multiple parent refs",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "gateway-1",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						},
					},
				},
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "gateway-2",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
						},
					},
				},
			},
			route: &mockRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				parentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "gateway-1"},
					{Name: "gateway-2"},
				},
			},
			matcher:      &HTTPListenerMatcher{},
			wantErr:      false,
			wantStatuses: 2,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionTrue, statuses[0].Conditions[0].Status)
				assert.Equal(t, metav1.ConditionTrue, statuses[1].Conditions[0].Status)
			},
		},
		{
			name: "gateway in different namespace",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "other-namespace",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						},
					},
				},
			},
			route: &mockRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				parentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway", Namespace: ptrString("other-namespace")},
				},
			},
			matcher:      &HTTPListenerMatcher{},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionTrue, statuses[0].Conditions[0].Status)
			},
		},
		{
			name: "specific section name - listener found",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						},
					},
				},
			},
			route: &mockRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				parentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway", SectionName: ptrString("http")},
				},
			},
			matcher:      &HTTPListenerMatcher{},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionTrue, statuses[0].Conditions[0].Status)
			},
		},
		{
			name: "specific section name - listener not found",
			objects: []client.Object{
				&avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-gateway",
						Namespace: "default",
					},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{
							{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						},
					},
				},
			},
			route: &mockRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
				parentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway", SectionName: ptrString("missing")},
				},
			},
			matcher:      &HTTPListenerMatcher{},
			wantErr:      false,
			wantStatuses: 1,
			validateStatus: func(t *testing.T, statuses []avapigwv1alpha1.RouteParentStatus) {
				assert.Equal(t, metav1.ConditionFalse, statuses[0].Conditions[0].Status)
				assert.Contains(t, statuses[0].Conditions[0].Message, "Listener missing not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			recorder := record.NewFakeRecorder(100)
			validator := NewParentRefValidator(cl, recorder, "test-controller")

			statuses, err := validator.ValidateParentRefs(context.Background(), tt.route, tt.matcher)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Len(t, statuses, tt.wantStatuses)

			if tt.validateStatus != nil {
				tt.validateStatus(t, statuses)
			}
		})
	}
}

func TestBackendRefValidator_ValidateBackendRefs(t *testing.T) {
	scheme := newTestScheme(t)

	tests := []struct {
		name        string
		objects     []client.Object
		route       client.Object
		backendRefs []BackendRefInfo
		wantErr     bool
	}{
		{
			name: "Service backend found",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "default",
					},
				},
			},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
			},
			backendRefs: []BackendRefInfo{
				{Name: "test-service"},
			},
			wantErr: false,
		},
		{
			name:    "Service backend not found - continues without error",
			objects: []client.Object{},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
			},
			backendRefs: []BackendRefInfo{
				{Name: "missing-service"},
			},
			wantErr: false,
		},
		{
			name: "Backend CRD found",
			objects: []client.Object{
				&avapigwv1alpha1.Backend{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-backend",
						Namespace: "default",
					},
				},
			},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
			},
			backendRefs: []BackendRefInfo{
				{
					Name:  "test-backend",
					Kind:  ptrString("Backend"),
					Group: ptrString(avapigwv1alpha1.GroupVersion.Group),
				},
			},
			wantErr: false,
		},
		{
			name:    "Backend CRD not found - continues without error",
			objects: []client.Object{},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
			},
			backendRefs: []BackendRefInfo{
				{
					Name:  "missing-backend",
					Kind:  ptrString("Backend"),
					Group: ptrString(avapigwv1alpha1.GroupVersion.Group),
				},
			},
			wantErr: false,
		},
		{
			name:    "unsupported backend kind - continues without error",
			objects: []client.Object{},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
			},
			backendRefs: []BackendRefInfo{
				{
					Name:  "unknown",
					Kind:  ptrString("UnknownKind"),
					Group: ptrString("unknown.group"),
				},
			},
			wantErr: false,
		},
		{
			name: "backend in different namespace",
			objects: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "other-namespace",
					},
				},
			},
			route: &avapigwv1alpha1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: "default",
				},
			},
			backendRefs: []BackendRefInfo{
				{
					Name:      "test-service",
					Namespace: ptrString("other-namespace"),
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			recorder := record.NewFakeRecorder(100)
			validator := NewBackendRefValidator(cl, recorder)

			err := validator.ValidateBackendRefs(context.Background(), tt.route, tt.backendRefs)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHTTPListenerMatcher(t *testing.T) {
	matcher := &HTTPListenerMatcher{}

	t.Run("matches HTTP protocol", func(t *testing.T) {
		route := &mockRoute{hostnames: []avapigwv1alpha1.Hostname{}}
		listener := avapigwv1alpha1.Listener{Name: "http", Protocol: avapigwv1alpha1.ProtocolHTTP}

		matches, _ := matcher.MatchesListener(route, listener)
		assert.True(t, matches)
	})

	t.Run("matches HTTPS protocol", func(t *testing.T) {
		route := &mockRoute{hostnames: []avapigwv1alpha1.Hostname{}}
		listener := avapigwv1alpha1.Listener{Name: "https", Protocol: avapigwv1alpha1.ProtocolHTTPS}

		matches, _ := matcher.MatchesListener(route, listener)
		assert.True(t, matches)
	})

	t.Run("does not match TCP protocol", func(t *testing.T) {
		route := &mockRoute{hostnames: []avapigwv1alpha1.Hostname{}}
		listener := avapigwv1alpha1.Listener{Name: "tcp", Protocol: avapigwv1alpha1.ProtocolTCP}

		matches, msg := matcher.MatchesListener(route, listener)
		assert.False(t, matches)
		assert.Contains(t, msg, "does not support HTTP protocol")
	})

	t.Run("supported protocols", func(t *testing.T) {
		protocols := matcher.SupportedProtocols()
		assert.Contains(t, protocols, avapigwv1alpha1.ProtocolHTTP)
		assert.Contains(t, protocols, avapigwv1alpha1.ProtocolHTTPS)
	})
}

func TestGRPCListenerMatcher(t *testing.T) {
	matcher := &GRPCListenerMatcher{}

	t.Run("matches GRPC protocol", func(t *testing.T) {
		route := &mockRoute{hostnames: []avapigwv1alpha1.Hostname{}}
		listener := avapigwv1alpha1.Listener{Name: "grpc", Protocol: avapigwv1alpha1.ProtocolGRPC}

		matches, _ := matcher.MatchesListener(route, listener)
		assert.True(t, matches)
	})

	t.Run("matches GRPCS protocol", func(t *testing.T) {
		route := &mockRoute{hostnames: []avapigwv1alpha1.Hostname{}}
		listener := avapigwv1alpha1.Listener{Name: "grpcs", Protocol: avapigwv1alpha1.ProtocolGRPCS}

		matches, _ := matcher.MatchesListener(route, listener)
		assert.True(t, matches)
	})

	t.Run("does not match HTTP protocol", func(t *testing.T) {
		route := &mockRoute{hostnames: []avapigwv1alpha1.Hostname{}}
		listener := avapigwv1alpha1.Listener{Name: "http", Protocol: avapigwv1alpha1.ProtocolHTTP}

		matches, msg := matcher.MatchesListener(route, listener)
		assert.False(t, matches)
		assert.Contains(t, msg, "does not support gRPC protocol")
	})

	t.Run("supported protocols", func(t *testing.T) {
		protocols := matcher.SupportedProtocols()
		assert.Contains(t, protocols, avapigwv1alpha1.ProtocolGRPC)
		assert.Contains(t, protocols, avapigwv1alpha1.ProtocolGRPCS)
	})
}

func TestTCPListenerMatcher(t *testing.T) {
	t.Run("matches TCP protocol", func(t *testing.T) {
		matcher := &TCPListenerMatcher{}
		route := &mockRoute{}
		listener := avapigwv1alpha1.Listener{Name: "tcp", Protocol: avapigwv1alpha1.ProtocolTCP, Port: 9000}

		matches, _ := matcher.MatchesListener(route, listener)
		assert.True(t, matches)
	})

	t.Run("does not match HTTP protocol", func(t *testing.T) {
		matcher := &TCPListenerMatcher{}
		route := &mockRoute{}
		listener := avapigwv1alpha1.Listener{Name: "http", Protocol: avapigwv1alpha1.ProtocolHTTP}

		matches, msg := matcher.MatchesListener(route, listener)
		assert.False(t, matches)
		assert.Contains(t, msg, "does not support TCP protocol")
	})

	t.Run("matches port when specified", func(t *testing.T) {
		port := int32(9000)
		matcher := NewTCPListenerMatcherWithPort(&port)
		route := &mockRoute{}
		listener := avapigwv1alpha1.Listener{Name: "tcp", Protocol: avapigwv1alpha1.ProtocolTCP, Port: 9000}

		matches, _ := matcher.MatchesListener(route, listener)
		assert.True(t, matches)
	})

	t.Run("does not match wrong port", func(t *testing.T) {
		port := int32(8080)
		matcher := NewTCPListenerMatcherWithPort(&port)
		route := &mockRoute{}
		listener := avapigwv1alpha1.Listener{Name: "tcp", Protocol: avapigwv1alpha1.ProtocolTCP, Port: 9000}

		matches, msg := matcher.MatchesListener(route, listener)
		assert.False(t, matches)
		assert.Contains(t, msg, "Port 8080 does not match")
	})

	t.Run("supported protocols", func(t *testing.T) {
		matcher := &TCPListenerMatcher{}
		protocols := matcher.SupportedProtocols()
		assert.Contains(t, protocols, avapigwv1alpha1.ProtocolTCP)
	})
}

func TestTLSListenerMatcher(t *testing.T) {
	matcher := &TLSListenerMatcher{}

	t.Run("matches TLS protocol", func(t *testing.T) {
		route := &mockRoute{hostnames: []avapigwv1alpha1.Hostname{}}
		listener := avapigwv1alpha1.Listener{Name: "tls", Protocol: avapigwv1alpha1.ProtocolTLS}

		matches, _ := matcher.MatchesListener(route, listener)
		assert.True(t, matches)
	})

	t.Run("does not match HTTP protocol", func(t *testing.T) {
		route := &mockRoute{hostnames: []avapigwv1alpha1.Hostname{}}
		listener := avapigwv1alpha1.Listener{Name: "http", Protocol: avapigwv1alpha1.ProtocolHTTP}

		matches, msg := matcher.MatchesListener(route, listener)
		assert.False(t, matches)
		assert.Contains(t, msg, "does not support TLS protocol")
	})

	t.Run("supported protocols", func(t *testing.T) {
		protocols := matcher.SupportedProtocols()
		assert.Contains(t, protocols, avapigwv1alpha1.ProtocolTLS)
	})

	t.Run("no matching listener message", func(t *testing.T) {
		msg := matcher.NoMatchingListenerMessage()
		assert.Equal(t, "No matching TLS listener found on Gateway", msg)
	})
}

func TestTCPListenerMatcher_NoMatchingListenerMessage(t *testing.T) {
	matcher := &TCPListenerMatcher{}
	msg := matcher.NoMatchingListenerMessage()
	assert.Equal(t, "No matching TCP listener found on Gateway", msg)
}

func TestGRPCListenerMatcher_NoMatchingListenerMessage(t *testing.T) {
	matcher := &GRPCListenerMatcher{}
	msg := matcher.NoMatchingListenerMessage()
	assert.Equal(t, "No matching GRPC/GRPCS listener found on Gateway", msg)
}

func TestHTTPListenerMatcher_NoMatchingListenerMessage(t *testing.T) {
	matcher := &HTTPListenerMatcher{}
	msg := matcher.NoMatchingListenerMessage()
	assert.Equal(t, "No matching HTTP/HTTPS listener found on Gateway", msg)
}

func TestNewTCPListenerMatcherWithPort(t *testing.T) {
	t.Run("with port", func(t *testing.T) {
		port := int32(9000)
		matcher := NewTCPListenerMatcherWithPort(&port)
		require.NotNil(t, matcher)
		require.NotNil(t, matcher.Port)
		assert.Equal(t, int32(9000), *matcher.Port)
	})

	t.Run("with nil port", func(t *testing.T) {
		matcher := NewTCPListenerMatcherWithPort(nil)
		require.NotNil(t, matcher)
		assert.Nil(t, matcher.Port)
	})
}
