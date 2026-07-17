// Package grpc — tests for deterministic snapshot ordering and checksums
// (C5): buildSnapshot must order every resource slice by ascending resource
// key so identical store contents always yield byte-identical checksums,
// independent of Go map insertion/iteration order.
package grpc

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// determinismFixture is one resource entry applied to a test server. The
// apply field holds a method expression, so the receiver is the first arg.
type determinismFixture struct {
	apply     func(s *Server, ctx context.Context, name, namespace string, config []byte) error
	name      string
	namespace string
	spec      string
}

// determinismFixtures spans all six resource types and multiple namespaces
// with enough keys per type to make map-iteration randomization observable.
func determinismFixtures() []determinismFixture {
	return []determinismFixture{
		{(*Server).ApplyAPIRoute, "zeta", "ns-b", `{"path":"/z"}`},
		{(*Server).ApplyAPIRoute, "alpha", "ns-b", `{"path":"/a"}`},
		{(*Server).ApplyAPIRoute, "alpha", "ns-a", `{"path":"/a2"}`},
		{(*Server).ApplyAPIRoute, "mid", "ns-a", `{"path":"/m"}`},
		{(*Server).ApplyAPIRoute, "omega", "ns-c", `{"path":"/o"}`},
		{(*Server).ApplyAPIRoute, "beta", "ns-c", `{"path":"/b"}`},
		{(*Server).ApplyAPIRoute, "gamma", "ns-a", `{"path":"/g"}`},
		{(*Server).ApplyAPIRoute, "delta", "ns-b", `{"path":"/d"}`},
		{(*Server).ApplyGRPCRoute, "grpc-2", "ns-a", `{"service":"b"}`},
		{(*Server).ApplyGRPCRoute, "grpc-1", "ns-b", `{"service":"a"}`},
		{(*Server).ApplyBackend, "be-2", "ns-a", `{"host":"h2"}`},
		{(*Server).ApplyBackend, "be-1", "ns-b", `{"host":"h1"}`},
		{(*Server).ApplyGRPCBackend, "gbe-2", "ns-a", `{"host":"g2"}`},
		{(*Server).ApplyGRPCBackend, "gbe-1", "ns-b", `{"host":"g1"}`},
		{(*Server).ApplyGraphQLRoute, "gql-2", "ns-a", `{"path":"/q2"}`},
		{(*Server).ApplyGraphQLRoute, "gql-1", "ns-b", `{"path":"/q1"}`},
		{(*Server).ApplyGraphQLBackend, "qbe-2", "ns-a", `{"host":"q2"}`},
		{(*Server).ApplyGraphQLBackend, "qbe-1", "ns-b", `{"host":"q1"}`},
	}
}

// populateService applies the fixtures to a fresh test service in the given
// order and returns the service.
func populateService(t *testing.T, fixtures []determinismFixture) *configurationServiceImpl {
	t.Helper()
	svc, srv := newTestService(t)
	ctx := context.Background()
	for _, f := range fixtures {
		require.NoError(t, f.apply(srv, ctx, f.name, f.namespace, []byte(f.spec)))
	}
	return svc
}

// resourceNames extracts the Name sequence from a resource slice.
func resourceNames(resources []*operatorv1alpha1.ConfigurationResource) []string {
	names := make([]string, 0, len(resources))
	for _, r := range resources {
		names = append(names, r.GetName())
	}
	return names
}

// reversedFixtures returns a reversed copy of the fixtures slice.
func reversedFixtures(fixtures []determinismFixture) []determinismFixture {
	out := make([]determinismFixture, len(fixtures))
	for i, f := range fixtures {
		out[len(fixtures)-1-i] = f
	}
	return out
}

// TestBuildSnapshot_DeterministicChecksum_AcrossInsertionOrders verifies that
// the same store contents produce byte-identical checksums (and identical
// resource ordering) regardless of the order the resources were applied in,
// across repeated builds (each build re-iterates the randomized Go maps).
func TestBuildSnapshot_DeterministicChecksum_AcrossInsertionOrders(t *testing.T) {
	fixtures := determinismFixtures()
	svcForward := populateService(t, fixtures)
	svcReverse := populateService(t, reversedFixtures(fixtures))

	ctx := context.Background()
	reference, err := svcForward.buildSnapshot(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, reference.Checksum)

	const rebuilds = 10
	for i := 0; i < rebuilds; i++ {
		forward, err := svcForward.buildSnapshot(ctx)
		require.NoError(t, err)
		reverse, err := svcReverse.buildSnapshot(ctx)
		require.NoError(t, err)

		assert.Equal(t, reference.Checksum, forward.Checksum,
			"rebuild %d: checksum must be stable across builds", i)
		assert.Equal(t, reference.Checksum, reverse.Checksum,
			"rebuild %d: checksum must be independent of insertion order", i)
		assert.Equal(t, resourceNames(reference.ApiRoutes), resourceNames(reverse.ApiRoutes),
			"rebuild %d: API route ordering must be deterministic", i)
	}
}

// TestBuildSnapshot_SlicesSortedByResourceKey verifies every resource slice
// is ordered by ascending "namespace/name" key.
func TestBuildSnapshot_SlicesSortedByResourceKey(t *testing.T) {
	svc := populateService(t, determinismFixtures())

	snapshot, err := svc.buildSnapshot(context.Background())
	require.NoError(t, err)

	slices := map[string][]*operatorv1alpha1.ConfigurationResource{
		"ApiRoutes":       snapshot.ApiRoutes,
		"GrpcRoutes":      snapshot.GrpcRoutes,
		"Backends":        snapshot.Backends,
		"GrpcBackends":    snapshot.GrpcBackends,
		"GraphqlRoutes":   snapshot.GraphqlRoutes,
		"GraphqlBackends": snapshot.GraphqlBackends,
	}
	for kind, resources := range slices {
		require.NotEmpty(t, resources, "%s must be populated", kind)
		names := resourceNames(resources)
		assert.True(t, sort.StringsAreSorted(names),
			"%s must be sorted by resource key, got %v", kind, names)
	}

	// Spot-check the composite namespace/name ordering.
	assert.Equal(t,
		[]string{
			"ns-a/alpha", "ns-a/gamma", "ns-a/mid",
			"ns-b/alpha", "ns-b/delta", "ns-b/zeta",
			"ns-c/beta", "ns-c/omega",
		},
		resourceNames(snapshot.ApiRoutes),
	)
}

// TestBuildSnapshot_ChecksumChangesOnContentChange verifies the checksum is
// content-sensitive: any spec change must produce a different checksum.
func TestBuildSnapshot_ChecksumChangesOnContentChange(t *testing.T) {
	fixtures := determinismFixtures()
	svc := populateService(t, fixtures)
	ctx := context.Background()

	before, err := svc.buildSnapshot(ctx)
	require.NoError(t, err)

	require.NoError(t, svc.server.ApplyAPIRoute(ctx, "alpha", "ns-a", []byte(`{"path":"/changed"}`)))

	after, err := svc.buildSnapshot(ctx)
	require.NoError(t, err)

	assert.NotEqual(t, before.Checksum, after.Checksum,
		"changed content must change the checksum")
}

// TestBuildSnapshot_EmptyTypesStayNil guards the wire shape: absent resource
// types must remain nil slices (JSON null) so checksums of configurations
// with empty types are unchanged from prior releases.
func TestBuildSnapshot_EmptyTypesStayNil(t *testing.T) {
	svc, srv := newTestService(t)
	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "only", "ns", []byte(`{}`)))

	snapshot, err := svc.buildSnapshot(context.Background())
	require.NoError(t, err)

	assert.Len(t, snapshot.ApiRoutes, 1)
	assert.Nil(t, snapshot.GrpcRoutes)
	assert.Nil(t, snapshot.Backends)
	assert.Nil(t, snapshot.GrpcBackends)
	assert.Nil(t, snapshot.GraphqlRoutes)
	assert.Nil(t, snapshot.GraphqlBackends)
	assert.Equal(t, int32(1), snapshot.TotalResources)
}

// TestBuildSortedResources_Empty verifies the nil contract directly.
func TestBuildSortedResources_Empty(t *testing.T) {
	assert.Nil(t, buildSortedResources(
		operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE, nil,
	))
	assert.Nil(t, buildSortedResources(
		operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE, map[string][]byte{},
	))
}
