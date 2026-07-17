package main

// Reflection guard for mergeOperatorConfig (operator_mode.go).
//
// Operator FULL_SYNC pushes carry only CRD-owned resources, and the merged
// result REPLACES a.app.config after every sync. Any config.GatewaySpec field
// that mergeOperatorConfig does not explicitly carry through its literal is
// silently dropped from the stored config, and the loss compounds on each
// subsequent sync (A-1). The tests in this file turn that latent bug class
// into an immediate, named test failure for every future GatewaySpec field.

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Merge sources: which side of mergeOperatorConfig supplies a GatewaySpec field.
const (
	// mergeSourceExisting marks boot-config-owned sections (config file or
	// createMinimalConfig); operator FULL_SYNC pushes never carry them.
	mergeSourceExisting = "existing"
	// mergeSourceOperator marks CRD-owned resources taken from the operator push.
	mergeSourceOperator = "operator"
	// mergeSourceMerged marks fields combined from both sides with the
	// operator value preferred when set (see mergeAuditConfig).
	mergeSourceMerged = "merged"
)

// mergedGatewaySpecFieldSources is the explicit handled-fields list for
// mergeOperatorConfig. EVERY config.GatewaySpec field MUST appear here with
// the merge side that supplies it. When a new field is added to GatewaySpec,
// the guard tests below fail (naming the field) until the field is carried
// through the merge literal in operator_mode.go AND registered here.
var mergedGatewaySpecFieldSources = map[string]string{
	"Listeners":         mergeSourceExisting,
	"Routes":            mergeSourceOperator,
	"Backends":          mergeSourceOperator,
	"GRPCRoutes":        mergeSourceOperator,
	"GRPCBackends":      mergeSourceOperator,
	"GraphQLRoutes":     mergeSourceOperator,
	"GraphQLBackends":   mergeSourceOperator,
	"RateLimit":         mergeSourceOperator,
	"CircuitBreaker":    mergeSourceExisting,
	"CORS":              mergeSourceExisting,
	"Observability":     mergeSourceExisting,
	"Authentication":    mergeSourceExisting,
	"Authorization":     mergeSourceExisting,
	"Security":          mergeSourceExisting,
	"Audit":             mergeSourceMerged,
	"RequestLimits":     mergeSourceExisting,
	"MaxSessions":       mergeSourceOperator,
	"TrustedProxies":    mergeSourceExisting,
	"GraphQL":           mergeSourceExisting,
	"OpenAPIValidation": mergeSourceExisting,
	"WebSocket":         mergeSourceExisting,
	"Vault":             mergeSourceExisting,
}

// TestMergeOperatorConfig_ReflectionGuard_AllSpecFieldsHandled enumerates
// config.GatewaySpec via reflection and asserts every field is registered in
// mergedGatewaySpecFieldSources (and vice versa, so stale entries are caught).
// A newly added GatewaySpec field turns this test RED with a message naming
// the unhandled field.
func TestMergeOperatorConfig_ReflectionGuard_AllSpecFieldsHandled(t *testing.T) {
	t.Parallel()

	specType := reflect.TypeOf(config.GatewaySpec{})

	seen := make(map[string]bool, specType.NumField())
	for _, field := range reflect.VisibleFields(specType) {
		seen[field.Name] = true
		_, handled := mergedGatewaySpecFieldSources[field.Name]
		assert.True(t, handled,
			"GatewaySpec field %s not handled in mergeOperatorConfig: carry it through the "+
				"merge literal in operator_mode.go (existing.Spec for boot-config-owned fields, "+
				"cfg.Spec for operator-owned resources) and register its source in "+
				"mergedGatewaySpecFieldSources", field.Name)
	}

	for name := range mergedGatewaySpecFieldSources {
		assert.True(t, seen[name],
			"mergedGatewaySpecFieldSources lists %s which no longer exists in "+
				"config.GatewaySpec: remove it here and from the mergeOperatorConfig literal", name)
	}
}

// TestMergeOperatorConfig_ReflectionGuard_NoFieldDropped seeds EVERY
// GatewaySpec field non-zero on both merge inputs (with distinguishable
// values per side), runs mergeOperatorConfig, and asserts via reflection that
// no field of the result is zero and that each field was taken from its
// documented merge source. This behavioral net catches a field that is
// registered in the handled list but still missing from the merge literal.
func TestMergeOperatorConfig_ReflectionGuard_NoFieldDropped(t *testing.T) {
	t.Parallel()

	existingCfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "boot-gateway"},
		Spec:       seededGatewaySpec(t, 1),
	}
	operatorCfg := &config.GatewayConfig{Spec: seededGatewaySpec(t, 2)}

	applier := &gatewayConfigApplier{
		app:    &operatorApplication{application: &application{config: existingCfg}},
		logger: observability.NopLogger(),
	}

	merged := applier.mergeOperatorConfig(operatorCfg)
	require.NotNil(t, merged)

	mergedSpec := reflect.ValueOf(merged.Spec)
	existingSpec := reflect.ValueOf(existingCfg.Spec)
	operatorSpec := reflect.ValueOf(operatorCfg.Spec)

	for _, field := range reflect.VisibleFields(mergedSpec.Type()) {
		got := mergedSpec.FieldByIndex(field.Index)

		assert.False(t, got.IsZero(),
			"GatewaySpec field %s is zero after mergeOperatorConfig although both merge inputs "+
				"set it — the merge literal in operator_mode.go drops it (A-1 regression)", field.Name)

		source, handled := mergedGatewaySpecFieldSources[field.Name]
		if !handled {
			// Unregistered field: already reported with a precise message by
			// TestMergeOperatorConfig_ReflectionGuard_AllSpecFieldsHandled.
			continue
		}

		want := existingSpec.FieldByIndex(field.Index)
		if source == mergeSourceOperator || source == mergeSourceMerged {
			// mergeSourceMerged (Audit) prefers the operator value when set,
			// and both sides are seeded here, so the operator side must win.
			want = operatorSpec.FieldByIndex(field.Index)
		}
		assertMergedFieldFromSource(t, field.Name, source, want, got)
	}
}

// TestMergeOperatorConfig_PreservesGraphQLOpenAPIWebSocket is the explicit
// A-1 behavioral regression: FULL_SYNC merges must preserve the boot config's
// GraphQL, OpenAPIValidation, and WebSocket sections, including across
// repeated syncs (the pre-fix bug compounded the loss on every merge because
// the merged result replaces the stored config).
func TestMergeOperatorConfig_PreservesGraphQLOpenAPIWebSocket(t *testing.T) {
	t.Parallel()

	failOnError := true
	existingCfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "boot-gateway"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
			GraphQL: &config.GraphQLConfig{
				MaxBodySize: 4 * 1024 * 1024,
				Path:        "/graphql-api",
			},
			OpenAPIValidation: &config.OpenAPIValidationConfig{
				Enabled:     true,
				SpecFile:    "/etc/gateway/openapi.yaml",
				FailOnError: &failOnError,
			},
			WebSocket: &config.WebSocketConfig{
				AllowedOrigins: []string{"https://app.example.com"},
			},
		},
	}

	applier := &gatewayConfigApplier{
		app:    &operatorApplication{application: &application{config: existingCfg}},
		logger: observability.NopLogger(),
	}

	// A FULL_SYNC push from the operator carries CRD resources only — never
	// the GraphQL/OpenAPIValidation/WebSocket sections.
	operatorCfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes:   []config.Route{{Name: "crd-route"}},
			Backends: []config.Backend{{Name: "crd-backend"}},
		},
	}

	merged := applier.mergeOperatorConfig(operatorCfg)
	require.NotNil(t, merged)
	assert.Same(t, existingCfg.Spec.GraphQL, merged.Spec.GraphQL,
		"GraphQL section must be preserved from the boot config on FULL_SYNC merge")
	assert.Same(t, existingCfg.Spec.OpenAPIValidation, merged.Spec.OpenAPIValidation,
		"OpenAPIValidation section must be preserved from the boot config on FULL_SYNC merge")
	assert.Same(t, existingCfg.Spec.WebSocket, merged.Spec.WebSocket,
		"WebSocket section must be preserved from the boot config on FULL_SYNC merge")

	// Second sync on top of the stored merge result: pre-fix the sections were
	// already gone from the stored config, so the loss compounded silently.
	applier.app.config = merged
	merged2 := applier.mergeOperatorConfig(operatorCfg)
	require.NotNil(t, merged2)
	assert.Same(t, existingCfg.Spec.GraphQL, merged2.Spec.GraphQL,
		"GraphQL section must survive repeated FULL_SYNC merges")
	assert.Same(t, existingCfg.Spec.OpenAPIValidation, merged2.Spec.OpenAPIValidation,
		"OpenAPIValidation section must survive repeated FULL_SYNC merges")
	assert.Same(t, existingCfg.Spec.WebSocket, merged2.Spec.WebSocket,
		"WebSocket section must survive repeated FULL_SYNC merges")
}

// seededGatewaySpec builds a GatewaySpec with EVERY field set to a
// deterministic non-zero value via reflection, so the guard automatically
// covers future fields without manual seeding. The variant disambiguates the
// existing-config seed from the operator-config seed, making the merge source
// of each field observable.
func seededGatewaySpec(t *testing.T, variant int) config.GatewaySpec {
	t.Helper()

	spec := config.GatewaySpec{}
	v := reflect.ValueOf(&spec).Elem()
	for _, field := range reflect.VisibleFields(v.Type()) {
		fv := v.FieldByIndex(field.Index)
		require.True(t, fv.CanSet(),
			"GatewaySpec field %s is not settable via reflection — the merge guard cannot seed it", field.Name)
		fv.Set(seedValueForType(t, field.Name, field.Type, variant))
	}
	return spec
}

// seedValueForType returns a deterministic non-zero reflect.Value of type typ.
// Values differ per variant so the two merge inputs are distinguishable:
// pointers/slices/maps get distinct allocations (compared by identity later),
// strings and numerics encode the variant directly.
func seedValueForType(t *testing.T, fieldName string, typ reflect.Type, variant int) reflect.Value {
	t.Helper()

	switch typ.Kind() {
	case reflect.Pointer:
		return reflect.New(typ.Elem())
	case reflect.Slice:
		return reflect.MakeSlice(typ, variant, variant)
	case reflect.Map:
		return reflect.MakeMapWithSize(typ, 0)
	case reflect.String:
		return reflect.ValueOf("seed-" + strconv.Itoa(variant)).Convert(typ)
	case reflect.Bool:
		return reflect.ValueOf(true).Convert(typ)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return reflect.ValueOf(variant).Convert(typ)
	default:
		t.Fatalf("seedValueForType: unsupported kind %s for GatewaySpec field %s (type %s) — "+
			"extend the reflection guard's seeder for this kind", typ.Kind(), fieldName, typ)
		return reflect.Value{} // unreachable; t.Fatalf stops the test
	}
}

// assertMergedFieldFromSource asserts that a merged GatewaySpec field carries
// the value of its documented merge source. Reference kinds are compared by
// identity (the merge copies pointers and slice/map headers verbatim);
// value kinds are compared by deep equality of the variant-distinct seeds.
func assertMergedFieldFromSource(t *testing.T, fieldName, source string, want, got reflect.Value) {
	t.Helper()

	switch want.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice:
		assert.Equal(t, want.Pointer(), got.Pointer(),
			"GatewaySpec field %s must be carried verbatim from the %s config by "+
				"mergeOperatorConfig (reference identity lost)", fieldName, source)
	default:
		assert.True(t, reflect.DeepEqual(want.Interface(), got.Interface()),
			"GatewaySpec field %s must equal the %s config's value after mergeOperatorConfig "+
				"(got %v, want %v)", fieldName, source, got.Interface(), want.Interface())
	}
}
