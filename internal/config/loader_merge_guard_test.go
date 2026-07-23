package config

// Reflection guard for mergeTwo (loader.go), mirroring the
// cmd/gateway/operator_merge_guard_test.go pattern (review M5).
//
// Include-based configurations flow through mergeTwo; any GatewaySpec field
// the merge does not explicitly carry is silently dropped from the merged
// result. These tests turn that latent bug class into an immediate, named
// test failure for every future GatewaySpec field.

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Merge strategies used by mergeTwo per GatewaySpec field.
const (
	// mergeStrategyReplace marks fields replaced entirely when the override
	// provides them (listeners, trustedProxies, pointer sections).
	mergeStrategyReplace = "replace"
	// mergeStrategyAppend marks resource lists appended across configs.
	mergeStrategyAppend = "append"
)

// mergedSpecFieldStrategies is the explicit handled-fields list for
// mergeTwo. EVERY config.GatewaySpec field MUST appear here with its merge
// strategy. When a new field is added to GatewaySpec, the guard tests below
// fail (naming the field) until the field is carried through
// mergeSpecResources/mergeSpecSections AND registered here.
var mergedSpecFieldStrategies = map[string]string{
	"Listeners":         mergeStrategyReplace,
	"Routes":            mergeStrategyAppend,
	"Backends":          mergeStrategyAppend,
	"GRPCRoutes":        mergeStrategyAppend,
	"GRPCBackends":      mergeStrategyAppend,
	"GraphQLRoutes":     mergeStrategyAppend,
	"GraphQLBackends":   mergeStrategyAppend,
	"RateLimit":         mergeStrategyReplace,
	"CircuitBreaker":    mergeStrategyReplace,
	"CORS":              mergeStrategyReplace,
	"Observability":     mergeStrategyReplace,
	"Authentication":    mergeStrategyReplace,
	"Authorization":     mergeStrategyReplace,
	"Security":          mergeStrategyReplace,
	"Audit":             mergeStrategyReplace,
	"RequestLimits":     mergeStrategyReplace,
	"MaxSessions":       mergeStrategyReplace,
	"TrustedProxies":    mergeStrategyReplace,
	"GraphQL":           mergeStrategyReplace,
	"OpenAPIValidation": mergeStrategyReplace,
	"WebSocket":         mergeStrategyReplace,
	"Vault":             mergeStrategyReplace,
}

// TestMergeTwo_ReflectionGuard_AllSpecFieldsHandled enumerates
// config.GatewaySpec via reflection and asserts every field is registered
// in mergedSpecFieldStrategies (and vice versa, catching stale entries).
func TestMergeTwo_ReflectionGuard_AllSpecFieldsHandled(t *testing.T) {
	t.Parallel()

	specType := reflect.TypeOf(GatewaySpec{})

	seen := make(map[string]bool, specType.NumField())
	for _, field := range reflect.VisibleFields(specType) {
		seen[field.Name] = true
		_, handled := mergedSpecFieldStrategies[field.Name]
		assert.True(t, handled,
			"GatewaySpec field %s not handled by mergeTwo: carry it through "+
				"mergeSpecResources/mergeSpecSections in loader.go and register its "+
				"strategy in mergedSpecFieldStrategies", field.Name)
	}

	for name := range mergedSpecFieldStrategies {
		assert.True(t, seen[name],
			"mergedSpecFieldStrategies lists %s which no longer exists in "+
				"config.GatewaySpec: remove it here and from mergeTwo", name)
	}
}

// TestMergeTwo_ReflectionGuard_NoFieldDropped seeds EVERY GatewaySpec field
// non-zero on both merge inputs, runs mergeTwo, and asserts via reflection
// that no field of the result is zero and that each field honors its
// documented strategy (override wins for replace, both survive for append).
func TestMergeTwo_ReflectionGuard_NoFieldDropped(t *testing.T) {
	t.Parallel()

	base := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "base"},
		Spec:       seededSpec(t, 1),
	}
	override := &GatewayConfig{Spec: seededSpec(t, 2)}

	merged := mergeTwo(base, override)
	require.NotNil(t, merged)

	mergedSpec := reflect.ValueOf(merged.Spec)
	overrideSpec := reflect.ValueOf(override.Spec)

	for _, field := range reflect.VisibleFields(mergedSpec.Type()) {
		got := mergedSpec.FieldByIndex(field.Index)

		assert.False(t, got.IsZero(),
			"GatewaySpec field %s is zero after mergeTwo although both merge inputs set it — "+
				"the merge in loader.go drops it (M5 regression)", field.Name)

		strategy, handled := mergedSpecFieldStrategies[field.Name]
		if !handled {
			continue // reported precisely by the AllSpecFieldsHandled guard
		}

		switch strategy {
		case mergeStrategyReplace:
			assertReplacedField(t, field.Name, overrideSpec.FieldByIndex(field.Index), got)
		case mergeStrategyAppend:
			// Base seeded 1 element, override seeded 2: append yields 3.
			assert.Equal(t, 3, got.Len(),
				"GatewaySpec field %s must append base+override elements in mergeTwo", field.Name)
		}
	}
}

// TestMergeTwo_NilOverrideSectionPreservesBase asserts that absent override
// sections keep the base values (the merge only overrides what is set).
func TestMergeTwo_NilOverrideSectionPreservesBase(t *testing.T) {
	t.Parallel()

	base := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "base"},
		Spec:       seededSpec(t, 1),
	}
	override := &GatewayConfig{}

	merged := mergeTwo(base, override)
	require.NotNil(t, merged)

	assert.Same(t, base.Spec.Vault, merged.Spec.Vault,
		"spec.vault must be preserved from the base when the override omits it")
	assert.Same(t, base.Spec.Authentication, merged.Spec.Authentication)
	assert.Same(t, base.Spec.WebSocket, merged.Spec.WebSocket)
	assert.Equal(t, base.Spec.TrustedProxies, merged.Spec.TrustedProxies)
}

// TestMergeTwo_IncludedVaultSurvivesMerge is the M5 behavioral regression:
// an included file's spec.vault (and other newer sections) must survive the
// include merge.
func TestMergeTwo_IncludedVaultSurvivesMerge(t *testing.T) {
	t.Parallel()

	included := &GatewayConfig{
		Spec: GatewaySpec{
			Vault: &VaultConfig{
				Enabled: true,
				Address: "https://vault:8200",
				Token:   "root",
			},
			Audit: &AuditConfig{Enabled: true},
		},
	}
	main := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "main"},
		Spec: GatewaySpec{
			Listeners: []Listener{{Name: "http", Port: 8080, Protocol: ProtocolHTTP}},
		},
	}

	merged := mergeTwo(included, main)
	require.NotNil(t, merged)
	assert.Same(t, included.Spec.Vault, merged.Spec.Vault,
		"included file's spec.vault must survive the include merge")
	assert.Same(t, included.Spec.Audit, merged.Spec.Audit,
		"included file's spec.audit must survive the include merge")
	assert.Len(t, merged.Spec.Listeners, 1)
}

// seededSpec builds a GatewaySpec with EVERY field set to a deterministic
// non-zero value via reflection, so the guard automatically covers future
// fields without manual seeding. Slices get `variant` elements so append
// semantics are observable.
func seededSpec(t *testing.T, variant int) GatewaySpec {
	t.Helper()

	spec := GatewaySpec{}
	v := reflect.ValueOf(&spec).Elem()
	for _, field := range reflect.VisibleFields(v.Type()) {
		fv := v.FieldByIndex(field.Index)
		require.True(t, fv.CanSet(),
			"GatewaySpec field %s is not settable via reflection", field.Name)
		fv.Set(seedValue(t, field.Name, field.Type, variant))
	}
	return spec
}

// seedValue returns a deterministic non-zero reflect.Value of type typ.
func seedValue(t *testing.T, fieldName string, typ reflect.Type, variant int) reflect.Value {
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
		t.Fatalf("seedValue: unsupported kind %s for GatewaySpec field %s (type %s)",
			typ.Kind(), fieldName, typ)
		return reflect.Value{} // unreachable; t.Fatalf stops the test
	}
}

// assertReplacedField asserts a replace-strategy field carries the override
// value (reference identity for pointers/slices/maps).
func assertReplacedField(t *testing.T, fieldName string, want, got reflect.Value) {
	t.Helper()

	switch want.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice:
		assert.Equal(t, want.Pointer(), got.Pointer(),
			"GatewaySpec field %s must be carried verbatim from the override config by mergeTwo",
			fieldName)
	default:
		assert.True(t, reflect.DeepEqual(want.Interface(), got.Interface()),
			"GatewaySpec field %s must equal the override config's value after mergeTwo",
			fieldName)
	}
}
