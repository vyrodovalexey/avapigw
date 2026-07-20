package schema

// Guard tests keeping pkg/schema/gateway.schema.json aligned with the
// internal/config Go types (review H2):
//
//   - every config.GatewaySpec section must be declared as a schema
//     property (reflection guard — a new spec field turns the build RED
//     until the schema documents it);
//   - the shipped configs/gateway.yaml must validate against the schema;
//   - GRPC/GRAPHQL listeners and the documented spec.vault example must
//     validate (they were rejected by the pre-fix schema).

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// compileGatewaySchema compiles the embedded gateway schema.
func compileGatewaySchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(GatewaySchemaJSON))
	require.NoError(t, err, "gateway.schema.json must be valid JSON")

	compiler := jsonschema.NewCompiler()
	require.NoError(t, compiler.AddResource("gateway.schema.json", doc))

	sch, err := compiler.Compile("gateway.schema.json")
	require.NoError(t, err, "gateway.schema.json must compile as JSON Schema 2020-12")
	return sch
}

// validateYAMLAgainstSchema converts a YAML document to JSON and validates
// it against the gateway schema.
func validateYAMLAgainstSchema(t *testing.T, sch *jsonschema.Schema, yamlDoc []byte) error {
	t.Helper()

	jsonDoc, err := sigsyaml.YAMLToJSON(yamlDoc)
	require.NoError(t, err, "test YAML must convert to JSON")

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonDoc))
	require.NoError(t, err)

	return sch.Validate(inst)
}

// envVarPattern mirrors the config loader's ${VAR} / ${VAR:-default}
// substitution so the shipped file can be validated as booted.
var envVarPattern = regexp.MustCompile(`\$\{([^}:]+)(?::-([^}]*))?\}`)

// substituteEnvDefaults replaces ${VAR:-default} with default and ${VAR}
// with the empty string (no environment is consulted: the shipped file must
// validate with its own defaults).
func substituteEnvDefaults(content string) string {
	return envVarPattern.ReplaceAllStringFunc(content, func(match string) string {
		sub := envVarPattern.FindStringSubmatch(match)
		if len(sub) >= 3 {
			return sub[2]
		}
		return ""
	})
}

// schemaSpecProperties extracts the property names of spec from the schema.
func schemaSpecProperties(t *testing.T) map[string]bool {
	t.Helper()

	var root struct {
		Properties struct {
			Spec struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"spec"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(GatewaySchemaJSON, &root))

	props := make(map[string]bool, len(root.Properties.Spec.Properties))
	for name := range root.Properties.Spec.Properties {
		props[name] = true
	}
	require.NotEmpty(t, props, "schema spec.properties must not be empty")
	return props
}

// yamlTagName extracts the YAML key of a struct field (first tag segment).
func yamlTagName(field reflect.StructField) string {
	tag := field.Tag.Get("yaml")
	if tag == "" || tag == "-" {
		return ""
	}
	if comma := strings.IndexByte(tag, ','); comma >= 0 {
		tag = tag[:comma]
	}
	return tag
}

// TestSchema_SpecCoversAllGatewaySpecFields is the drift guard: every
// config.GatewaySpec field must be declared in the schema's spec.properties
// and vice versa (stale schema entries are caught too).
func TestSchema_SpecCoversAllGatewaySpecFields(t *testing.T) {
	t.Parallel()

	props := schemaSpecProperties(t)

	specType := reflect.TypeOf(config.GatewaySpec{})
	seen := make(map[string]bool, specType.NumField())
	for _, field := range reflect.VisibleFields(specType) {
		name := yamlTagName(field)
		require.NotEmpty(t, name, "GatewaySpec field %s must carry a yaml tag", field.Name)
		seen[name] = true

		assert.True(t, props[name],
			"config.GatewaySpec field %s (yaml %q) has no property in "+
				"pkg/schema/gateway.schema.json spec.properties — extend the schema", field.Name, name)
	}

	for name := range props {
		assert.True(t, seen[name],
			"schema spec.properties declares %q which no longer exists in config.GatewaySpec — "+
				"remove it from gateway.schema.json", name)
	}
}

// TestSchema_ConfigsGatewayYamlValidates validates the shipped default
// configuration file (with env defaults substituted) against the schema.
func TestSchema_ConfigsGatewayYamlValidates(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "gateway.yaml"))
	require.NoError(t, err, "configs/gateway.yaml must be readable")

	sch := compileGatewaySchema(t)
	substituted := substituteEnvDefaults(string(raw))

	assert.NoError(t, validateYAMLAgainstSchema(t, sch, []byte(substituted)),
		"configs/gateway.yaml must validate against pkg/schema/gateway.schema.json")
}

// minimalConfigWithSpec wraps a spec YAML fragment into a full gateway
// configuration document.
func minimalConfigWithSpec(spec string) string {
	return "apiVersion: gateway.avapigw.io/v1\n" +
		"kind: Gateway\n" +
		"metadata:\n" +
		"  name: schema-test\n" +
		"spec:\n" + spec
}

// TestSchema_GRPCAndGraphQLListenersValidate covers the pre-fix rejection:
// the listener protocol enum lacked GRPC and GRAPHQL.
func TestSchema_GRPCAndGraphQLListenersValidate(t *testing.T) {
	t.Parallel()

	sch := compileGatewaySchema(t)

	doc := minimalConfigWithSpec(`  listeners:
    - name: grpc
      port: 9000
      protocol: GRPC
      bind: 0.0.0.0
      grpc:
        maxConcurrentStreams: 100
        reflection: true
        healthCheck: true
        keepalive:
          time: 30s
          timeout: 10s
    - name: graphql
      port: 8090
      protocol: GRAPHQL
    - name: https
      port: 8443
      protocol: HTTPS
      tls:
        mode: SIMPLE
        certFile: /etc/tls/tls.crt
        keyFile: /etc/tls/tls.key
  grpcRoutes:
    - name: grpc-route
      match:
        - service:
            exact: api.v1.TestService
      route:
        - destination:
            host: 127.0.0.1
            port: 8803
      retries:
        attempts: 3
        perTryTimeout: 10s
        retryOn: "unavailable,resource-exhausted"
  grpcBackends:
    - name: grpc-backend
      hosts:
        - address: 127.0.0.1
          port: 8803
      healthCheck:
        enabled: true
        interval: 10s
  graphqlRoutes:
    - name: graphql-route
      route:
        - destination:
            host: 127.0.0.1
            port: 8804
  graphqlBackends:
    - name: graphql-backend
      hosts:
        - address: 127.0.0.1
          port: 8804
`)

	assert.NoError(t, validateYAMLAgainstSchema(t, sch, []byte(doc)),
		"GRPC/GRAPHQL/HTTPS listeners and grpc/graphql resources must validate")
}

// TestSchema_VaultExampleValidates validates the spec.vault example
// documented (commented out) in configs/gateway.yaml, plus the approle and
// token variants, against the schema AND the config validator, proving the
// example boots when uncommented.
func TestSchema_VaultExampleValidates(t *testing.T) {
	t.Parallel()

	sch := compileGatewaySchema(t)

	// Mirrors the commented spec.vault example in configs/gateway.yaml
	// (kubernetes variant with VAULT_ADDR default substituted).
	vaultSpec := `  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  vault:
    enabled: true
    address: https://vault:8200
    authMethod: kubernetes
    kubernetes:
      role: avapigw
      mountPath: kubernetes
      tokenPath: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls:
      caCert: /etc/vault/ca.crt
    cache:
      enabled: true
      ttl: 5m
      maxSize: 1000
    retry:
      maxRetries: 3
      backoffBase: 100ms
      backoffMax: 5s
    auth:
      maxRetries: 3
      initialBackoff: 1s
      maxBackoff: 10s
      timeout: 30s
`
	doc := minimalConfigWithSpec(vaultSpec)

	assert.NoError(t, validateYAMLAgainstSchema(t, sch, []byte(doc)),
		"the documented spec.vault example must validate against the schema")

	// The same document must pass the config parser + validator (i.e. the
	// uncommented example boots).
	cfg, err := config.LoadConfigFromReader(strings.NewReader(doc))
	require.NoError(t, err)
	assert.NoError(t, config.ValidateConfig(cfg),
		"the documented spec.vault example must pass gateway validation")
}

// TestSchema_RejectsInvalidDocuments keeps the schema honest: clearly
// invalid documents must fail.
func TestSchema_RejectsInvalidDocuments(t *testing.T) {
	t.Parallel()

	sch := compileGatewaySchema(t)

	tests := []struct {
		name string
		doc  string
	}{
		{
			name: "unknown protocol",
			doc: minimalConfigWithSpec(`  listeners:
    - name: bad
      port: 8080
      protocol: SMTP
`),
		},
		{
			name: "missing listeners",
			doc: "apiVersion: gateway.avapigw.io/v1\n" +
				"kind: Gateway\n" +
				"metadata:\n" +
				"  name: schema-test\n" +
				"spec: {}\n",
		},
		{
			name: "invalid vault auth method",
			doc: minimalConfigWithSpec(`  listeners:
    - name: http
      port: 8080
      protocol: HTTP
  vault:
    enabled: true
    address: https://vault:8200
    authMethod: ldap
`),
		},
		{
			name: "invalid port",
			doc: minimalConfigWithSpec(`  listeners:
    - name: http
      port: 70000
      protocol: HTTP
`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Error(t, validateYAMLAgainstSchema(t, sch, []byte(tt.doc)),
				"schema must reject: %s", tt.name)
		})
	}
}
