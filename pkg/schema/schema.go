// Package schema publishes the JSON Schema describing the avapigw gateway
// configuration file format. The schema is the public contract for the YAML
// configuration consumed by cmd/gateway; the guard tests in this package
// keep it aligned with the internal/config Go types (every
// config.GatewaySpec section must have a schema property) and verify that
// the shipped configs/gateway.yaml validates against it.
package schema

import _ "embed"

// GatewaySchemaJSON is the embedded JSON Schema for the gateway
// configuration file (gateway.schema.json). Consumers can compile it with
// any JSON Schema 2020-12 validator to validate configuration documents.
//
//go:embed gateway.schema.json
var GatewaySchemaJSON []byte
