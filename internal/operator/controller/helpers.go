// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"encoding/json"
	"fmt"
)

// injectName injects the resource name into the serialized JSON spec.
// CRD specs don't have a "name" field (it's in ObjectMeta), but the gateway
// config types (config.Route, config.Backend, etc.) expect a "name" field.
// This function adds the name to the JSON map so that deserialization on the
// gateway side populates the Name field correctly.
func injectName(specJSON []byte, name string) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(specJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal spec for name injection: %w", err)
	}

	nameJSON, err := json.Marshal(name)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal name: %w", err)
	}

	m["name"] = nameJSON

	result, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal spec with injected name: %w", err)
	}

	return result, nil
}
