// Package keys provides shared key formatting utilities for the operator components.
package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResourceKey(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		resName   string
		expected  string
	}{
		{
			name:      "basic",
			namespace: "default",
			resName:   "my-route",
			expected:  "default/my-route",
		},
		{
			name:      "empty namespace",
			namespace: "",
			resName:   "my-route",
			expected:  "/my-route",
		},
		{
			name:      "empty name",
			namespace: "default",
			resName:   "",
			expected:  "default/",
		},
		{
			name:      "both empty",
			namespace: "",
			resName:   "",
			expected:  "/",
		},
		{
			name:      "special chars in namespace",
			namespace: "ns-1",
			resName:   "route.v1",
			expected:  "ns-1/route.v1",
		},
		{
			name:      "long namespace and name",
			namespace: "very-long-namespace-name-for-testing",
			resName:   "very-long-resource-name-for-testing",
			expected:  "very-long-namespace-name-for-testing/very-long-resource-name-for-testing",
		},
		{
			name:      "namespace with dots",
			namespace: "my.namespace.v1",
			resName:   "my-resource",
			expected:  "my.namespace.v1/my-resource",
		},
		{
			name:      "name with underscores",
			namespace: "default",
			resName:   "my_resource_name",
			expected:  "default/my_resource_name",
		},
		{
			name:      "kubernetes system namespace",
			namespace: "kube-system",
			resName:   "coredns",
			expected:  "kube-system/coredns",
		},
		{
			name:      "name with numbers",
			namespace: "prod",
			resName:   "backend-v2-12345",
			expected:  "prod/backend-v2-12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResourceKey(tt.namespace, tt.resName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestResourceKey_Consistency verifies that the function produces consistent results
func TestResourceKey_Consistency(t *testing.T) {
	namespace := "test-namespace"
	name := "test-resource"

	// Call multiple times and verify consistency
	result1 := ResourceKey(namespace, name)
	result2 := ResourceKey(namespace, name)
	result3 := ResourceKey(namespace, name)

	assert.Equal(t, result1, result2)
	assert.Equal(t, result2, result3)
}

// TestResourceKey_UniqueKeys verifies that different inputs produce different keys
func TestResourceKey_UniqueKeys(t *testing.T) {
	key1 := ResourceKey("ns1", "name1")
	key2 := ResourceKey("ns1", "name2")
	key3 := ResourceKey("ns2", "name1")
	key4 := ResourceKey("ns2", "name2")

	// All keys should be unique
	keys := []string{key1, key2, key3, key4}
	uniqueKeys := make(map[string]bool)
	for _, k := range keys {
		uniqueKeys[k] = true
	}

	assert.Equal(t, len(keys), len(uniqueKeys), "All keys should be unique")
}

// TestResourceKey_Format verifies the key format contains the separator
func TestResourceKey_Format(t *testing.T) {
	result := ResourceKey("namespace", "name")

	// Should contain exactly one slash
	slashCount := 0
	for _, c := range result {
		if c == '/' {
			slashCount++
		}
	}
	assert.Equal(t, 1, slashCount, "Key should contain exactly one slash separator")
}
