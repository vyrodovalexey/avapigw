// Package keys provides shared key formatting utilities for the operator components.
package keys

import "fmt"

// ResourceKey returns a formatted key for Kubernetes resources in the format "namespace/name".
// This is the standard format used throughout the operator for identifying resources.
func ResourceKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}
