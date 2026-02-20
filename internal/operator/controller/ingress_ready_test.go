// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"strconv"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// isIngressReady Tests (55.6% -> 100%)
// ============================================================================

func TestIsIngressReady(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		generation  int64
		expected    bool
	}{
		{
			name:        "nil annotations - returns false",
			annotations: nil,
			generation:  1,
			expected:    false,
		},
		{
			name:        "no observed-generation annotation - returns false",
			annotations: map[string]string{"other": "value"},
			generation:  1,
			expected:    false,
		},
		{
			name: "matching observed-generation - returns true",
			annotations: map[string]string{
				AnnotationObservedGeneration: "5",
			},
			generation: 5,
			expected:   true,
		},
		{
			name: "mismatched observed-generation - returns false",
			annotations: map[string]string{
				AnnotationObservedGeneration: "3",
			},
			generation: 5,
			expected:   false,
		},
		{
			name: "non-numeric observed-generation - returns false",
			annotations: map[string]string{
				AnnotationObservedGeneration: "not-a-number",
			},
			generation: 1,
			expected:   false,
		},
		{
			name: "empty observed-generation - returns false",
			annotations: map[string]string{
				AnnotationObservedGeneration: "",
			},
			generation: 1,
			expected:   false,
		},
		{
			name: "generation zero matches annotation zero - returns true",
			annotations: map[string]string{
				AnnotationObservedGeneration: "0",
			},
			generation: 0,
			expected:   true,
		},
		{
			name: "large generation number matches - returns true",
			annotations: map[string]string{
				AnnotationObservedGeneration: strconv.FormatInt(999999, 10),
			},
			generation: 999999,
			expected:   true,
		},
		{
			name: "negative generation in annotation - returns false for positive generation",
			annotations: map[string]string{
				AnnotationObservedGeneration: "-1",
			},
			generation: 1,
			expected:   false,
		},
		{
			name: "observed-generation with extra whitespace - returns false",
			annotations: map[string]string{
				AnnotationObservedGeneration: " 1 ",
			},
			generation: 1,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-ingress",
					Namespace:   "default",
					Annotations: tt.annotations,
					Generation:  tt.generation,
				},
			}

			result := isIngressReady(ingress)
			if result != tt.expected {
				t.Errorf("isIngressReady() = %v, want %v", result, tt.expected)
			}
		})
	}
}
