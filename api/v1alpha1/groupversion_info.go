// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
// This package defines Custom Resource Definitions (CRDs) for the Kubernetes Ingress API Gateway,
// including Gateway, HTTPRoute, GRPCRoute, TCPRoute, TLSRoute, Backend, RateLimitPolicy,
// AuthPolicy, TLSConfig, and VaultSecret resources.
//
// +kubebuilder:object:generate=true
// +groupName=avapigw.vyrodovalexey.github.com
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: "avapigw.vyrodovalexey.github.com", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
