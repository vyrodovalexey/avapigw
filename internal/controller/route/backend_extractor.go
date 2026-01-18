// Package route provides shared utilities for route controllers.
package route

import (
	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// BackendRefExtractor is an interface for extracting backend references from route rules.
// This allows generic handling of different route types that have backend references.
type BackendRefExtractor interface {
	// ExtractBackendRefs extracts all backend references from the route.
	ExtractBackendRefs() []BackendRefInfo
}

// HTTPRouteBackendExtractor extracts backend references from HTTPRoute.
type HTTPRouteBackendExtractor struct {
	Route *avapigwv1alpha1.HTTPRoute
}

// ExtractBackendRefs extracts all backend references from an HTTPRoute's rules.
func (e *HTTPRouteBackendExtractor) ExtractBackendRefs() []BackendRefInfo {
	if e.Route == nil {
		return nil
	}
	var refs []BackendRefInfo
	for _, rule := range e.Route.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			refs = append(refs, BackendRefInfo{
				Name:      backendRef.Name,
				Namespace: backendRef.Namespace,
				Kind:      backendRef.Kind,
				Group:     backendRef.Group,
			})
		}
	}
	return refs
}

// GRPCRouteBackendExtractor extracts backend references from GRPCRoute.
type GRPCRouteBackendExtractor struct {
	Route *avapigwv1alpha1.GRPCRoute
}

// ExtractBackendRefs extracts all backend references from a GRPCRoute's rules.
func (e *GRPCRouteBackendExtractor) ExtractBackendRefs() []BackendRefInfo {
	if e.Route == nil {
		return nil
	}
	var refs []BackendRefInfo
	for _, rule := range e.Route.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			refs = append(refs, BackendRefInfo{
				Name:      backendRef.Name,
				Namespace: backendRef.Namespace,
				Kind:      backendRef.Kind,
				Group:     backendRef.Group,
			})
		}
	}
	return refs
}

// TCPRouteBackendExtractor extracts backend references from TCPRoute.
type TCPRouteBackendExtractor struct {
	Route *avapigwv1alpha1.TCPRoute
}

// ExtractBackendRefs extracts all backend references from a TCPRoute's rules.
func (e *TCPRouteBackendExtractor) ExtractBackendRefs() []BackendRefInfo {
	if e.Route == nil {
		return nil
	}
	var refs []BackendRefInfo
	for _, rule := range e.Route.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			refs = append(refs, BackendRefInfo{
				Name:      backendRef.Name,
				Namespace: backendRef.Namespace,
				Kind:      backendRef.Kind,
				Group:     backendRef.Group,
			})
		}
	}
	return refs
}

// TLSRouteBackendExtractor extracts backend references from TLSRoute.
type TLSRouteBackendExtractor struct {
	Route *avapigwv1alpha1.TLSRoute
}

// ExtractBackendRefs extracts all backend references from a TLSRoute's rules.
func (e *TLSRouteBackendExtractor) ExtractBackendRefs() []BackendRefInfo {
	if e.Route == nil {
		return nil
	}
	var refs []BackendRefInfo
	for _, rule := range e.Route.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			refs = append(refs, BackendRefInfo{
				Name:      backendRef.Name,
				Namespace: backendRef.Namespace,
				Kind:      backendRef.Kind,
				Group:     backendRef.Group,
			})
		}
	}
	return refs
}

// NewBackendExtractor creates the appropriate backend extractor for a route type.
// Returns nil if the route type is not supported.
func NewBackendExtractor(route interface{}) BackendRefExtractor {
	switch r := route.(type) {
	case *avapigwv1alpha1.HTTPRoute:
		return &HTTPRouteBackendExtractor{Route: r}
	case *avapigwv1alpha1.GRPCRoute:
		return &GRPCRouteBackendExtractor{Route: r}
	case *avapigwv1alpha1.TCPRoute:
		return &TCPRouteBackendExtractor{Route: r}
	case *avapigwv1alpha1.TLSRoute:
		return &TLSRouteBackendExtractor{Route: r}
	default:
		return nil
	}
}

// ExtractBackendRefsFromRoute is a convenience function that extracts backend references
// from any supported route type.
func ExtractBackendRefsFromRoute(route interface{}) []BackendRefInfo {
	extractor := NewBackendExtractor(route)
	if extractor == nil {
		return nil
	}
	return extractor.ExtractBackendRefs()
}
