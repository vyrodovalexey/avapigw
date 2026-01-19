package v1alpha1

// GetParentRefs returns the parent references for HTTPRoute.
func (r *HTTPRoute) GetParentRefs() []ParentRef {
	return r.Spec.ParentRefs
}

// GetHostnames returns the hostnames for HTTPRoute.
func (r *HTTPRoute) GetHostnames() []Hostname {
	return r.Spec.Hostnames
}

// GetParentRefs returns the parent references for GRPCRoute.
func (r *GRPCRoute) GetParentRefs() []ParentRef {
	return r.Spec.ParentRefs
}

// GetHostnames returns the hostnames for GRPCRoute.
func (r *GRPCRoute) GetHostnames() []Hostname {
	return r.Spec.Hostnames
}

// GetParentRefs returns the parent references for TCPRoute.
func (r *TCPRoute) GetParentRefs() []ParentRef {
	return r.Spec.ParentRefs
}

// GetHostnames returns an empty slice for TCPRoute (TCP routes don't have hostnames).
func (r *TCPRoute) GetHostnames() []Hostname {
	return nil
}

// GetParentRefs returns the parent references for TLSRoute.
func (r *TLSRoute) GetParentRefs() []ParentRef {
	return r.Spec.ParentRefs
}

// GetHostnames returns the hostnames for TLSRoute.
func (r *TLSRoute) GetHostnames() []Hostname {
	return r.Spec.Hostnames
}
