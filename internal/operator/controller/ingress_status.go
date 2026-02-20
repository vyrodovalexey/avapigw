// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"fmt"
	"net"
	"sync"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// IngressStatusUpdater manages the LoadBalancer status of Ingress resources.
// It sets the load balancer IP or hostname on the Ingress status so that
// external DNS or other tools can discover the gateway address.
type IngressStatusUpdater struct {
	client    client.Client
	lbAddress string
	mu        sync.RWMutex
}

// NewIngressStatusUpdater creates a new IngressStatusUpdater.
// The lbAddress parameter is the initial load balancer address (IP or hostname).
func NewIngressStatusUpdater(c client.Client, lbAddress string) *IngressStatusUpdater {
	return &IngressStatusUpdater{
		client:    c,
		lbAddress: lbAddress,
	}
}

// SetLoadBalancerAddress dynamically updates the load balancer address.
// This can be called when the gateway service's external IP changes.
func (u *IngressStatusUpdater) SetLoadBalancerAddress(address string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lbAddress = address
}

// GetLoadBalancerAddress returns the current load balancer address.
func (u *IngressStatusUpdater) GetLoadBalancerAddress() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.lbAddress
}

// UpdateIngressStatus updates the Ingress status with the load balancer address.
// If no address is configured, the status update is skipped.
func (u *IngressStatusUpdater) UpdateIngressStatus(
	ctx context.Context,
	ingress *networkingv1.Ingress,
) error {
	logger := log.FromContext(ctx)

	address := u.GetLoadBalancerAddress()
	if address == "" {
		// No load balancer address configured; skip status update
		return nil
	}

	// Build the desired LoadBalancer ingress entry
	desiredIngress := buildLoadBalancerIngress(address)

	// Check if status already matches to avoid unnecessary updates
	if ingressStatusMatches(ingress.Status.LoadBalancer.Ingress, desiredIngress) {
		return nil
	}

	// Capture the base state before modifications for the merge patch
	patch := client.MergeFrom(ingress.DeepCopy())

	// Update the status
	ingress.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{desiredIngress}

	if err := u.client.Status().Patch(ctx, ingress, patch); err != nil {
		logger.Error(err, "failed to patch Ingress LoadBalancer status",
			"name", ingress.Name,
			"namespace", ingress.Namespace,
			"address", address,
		)
		return fmt.Errorf("failed to patch Ingress status: %w", err)
	}

	logger.V(1).Info("patched Ingress LoadBalancer status",
		"name", ingress.Name,
		"namespace", ingress.Namespace,
		"address", address,
	)

	return nil
}

// buildLoadBalancerIngress creates an IngressLoadBalancerIngress entry
// from the given address. It determines whether the address is an IP or hostname.
func buildLoadBalancerIngress(address string) networkingv1.IngressLoadBalancerIngress {
	entry := networkingv1.IngressLoadBalancerIngress{}

	// Simple heuristic: if it looks like an IP, set IP; otherwise set Hostname
	if isIPAddress(address) {
		entry.IP = address
	} else {
		entry.Hostname = address
	}

	// Set default HTTP port for traffic
	httpPort := int32(DefaultHTTPPort)
	entry.Ports = []networkingv1.IngressPortStatus{
		{
			Port:     httpPort,
			Protocol: corev1.ProtocolTCP,
		},
	}

	return entry
}

// ingressStatusMatches checks if the current Ingress LoadBalancer status
// already matches the desired state.
func ingressStatusMatches(
	current []networkingv1.IngressLoadBalancerIngress,
	desired networkingv1.IngressLoadBalancerIngress,
) bool {
	if len(current) != 1 {
		return false
	}
	return current[0].IP == desired.IP && current[0].Hostname == desired.Hostname
}

// isIPAddress checks whether s is a valid IP address (IPv4 or IPv6)
// using the standard library net.ParseIP.
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}
