//go:build integration
// +build integration

/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/controller"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
	mgr       ctrl.Manager
)

const (
	// TestNamespace is the namespace used for integration tests
	TestNamespace = "avapigw-test"

	// Timeout for test operations
	Timeout = time.Second * 30

	// Interval for polling
	Interval = time.Millisecond * 250

	// ShortTimeout for quick operations
	ShortTimeout = time.Second * 10

	// LongTimeout for operations that may take longer
	LongTimeout = time.Second * 60
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	// Register API types
	err = avapigwv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// Create controller manager
	mgr, err = ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0", // Disable metrics server for tests
		},
	})
	Expect(err).NotTo(HaveOccurred())

	// Setup field indexers
	err = controller.SetupIndexers(ctx, mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup Gateway controller
	err = (&controller.GatewayReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("gateway-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup HTTPRoute controller
	err = (&controller.HTTPRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("httproute-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup Backend controller
	err = (&controller.BackendReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("backend-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup RateLimitPolicy controller
	err = (&controller.RateLimitPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("ratelimitpolicy-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup AuthPolicy controller
	err = (&controller.AuthPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("authpolicy-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup VaultSecret controller (with Vault disabled for tests)
	vaultSecretReconciler := &controller.VaultSecretReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		Recorder:     mgr.GetEventRecorderFor("vaultsecret-controller"),
		VaultEnabled: false, // Disable Vault for integration tests
	}
	err = vaultSecretReconciler.SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup GRPCRoute controller
	err = (&controller.GRPCRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("grpcroute-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup TCPRoute controller
	err = (&controller.TCPRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("tcproute-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup TLSRoute controller
	err = (&controller.TLSRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("tlsroute-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Setup TLSConfig controller
	err = (&controller.TLSConfigReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("tlsconfig-controller"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	// Start the manager in a goroutine
	go func() {
		defer GinkgoRecover()
		err = mgr.Start(ctx)
		Expect(err).NotTo(HaveOccurred())
	}()

	// Create Kubernetes client
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	// Create test namespace
	testNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: TestNamespace,
		},
	}
	err = k8sClient.Create(ctx, testNs)
	Expect(err).NotTo(HaveOccurred())

	// Wait for namespace to be ready
	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Name: TestNamespace}, &corev1.Namespace{})
	}, Timeout, Interval).Should(Succeed())
})

var _ = AfterSuite(func() {
	By("cleaning up test namespace")
	testNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: TestNamespace,
		},
	}
	_ = k8sClient.Delete(ctx, testNs)

	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

// createTestNamespace creates a unique namespace for a test
func createTestNamespace(baseName string) string {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: baseName + "-",
		},
	}
	ExpectWithOffset(1, k8sClient.Create(ctx, ns)).To(Succeed())
	return ns.Name
}

// deleteTestNamespace deletes a test namespace
func deleteTestNamespace(name string) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	_ = k8sClient.Delete(ctx, ns)
}

// waitForCondition waits for a specific condition on a resource
func waitForCondition(obj client.Object, conditionType avapigwv1alpha1.ConditionType, status metav1.ConditionStatus, timeout time.Duration) {
	EventuallyWithOffset(1, func() bool {
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			return false
		}

		// Check condition based on object type
		switch o := obj.(type) {
		case *avapigwv1alpha1.Gateway:
			cond := o.Status.GetCondition(conditionType)
			return cond != nil && cond.Status == status
		case *avapigwv1alpha1.HTTPRoute:
			// HTTPRoute uses RouteStatus with Parents
			for _, parent := range o.Status.Parents {
				for _, cond := range parent.Conditions {
					if cond.Type == conditionType && cond.Status == status {
						return true
					}
				}
			}
			return false
		case *avapigwv1alpha1.GRPCRoute:
			// GRPCRoute uses RouteStatus with Parents
			for _, parent := range o.Status.Parents {
				for _, cond := range parent.Conditions {
					if cond.Type == conditionType && cond.Status == status {
						return true
					}
				}
			}
			return false
		case *avapigwv1alpha1.TCPRoute:
			// TCPRoute uses RouteStatus with Parents
			for _, parent := range o.Status.Parents {
				for _, cond := range parent.Conditions {
					if cond.Type == conditionType && cond.Status == status {
						return true
					}
				}
			}
			return false
		case *avapigwv1alpha1.TLSRoute:
			// TLSRoute uses RouteStatus with Parents
			for _, parent := range o.Status.Parents {
				for _, cond := range parent.Conditions {
					if cond.Type == conditionType && cond.Status == status {
						return true
					}
				}
			}
			return false
		case *avapigwv1alpha1.TLSConfig:
			cond := o.Status.GetCondition(conditionType)
			return cond != nil && cond.Status == status
		case *avapigwv1alpha1.Backend:
			cond := o.Status.GetCondition(conditionType)
			return cond != nil && cond.Status == status
		case *avapigwv1alpha1.RateLimitPolicy:
			cond := o.Status.GetCondition(conditionType)
			return cond != nil && cond.Status == status
		case *avapigwv1alpha1.AuthPolicy:
			cond := o.Status.GetCondition(conditionType)
			return cond != nil && cond.Status == status
		case *avapigwv1alpha1.VaultSecret:
			cond := o.Status.GetCondition(conditionType)
			return cond != nil && cond.Status == status
		}
		return false
	}, timeout, Interval).Should(BeTrue())
}

// waitForPhase waits for a specific phase on a resource
func waitForPhase(obj client.Object, phase avapigwv1alpha1.PhaseStatus, timeout time.Duration) {
	EventuallyWithOffset(1, func() avapigwv1alpha1.PhaseStatus {
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			return ""
		}

		switch o := obj.(type) {
		case *avapigwv1alpha1.Gateway:
			return o.Status.Phase
		case *avapigwv1alpha1.Backend:
			return o.Status.Phase
		case *avapigwv1alpha1.RateLimitPolicy:
			return o.Status.Phase
		case *avapigwv1alpha1.AuthPolicy:
			return o.Status.Phase
		case *avapigwv1alpha1.VaultSecret:
			return o.Status.Phase
		case *avapigwv1alpha1.TLSConfig:
			return o.Status.Phase
		}
		return ""
	}, timeout, Interval).Should(Equal(phase))
}

// waitForDeletion waits for a resource to be deleted
func waitForDeletion(obj client.Object, timeout time.Duration) {
	EventuallyWithOffset(1, func() bool {
		err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)
		return err != nil && client.IgnoreNotFound(err) == nil
	}, timeout, Interval).Should(BeTrue())
}

// cleanupResource deletes a resource and waits for it to be deleted
func cleanupResource(obj client.Object) {
	err := k8sClient.Delete(ctx, obj)
	if err == nil {
		waitForDeletion(obj, Timeout)
	}
}
