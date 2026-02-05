// Package operator provides performance tests for the apigw-operator.
//
//go:build performance
// +build performance

package operator

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/vyrodovalexey/avapigw/internal/operator/controller"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

func init() {
	_ = networkingv1.AddToScheme(scheme.Scheme)
}

// pathTypePtr returns a pointer to the given PathType.
func pathTypePtr(pt networkingv1.PathType) *networkingv1.PathType { return &pt }

// createBasicIngress creates a basic Ingress with a single rule and single path.
func createBasicIngress(name, namespace string) *networkingv1.Ingress {
	className := "avapigw"
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api/v1",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "backend-svc",
											Port: networkingv1.ServiceBackendPort{
												Number: 8080,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// createComplexIngress creates a complex Ingress with multiple rules, paths, TLS, and all annotations.
func createComplexIngress(name, namespace string) *networkingv1.Ingress {
	className := "avapigw"
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
			Annotations: map[string]string{
				// Timeout and retries
				"avapigw.io/timeout":               "30s",
				"avapigw.io/retry-attempts":        "3",
				"avapigw.io/retry-per-try-timeout": "5s",
				"avapigw.io/retry-on":              "5xx,reset,connect-failure",
				// Rate limiting
				"avapigw.io/rate-limit-enabled":    "true",
				"avapigw.io/rate-limit-rps":        "1000",
				"avapigw.io/rate-limit-burst":      "50",
				"avapigw.io/rate-limit-per-client": "true",
				// CORS
				"avapigw.io/cors-allow-origins":     "https://example.com,https://app.example.com",
				"avapigw.io/cors-allow-methods":     "GET,POST,PUT,DELETE,OPTIONS",
				"avapigw.io/cors-allow-headers":     "Authorization,Content-Type,X-Request-ID",
				"avapigw.io/cors-expose-headers":    "X-Request-ID,X-Trace-ID",
				"avapigw.io/cors-max-age":           "3600",
				"avapigw.io/cors-allow-credentials": "true",
				// Circuit breaker
				"avapigw.io/circuit-breaker-enabled":   "true",
				"avapigw.io/circuit-breaker-threshold": "5",
				"avapigw.io/circuit-breaker-timeout":   "30s",
				"avapigw.io/circuit-breaker-half-open": "3",
				// Health check
				"avapigw.io/health-check-path":                "/healthz",
				"avapigw.io/health-check-interval":            "10s",
				"avapigw.io/health-check-timeout":             "5s",
				"avapigw.io/health-check-healthy-threshold":   "2",
				"avapigw.io/health-check-unhealthy-threshold": "3",
				// Load balancer
				"avapigw.io/load-balancer-algorithm": "round-robin",
				// TLS
				"avapigw.io/tls-min-version": "1.2",
				"avapigw.io/tls-max-version": "1.3",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"api.example.com", "admin.example.com"},
					SecretName: "tls-secret",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "api.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api/v1/users",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "users-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
								{
									Path:     "/api/v1/orders",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "orders-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8081},
										},
									},
								},
								{
									Path:     "/api/v1/products",
									PathType: pathTypePtr(networkingv1.PathTypeExact),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "products-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8082},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "admin.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/admin",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "admin-svc",
											Port: networkingv1.ServiceBackendPort{Number: 9090},
										},
									},
								},
								{
									Path:     "/admin/metrics",
									PathType: pathTypePtr(networkingv1.PathTypeExact),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "metrics-svc",
											Port: networkingv1.ServiceBackendPort{Number: 9091},
										},
									},
								},
							},
						},
					},
				},
			},
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "default-svc",
					Port: networkingv1.ServiceBackendPort{Number: 80},
				},
			},
		},
	}
}

// createBasicGRPCIngress creates a basic gRPC Ingress with a single rule and single path.
func createBasicGRPCIngress(name, namespace string) *networkingv1.Ingress {
	className := "avapigw"
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
			Annotations: map[string]string{
				"avapigw.io/protocol": "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/myservice.MyService",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-backend",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// createComplexGRPCIngress creates a complex gRPC Ingress with multiple rules, paths, TLS, and all annotations.
func createComplexGRPCIngress(name, namespace string) *networkingv1.Ingress {
	className := "avapigw"
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
			Annotations: map[string]string{
				// Protocol
				"avapigw.io/protocol": "grpc",
				// gRPC service/method matching
				"avapigw.io/grpc-service":            "api.v1.UserService",
				"avapigw.io/grpc-service-match-type": "exact",
				"avapigw.io/grpc-method":             "GetUser",
				"avapigw.io/grpc-method-match-type":  "exact",
				// Timeout and retries
				"avapigw.io/timeout":                    "30s",
				"avapigw.io/retry-attempts":             "3",
				"avapigw.io/retry-per-try-timeout":      "5s",
				"avapigw.io/grpc-retry-on":              "unavailable,resource-exhausted,internal",
				"avapigw.io/grpc-backoff-base-interval": "100ms",
				"avapigw.io/grpc-backoff-max-interval":  "1s",
				// Rate limiting
				"avapigw.io/rate-limit-enabled":    "true",
				"avapigw.io/rate-limit-rps":        "1000",
				"avapigw.io/rate-limit-burst":      "50",
				"avapigw.io/rate-limit-per-client": "true",
				// CORS
				"avapigw.io/cors-allow-origins":     "https://example.com,https://app.example.com",
				"avapigw.io/cors-allow-methods":     "GET,POST,PUT,DELETE,OPTIONS",
				"avapigw.io/cors-allow-headers":     "Authorization,Content-Type,X-Request-ID",
				"avapigw.io/cors-expose-headers":    "X-Request-ID,X-Trace-ID",
				"avapigw.io/cors-max-age":           "3600",
				"avapigw.io/cors-allow-credentials": "true",
				// Circuit breaker
				"avapigw.io/circuit-breaker-enabled":   "true",
				"avapigw.io/circuit-breaker-threshold": "5",
				"avapigw.io/circuit-breaker-timeout":   "30s",
				"avapigw.io/circuit-breaker-half-open": "3",
				// gRPC Health check
				"avapigw.io/grpc-health-check-enabled":             "true",
				"avapigw.io/grpc-health-check-service":             "grpc.health.v1.Health",
				"avapigw.io/grpc-health-check-interval":            "10s",
				"avapigw.io/grpc-health-check-timeout":             "5s",
				"avapigw.io/grpc-health-check-healthy-threshold":   "2",
				"avapigw.io/grpc-health-check-unhealthy-threshold": "3",
				// gRPC Connection pool
				"avapigw.io/grpc-max-idle-conns":     "50",
				"avapigw.io/grpc-max-conns-per-host": "100",
				"avapigw.io/grpc-idle-conn-timeout":  "5m",
				// Load balancer
				"avapigw.io/load-balancer-algorithm": "round-robin",
				// TLS
				"avapigw.io/tls-min-version": "1.2",
				"avapigw.io/tls-max-version": "1.3",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"grpc-api.example.com", "grpc-admin.example.com"},
					SecretName: "grpc-tls-secret",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc-api.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "users-grpc-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
								{
									Path:     "/api.v1.OrderService",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "orders-grpc-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50052},
										},
									},
								},
								{
									Path:     "/api.v1.ProductService",
									PathType: pathTypePtr(networkingv1.PathTypeExact),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "products-grpc-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50053},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "grpc-admin.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/admin.v1.AdminService",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "admin-grpc-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50060},
										},
									},
								},
								{
									Path:     "/admin.v1.MetricsService",
									PathType: pathTypePtr(networkingv1.PathTypeExact),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "metrics-grpc-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50061},
										},
									},
								},
							},
						},
					},
				},
			},
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "default-grpc-svc",
					Port: networkingv1.ServiceBackendPort{Number: 50000},
				},
			},
		},
	}
}

// createAnnotatedGRPCIngress creates a gRPC Ingress with all gRPC-specific annotations.
func createAnnotatedGRPCIngress(name, namespace string) *networkingv1.Ingress {
	className := "avapigw"
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
			Annotations: map[string]string{
				// Protocol
				"avapigw.io/protocol": "grpc",
				// gRPC service/method matching
				"avapigw.io/grpc-service":            "api.v1.UserService",
				"avapigw.io/grpc-service-match-type": "prefix",
				"avapigw.io/grpc-method":             "Get",
				"avapigw.io/grpc-method-match-type":  "prefix",
				// Timeout
				"avapigw.io/timeout": "30s",
				// gRPC Retries
				"avapigw.io/retry-attempts":             "3",
				"avapigw.io/retry-per-try-timeout":      "5s",
				"avapigw.io/grpc-retry-on":              "unavailable,resource-exhausted",
				"avapigw.io/grpc-backoff-base-interval": "100ms",
				"avapigw.io/grpc-backoff-max-interval":  "1s",
				// Rate limit
				"avapigw.io/rate-limit-enabled":    "true",
				"avapigw.io/rate-limit-rps":        "500",
				"avapigw.io/rate-limit-burst":      "25",
				"avapigw.io/rate-limit-per-client": "true",
				// CORS
				"avapigw.io/cors-allow-origins":     "https://example.com",
				"avapigw.io/cors-allow-methods":     "GET,POST,PUT,DELETE",
				"avapigw.io/cors-allow-headers":     "Authorization,Content-Type",
				"avapigw.io/cors-expose-headers":    "X-Request-ID",
				"avapigw.io/cors-max-age":           "7200",
				"avapigw.io/cors-allow-credentials": "true",
				// Circuit breaker
				"avapigw.io/circuit-breaker-enabled":   "true",
				"avapigw.io/circuit-breaker-threshold": "10",
				"avapigw.io/circuit-breaker-timeout":   "60s",
				"avapigw.io/circuit-breaker-half-open": "5",
				// gRPC Health check
				"avapigw.io/grpc-health-check-enabled":             "true",
				"avapigw.io/grpc-health-check-service":             "grpc.health.v1.Health",
				"avapigw.io/grpc-health-check-interval":            "15s",
				"avapigw.io/grpc-health-check-timeout":             "3s",
				"avapigw.io/grpc-health-check-healthy-threshold":   "3",
				"avapigw.io/grpc-health-check-unhealthy-threshold": "5",
				// gRPC Connection pool
				"avapigw.io/grpc-max-idle-conns":     "100",
				"avapigw.io/grpc-max-conns-per-host": "200",
				"avapigw.io/grpc-idle-conn-timeout":  "10m",
				// Load balancer
				"avapigw.io/load-balancer-algorithm": "least-connections",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc-app.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-api-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// createAnnotatedIngress creates an Ingress with all annotation types for annotation parsing benchmarks.
func createAnnotatedIngress(name, namespace string) *networkingv1.Ingress {
	className := "avapigw"
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
			Annotations: map[string]string{
				// Timeout
				"avapigw.io/timeout": "30s",
				// Retries
				"avapigw.io/retry-attempts":        "3",
				"avapigw.io/retry-per-try-timeout": "5s",
				"avapigw.io/retry-on":              "5xx,reset",
				// Rate limit
				"avapigw.io/rate-limit-enabled":    "true",
				"avapigw.io/rate-limit-rps":        "500",
				"avapigw.io/rate-limit-burst":      "25",
				"avapigw.io/rate-limit-per-client": "true",
				// CORS
				"avapigw.io/cors-allow-origins":     "https://example.com",
				"avapigw.io/cors-allow-methods":     "GET,POST,PUT,DELETE",
				"avapigw.io/cors-allow-headers":     "Authorization,Content-Type",
				"avapigw.io/cors-expose-headers":    "X-Request-ID",
				"avapigw.io/cors-max-age":           "7200",
				"avapigw.io/cors-allow-credentials": "true",
				// Circuit breaker
				"avapigw.io/circuit-breaker-enabled":   "true",
				"avapigw.io/circuit-breaker-threshold": "10",
				"avapigw.io/circuit-breaker-timeout":   "60s",
				"avapigw.io/circuit-breaker-half-open": "5",
				// Health check
				"avapigw.io/health-check-path":                "/health",
				"avapigw.io/health-check-interval":            "15s",
				"avapigw.io/health-check-timeout":             "3s",
				"avapigw.io/health-check-healthy-threshold":   "3",
				"avapigw.io/health-check-unhealthy-threshold": "5",
				// Load balancer
				"avapigw.io/load-balancer-algorithm": "least-connections",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			Rules: []networkingv1.IngressRule{
				{
					Host: "app.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: pathTypePtr(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "api-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// ingressGRPCServer is a shared gRPC server instance for ingress benchmarks
// to avoid duplicate Prometheus metrics registration.
var (
	ingressGRPCServer     *operatorgrpc.Server
	ingressGRPCServerOnce sync.Once
)

// getIngressGRPCServer returns a shared gRPC server for ingress benchmarks.
func getIngressGRPCServer(b *testing.B) *operatorgrpc.Server {
	b.Helper()
	ingressGRPCServerOnce.Do(func() {
		var err error
		ingressGRPCServer, err = operatorgrpc.NewServer(&operatorgrpc.ServerConfig{
			Port: 0, // Don't actually listen
		})
		if err != nil {
			b.Fatalf("Failed to create gRPC server: %v", err)
		}
	})
	return ingressGRPCServer
}

// ingressReconcilerKit holds the reconciler and its underlying client for benchmarks.
type ingressReconcilerKit struct {
	Reconciler *controller.IngressReconciler
	Client     ctrlclient.Client
}

// setupIngressReconciler creates an IngressReconciler with a fake client for benchmarking.
func setupIngressReconciler(b *testing.B) ingressReconcilerKit {
	b.Helper()

	grpcServer := getIngressGRPCServer(b)

	s := runtime.NewScheme()
	_ = networkingv1.AddToScheme(s)

	clientBuilder := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&networkingv1.Ingress{})
	fakeClient := clientBuilder.Build()

	recorder := record.NewFakeRecorder(100)

	reconciler := &controller.IngressReconciler{
		Client:              fakeClient,
		Scheme:              s,
		Recorder:            recorder,
		GRPCServer:          grpcServer,
		IngressStatusUpdate: controller.NewIngressStatusUpdater(fakeClient, ""),
		Converter:           controller.NewIngressConverter(),
		IngressClassName:    "avapigw",
	}

	return ingressReconcilerKit{
		Reconciler: reconciler,
		Client:     fakeClient,
	}
}

// BenchmarkIngressConversion_Basic benchmarks converting a basic Ingress
// (single rule, single path) to config.Route/Backend.
func BenchmarkIngressConversion_Basic(b *testing.B) {
	conv := controller.NewIngressConverter()
	ingress := createBasicIngress("bench-basic", "default")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := conv.ConvertIngress(ingress)
		if err != nil {
			b.Fatalf("ConvertIngress failed: %v", err)
		}
		if len(result.Routes) == 0 {
			b.Fatal("expected at least one route")
		}
	}
}

// BenchmarkIngressConversion_Complex benchmarks converting a complex Ingress
// (multiple rules, multiple paths, TLS, default backend, all annotations).
func BenchmarkIngressConversion_Complex(b *testing.B) {
	conv := controller.NewIngressConverter()
	ingress := createComplexIngress("bench-complex", "default")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := conv.ConvertIngress(ingress)
		if err != nil {
			b.Fatalf("ConvertIngress failed: %v", err)
		}
		// Complex ingress: 5 rule paths + 1 default = 6 routes
		if len(result.Routes) == 0 {
			b.Fatal("expected routes from complex ingress")
		}
	}
}

// BenchmarkIngressConversion_WithAnnotations benchmarks annotation parsing overhead
// (timeout, retries, rate-limit, CORS, circuit-breaker, health-check).
func BenchmarkIngressConversion_WithAnnotations(b *testing.B) {
	conv := controller.NewIngressConverter()
	ingress := createAnnotatedIngress("bench-annotated", "default")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := conv.ConvertIngress(ingress)
		if err != nil {
			b.Fatalf("ConvertIngress failed: %v", err)
		}
		if len(result.Routes) == 0 {
			b.Fatal("expected at least one route")
		}
	}
}

// BenchmarkIngressReconciliation_Create benchmarks the full reconciliation cycle
// for creating an Ingress resource.
func BenchmarkIngressReconciliation_Create(b *testing.B) {
	ctx := context.Background()

	kit := setupIngressReconciler(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		// Create a fresh Ingress for each iteration
		ingress := createBasicIngress(fmt.Sprintf("bench-create-%d", i), "default")
		if err := kit.Client.Create(ctx, ingress); err != nil {
			b.Fatalf("Failed to create Ingress: %v", err)
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      ingress.Name,
				Namespace: ingress.Namespace,
			},
		}

		b.StartTimer()

		// First reconcile adds the finalizer
		_, _ = kit.Reconciler.Reconcile(ctx, req)
		// Second reconcile performs the actual conversion and apply
		_, _ = kit.Reconciler.Reconcile(ctx, req)
	}
}

// BenchmarkIngressReconciliation_Update benchmarks the full reconciliation cycle
// for updating an existing Ingress resource.
func BenchmarkIngressReconciliation_Update(b *testing.B) {
	ctx := context.Background()

	kit := setupIngressReconciler(b)

	// Pre-create and reconcile the Ingress
	ingress := createBasicIngress("bench-update", "default")
	if err := kit.Client.Create(ctx, ingress); err != nil {
		b.Fatalf("Failed to create Ingress: %v", err)
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      ingress.Name,
			Namespace: ingress.Namespace,
		},
	}

	// Initial reconcile to add finalizer
	_, _ = kit.Reconciler.Reconcile(ctx, req)
	// Second reconcile to apply routes
	_, _ = kit.Reconciler.Reconcile(ctx, req)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate update by reconciling again (routes get re-applied)
		_, _ = kit.Reconciler.Reconcile(ctx, req)
	}
}

// BenchmarkIngressReconciliation_Delete benchmarks the full reconciliation cycle
// for deleting an Ingress resource.
func BenchmarkIngressReconciliation_Delete(b *testing.B) {
	ctx := context.Background()

	kit := setupIngressReconciler(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		// Create and fully reconcile an Ingress
		ingress := createBasicIngress(fmt.Sprintf("bench-delete-%d", i), "default")
		if err := kit.Client.Create(ctx, ingress); err != nil {
			b.Fatalf("Failed to create Ingress: %v", err)
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      ingress.Name,
				Namespace: ingress.Namespace,
			},
		}

		// Add finalizer
		_, _ = kit.Reconciler.Reconcile(ctx, req)
		// Apply routes
		_, _ = kit.Reconciler.Reconcile(ctx, req)

		// Re-fetch the Ingress to get the updated version with finalizer
		updatedIngress := &networkingv1.Ingress{}
		if err := kit.Client.Get(ctx, req.NamespacedName, updatedIngress); err != nil {
			b.Fatalf("Failed to get Ingress: %v", err)
		}

		// Delete via the client and then reconcile
		if err := kit.Client.Delete(ctx, updatedIngress); err != nil {
			b.Fatalf("Failed to delete Ingress: %v", err)
		}

		b.StartTimer()

		// Reconcile the deletion (cleanup routes and remove finalizer)
		_, _ = kit.Reconciler.Reconcile(ctx, req)
	}
}

// BenchmarkIngressConversion_Parallel benchmarks concurrent Ingress conversions.
func BenchmarkIngressConversion_Parallel(b *testing.B) {
	conv := controller.NewIngressConverter()

	// Pre-create a set of Ingress objects
	ingresses := make([]*networkingv1.Ingress, 100)
	for i := 0; i < 100; i++ {
		ingresses[i] = createComplexIngress(
			fmt.Sprintf("bench-parallel-%d", i),
			"default",
		)
	}

	b.ResetTimer()
	b.ReportAllocs()

	var counter int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddInt64(&counter, 1) % 100
			result, err := conv.ConvertIngress(ingresses[idx])
			if err != nil {
				b.Errorf("ConvertIngress failed: %v", err)
				return
			}
			if len(result.Routes) == 0 {
				b.Error("expected routes from parallel conversion")
				return
			}
		}
	})
}

// ============================================================================
// gRPC Ingress Benchmarks
// ============================================================================

// BenchmarkGRPCIngressConversion_Basic benchmarks converting a basic gRPC Ingress
// (single rule, single path) to config.GRPCRoute/GRPCBackend.
func BenchmarkGRPCIngressConversion_Basic(b *testing.B) {
	conv := controller.NewIngressConverter()
	ingress := createBasicGRPCIngress("bench-grpc-basic", "default")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := conv.ConvertIngress(ingress)
		if err != nil {
			b.Fatalf("ConvertIngress failed: %v", err)
		}
		if len(result.GRPCRoutes) == 0 {
			b.Fatal("expected at least one gRPC route")
		}
	}
}

// BenchmarkGRPCIngressConversion_Complex benchmarks converting a complex gRPC Ingress
// (multiple rules, multiple paths, TLS, default backend, all annotations).
func BenchmarkGRPCIngressConversion_Complex(b *testing.B) {
	conv := controller.NewIngressConverter()
	ingress := createComplexGRPCIngress("bench-grpc-complex", "default")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := conv.ConvertIngress(ingress)
		if err != nil {
			b.Fatalf("ConvertIngress failed: %v", err)
		}
		// Complex gRPC ingress: 5 rule paths + 1 default = 6 gRPC routes
		if len(result.GRPCRoutes) == 0 {
			b.Fatal("expected gRPC routes from complex ingress")
		}
	}
}

// BenchmarkGRPCIngressConversion_WithAnnotations benchmarks gRPC annotation parsing overhead
// (gRPC-specific: service/method matching, retry-on, backoff, health check, connection pool).
func BenchmarkGRPCIngressConversion_WithAnnotations(b *testing.B) {
	conv := controller.NewIngressConverter()
	ingress := createAnnotatedGRPCIngress("bench-grpc-annotated", "default")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := conv.ConvertIngress(ingress)
		if err != nil {
			b.Fatalf("ConvertIngress failed: %v", err)
		}
		if len(result.GRPCRoutes) == 0 {
			b.Fatal("expected at least one gRPC route")
		}
	}
}

// BenchmarkGRPCIngressReconciliation_Create benchmarks the full reconciliation cycle
// for creating a gRPC Ingress resource.
func BenchmarkGRPCIngressReconciliation_Create(b *testing.B) {
	ctx := context.Background()

	kit := setupIngressReconciler(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		// Create a fresh gRPC Ingress for each iteration
		ingress := createBasicGRPCIngress(fmt.Sprintf("bench-grpc-create-%d", i), "default")
		if err := kit.Client.Create(ctx, ingress); err != nil {
			b.Fatalf("Failed to create gRPC Ingress: %v", err)
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      ingress.Name,
				Namespace: ingress.Namespace,
			},
		}

		b.StartTimer()

		// First reconcile adds the finalizer
		_, _ = kit.Reconciler.Reconcile(ctx, req)
		// Second reconcile performs the actual conversion and apply
		_, _ = kit.Reconciler.Reconcile(ctx, req)
	}
}

// BenchmarkGRPCIngressReconciliation_Update benchmarks the full reconciliation cycle
// for updating an existing gRPC Ingress resource.
func BenchmarkGRPCIngressReconciliation_Update(b *testing.B) {
	ctx := context.Background()

	kit := setupIngressReconciler(b)

	// Pre-create and reconcile the gRPC Ingress
	ingress := createBasicGRPCIngress("bench-grpc-update", "default")
	if err := kit.Client.Create(ctx, ingress); err != nil {
		b.Fatalf("Failed to create gRPC Ingress: %v", err)
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      ingress.Name,
			Namespace: ingress.Namespace,
		},
	}

	// Initial reconcile to add finalizer
	_, _ = kit.Reconciler.Reconcile(ctx, req)
	// Second reconcile to apply gRPC routes
	_, _ = kit.Reconciler.Reconcile(ctx, req)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate update by reconciling again (gRPC routes get re-applied)
		_, _ = kit.Reconciler.Reconcile(ctx, req)
	}
}

// BenchmarkGRPCIngressConversion_Parallel benchmarks concurrent gRPC Ingress conversions.
func BenchmarkGRPCIngressConversion_Parallel(b *testing.B) {
	conv := controller.NewIngressConverter()

	// Pre-create a set of gRPC Ingress objects
	ingresses := make([]*networkingv1.Ingress, 100)
	for i := 0; i < 100; i++ {
		ingresses[i] = createComplexGRPCIngress(
			fmt.Sprintf("bench-grpc-parallel-%d", i),
			"default",
		)
	}

	b.ResetTimer()
	b.ReportAllocs()

	var counter int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddInt64(&counter, 1) % 100
			result, err := conv.ConvertIngress(ingresses[idx])
			if err != nil {
				b.Errorf("ConvertIngress failed: %v", err)
				return
			}
			if len(result.GRPCRoutes) == 0 {
				b.Error("expected gRPC routes from parallel conversion")
				return
			}
		}
	})
}

// BenchmarkGRPCvsHTTPIngressConversion compares gRPC vs HTTP Ingress conversion performance.
func BenchmarkGRPCvsHTTPIngressConversion(b *testing.B) {
	conv := controller.NewIngressConverter()

	httpIngress := createComplexIngress("bench-http-compare", "default")
	grpcIngress := createComplexGRPCIngress("bench-grpc-compare", "default")

	b.Run("HTTP", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := conv.ConvertIngress(httpIngress)
			if err != nil {
				b.Fatalf("ConvertIngress failed: %v", err)
			}
			if len(result.Routes) == 0 {
				b.Fatal("expected HTTP routes")
			}
		}
	})

	b.Run("gRPC", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := conv.ConvertIngress(grpcIngress)
			if err != nil {
				b.Fatalf("ConvertIngress failed: %v", err)
			}
			if len(result.GRPCRoutes) == 0 {
				b.Fatal("expected gRPC routes")
			}
		}
	})
}
