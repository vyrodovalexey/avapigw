# Contributing to AV API Gateway

Welcome to the AV API Gateway project! We're excited that you're interested in contributing to this high-performance, production-ready API Gateway built with Go and gin-gonic. This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Welcome and Project Overview](#welcome-and-project-overview)
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Code Quality Standards](#code-quality-standards)
- [Helm Chart Contributions](#helm-chart-contributions)
- [Release Process](#release-process)
- [Getting Help](#getting-help)

## Welcome and Project Overview

Ava API Gateway is a cloud-native, high-performance API Gateway designed for modern microservices architectures. The project focuses on:

- **Performance**: Built with Go and gin-gonic for high throughput and low latency
- **Security**: Comprehensive authentication, authorization, and TLS support
- **Observability**: Built-in metrics, tracing, and logging capabilities
- **Reliability**: Circuit breakers, retries, health checks, and fault tolerance
- **Flexibility**: Declarative YAML configuration with hot-reload support

We welcome contributions of all kinds, including:
- Bug fixes and feature enhancements
- Documentation improvements
- Test coverage improvements
- Performance optimizations
- Security enhancements
- Helm chart improvements

## Code of Conduct

This project adheres to a Code of Conduct to ensure a welcoming and inclusive environment for all contributors. By participating in this project, you agree to abide by its terms.

### Our Standards

- **Be respectful**: Treat everyone with respect and kindness
- **Be inclusive**: Welcome newcomers and help them get started
- **Be collaborative**: Work together constructively and professionally
- **Be patient**: Help others learn and grow
- **Be constructive**: Provide helpful feedback and suggestions

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Personal attacks or trolling
- Publishing private information without permission
- Any conduct that would be inappropriate in a professional setting

If you experience or witness unacceptable behavior, please report it to the project maintainers.

## Getting Started

### Prerequisites

Before contributing, ensure you have the following installed:

- **Go 1.25.7+** - [Download Go](https://golang.org/dl/)
- **Docker** - [Install Docker](https://docs.docker.com/get-docker/)
- **kubectl** - [Install kubectl](https://kubernetes.io/docs/tasks/tools/)
- **Helm 3.x** - [Install Helm](https://helm.sh/docs/intro/install/)
- **Git** - [Install Git](https://git-scm.com/downloads)

### Fork and Clone

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/avapigw.git
   cd avapigw
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/vyrodovalexey/avapigw.git
   ```

### Development Environment Setup

1. **Install dependencies**:
   ```bash
   make deps
   ```

2. **Install development tools**:
   ```bash
   make tools
   ```

3. **Verify your setup**:
   ```bash
   make lint
   make test-unit
   make build
   ```

4. **Run the gateway locally**:
   ```bash
   make run
   ```

The gateway will start on:
- HTTP: `http://localhost:8080`
- gRPC: `localhost:9000` (if enabled)
- Metrics/Health: `http://localhost:9090`

## Development Workflow

### Branch Naming Conventions

Use descriptive branch names that follow this pattern:

- **Features**: `feature/description-of-feature`
- **Bug fixes**: `fix/description-of-bug`
- **Documentation**: `docs/description-of-change`
- **Refactoring**: `refactor/description-of-change`
- **Tests**: `test/description-of-test`

Examples:
```bash
git checkout -b feature/add-oauth2-support
git checkout -b fix/memory-leak-in-cache
git checkout -b docs/update-api-documentation
```

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

#### Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **chore**: Changes to the build process or auxiliary tools

#### Examples

```bash
feat(auth): add OAuth2 authentication support

Add OAuth2 authentication provider with support for authorization code flow.
Includes token validation, refresh token handling, and PKCE support.

Closes #123

fix(cache): resolve memory leak in Redis connection pool

The Redis connection pool was not properly releasing connections,
causing memory usage to grow over time.

perf(proxy): optimize request routing performance

Improve routing performance by 15% through better path matching
algorithm and reduced memory allocations.

docs(api): update authentication examples

Add comprehensive examples for JWT, API key, and mTLS authentication
methods with curl and gRPC examples.
```

### Code Style Guidelines

#### Go Code Style

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` for formatting (automatically applied by `make fmt`)
- Follow the [Effective Go](https://golang.org/doc/effective_go.html) guidelines
- Use meaningful variable and function names
- Add comments for exported functions and types
- Keep functions small and focused

#### Package Organization

- Place new functionality in appropriate internal packages
- Follow the existing package structure:
  ```
  internal/
  ├── auth/          # Authentication logic
  ├── authz/         # Authorization logic
  ├── cache/         # Caching implementations
  ├── config/        # Configuration handling (split into domain files)
  │   ├── config.go        # Core GatewayConfig, Metadata, GatewaySpec
  │   ├── listener.go      # Listener types
  │   ├── route.go         # Route types
  │   ├── backend.go       # Backend types
  │   ├── grpc_config.go   # gRPC config types
  │   ├── middleware.go    # Middleware config types
  │   ├── observability.go # Observability config types
  │   ├── security.go      # Security/Auth/Audit config types
  │   └── duration.go      # Duration type
  ├── grpc/          # gRPC server and handlers
  ├── middleware/    # HTTP middleware
  ├── observability/ # Metrics, tracing, logging
  ├── proxy/         # HTTP proxy logic
  ├── security/      # Security utilities
  └── ...
  ```

#### Main Application Organization

The main application (`cmd/gateway/`) has been split into focused files:
```
cmd/gateway/
├── main.go          # main(), parseFlags(), printVersion()
├── app.go           # application struct, initApplication()
├── config_loader.go # loadAndValidateConfig(), initAuditLogger(), initTracer()
├── middleware.go    # buildMiddlewareChain()
├── metrics.go       # metrics server functions
├── vault.go         # vault client functions
├── reload.go        # config reload functions
├── shutdown.go      # shutdown functions
└── env.go           # getEnvOrDefault()
```

#### Error Handling

- Use explicit error handling, avoid panic
- Wrap errors with context using `fmt.Errorf`
- Log errors at appropriate levels
- Return meaningful error messages
- Use shared error types like `util.ServerError` for consistent circuit breaker tracking
- Use `util.StatusCapturingResponseWriter` for middleware that needs to inspect response status codes
- Use `ValidateConfigWithWarnings()` to provide helpful warnings for deprecated settings

Example:
```go
func processRequest(req *http.Request) error {
    if req == nil {
        return fmt.Errorf("request cannot be nil")
    }
    
    if err := validateRequest(req); err != nil {
        return fmt.Errorf("request validation failed: %w", err)
    }
    
    return nil
}

// Use shared error types for consistent behavior
func handleBackendResponse(statusCode int) error {
    if statusCode >= 500 {
        return util.NewServerError(statusCode)
    }
    return nil
}

// Use status capturing for middleware
func myMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        w := util.NewStatusCapturingResponseWriter(c.Writer)
        c.Writer = w
        c.Next()
        
        // Now you can inspect w.StatusCode
        if w.StatusCode >= 500 {
            // Handle server error
        }
    }
}
```

### Adding New Metrics

When adding new Prometheus metrics, follow these guidelines:

#### Metric Design Principles

1. **Bounded Cardinality**: Ensure metric labels have bounded cardinality to prevent memory issues
   ```go
   // Good: bounded cardinality
   requestsTotal.WithLabelValues(method, routeName, statusCode)
   
   // Bad: unbounded cardinality (user IDs can be infinite)
   requestsTotal.WithLabelValues(method, userID, statusCode)
   ```

2. **Meaningful Labels**: Use labels that provide actionable insights
   ```go
   // Good: actionable labels
   authRequests.WithLabelValues("jwt", "success")
   
   // Bad: too granular
   authRequests.WithLabelValues("jwt", "RS256", "issuer.example.com", "success")
   ```

3. **Consistent Naming**: Follow Prometheus naming conventions
   ```go
   // Good: follows conventions
   gateway_requests_total
   gateway_request_duration_seconds
   gateway_cache_hits_total
   
   // Bad: inconsistent naming
   gateway_total_requests
   gateway_request_time_ms
   gateway_cache_hit_count
   ```

#### Implementation Steps

1. **Define the metric** in the appropriate metrics file:
   ```go
   // internal/auth/metrics.go
   authTokenValidations := promauto.NewCounterVec(
       prometheus.CounterOpts{
           Namespace: "gateway",
           Subsystem: "auth",
           Name:      "token_validations_total",
           Help:      "Total number of token validations",
       },
       []string{"provider", "status"},
   )
   ```

2. **Add metric recording** in the business logic:
   ```go
   // Record successful validation
   authTokenValidations.WithLabelValues("jwt", "success").Inc()
   
   // Record failed validation
   authTokenValidations.WithLabelValues("jwt", "failed").Inc()
   ```

3. **Add tests** for the metric:
   ```go
   func TestAuthMetrics(t *testing.T) {
       // Reset metrics
       authTokenValidations.Reset()
       
       // Perform operation that should record metric
       err := validateToken(validToken)
       require.NoError(t, err)
       
       // Verify metric was recorded
       metric := testutil.ToFloat64(authTokenValidations.WithLabelValues("jwt", "success"))
       assert.Equal(t, 1.0, metric)
   }
   ```

4. **Update documentation** in `docs/features/metrics.md`

5. **Add to configuration** if the metric should be configurable

#### Metric Categories

The gateway organizes metrics into these categories:
- **Core Gateway**: Request processing, build info, uptime
- **Middleware**: Rate limiting, circuit breaker, timeouts, retries
- **Cache**: Hits, misses, evictions, size, duration
- **Authentication**: JWT, API key, OIDC, mTLS validation
- **Authorization**: RBAC, ABAC, external authorization
- **TLS**: Handshakes, certificate lifecycle
- **Vault**: API requests, authentication, secret retrieval
- **Backend Auth**: Backend authentication operations
- **Proxy**: Backend communication, errors, duration
- **WebSocket**: Connections, messages, errors
- **gRPC**: Requests, streaming, method-level tracking
- **Config Reload**: Hot reload operations
- **Health Check**: Backend health monitoring
- **Operator**: Controller, webhook, certificate metrics

### Performance Testing Procedures

When making changes that may affect performance:

1. **Run baseline tests** before your changes:
   ```bash
   make perf-test-http
   make perf-test-grpc-unary
   ```

2. **Run tests after your changes** and compare results:
   ```bash
   # Compare with baseline
   ./test/performance/scripts/analyze-results.sh results/baseline/ --compare=results/latest/
   ```

3. **Performance regression thresholds**:
   - HTTP throughput: < 5% reduction
   - HTTP latency P95: < 10% increase
   - gRPC throughput: < 5% reduction
   - Memory usage: < 10% increase

4. **Document performance impact** in your PR if changes affect performance

### Performance Considerations

- **Benchmarks**: Add benchmarks for performance-critical code
- **Memory usage**: Avoid memory leaks and excessive allocations
- **Concurrency**: Use proper synchronization for concurrent code
- **Profiling**: Profile code for performance bottlenecks
- **Resource cleanup**: Always clean up timers, goroutines, and other resources
- **Timer management**: Use defer statements to prevent timer leaks (see config watcher implementation)
- **Hot-reload capabilities**: gRPC backends support hot-reload in both file-based and operator modes; gRPC routes only support hot-reload in operator mode; audit logger supports hot-reload in both modes via AtomicAuditLogger
- **Metrics impact**: Consider the performance impact of new metrics (use bounded cardinality)
- **Performance testing**: Run performance tests for changes that may affect throughput or latency

Example benchmark:
```go
func BenchmarkRouteMatching(b *testing.B) {
    router := setupTestRouter()
    req := httptest.NewRequest("GET", "/api/v1/users/123", nil)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        router.Match(req)
    }
}
```

#### Resource Management Best Practices

Always clean up resources to prevent leaks:

```go
// Timer cleanup example (from config watcher)
func (w *Watcher) watch(ctx context.Context) {
    defer close(w.stoppedCh)

    var debounceTimer *time.Timer
    var debounceCh <-chan time.Time

    // Ensure debounce timer is cleaned up on exit to prevent goroutine leak
    defer func() {
        if debounceTimer != nil {
            debounceTimer.Stop()
        }
    }()

    // ... rest of implementation
}

// Goroutine cleanup example
func startWorker(ctx context.Context) {
    go func() {
        defer func() {
            // Clean up resources
        }()
        
        for {
            select {
            case <-ctx.Done():
                return // Proper cleanup on context cancellation
            // ... other cases
            }
        }
    }()
}
```

## Helm Chart Contributions

### Chart Structure

The Helm chart is located in `helm/avapigw/` and follows standard Helm practices:

```
helm/avapigw/
├── Chart.yaml          # Chart metadata
├── values.yaml         # Default values
├── templates/          # Kubernetes manifests
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── configmap.yaml
│   ├── ingress.yaml
│   └── ...
└── README.md          # Chart documentation
```

### Chart Development Guidelines

1. **Follow Helm best practices**:
   - Use semantic versioning
   - Include resource limits and requests
   - Support multiple environments
   - Use proper labels and annotations

2. **Testing Helm changes**:
   ```bash
   # Lint the chart
   helm lint helm/avapigw/
   
   # Test template rendering
   helm template test helm/avapigw/ --values helm/avapigw/values.yaml
   
   # Test installation (requires Kubernetes cluster)
   helm install test helm/avapigw/ --dry-run --debug
   ```

3. **Documentation**:
   - Update `helm/avapigw/README.md` for new values
   - Include examples for complex configurations
   - Document breaking changes in chart versions

### Chart Values

When adding new configuration options:

1. **Add to `values.yaml`** with sensible defaults
2. **Document in comments** within the values file
3. **Update chart README** with parameter descriptions
4. **Test with different value combinations**

Example:
```yaml
# Authentication configuration
auth:
  # Enable authentication
  enabled: true
  
  # JWT authentication settings
  jwt:
    # Enable JWT authentication
    enabled: true
    # JWT signing algorithm (RS256, ES256, HS256)
    algorithm: "RS256"
    # JWT issuer URL
    issuer: ""
```

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

### Release Workflow

1. **Version bump**: Update version in relevant files
2. **Changelog**: Update `CHANGELOG.md` with release notes
3. **Tag creation**: Create and push a git tag
4. **Automated release**: GitHub Actions handles the rest

### Release Notes Format

```markdown
## [1.2.0] - 2024-01-15

### Added
- OAuth2 authentication support
- New rate limiting algorithms
- Helm chart improvements

### Changed
- Improved error handling in proxy module
- Updated dependencies to latest versions

### Fixed
- Memory leak in cache implementation
- Race condition in health checks

### Security
- Updated JWT library to fix security vulnerability
```

### Pre-release Checklist

- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Changelog is updated
- [ ] Version numbers are bumped
- [ ] Security scan passes
- [ ] Performance regression tests pass

## Getting Help

### Communication Channels

- **GitHub Issues**: For bug reports and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Pull Request Comments**: For code review discussions

### Asking Questions

When asking for help:

1. **Search existing issues** first
2. **Provide context**: What are you trying to achieve?
3. **Include details**: Version, configuration, error messages
4. **Minimal reproduction**: Provide steps to reproduce the issue

### Issue Reporting

#### Bug Reports

Use the bug report template and include:

- **Environment**: OS, Go version, gateway version
- **Configuration**: Relevant configuration snippets
- **Steps to reproduce**: Clear, minimal steps
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Logs**: Relevant log output (with sensitive data removed)

#### Feature Requests

Use the feature request template and include:

- **Problem description**: What problem does this solve?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches you've considered
- **Additional context**: Any other relevant information

### Contributing Documentation

Documentation contributions are highly valued:

- **README improvements**: Clarify setup instructions
- **API documentation**: Add examples and use cases
- **Tutorials**: Step-by-step guides for common scenarios
- **Architecture docs**: Explain design decisions and patterns

### Code Review Guidelines

When reviewing code:

- **Be constructive**: Suggest improvements, don't just point out problems
- **Be specific**: Reference line numbers and provide examples
- **Be timely**: Review promptly to keep development moving
- **Be thorough**: Check functionality, tests, and documentation

When receiving reviews:

- **Be responsive**: Address feedback promptly
- **Be open**: Consider suggestions and ask questions if unclear
- **Be collaborative**: Work with reviewers to improve the code

---

Thank you for contributing to Ava API Gateway! Your contributions help make this project better for everyone. If you have any questions about contributing, please don't hesitate to ask in GitHub Discussions or create an issue.

Happy coding! 🚀