# Contributing to Ava API Gateway

Welcome to the Ava API Gateway project! We're excited that you're interested in contributing to this high-performance, production-ready API Gateway built with Go and gin-gonic. This document provides guidelines and information for contributors.

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

- **Go 1.25+** - [Download Go](https://golang.org/dl/)
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
  ├── config/        # Configuration handling
  ├── grpc/          # gRPC server and handlers
  ├── middleware/    # HTTP middleware
  ├── observability/ # Metrics, tracing, logging
  ├── proxy/         # HTTP proxy logic
  ├── security/      # Security utilities
  └── ...
  ```

#### Error Handling

- Use explicit error handling, avoid panic
- Wrap errors with context using `fmt.Errorf`
- Log errors at appropriate levels
- Return meaningful error messages

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
```

### Running Tests Locally

Before submitting changes, ensure all tests pass:

```bash
# Run unit tests
make test-unit

# Run functional tests
make test-functional

# Run all tests (requires test backends)
make test-all

# Generate coverage report
make test-coverage
```

## Testing Requirements

### Test Coverage Requirements

- **Minimum coverage**: 90% for new code
- **Unit tests**: Required for all new functions and methods
- **Integration tests**: Required for new features that interact with external systems
- **End-to-end tests**: Required for new API endpoints or major features

### Test Categories

#### 1. Unit Tests (`make test-unit`)
- Test individual functions and methods in isolation
- Use mocks for external dependencies
- Fast execution (< 1 second per test)
- No external dependencies required

#### 2. Functional Tests (`make test-functional`)
- Test feature functionality with minimal external dependencies
- Use in-memory implementations where possible
- Medium execution time (< 10 seconds per test)

#### 3. Integration Tests (`make test-integration`)
- Test integration with external systems
- Require test backends on ports 8801, 8802 (HTTP) and 8803, 8804 (gRPC)
- Test real network communication
- Longer execution time acceptable

#### 4. End-to-End Tests (`make test-e2e`)
- Test complete user workflows
- Test the full system including configuration loading
- Require all external dependencies
- Longest execution time acceptable

### Writing Tests

#### Test File Naming
- Unit tests: `*_test.go` in the same package
- Integration tests: `*_integration_test.go` with `//go:build integration` tag
- E2E tests: `*_e2e_test.go` with `//go:build e2e` tag

#### Test Structure
```go
func TestFunctionName(t *testing.T) {
    // Arrange
    input := "test input"
    expected := "expected output"
    
    // Act
    result, err := FunctionToTest(input)
    
    // Assert
    require.NoError(t, err)
    assert.Equal(t, expected, result)
}
```

#### Table-Driven Tests
```go
func TestValidateConfig(t *testing.T) {
    tests := []struct {
        name    string
        config  Config
        wantErr bool
    }{
        {
            name:    "valid config",
            config:  Config{Port: 8080},
            wantErr: false,
        },
        {
            name:    "invalid port",
            config:  Config{Port: -1},
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateConfig(tt.config)
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

### Test Environment Setup

For integration and e2e tests, you'll need test backends:

```bash
# Start test HTTP backends
go run test/backends/http/main.go -port 8801 &
go run test/backends/http/main.go -port 8802 &

# Start test gRPC backends
go run test/backends/grpc/main.go -port 8803 &
go run test/backends/grpc/main.go -port 8804 &

# Run integration tests
make test-integration

# Run e2e tests
make test-e2e

# Clean up
pkill -f "test/backends"
```

## Pull Request Process

### Before Submitting

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all checks**:
   ```bash
   make ci
   ```

3. **Update documentation** if needed
4. **Add or update tests** for your changes
5. **Update CHANGELOG.md** if applicable

### Pull Request Template

When creating a pull request, include:

```markdown
## Description
Brief description of the changes and why they're needed.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass (if applicable)
- [ ] E2E tests pass (if applicable)
- [ ] Manual testing completed

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
```

### Review Process

1. **Automated checks** must pass (CI/CD pipeline)
2. **Code review** by at least one maintainer
3. **Testing** verification by reviewers
4. **Documentation** review if applicable
5. **Final approval** by project maintainer

### CI Checks That Must Pass

- **Linting**: `golangci-lint` with no errors
- **Security**: `govulncheck` with no vulnerabilities
- **Tests**: All unit and functional tests pass
- **Build**: Binary builds successfully
- **Format**: Code is properly formatted

## Code Quality Standards

### Linting Requirements

We use `golangci-lint` with strict settings:

```bash
# Run linter
make lint

# Auto-fix issues where possible
make lint-fix
```

### Security Scanning

All code must pass security scanning:

```bash
# Run vulnerability check
make vuln
```

### Documentation Requirements

#### Code Documentation
- All exported functions and types must have comments
- Comments should explain the "why", not just the "what"
- Use proper Go doc comment format

Example:
```go
// AuthenticateRequest validates the authentication credentials in the request
// and returns the authenticated user information. It supports JWT, API key,
// and mTLS authentication methods based on the gateway configuration.
//
// Returns an error if authentication fails or if the request is malformed.
func AuthenticateRequest(req *http.Request, config *AuthConfig) (*User, error) {
    // Implementation...
}
```

#### API Documentation
- Update OpenAPI/Swagger specs for API changes
- Include request/response examples
- Document error codes and messages

#### Configuration Documentation
- Document new configuration options
- Provide examples for complex configurations
- Update the main README.md if needed

### Performance Considerations

- **Benchmarks**: Add benchmarks for performance-critical code
- **Memory usage**: Avoid memory leaks and excessive allocations
- **Concurrency**: Use proper synchronization for concurrent code
- **Profiling**: Profile code for performance bottlenecks

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