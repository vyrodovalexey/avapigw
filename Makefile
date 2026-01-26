# Makefile for avapigw API Gateway
# Production-ready build and test automation

# ==============================================================================
# Variables
# ==============================================================================

BINARY_NAME := gateway
BUILD_DIR := bin
CMD_DIR := cmd/gateway
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go variables
GO := go
GOFLAGS := -v -trimpath
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT) -s -w"

# Docker variables
DOCKER_REGISTRY ?= ghcr.io
DOCKER_IMAGE ?= $(DOCKER_REGISTRY)/avapigw/avapigw
DOCKER_TAG ?= $(VERSION)

# Linting and security tools
GOLANGCI_LINT := golangci-lint
GOVULNCHECK := govulncheck

# Test backend URLs (HTTP REST API)
TEST_BACKEND1_URL ?= http://127.0.0.1:8801
TEST_BACKEND2_URL ?= http://127.0.0.1:8802

# Test backend URLs (gRPC)
TEST_GRPC_BACKEND1_URL ?= 127.0.0.1:8803
TEST_GRPC_BACKEND2_URL ?= 127.0.0.1:8804

# Vault settings
TEST_VAULT_ADDR ?= http://127.0.0.1:8200
TEST_VAULT_TOKEN ?= myroot

# Keycloak settings
TEST_KEYCLOAK_ADDR ?= http://127.0.0.1:8090
TEST_KEYCLOAK_REALM ?= gateway-test
TEST_KEYCLOAK_CLIENT_ID ?= gateway
TEST_KEYCLOAK_CLIENT_SECRET ?= gateway-secret

# Coverage settings
COVERAGE_DIR := coverage
COVERAGE_UNIT := $(COVERAGE_DIR)/unit.out
COVERAGE_FUNCTIONAL := $(COVERAGE_DIR)/functional.out
COVERAGE_INTEGRATION := $(COVERAGE_DIR)/integration.out
COVERAGE_E2E := $(COVERAGE_DIR)/e2e.out
COVERAGE_MERGED := $(COVERAGE_DIR)/merged.out

.PHONY: all build build-linux build-darwin build-windows build-all \
        test test-unit test-coverage test-functional test-integration test-e2e test-all \
        test-grpc-unit test-grpc-integration test-grpc-e2e \
        test-auth-unit test-auth-integration test-auth-e2e \
        lint lint-fix fmt vet vuln \
        docker-build docker-run docker-push docker-clean \
        run dev clean deps tools generate proto-generate \
        perf-test perf-test-http perf-test-post perf-test-mixed perf-test-all \
        perf-test-grpc-unary perf-test-grpc-streaming perf-test-websocket \
        perf-generate-ammo perf-generate-charts perf-analyze \
        perf-start-gateway perf-stop-gateway perf-setup-infra \
        ci help version

# ==============================================================================
# Default target
# ==============================================================================

all: lint test build

# ==============================================================================
# Build targets
# ==============================================================================

## build: Build the gateway binary for current platform
build:
	@echo "==> Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "==> Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

## build-linux: Cross-compile for Linux (amd64 and arm64)
build-linux:
	@echo "==> Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./$(CMD_DIR)
	@echo "==> Linux binaries built"

## build-darwin: Cross-compile for macOS (amd64 and arm64)
build-darwin:
	@echo "==> Building for macOS..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -trimpath $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	@echo "==> macOS binaries built"

## build-windows: Cross-compile for Windows (amd64)
build-windows:
	@echo "==> Building for Windows..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)
	@echo "==> Windows binary built"

## build-all: Build for all platforms
build-all: build-linux build-darwin build-windows

# ==============================================================================
# Test targets
# ==============================================================================

## test: Run unit tests (alias for test-unit)
test: test-unit

## test-unit: Run unit tests with race detection
test-unit:
	@echo "==> Running unit tests..."
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -race -coverprofile=$(COVERAGE_UNIT) -covermode=atomic ./internal/... ./cmd/...
	@echo "==> Unit tests completed"

## test-coverage: Run unit tests and generate HTML coverage report
test-coverage: test-unit
	@echo "==> Generating coverage report..."
	$(GO) tool cover -html=$(COVERAGE_UNIT) -o $(COVERAGE_DIR)/coverage.html
	$(GO) tool cover -func=$(COVERAGE_UNIT)
	@echo "==> Coverage report: $(COVERAGE_DIR)/coverage.html"

## test-functional: Run functional tests
test-functional:
	@echo "==> Running functional tests..."
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -race -coverprofile=$(COVERAGE_FUNCTIONAL) -covermode=atomic -tags=functional ./test/functional/...
	@echo "==> Functional tests completed"

## test-integration: Run integration tests (requires HTTP backends on 8801, 8802 and gRPC backends on 8803, 8804)
test-integration:
	@echo "==> Running integration tests..."
	@echo "==> HTTP backends expected at $(TEST_BACKEND1_URL) and $(TEST_BACKEND2_URL)"
	@echo "==> gRPC backends expected at $(TEST_GRPC_BACKEND1_URL) and $(TEST_GRPC_BACKEND2_URL)"
	@mkdir -p $(COVERAGE_DIR)
	TEST_BACKEND1_URL=$(TEST_BACKEND1_URL) TEST_BACKEND2_URL=$(TEST_BACKEND2_URL) \
	TEST_GRPC_BACKEND1_URL=$(TEST_GRPC_BACKEND1_URL) TEST_GRPC_BACKEND2_URL=$(TEST_GRPC_BACKEND2_URL) \
		$(GO) test -race -coverprofile=$(COVERAGE_INTEGRATION) -covermode=atomic -tags=integration ./test/integration/...
	@echo "==> Integration tests completed"

## test-e2e: Run end-to-end tests (requires HTTP backends on 8801, 8802 and gRPC backends on 8803, 8804)
test-e2e:
	@echo "==> Running e2e tests..."
	@echo "==> HTTP backends expected at $(TEST_BACKEND1_URL) and $(TEST_BACKEND2_URL)"
	@echo "==> gRPC backends expected at $(TEST_GRPC_BACKEND1_URL) and $(TEST_GRPC_BACKEND2_URL)"
	@mkdir -p $(COVERAGE_DIR)
	TEST_BACKEND1_URL=$(TEST_BACKEND1_URL) TEST_BACKEND2_URL=$(TEST_BACKEND2_URL) \
	TEST_GRPC_BACKEND1_URL=$(TEST_GRPC_BACKEND1_URL) TEST_GRPC_BACKEND2_URL=$(TEST_GRPC_BACKEND2_URL) \
		$(GO) test -race -coverprofile=$(COVERAGE_E2E) -covermode=atomic -tags=e2e ./test/e2e/...
	@echo "==> E2E tests completed"

## test-all: Run all tests (unit, functional, integration, e2e)
test-all: test-unit test-functional test-integration test-e2e
	@echo "==> All tests completed"

# ==============================================================================
# gRPC-specific test targets
# ==============================================================================

## test-grpc-unit: Run gRPC-specific unit tests
test-grpc-unit:
	@echo "==> Running gRPC unit tests..."
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -race -coverprofile=$(COVERAGE_DIR)/grpc-unit.out -covermode=atomic ./internal/grpc/...
	@echo "==> gRPC unit tests completed"

## test-grpc-integration: Run gRPC integration tests (requires gRPC backends on 8803, 8804)
test-grpc-integration:
	@echo "==> Running gRPC integration tests..."
	@echo "==> gRPC backends expected at $(TEST_GRPC_BACKEND1_URL) and $(TEST_GRPC_BACKEND2_URL)"
	@mkdir -p $(COVERAGE_DIR)
	TEST_GRPC_BACKEND1_URL=$(TEST_GRPC_BACKEND1_URL) TEST_GRPC_BACKEND2_URL=$(TEST_GRPC_BACKEND2_URL) \
		$(GO) test -race -coverprofile=$(COVERAGE_DIR)/grpc-integration.out -covermode=atomic -tags=integration -run ".*[Gg]rpc.*|.*[Gg]RPC.*" ./test/integration/...
	@echo "==> gRPC integration tests completed"

## test-grpc-e2e: Run gRPC e2e tests (requires gRPC backends on 8803, 8804)
test-grpc-e2e:
	@echo "==> Running gRPC e2e tests..."
	@echo "==> gRPC backends expected at $(TEST_GRPC_BACKEND1_URL) and $(TEST_GRPC_BACKEND2_URL)"
	@mkdir -p $(COVERAGE_DIR)
	TEST_GRPC_BACKEND1_URL=$(TEST_GRPC_BACKEND1_URL) TEST_GRPC_BACKEND2_URL=$(TEST_GRPC_BACKEND2_URL) \
		$(GO) test -race -coverprofile=$(COVERAGE_DIR)/grpc-e2e.out -covermode=atomic -tags=e2e -run ".*[Gg]rpc.*|.*[Gg]RPC.*" ./test/e2e/...
	@echo "==> gRPC e2e tests completed"

# ==============================================================================
# Auth-specific test targets
# ==============================================================================

## test-auth-unit: Run authentication/authorization unit tests
test-auth-unit:
	@echo "==> Running auth unit tests..."
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -race -coverprofile=$(COVERAGE_DIR)/auth-unit.out -covermode=atomic ./internal/auth/... ./internal/authz/... ./internal/security/... ./internal/audit/...
	@echo "==> Auth unit tests completed"

## test-auth-integration: Run authentication/authorization integration tests (requires Vault and Keycloak)
test-auth-integration:
	@echo "==> Running auth integration tests..."
	@echo "==> Vault expected at $(TEST_VAULT_ADDR)"
	@echo "==> Keycloak expected at $(TEST_KEYCLOAK_ADDR)"
	@mkdir -p $(COVERAGE_DIR)
	TEST_VAULT_ADDR=$(TEST_VAULT_ADDR) TEST_VAULT_TOKEN=$(TEST_VAULT_TOKEN) \
	TEST_KEYCLOAK_ADDR=$(TEST_KEYCLOAK_ADDR) TEST_KEYCLOAK_REALM=$(TEST_KEYCLOAK_REALM) \
	TEST_KEYCLOAK_CLIENT_ID=$(TEST_KEYCLOAK_CLIENT_ID) TEST_KEYCLOAK_CLIENT_SECRET=$(TEST_KEYCLOAK_CLIENT_SECRET) \
		$(GO) test -race -coverprofile=$(COVERAGE_DIR)/auth-integration.out -covermode=atomic -tags=integration -run ".*[Aa]uth.*|.*[Oo]idc.*|.*[Jj]wt.*|.*[Aa]pikey.*" ./test/integration/...
	@echo "==> Auth integration tests completed"

## test-auth-e2e: Run authentication/authorization e2e tests (requires Vault and Keycloak)
test-auth-e2e:
	@echo "==> Running auth e2e tests..."
	@echo "==> Vault expected at $(TEST_VAULT_ADDR)"
	@echo "==> Keycloak expected at $(TEST_KEYCLOAK_ADDR)"
	@mkdir -p $(COVERAGE_DIR)
	TEST_VAULT_ADDR=$(TEST_VAULT_ADDR) TEST_VAULT_TOKEN=$(TEST_VAULT_TOKEN) \
	TEST_KEYCLOAK_ADDR=$(TEST_KEYCLOAK_ADDR) TEST_KEYCLOAK_REALM=$(TEST_KEYCLOAK_REALM) \
	TEST_KEYCLOAK_CLIENT_ID=$(TEST_KEYCLOAK_CLIENT_ID) TEST_KEYCLOAK_CLIENT_SECRET=$(TEST_KEYCLOAK_CLIENT_SECRET) \
		$(GO) test -race -coverprofile=$(COVERAGE_DIR)/auth-e2e.out -covermode=atomic -tags=e2e -run ".*[Aa]uth.*|.*[Rr]bac.*|.*[Jj]wt.*|.*[Aa]pikey.*" ./test/e2e/...
	@echo "==> Auth e2e tests completed"

## test-merge-coverage: Merge all coverage reports
test-merge-coverage:
	@echo "==> Merging coverage reports..."
	@mkdir -p $(COVERAGE_DIR)
	@if command -v gocovmerge > /dev/null 2>&1; then \
		gocovmerge $(COVERAGE_UNIT) $(COVERAGE_FUNCTIONAL) $(COVERAGE_INTEGRATION) $(COVERAGE_E2E) > $(COVERAGE_MERGED) 2>/dev/null || true; \
		echo "==> Merged coverage: $(COVERAGE_MERGED)"; \
	else \
		echo "==> gocovmerge not installed, skipping merge"; \
	fi

# ==============================================================================
# Quality targets
# ==============================================================================

## lint: Run golangci-lint
lint:
	@echo "==> Running linter..."
	$(GOLANGCI_LINT) run ./...

## lint-fix: Run golangci-lint with auto-fix
lint-fix:
	@echo "==> Running linter with auto-fix..."
	$(GOLANGCI_LINT) run --fix ./...

## fmt: Format code
fmt:
	@echo "==> Formatting code..."
	$(GO) fmt ./...
	@echo "==> Code formatted"

## vet: Run go vet
vet:
	@echo "==> Running go vet..."
	$(GO) vet ./...
	@echo "==> Vet completed"

## vuln: Run govulncheck for vulnerability scanning
vuln:
	@echo "==> Running vulnerability check..."
	$(GOVULNCHECK) ./...
	@echo "==> Vulnerability check completed"

# ==============================================================================
# Docker targets
# ==============================================================================

## docker-build: Build Docker image
docker-build:
	@echo "==> Building Docker image..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest \
		.
	@echo "==> Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

## docker-run: Run Docker container
docker-run:
	@echo "==> Running Docker container..."
	docker run --rm -it \
		-p 8080:8080 \
		-p 9000:9000 \
		-p 9090:9090 \
		-v $(PWD)/configs:/app/configs:ro \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

## docker-push: Push Docker image to registry
docker-push:
	@echo "==> Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest
	@echo "==> Docker image pushed"

## docker-clean: Remove local Docker images
docker-clean:
	@echo "==> Cleaning Docker images..."
	docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest 2>/dev/null || true
	@echo "==> Docker images cleaned"

# ==============================================================================
# Development targets
# ==============================================================================

## run: Build and run the gateway locally
run: build
	@echo "==> Running gateway..."
	./$(BUILD_DIR)/$(BINARY_NAME) -config configs/gateway.yaml

## dev: Run with hot-reload using air (if available)
dev:
	@echo "==> Running in development mode..."
	@if command -v air > /dev/null 2>&1; then \
		air -c .air.toml; \
	else \
		echo "air not installed, falling back to standard run"; \
		$(MAKE) run; \
	fi

## run-debug: Run with debug logging
run-debug: build
	@echo "==> Running gateway with debug logging..."
	./$(BUILD_DIR)/$(BINARY_NAME) -config configs/gateway.yaml -log-level debug -log-format console

## clean: Clean build artifacts and caches
clean:
	@echo "==> Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(COVERAGE_DIR)
	@rm -f coverage.out coverage.html
	$(GO) clean -cache -testcache
	@echo "==> Clean completed"

## deps: Download and tidy dependencies
deps:
	@echo "==> Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy
	@echo "==> Dependencies installed"

## tools: Install development tools
tools:
	@echo "==> Installing development tools..."
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	$(GO) install github.com/wadey/gocovmerge@latest
	@echo "==> Development tools installed"

## generate: Generate code (mocks, etc.)
generate:
	@echo "==> Generating code..."
	$(GO) generate ./...
	@echo "==> Code generation completed"

## proto-generate: Generate gRPC code from proto files (requires protoc and plugins)
proto-generate:
	@echo "==> Generating gRPC code from proto files..."
	@if command -v protoc > /dev/null 2>&1; then \
		find . -name "*.proto" -exec dirname {} \; | sort -u | while read dir; do \
			protoc --go_out=. --go_opt=paths=source_relative \
				--go-grpc_out=. --go-grpc_opt=paths=source_relative \
				$$dir/*.proto; \
		done; \
		echo "==> Proto generation completed"; \
	else \
		echo "==> protoc not installed, skipping proto generation"; \
		echo "==> Install with: brew install protobuf (macOS) or apt install protobuf-compiler (Linux)"; \
		echo "==> Also install Go plugins: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"; \
		echo "==>                          go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"; \
	fi

# ==============================================================================
# Performance test targets (Yandex Tank)
# ==============================================================================

# Performance test directory
PERF_DIR := test/performance
PERF_SCRIPTS := $(PERF_DIR)/scripts

## perf-test: Run HTTP throughput performance test (default)
perf-test: perf-test-http

## perf-test-http: Run HTTP GET throughput test
perf-test-http: build
	@echo "==> Running HTTP throughput performance test..."
	@$(PERF_SCRIPTS)/run-test.sh http-throughput

## perf-test-post: Run HTTP POST performance test
perf-test-post: build
	@echo "==> Running HTTP POST performance test..."
	@$(PERF_SCRIPTS)/run-test.sh http-post

## perf-test-mixed: Run mixed workload performance test
perf-test-mixed: build
	@echo "==> Running mixed workload performance test..."
	@$(PERF_SCRIPTS)/run-test.sh mixed-workload

## perf-test-load-balancing: Run load balancing verification test
perf-test-load-balancing: build
	@echo "==> Running load balancing performance test..."
	@$(PERF_SCRIPTS)/run-test.sh load-balancing

## perf-test-rate-limiting: Run rate limiting stress test
perf-test-rate-limiting: build
	@echo "==> Running rate limiting performance test..."
	@$(PERF_SCRIPTS)/run-test.sh rate-limiting

## perf-test-circuit-breaker: Run circuit breaker test
perf-test-circuit-breaker: build
	@echo "==> Running circuit breaker performance test..."
	@$(PERF_SCRIPTS)/run-test.sh circuit-breaker

## perf-test-all: Run all performance tests sequentially
perf-test-all: build
	@echo "==> Running all performance tests..."
	@$(PERF_SCRIPTS)/run-test.sh all

## perf-generate-ammo: Generate ammo files for performance tests
perf-generate-ammo:
	@echo "==> Generating ammo files..."
	@$(PERF_SCRIPTS)/generate-ammo.sh get --count=1000
	@$(PERF_SCRIPTS)/generate-ammo.sh post --count=500
	@$(PERF_SCRIPTS)/generate-ammo.sh mixed --count=2000
	@echo "==> Ammo files generated"

## perf-analyze: Analyze latest performance test results
perf-analyze:
	@echo "==> Analyzing performance test results..."
	@$(PERF_SCRIPTS)/analyze-results.sh --detailed

## perf-start-gateway: Start gateway for performance testing
perf-start-gateway: build
	@echo "==> Starting gateway for performance testing..."
	@$(PERF_SCRIPTS)/start-gateway.sh

## perf-stop-gateway: Stop performance test gateway
perf-stop-gateway:
	@echo "==> Stopping performance test gateway..."
	@$(PERF_SCRIPTS)/start-gateway.sh --stop

## perf-clean: Clean performance test results
perf-clean:
	@echo "==> Cleaning performance test results..."
	@rm -rf $(PERF_DIR)/results/*
	@echo "==> Performance test results cleaned"

# ==============================================================================
# gRPC Performance test targets (ghz)
# ==============================================================================

## perf-test-grpc-unary: Run gRPC unary RPC throughput test
perf-test-grpc-unary: build
	@echo "==> Running gRPC unary performance test..."
	@$(PERF_SCRIPTS)/run-grpc-test.sh unary

## perf-test-grpc-streaming: Run all gRPC streaming tests
perf-test-grpc-streaming: build
	@echo "==> Running gRPC streaming performance tests..."
	@$(PERF_SCRIPTS)/run-grpc-test.sh server-stream
	@$(PERF_SCRIPTS)/run-grpc-test.sh client-stream
	@$(PERF_SCRIPTS)/run-grpc-test.sh bidi-stream

## perf-test-grpc-all: Run all gRPC performance tests
perf-test-grpc-all: build
	@echo "==> Running all gRPC performance tests..."
	@$(PERF_SCRIPTS)/run-grpc-test.sh all

# ==============================================================================
# WebSocket Performance test targets (k6)
# ==============================================================================

## perf-test-websocket: Run all WebSocket performance tests
perf-test-websocket: build
	@echo "==> Running WebSocket performance tests..."
	@$(PERF_SCRIPTS)/run-websocket-test.sh all

## perf-test-websocket-connection: Run WebSocket connection throughput test
perf-test-websocket-connection: build
	@echo "==> Running WebSocket connection test..."
	@$(PERF_SCRIPTS)/run-websocket-test.sh connection

## perf-test-websocket-message: Run WebSocket message throughput test
perf-test-websocket-message: build
	@echo "==> Running WebSocket message test..."
	@$(PERF_SCRIPTS)/run-websocket-test.sh message

## perf-test-websocket-concurrent: Run WebSocket concurrent connections test
perf-test-websocket-concurrent: build
	@echo "==> Running WebSocket concurrent connections test..."
	@$(PERF_SCRIPTS)/run-websocket-test.sh concurrent

# ==============================================================================
# Performance test utilities
# ==============================================================================

## perf-generate-charts: Generate charts from performance test results
perf-generate-charts:
	@echo "==> Generating performance charts..."
	@if command -v python3 > /dev/null 2>&1; then \
		python3 $(PERF_SCRIPTS)/generate-charts.py $(PERF_DIR)/results --all --format=png; \
	else \
		echo "==> Python3 not found, using Docker..."; \
		docker run --rm -v $(PWD)/$(PERF_DIR):/perf python:3.11-slim bash -c \
			"pip install matplotlib numpy --quiet && python /perf/scripts/generate-charts.py /perf/results --all"; \
	fi
	@echo "==> Charts generated"

## perf-setup-infra: Setup Vault and Keycloak for performance testing
perf-setup-infra:
	@echo "==> Setting up infrastructure for performance testing..."
	@$(PERF_SCRIPTS)/setup-vault.sh
	@$(PERF_SCRIPTS)/setup-keycloak.sh
	@echo "==> Infrastructure setup completed"

## perf-setup-vault: Setup Vault for performance testing
perf-setup-vault:
	@echo "==> Setting up Vault..."
	@$(PERF_SCRIPTS)/setup-vault.sh

## perf-setup-keycloak: Setup Keycloak for performance testing
perf-setup-keycloak:
	@echo "==> Setting up Keycloak..."
	@$(PERF_SCRIPTS)/setup-keycloak.sh

## perf-verify-infra: Verify infrastructure setup
perf-verify-infra:
	@echo "==> Verifying infrastructure..."
	@$(PERF_SCRIPTS)/setup-vault.sh --verify
	@$(PERF_SCRIPTS)/setup-keycloak.sh --verify

# ==============================================================================
# CI targets
# ==============================================================================

## ci: Run all CI checks (lint, vet, vuln, test, build)
ci: deps lint vet vuln test-unit test-functional build
	@echo "==> CI checks completed successfully"

## ci-full: Run full CI including integration tests (requires backends)
ci-full: ci test-integration test-e2e
	@echo "==> Full CI checks completed successfully"

# ==============================================================================
# Utility targets
# ==============================================================================

## version: Show version information
version:
	@echo "Version:    $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"

## help: Show available targets
help:
	@echo "avapigw API Gateway - Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  build           Build the gateway binary for current platform"
	@echo "  build-linux     Cross-compile for Linux (amd64 and arm64)"
	@echo "  build-darwin    Cross-compile for macOS (amd64 and arm64)"
	@echo "  build-windows   Cross-compile for Windows (amd64)"
	@echo "  build-all       Build for all platforms"
	@echo ""
	@echo "Test targets:"
	@echo "  test            Run unit tests (alias for test-unit)"
	@echo "  test-unit       Run unit tests with race detection"
	@echo "  test-coverage   Run tests with HTML coverage report"
	@echo "  test-functional Run functional tests"
	@echo "  test-integration Run integration tests (requires HTTP and gRPC backends)"
	@echo "  test-e2e        Run end-to-end tests (requires HTTP and gRPC backends)"
	@echo "  test-all        Run all tests"
	@echo ""
	@echo "gRPC test targets:"
	@echo "  test-grpc-unit        Run gRPC unit tests"
	@echo "  test-grpc-integration Run gRPC integration tests (requires gRPC backends)"
	@echo "  test-grpc-e2e         Run gRPC e2e tests (requires gRPC backends)"
	@echo ""
	@echo "Auth test targets:"
	@echo "  test-auth-unit        Run auth unit tests"
	@echo "  test-auth-integration Run auth integration tests (requires Vault and Keycloak)"
	@echo "  test-auth-e2e         Run auth e2e tests (requires Vault and Keycloak)"
	@echo ""
	@echo "Quality targets:"
	@echo "  lint            Run golangci-lint"
	@echo "  lint-fix        Run golangci-lint with auto-fix"
	@echo "  fmt             Format code"
	@echo "  vet             Run go vet"
	@echo "  vuln            Run govulncheck"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker-build    Build Docker image"
	@echo "  docker-run      Run Docker container"
	@echo "  docker-push     Push to registry"
	@echo "  docker-clean    Remove local Docker images"
	@echo ""
	@echo "Development targets:"
	@echo "  run             Build and run locally"
	@echo "  dev             Run with hot-reload (requires air)"
	@echo "  run-debug       Run with debug logging"
	@echo "  clean           Clean build artifacts"
	@echo "  deps            Download dependencies"
	@echo "  tools           Install development tools"
	@echo "  generate        Generate code"
	@echo "  proto-generate  Generate gRPC code from proto files"
	@echo ""
	@echo "CI targets:"
	@echo "  ci              Run all CI checks (lint, test, build)"
	@echo "  ci-full         Run full CI including integration tests"
	@echo ""
	@echo "Performance test targets (HTTP - Yandex Tank):"
	@echo "  perf-test              Run HTTP throughput test (default)"
	@echo "  perf-test-http         Run HTTP GET throughput test"
	@echo "  perf-test-post         Run HTTP POST performance test"
	@echo "  perf-test-mixed        Run mixed workload test"
	@echo "  perf-test-load-balancing  Run load balancing verification"
	@echo "  perf-test-rate-limiting   Run rate limiting stress test"
	@echo "  perf-test-circuit-breaker Run circuit breaker test"
	@echo "  perf-test-all          Run all HTTP performance tests"
	@echo ""
	@echo "Performance test targets (gRPC - ghz):"
	@echo "  perf-test-grpc-unary      Run gRPC unary RPC test"
	@echo "  perf-test-grpc-streaming  Run gRPC streaming tests"
	@echo "  perf-test-grpc-all        Run all gRPC tests"
	@echo ""
	@echo "Performance test targets (WebSocket - k6):"
	@echo "  perf-test-websocket           Run all WebSocket tests"
	@echo "  perf-test-websocket-connection Run connection throughput test"
	@echo "  perf-test-websocket-message    Run message throughput test"
	@echo "  perf-test-websocket-concurrent Run concurrent connections test"
	@echo ""
	@echo "Performance test utilities:"
	@echo "  perf-generate-ammo     Generate ammo files"
	@echo "  perf-generate-charts   Generate charts from results"
	@echo "  perf-analyze           Analyze test results"
	@echo "  perf-start-gateway     Start gateway for perf testing"
	@echo "  perf-stop-gateway      Stop perf test gateway"
	@echo "  perf-setup-infra       Setup Vault and Keycloak"
	@echo "  perf-verify-infra      Verify infrastructure setup"
	@echo "  perf-clean             Clean test results"
	@echo ""
	@echo "Utility targets:"
	@echo "  version         Show version information"
	@echo "  help            Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  TEST_BACKEND1_URL          HTTP Backend 1 URL (default: http://127.0.0.1:8801)"
	@echo "  TEST_BACKEND2_URL          HTTP Backend 2 URL (default: http://127.0.0.1:8802)"
	@echo "  TEST_GRPC_BACKEND1_URL     gRPC Backend 1 URL (default: 127.0.0.1:8803)"
	@echo "  TEST_GRPC_BACKEND2_URL     gRPC Backend 2 URL (default: 127.0.0.1:8804)"
	@echo "  TEST_VAULT_ADDR            Vault address (default: http://127.0.0.1:8200)"
	@echo "  TEST_VAULT_TOKEN           Vault token (default: myroot)"
	@echo "  TEST_KEYCLOAK_ADDR         Keycloak address (default: http://127.0.0.1:8090)"
	@echo "  TEST_KEYCLOAK_REALM        Keycloak realm (default: gateway-test)"
	@echo "  TEST_KEYCLOAK_CLIENT_ID    Keycloak client ID (default: gateway)"
	@echo "  TEST_KEYCLOAK_CLIENT_SECRET Keycloak client secret (default: gateway-secret)"
	@echo "  DOCKER_REGISTRY            Docker registry (default: ghcr.io)"
	@echo "  DOCKER_IMAGE               Docker image name"
	@echo "  DOCKER_TAG                 Docker image tag (default: VERSION)"
