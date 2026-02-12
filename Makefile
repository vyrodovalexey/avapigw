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

# Redis Sentinel settings
TEST_REDIS_SENTINEL_ADDRS ?= 127.0.0.1:26379,127.0.0.1:26380,127.0.0.1:26381
TEST_REDIS_SENTINEL_MASTER_NAME ?= mymaster
TEST_REDIS_MASTER_PASSWORD ?= password

# Coverage settings
COVERAGE_DIR := coverage
COVERAGE_UNIT := $(COVERAGE_DIR)/unit.out
COVERAGE_FUNCTIONAL := $(COVERAGE_DIR)/functional.out
COVERAGE_INTEGRATION := $(COVERAGE_DIR)/integration.out
COVERAGE_E2E := $(COVERAGE_DIR)/e2e.out
COVERAGE_MERGED := $(COVERAGE_DIR)/merged.out

# Operator variables
OPERATOR_BINARY_NAME := operator
OPERATOR_CMD_DIR := cmd/operator
OPERATOR_DOCKER_IMAGE ?= $(DOCKER_REGISTRY)/avapigw/avapigw-operator
CONTROLLER_GEN := $(shell which controller-gen 2>/dev/null || echo "$(shell go env GOPATH)/bin/controller-gen")

.PHONY: all build build-linux build-darwin build-windows build-all \
        test test-unit test-coverage test-functional test-integration test-e2e test-all \
        test-grpc-unit test-grpc-integration test-grpc-e2e \
        test-auth-unit test-auth-integration test-auth-e2e \
        test-ingress-unit test-ingress-functional \
        test-sentinel \
        lint lint-fix fmt vet vuln \
        docker-build docker-run docker-push docker-clean \
        run dev clean deps tools generate proto-generate \
        perf-test perf-test-http perf-test-post perf-test-mixed perf-test-all \
        perf-test-grpc-unary perf-test-grpc-streaming perf-test-websocket \
        perf-test-k8s perf-test-k8s-http perf-test-k8s-grpc \
        perf-generate-ammo perf-generate-charts perf-analyze \
        perf-start-gateway perf-stop-gateway perf-setup-infra \
        perf-setup-vault-k8s perf-verify-vault-k8s \
        perf-test-ingress \
        ci help version \
        build-operator operator-generate operator-manifests operator-install-crds \
        operator-docker-build operator-docker-push operator-deploy operator-undeploy \
        test-operator-unit test-operator-functional test-operator-integration \
        helm-template-ingress helm-install-ingress

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
	TEST_REDIS_SENTINEL_ADDRS=$(TEST_REDIS_SENTINEL_ADDRS) \
	TEST_REDIS_SENTINEL_MASTER_NAME=$(TEST_REDIS_SENTINEL_MASTER_NAME) \
	TEST_REDIS_MASTER_PASSWORD=$(TEST_REDIS_MASTER_PASSWORD) \
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
	TEST_REDIS_SENTINEL_ADDRS=$(TEST_REDIS_SENTINEL_ADDRS) \
	TEST_REDIS_SENTINEL_MASTER_NAME=$(TEST_REDIS_SENTINEL_MASTER_NAME) \
	TEST_REDIS_MASTER_PASSWORD=$(TEST_REDIS_MASTER_PASSWORD) \
		$(GO) test -race -coverprofile=$(COVERAGE_E2E) -covermode=atomic -tags=e2e ./test/e2e/...
	@echo "==> E2E tests completed"

## test-all: Run all tests (unit, functional, integration, e2e)
test-all: test-unit test-functional test-integration test-e2e
	@echo "==> All tests completed"

## test-sentinel: Run Redis Sentinel specific tests
test-sentinel:
	@echo "==> Running Redis Sentinel tests..."
	@mkdir -p $(COVERAGE_DIR)
	TEST_REDIS_SENTINEL_ADDRS=$(TEST_REDIS_SENTINEL_ADDRS) \
	TEST_REDIS_SENTINEL_MASTER_NAME=$(TEST_REDIS_SENTINEL_MASTER_NAME) \
	TEST_REDIS_MASTER_PASSWORD=$(TEST_REDIS_MASTER_PASSWORD) \
		$(GO) test -race -coverprofile=$(COVERAGE_DIR)/sentinel.out -covermode=atomic -tags=integration -run ".*[Ss]entinel.*" ./test/integration/...
	@echo "==> Redis Sentinel tests completed"

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

# ==============================================================================
# Ingress controller test targets
# ==============================================================================

## test-ingress-unit: Run ingress controller unit tests
test-ingress-unit:
	@echo "==> Running ingress controller unit tests..."
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -v -race -coverprofile=$(COVERAGE_DIR)/ingress-unit.out ./internal/operator/controller/... -run Ingress
	@echo "==> Ingress controller unit tests completed"

## test-ingress-functional: Run ingress controller functional tests
test-ingress-functional:
	@echo "==> Running ingress controller functional tests..."
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -v -race -tags=functional -coverprofile=$(COVERAGE_DIR)/ingress-functional.out ./test/functional/operator/... -run Ingress
	@echo "==> Ingress controller functional tests completed"

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

## docker-build: Build Docker image for gateway
docker-build:
	@echo "==> Building Docker image..."
	docker build \
		-f Dockerfile.gateway \
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
		export PATH="$$PATH:$$(go env GOPATH)/bin"; \
		protoc --go_out=proto --go_opt=paths=source_relative \
			--go-grpc_out=proto --go-grpc_opt=paths=source_relative \
			-I proto \
			proto/operator/v1alpha1/config.proto; \
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
# K8s Performance test targets
# ==============================================================================

## perf-test-k8s: Run all K8s performance tests (HTTP, gRPC if available)
perf-test-k8s:
	@echo "==> Running all K8s performance tests..."
	@$(PERF_SCRIPTS)/run-k8s-test.sh all

## perf-test-k8s-http: Run HTTP K8s performance test via Yandex Tank
perf-test-k8s-http:
	@echo "==> Running K8s HTTP performance test..."
	@$(PERF_SCRIPTS)/run-k8s-test.sh http

## perf-test-k8s-grpc: Run gRPC K8s performance test via ghz
perf-test-k8s-grpc:
	@echo "==> Running K8s gRPC performance test..."
	@$(PERF_SCRIPTS)/run-k8s-test.sh grpc

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

## perf-setup-vault-k8s: Setup Vault Kubernetes auth for K8s deployment
perf-setup-vault-k8s:
	@echo "==> Setting up Vault Kubernetes auth..."
	@$(PERF_SCRIPTS)/setup-vault-k8s.sh

## perf-verify-vault-k8s: Verify Vault Kubernetes auth setup
perf-verify-vault-k8s:
	@echo "==> Verifying Vault Kubernetes auth..."
	@$(PERF_SCRIPTS)/setup-vault-k8s.sh --verify

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
	@echo "  test-sentinel   Run Redis Sentinel specific tests"
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
	@echo "Ingress controller test targets:"
	@echo "  test-ingress-unit       Run ingress controller unit tests"
	@echo "  test-ingress-functional Run ingress controller functional tests"
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
	@echo "Performance test targets (K8s):"
	@echo "  perf-test-k8s          Run all K8s performance tests"
	@echo "  perf-test-k8s-http     Run HTTP K8s test (Yandex Tank)"
	@echo "  perf-test-k8s-grpc     Run gRPC K8s test (ghz)"
	@echo ""
	@echo "Performance test utilities:"
	@echo "  perf-generate-ammo     Generate ammo files"
	@echo "  perf-generate-charts   Generate charts from results"
	@echo "  perf-analyze           Analyze test results"
	@echo "  perf-start-gateway     Start gateway for perf testing"
	@echo "  perf-stop-gateway      Stop perf test gateway"
	@echo "  perf-setup-infra       Setup Vault and Keycloak"
	@echo "  perf-setup-vault-k8s   Setup Vault K8s auth for K8s deployment"
	@echo "  perf-verify-vault-k8s  Verify Vault K8s auth setup"
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
	@echo "  TEST_REDIS_SENTINEL_ADDRS  Redis Sentinel addresses (default: 127.0.0.1:26379,127.0.0.1:26380,127.0.0.1:26381)"
	@echo "  TEST_REDIS_SENTINEL_MASTER_NAME Redis Sentinel master name (default: mymaster)"
	@echo "  TEST_REDIS_MASTER_PASSWORD Redis master password (default: password)"
	@echo "  DOCKER_REGISTRY            Docker registry (default: ghcr.io)"
	@echo "  DOCKER_IMAGE               Docker image name"
	@echo "  DOCKER_TAG                 Docker image tag (default: VERSION)"
	@echo ""
	@echo "Helm chart targets:"
	@echo "  helm-lint                  Lint Helm chart"
	@echo "  helm-template              Template Helm chart (gateway only)"
	@echo "  helm-template-with-operator Template Helm chart with operator"
	@echo "  helm-template-ingress      Template Helm chart with ingress controller"
	@echo "  helm-template-local        Template Helm chart with local values"
	@echo "  helm-package               Package Helm chart"
	@echo "  helm-install               Install gateway to local K8s"
	@echo "  helm-install-with-operator Install gateway with operator to local K8s"
	@echo "  helm-install-ingress       Install with ingress controller to local K8s"
	@echo "  helm-uninstall             Uninstall from local K8s"
	@echo "  helm-test                  Run Helm tests"
	@echo "  helm-upgrade               Upgrade in local K8s"
	@echo "  helm-upgrade-with-operator Upgrade with operator in local K8s"
	@echo ""
	@echo "Operator targets:"
	@echo "  build-operator             Build the operator binary"
	@echo "  operator-generate          Generate DeepCopy methods"
	@echo "  operator-manifests         Generate CRD and RBAC manifests"
	@echo "  operator-install-crds      Install CRDs into the cluster"
	@echo "  operator-docker-build      Build operator Docker image"
	@echo "  operator-docker-push       Push operator Docker image"
	@echo "  operator-deploy            Deploy operator to cluster"
	@echo "  operator-undeploy          Remove operator from cluster"
	@echo "  test-operator-unit         Run operator unit tests"
	@echo "  test-operator-functional   Run operator functional tests"
	@echo "  test-operator-integration  Run operator integration tests"
	@echo ""
	@echo "Operator performance test targets:"
	@echo "  perf-test-operator              Run all operator performance tests"
	@echo "  perf-test-operator-local        Run local operator performance tests"
	@echo "  perf-test-operator-reconciliation Run reconciliation performance tests"
	@echo "  perf-test-operator-grpc         Run gRPC performance tests"
	@echo "  perf-test-operator-config-push  Run config push performance tests"
	@echo "  perf-test-operator-k8s          Run K8s operator performance tests"
	@echo "  perf-test-operator-benchmarks   Run operator Go benchmarks"
	@echo "  perf-test-ingress               Run ingress controller performance tests"
	@echo "  perf-analyze-operator           Analyze operator performance results"
	@echo "  perf-analyze-operator-charts    Generate charts from results"
	@echo "  perf-analyze-operator-export    Export results to JSON"

# ==============================================================================
# Operator targets
# ==============================================================================

## build-operator: Build the operator binary for current platform
build-operator:
	@echo "==> Building $(OPERATOR_BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(OPERATOR_BINARY_NAME) ./$(OPERATOR_CMD_DIR)
	@echo "==> Binary built: $(BUILD_DIR)/$(OPERATOR_BINARY_NAME)"

## operator-generate: Generate DeepCopy methods for CRD types
operator-generate:
	@echo "==> Generating DeepCopy methods..."
	$(CONTROLLER_GEN) object paths="./api/..."
	@echo "==> DeepCopy methods generated"

## operator-manifests: Generate CRD and RBAC manifests
operator-manifests: operator-generate
	@echo "==> Generating CRD manifests..."
	@mkdir -p config/crd/bases
	$(CONTROLLER_GEN) crd:allowDangerousTypes=true paths="./api/..." output:crd:artifacts:config=config/crd/bases
	@echo "==> Generating RBAC manifests..."
	@mkdir -p config/rbac
	$(CONTROLLER_GEN) rbac:roleName=avapigw-operator-role paths="./internal/operator/controller/..." output:rbac:artifacts:config=config/rbac
	@echo "==> Manifests generated"

## operator-install-crds: Install CRDs into the cluster
operator-install-crds: operator-manifests
	@echo "==> Installing CRDs..."
	kubectl apply -f config/crd/bases/
	@echo "==> CRDs installed"

## operator-docker-build: Build operator Docker image
operator-docker-build:
	@echo "==> Building operator Docker image..."
	docker build -f Dockerfile.operator -t $(OPERATOR_DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "==> Docker image built: $(OPERATOR_DOCKER_IMAGE):$(DOCKER_TAG)"

## operator-docker-push: Push operator Docker image
operator-docker-push: operator-docker-build
	@echo "==> Pushing operator Docker image..."
	docker push $(OPERATOR_DOCKER_IMAGE):$(DOCKER_TAG)
	@echo "==> Docker image pushed"

## operator-deploy: Deploy operator to cluster
operator-deploy: operator-manifests
	@echo "==> Deploying operator..."
	kubectl apply -k config/default/
	@echo "==> Operator deployed"

## operator-undeploy: Remove operator from cluster
operator-undeploy:
	@echo "==> Removing operator..."
	kubectl delete -k config/default/ --ignore-not-found
	@echo "==> Operator removed"

## test-operator-unit: Run operator unit tests
test-operator-unit:
	@echo "==> Running operator unit tests..."
	$(GO) test -v -race -coverprofile=$(COVERAGE_DIR)/operator-unit.out ./internal/operator/...
	@echo "==> Operator unit tests completed"

## test-operator-functional: Run operator functional tests
test-operator-functional:
	@echo "==> Running operator functional tests..."
	$(GO) test -v -race -tags=functional -coverprofile=$(COVERAGE_DIR)/operator-functional.out ./internal/operator/...
	@echo "==> Operator functional tests completed"

## test-operator-integration: Run operator integration tests
test-operator-integration:
	@echo "==> Running operator integration tests..."
	$(GO) test -v -race -tags=integration -coverprofile=$(COVERAGE_DIR)/operator-integration.out ./internal/operator/...
	@echo "==> Operator integration tests completed"

# ==============================================================================
# Helm chart targets (unified chart with optional operator)
# ==============================================================================

HELM := helm
CHART_DIR := helm/avapigw
CHART_NAME := avapigw
TEST_NAMESPACE := avapigw-test

## helm-lint: Lint Helm chart
helm-lint:
	@echo "==> Linting Helm chart..."
	$(HELM) lint $(CHART_DIR)
	@echo "==> Helm chart linting completed"

## helm-template: Template Helm chart (gateway only)
helm-template:
	@echo "==> Templating Helm chart..."
	$(HELM) template $(CHART_NAME) $(CHART_DIR) --namespace $(TEST_NAMESPACE)
	@echo "==> Helm chart templating completed"

## helm-template-with-operator: Template Helm chart with operator enabled
helm-template-with-operator:
	@echo "==> Templating Helm chart with operator..."
	$(HELM) template $(CHART_NAME) $(CHART_DIR) \
		--set operator.enabled=true \
		--namespace $(TEST_NAMESPACE)
	@echo "==> Helm chart templating completed"

## helm-template-local: Template Helm chart with local values
helm-template-local:
	@echo "==> Templating Helm chart with local values..."
	$(HELM) template $(CHART_NAME) $(CHART_DIR) \
		-f $(CHART_DIR)/values-local.yaml \
		--namespace $(TEST_NAMESPACE)
	@echo "==> Helm chart templating completed"

## helm-package: Package Helm chart
helm-package:
	@echo "==> Packaging Helm chart..."
	$(HELM) package $(CHART_DIR) -d $(BUILD_DIR)
	@echo "==> Helm chart packaged to $(BUILD_DIR)"

## helm-install: Install gateway to local K8s (without operator)
helm-install:
	@echo "==> Installing Helm chart..."
	$(HELM) upgrade --install $(CHART_NAME) $(CHART_DIR) \
		-f $(CHART_DIR)/values-local.yaml \
		--namespace $(TEST_NAMESPACE) \
		--create-namespace \
		--wait --timeout 120s
	@echo "==> Helm chart installed"

## helm-install-with-operator: Install gateway with operator to local K8s
helm-install-with-operator: operator-install-crds
	@echo "==> Installing Helm chart with operator..."
	$(HELM) upgrade --install $(CHART_NAME) $(CHART_DIR) \
		-f $(CHART_DIR)/values-local.yaml \
		--set operator.enabled=true \
		--namespace $(TEST_NAMESPACE) \
		--create-namespace \
		--wait --timeout 120s
	@echo "==> Helm chart with operator installed"

## helm-uninstall: Uninstall from local K8s
helm-uninstall:
	@echo "==> Uninstalling Helm chart..."
	$(HELM) uninstall $(CHART_NAME) --namespace $(TEST_NAMESPACE) --ignore-not-found
	@echo "==> Helm chart uninstalled"

## helm-test: Run Helm tests
helm-test:
	@echo "==> Running Helm tests..."
	$(HELM) test $(CHART_NAME) --namespace $(TEST_NAMESPACE)
	@echo "==> Helm tests completed"

## helm-upgrade: Upgrade in local K8s
helm-upgrade:
	@echo "==> Upgrading Helm chart..."
	$(HELM) upgrade $(CHART_NAME) $(CHART_DIR) \
		-f $(CHART_DIR)/values-local.yaml \
		--namespace $(TEST_NAMESPACE) \
		--wait --timeout 120s
	@echo "==> Helm chart upgraded"

## helm-upgrade-with-operator: Upgrade with operator in local K8s
helm-upgrade-with-operator:
	@echo "==> Upgrading Helm chart with operator..."
	$(HELM) upgrade $(CHART_NAME) $(CHART_DIR) \
		-f $(CHART_DIR)/values-local.yaml \
		--set operator.enabled=true \
		--namespace $(TEST_NAMESPACE) \
		--wait --timeout 120s
	@echo "==> Helm chart with operator upgraded"

## helm-template-ingress: Template Helm chart with ingress controller enabled
helm-template-ingress:
	@echo "==> Templating Helm chart with ingress controller..."
	$(HELM) template $(CHART_NAME) $(CHART_DIR) \
		--set operator.enabled=true \
		--set operator.ingressController.enabled=true \
		--namespace $(TEST_NAMESPACE)
	@echo "==> Helm chart templating with ingress controller completed"

## helm-install-ingress: Install with ingress controller to local K8s
helm-install-ingress:
	@echo "==> Installing Helm chart with ingress controller..."
	$(HELM) upgrade --install $(CHART_NAME) $(CHART_DIR) \
		-f $(CHART_DIR)/values-local.yaml \
		--set operator.enabled=true \
		--set operator.ingressController.enabled=true \
		--namespace $(TEST_NAMESPACE) \
		--create-namespace \
		--wait --timeout 120s
	@echo "==> Helm chart with ingress controller installed"

# Legacy aliases for backward compatibility
helm-lint-operator: helm-lint
helm-template-operator: helm-template-with-operator
helm-template-operator-local: helm-template-local
helm-package-operator: helm-package
helm-install-operator: helm-install-with-operator
helm-uninstall-operator: helm-uninstall
helm-test-operator: helm-test
helm-upgrade-operator: helm-upgrade-with-operator

# ==============================================================================
# Operator Performance Test targets
# ==============================================================================

## perf-test-operator: Run all operator performance tests
perf-test-operator: build-operator
	@echo "==> Running all operator performance tests..."
	@$(PERF_SCRIPTS)/run-operator-test.sh all

## perf-test-operator-local: Run local operator performance tests
perf-test-operator-local: build-operator
	@echo "==> Running local operator performance tests..."
	@$(PERF_SCRIPTS)/run-operator-test.sh local

## perf-test-operator-reconciliation: Run operator reconciliation performance tests
perf-test-operator-reconciliation: build-operator
	@echo "==> Running operator reconciliation performance tests..."
	@$(PERF_SCRIPTS)/run-operator-test.sh reconciliation

## perf-test-operator-grpc: Run operator gRPC performance tests
perf-test-operator-grpc: build-operator
	@echo "==> Running operator gRPC performance tests..."
	@$(PERF_SCRIPTS)/run-operator-test.sh grpc

## perf-test-operator-config-push: Run operator config push performance tests
perf-test-operator-config-push: build-operator
	@echo "==> Running operator config push performance tests..."
	@$(PERF_SCRIPTS)/run-operator-test.sh config-push

## perf-test-operator-k8s: Run Kubernetes-based operator performance tests
perf-test-operator-k8s: build-operator
	@echo "==> Running K8s operator performance tests..."
	@$(PERF_SCRIPTS)/run-operator-test.sh k8s

## perf-test-operator-benchmarks: Run operator Go benchmarks
perf-test-operator-benchmarks: build-operator
	@echo "==> Running operator benchmarks..."
	@$(PERF_SCRIPTS)/run-operator-test.sh benchmarks

## perf-analyze-operator: Analyze operator performance test results
perf-analyze-operator:
	@echo "==> Analyzing operator performance test results..."
	@$(PERF_SCRIPTS)/analyze-operator-results.sh --detailed

## perf-analyze-operator-charts: Generate charts from operator performance results
perf-analyze-operator-charts:
	@echo "==> Generating operator performance charts..."
	@$(PERF_SCRIPTS)/analyze-operator-results.sh --charts

## perf-test-ingress: Run ingress controller performance tests
perf-test-ingress: build-operator
	@echo "==> Running ingress controller performance tests..."
	@$(PERF_SCRIPTS)/run-operator-test.sh ingress

## perf-analyze-operator-export: Export operator performance results to JSON
perf-analyze-operator-export:
	@echo "==> Exporting operator performance results..."
	@$(PERF_SCRIPTS)/analyze-operator-results.sh --export=json
