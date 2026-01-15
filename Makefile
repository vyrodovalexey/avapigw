# ============================================================================
# AVAPIGW - API Gateway Operator Makefile
# ============================================================================

# Project Configuration
PROJECT_NAME := avapigw
MODULE := github.com/vyrodovalexey/avapigw

# Version Information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Docker Configuration
REGISTRY ?= docker.io
DOCKER_USERNAME ?= vyrodovalexey
IMG_GATEWAY ?= $(REGISTRY)/$(DOCKER_USERNAME)/avapigw-gateway:$(VERSION)
IMG_OPERATOR ?= $(REGISTRY)/$(DOCKER_USERNAME)/avapigw-operator:$(VERSION)
IMG_GATEWAY_LATEST ?= $(REGISTRY)/$(DOCKER_USERNAME)/avapigw-gateway:latest
IMG_OPERATOR_LATEST ?= $(REGISTRY)/$(DOCKER_USERNAME)/avapigw-operator:latest

# Helm Configuration
HELM_RELEASE_NAME ?= avapigw
HELM_NAMESPACE ?= avapigw-system
HELM_CHART_PATH := deployment/helm/avapigw

# Kubernetes Configuration
KUBECONFIG ?= $(HOME)/.kube/config
ENVTEST_K8S_VERSION ?= 1.29.x

# CRD Options
CRD_OPTIONS ?= "crd:generateEmbeddedObjectMeta=true"

# Go Configuration
GO_VERSION := 1.24
GOBIN := $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif

# Build Configuration
LDFLAGS := -w -s \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.GitCommit=$(GIT_COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

# Local bin directory
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

# Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
KUSTOMIZE ?= $(LOCALBIN)/kustomize
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GINKGO ?= $(LOCALBIN)/ginkgo
HELM ?= helm

# Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.17.0
KUSTOMIZE_VERSION ?= v5.2.1
GOLANGCI_LINT_VERSION ?= v1.62.2
GINKGO_VERSION ?= v2.15.0

# Shell Configuration
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# Default target
.DEFAULT_GOAL := help

# ============================================================================
# General Targets
# ============================================================================

.PHONY: all
all: generate fmt vet lint test build ## Run all checks and build

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: version
version: ## Display version information
	@echo "Version:    $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Go Version: $(GO_VERSION)"

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate ClusterRole and CustomResourceDefinition objects
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code
	go vet ./...

.PHONY: tidy
tidy: ## Run go mod tidy
	go mod tidy

.PHONY: verify
verify: generate manifests fmt ## Verify code generation is up to date
	git diff --exit-code

##@ Testing

.PHONY: test
test: manifests generate fmt vet ## Run unit tests
	go test ./... -coverprofile $(LOCALBIN)/cover.out -covermode=atomic

.PHONY: test-unit
test-unit: ## Run unit tests only (no generation)
	go test ./... -short -coverprofile $(LOCALBIN)/cover-unit.out -covermode=atomic

.PHONY: test-functional
test-functional: ## Run functional tests
	go test ./test/functional/... -tags=functional -v -coverprofile $(LOCALBIN)/cover-functional.out

.PHONY: test-integration
test-integration: manifests generate fmt vet envtest ## Run integration tests with envtest
	KUBEBUILDER_ASSETS="$$($(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" \
		go test ./test/integration/... -tags=integration -v -coverprofile $(LOCALBIN)/cover-integration.out

.PHONY: test-e2e
test-e2e: ginkgo ## Run E2E tests (requires running cluster)
	$(GINKGO) -v -tags=e2e ./test/e2e/...

.PHONY: test-all
test-all: test test-functional test-integration ## Run all tests (unit + functional + integration)

.PHONY: test-coverage
test-coverage: test ## Generate test coverage report
	go tool cover -html=$(LOCALBIN)/cover.out -o $(LOCALBIN)/coverage.html
	@echo "Coverage report generated at $(LOCALBIN)/coverage.html"

##@ Authentication Testing

.PHONY: test-e2e-auth
test-e2e-auth: ginkgo ## Run authentication E2E tests
	$(GINKGO) -v -tags=e2e ./test/e2e/... -focus="Authentication"

.PHONY: test-e2e-basic-auth
test-e2e-basic-auth: ginkgo ## Run Basic Auth E2E tests
	$(GINKGO) -v -tags=e2e ./test/e2e/... -focus="Basic Authentication"

.PHONY: test-e2e-oauth
test-e2e-oauth: ginkgo ## Run OAuth2 E2E tests
	$(GINKGO) -v -tags=e2e ./test/e2e/... -focus="OAuth2"

.PHONY: test-e2e-vault
test-e2e-vault: ginkgo ## Run Vault-related E2E tests
	$(GINKGO) -v -tags=e2e ./test/e2e/... -focus="Vault"

.PHONY: test-e2e-setup
test-e2e-setup: ginkgo ## Run test environment setup (Vault + Keycloak)
	$(GINKGO) -v -tags=e2e ./test/e2e/... -focus="Setup"

##@ Test Environment

.PHONY: test-env-check
test-env-check: ## Check test environment configuration
	@echo "Checking test environment..."
	@echo "TEST_VAULT_ADDR: $${TEST_VAULT_ADDR:-http://localhost:8200}"
	@echo "TEST_KEYCLOAK_URL: $${TEST_KEYCLOAK_URL:-http://localhost:8080}"
	@echo "TEST_K8S_API_SERVER: $${TEST_K8S_API_SERVER:-https://127.0.0.1:6443}"
	@echo "TEST_NAMESPACE: $${TEST_NAMESPACE:-avapigw-e2e-test}"
	@echo ""
	@echo "Checking connectivity..."
	@curl -s -o /dev/null -w "Vault: %{http_code}\n" $${TEST_VAULT_ADDR:-http://localhost:8200}/v1/sys/health || echo "Vault: unreachable"
	@curl -s -o /dev/null -w "Keycloak: %{http_code}\n" $${TEST_KEYCLOAK_URL:-http://localhost:8080}/health/ready || echo "Keycloak: unreachable"
	@kubectl cluster-info --request-timeout=5s > /dev/null 2>&1 && echo "Kubernetes: connected" || echo "Kubernetes: unreachable"

.PHONY: test-env-setup
test-env-setup: test-e2e-setup ## Setup test environment (alias for test-e2e-setup)

.PHONY: test-env-export
test-env-export: ## Export test environment variables template
	@echo "# Test Environment Configuration"
	@echo "# Copy these to your shell or .env file"
	@echo ""
	@echo "export TEST_VAULT_ADDR=http://192.168.0.61:8200"
	@echo "export TEST_VAULT_TOKEN=myroot"
	@echo "export TEST_VAULT_ROLE=avapigw-test"
	@echo "export TEST_K8S_API_SERVER=https://127.0.0.1:6443"
	@echo "export TEST_KEYCLOAK_URL=http://192.168.0.61:8080"
	@echo "export TEST_KEYCLOAK_ADMIN=admin"
	@echo "export TEST_KEYCLOAK_PASSWORD=admin"
	@echo "export TEST_KEYCLOAK_REALM=avapigw-test"
	@echo "export TEST_KEYCLOAK_CLIENT_ID=avapigw-test-client"
	@echo "export TEST_NAMESPACE=avapigw-e2e-test"

##@ Build

.PHONY: build
build: generate fmt vet build-gateway build-operator ## Build all binaries

.PHONY: build-gateway
build-gateway: ## Build gateway binary
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(LOCALBIN)/gateway cmd/gateway/main.go

.PHONY: build-operator
build-operator: ## Build gateway-operator binary
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(LOCALBIN)/gateway-operator cmd/gateway-operator/main.go

.PHONY: run-gateway
run-gateway: manifests generate fmt vet ## Run gateway from your host
	go run ./cmd/gateway/main.go

.PHONY: run-operator
run-operator: manifests generate fmt vet ## Run operator from your host
	go run ./cmd/gateway-operator/main.go

##@ Docker

.PHONY: docker-build
docker-build: docker-build-gateway docker-build-operator ## Build all Docker images

.PHONY: docker-build-gateway
docker-build-gateway: ## Build gateway Docker image
	docker build -t $(IMG_GATEWAY) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-f deployment/docker/gateway/Dockerfile .

.PHONY: docker-build-operator
docker-build-operator: ## Build operator Docker image
	docker build -t $(IMG_OPERATOR) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-f deployment/docker/gateway-operator/Dockerfile .

.PHONY: docker-push
docker-push: docker-push-gateway docker-push-operator ## Push all Docker images

.PHONY: docker-push-gateway
docker-push-gateway: ## Push gateway Docker image
	docker push $(IMG_GATEWAY)

.PHONY: docker-push-operator
docker-push-operator: ## Push operator Docker image
	docker push $(IMG_OPERATOR)

.PHONY: docker-tag-latest
docker-tag-latest: ## Tag images as latest
	docker tag $(IMG_GATEWAY) $(IMG_GATEWAY_LATEST)
	docker tag $(IMG_OPERATOR) $(IMG_OPERATOR_LATEST)

.PHONY: docker-push-latest
docker-push-latest: docker-tag-latest ## Push latest tags
	docker push $(IMG_GATEWAY_LATEST)
	docker push $(IMG_OPERATOR_LATEST)

.PHONY: docker-buildx
docker-buildx: ## Build multi-platform Docker images
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t $(IMG_GATEWAY) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-f deployment/docker/gateway/Dockerfile \
		--push .
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t $(IMG_OPERATOR) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-f deployment/docker/gateway-operator/Dockerfile \
		--push .

##@ Linting

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run --timeout 5m

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter with auto-fix
	$(GOLANGCI_LINT) run --fix --timeout 5m

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint configuration
	$(GOLANGCI_LINT) linters

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster
	kubectl apply -f config/crd/bases

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster
	kubectl delete --ignore-not-found=$(ignore-not-found) -f config/crd/bases

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG_OPERATOR)
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

##@ Helm

.PHONY: helm-deps
helm-deps: ## Update Helm chart dependencies
	$(HELM) dependency update $(HELM_CHART_PATH)

.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	$(HELM) lint $(HELM_CHART_PATH)

.PHONY: helm-template
helm-template: ## Generate Helm templates for review
	$(HELM) template $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) \
		--namespace $(HELM_NAMESPACE) \
		--set operator.image.tag=$(VERSION) \
		--set gateway.image.tag=$(VERSION)

.PHONY: helm-package
helm-package: helm-lint ## Package Helm chart
	$(HELM) package $(HELM_CHART_PATH) --destination $(LOCALBIN)

.PHONY: helm-install
helm-install: ## Install Helm chart
	$(HELM) upgrade --install $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) \
		--namespace $(HELM_NAMESPACE) \
		--create-namespace \
		--set operator.image.tag=$(VERSION) \
		--set gateway.image.tag=$(VERSION) \
		--wait --timeout 5m

.PHONY: helm-install-dry-run
helm-install-dry-run: ## Dry-run Helm chart installation
	$(HELM) upgrade --install $(HELM_RELEASE_NAME) $(HELM_CHART_PATH) \
		--namespace $(HELM_NAMESPACE) \
		--create-namespace \
		--set operator.image.tag=$(VERSION) \
		--set gateway.image.tag=$(VERSION) \
		--dry-run

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall Helm chart
	$(HELM) uninstall $(HELM_RELEASE_NAME) --namespace $(HELM_NAMESPACE) || true
	kubectl delete namespace $(HELM_NAMESPACE) --ignore-not-found=true

.PHONY: helm-status
helm-status: ## Show Helm release status
	$(HELM) status $(HELM_RELEASE_NAME) --namespace $(HELM_NAMESPACE)

##@ Build Dependencies

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary
$(CONTROLLER_GEN): $(LOCALBIN)
	@test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
		GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary
$(KUSTOMIZE): $(LOCALBIN)
	@test -s $(LOCALBIN)/kustomize || GOBIN=$(LOCALBIN) go install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary
$(ENVTEST): $(LOCALBIN)
	@test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary
$(GOLANGCI_LINT): $(LOCALBIN)
	@test -s $(LOCALBIN)/golangci-lint && $(LOCALBIN)/golangci-lint --version | grep -q $(GOLANGCI_LINT_VERSION) || \
		GOBIN=$(LOCALBIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: ginkgo
ginkgo: $(GINKGO) ## Download ginkgo locally if necessary
$(GINKGO): $(LOCALBIN)
	@test -s $(LOCALBIN)/ginkgo || GOBIN=$(LOCALBIN) go install github.com/onsi/ginkgo/v2/ginkgo@$(GINKGO_VERSION)

##@ Utilities

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf $(LOCALBIN)
	rm -f cover*.out coverage.html

.PHONY: build-installer
build-installer: manifests kustomize ## Generate consolidated installer YAML
	$(KUSTOMIZE) build config/default > $(LOCALBIN)/installer.yaml

.PHONY: kind-create
kind-create: ## Create a kind cluster for testing
	kind create cluster --name $(PROJECT_NAME)-test --wait 5m

.PHONY: kind-delete
kind-delete: ## Delete the kind test cluster
	kind delete cluster --name $(PROJECT_NAME)-test

.PHONY: kind-load
kind-load: docker-build ## Load Docker images into kind cluster
	kind load docker-image $(IMG_GATEWAY) --name $(PROJECT_NAME)-test
	kind load docker-image $(IMG_OPERATOR) --name $(PROJECT_NAME)-test

##@ Security

.PHONY: security-scan
security-scan: ## Run security scanning with gosec
	@which gosec > /dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec -exclude-generated ./...

.PHONY: trivy-scan
trivy-scan: docker-build ## Scan Docker images with Trivy
	trivy image --severity HIGH,CRITICAL $(IMG_GATEWAY)
	trivy image --severity HIGH,CRITICAL $(IMG_OPERATOR)

##@ Release

.PHONY: release-dry-run
release-dry-run: ## Dry-run release process
	@echo "Would release version: $(VERSION)"
	@echo "Gateway image: $(IMG_GATEWAY)"
	@echo "Operator image: $(IMG_OPERATOR)"

.PHONY: release
release: test docker-build docker-push helm-package ## Full release process
	@echo "Released version: $(VERSION)"
