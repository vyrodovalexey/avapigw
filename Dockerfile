# ==============================================================================
# Build stage
# ==============================================================================
FROM golang:1.25-alpine AS builder

# Target architecture for cross-compilation (set by Docker buildx)
ARG TARGETARCH
ARG TARGETOS=linux

# Install build dependencies (sorted alphanumerically)
RUN apk add --no-cache \
    ca-certificates \
    git \
    tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments for version information
ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT=unknown

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH:-amd64} go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT}" \
    -trimpath \
    -o /build/bin/gateway \
    ./cmd/gateway

# ==============================================================================
# Runtime stage
# ==============================================================================
FROM alpine:3.23

# Build arguments for dynamic OCI labels
ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT=unknown

# OCI Labels (static and dynamic)
LABEL org.opencontainers.image.title="avapigw" \
      org.opencontainers.image.description="High-performance API Gateway built with Go and gin-gonic" \
      org.opencontainers.image.vendor="avapigw" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/vyrodovalexey/avapigw" \
      org.opencontainers.image.documentation="https://github.com/vyrodovalexey/avapigw/blob/main/README.md" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_TIME}"

# Install runtime dependencies (sorted alphanumerically)
RUN apk add --no-cache \
    ca-certificates \
    curl \
    tzdata

# Create non-root user and group
RUN addgroup -g 1000 -S gateway && \
    adduser -u 1000 -S -G gateway -h /app -s /sbin/nologin gateway

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=gateway:gateway /build/bin/gateway /app/gateway

# Copy default configuration
COPY --from=builder --chown=gateway:gateway /build/configs /app/configs

# Create directories for runtime data
RUN mkdir -p /app/data /app/logs && \
    chown -R gateway:gateway /app

# Switch to non-root user
USER gateway

# Expose ports
# 8080 - HTTP traffic (REST API)
# 9000 - gRPC traffic
# 9090 - Metrics and health endpoints
EXPOSE 8080 9000 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# Set environment variables
ENV GATEWAY_CONFIG_PATH=/app/configs/gateway.yaml \
    GATEWAY_LOG_LEVEL=info \
    GATEWAY_LOG_FORMAT=json

# Set entrypoint
ENTRYPOINT ["/app/gateway"]

# Default command arguments
CMD ["-config", "/app/configs/gateway.yaml"]
