# Build the gateway binary
FROM golang:1.24-alpine3.23 AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG GIT_COMMIT=unknown

WORKDIR /workspace

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Cache deps before building and copying source so that we don't need to re-download
# as much and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/gateway/ cmd/gateway/
COPY api/ api/
COPY internal/ internal/

# Build with optimizations
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT}" \
    -a -o gateway cmd/gateway/main.go

# Use alpine as minimal base image
FROM alpine:3.23

# Install runtime dependencies
RUN apk update \
    && apk upgrade --ignore alpine-baselayout \
    && apk add --no-cache ca-certificates tzdata curl \
    && addgroup -g 1001 -S appgroup \
    && adduser -u 1001 -D -S -G appgroup --home /app appuser \
    && mkdir -p /app/config \
    && chown -R appuser:appgroup /app

# Copy timezone data from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /workspace/gateway .

# Set ownership
RUN chown appuser:appgroup /app/gateway

# Use non-root user
USER 1001

# Expose ports
# HTTP port
EXPOSE 8080
# Health port
EXPOSE 8081
# Metrics port
EXPOSE 9090
# gRPC port
EXPOSE 9091
# TCP port
EXPOSE 9092
# TLS passthrough port
EXPOSE 9443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8081/healthz || exit 1

# Set entrypoint
ENTRYPOINT ["/app/gateway"]
