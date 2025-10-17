# Multi-stage build for DRA Secondary NIC Driver
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /src

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code including protobuf files
COPY *.go ./
COPY draProtos/ ./draProtos/

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o drasecondarynic .

# Final stage - use alpine for network utilities
FROM alpine:3.18

# Install required network utilities
RUN apk add --no-cache iproute2 ca-certificates

# Add metadata
LABEL maintainer="DRA Secondary NIC Team"
LABEL description="Dynamic Resource Allocation driver for secondary network interfaces with gRPC server"
LABEL version="2.0.0"

# Create non-root user (will be overridden by K8s securityContext for DRA)
RUN adduser -D -s /bin/sh -u 65532 nonroot

# Copy the binary from builder stage
COPY --from=builder /src/drasecondarynic /usr/local/bin/drasecondarynic

# Expose gRPC port for NRI plugin communication
EXPOSE 50051

# Expose the default plugin socket directory as a volume
VOLUME ["/var/lib/kubelet/plugins", "/var/lib/kubelet/plugins_registry", "/var/run/cdi"]

# Note: DRA drivers typically need root permissions to manage network interfaces
# and create plugin directories. The securityContext in Kubernetes deployment
# should specify runAsUser: 0 for proper operation.

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/drasecondarynic"]

# Health check (if your DRA driver supports health endpoints)
# HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
#   CMD ["/usr/local/bin/drasecondarynic", "--health-check"] || exit 1
