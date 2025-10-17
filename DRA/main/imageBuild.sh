
#!/bin/bash

set -e  # Exit on any error

echo "Building Enhanced DRA Driver with gRPC Server container image..."

# Tidy up dependencies
go mod tidy

# Build the enhanced DRA driver binary locally first
echo "Building enhanced DRA driver binary with gRPC server..."
go build -o dra-driver .
echo "✓ DRA driver binary built successfully"

# The multi-stage Dockerfile will handle the Go build inside the container
echo "Using multi-stage Dockerfile build for container image..."

# Build the Docker image with new gRPC functionality
IMAGE_TAG=${IMAGE_TAG:-localhost/dra-driver-grpc:latest}
echo "Building Docker image: $IMAGE_TAG"
docker build -t "$IMAGE_TAG" .

echo "Docker image built successfully: $IMAGE_TAG"

# Push to registry with new gRPC-enabled image
echo "Pushing enhanced DRA driver image to acnpublic.azurecr.io..."
docker tag "$IMAGE_TAG" acnpublic.azurecr.io/dra-driver-grpc:latest
docker push acnpublic.azurecr.io/dra-driver-grpc:latest

echo "Enhanced DRA Driver build completed successfully!"
echo ""
echo "Features:"
echo "  ✓ Standard DRA driver functionality"
echo "  ✓ gRPC server on port 50051 for NRI communication"
echo "  ✓ ConfigureNetwork gRPC service method"
echo ""
echo "To deploy the enhanced DRA driver:"
echo "  kubectl apply -f draDS.yaml"
echo ""
echo "Architecture: NRI Plugin (gRPC Client) -> DRA Driver (gRPC Server)"
echo "Communication: gRPC calls on port 50051"
