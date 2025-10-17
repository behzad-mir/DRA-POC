#!/bin/bash
set -e

echo "Building NRI gRPC Plugin container image..."

# First build the NRI gRPC client binary
echo "Building NRI gRPC client binary..."
go mod tidy
go build -o nri-plugin-grpc-client nri-plugin-grpc-client.go
echo "✓ NRI gRPC client binary built"

# Build the Docker image for NRI gRPC client
echo "Building Docker image: acnpublic.azurecr.io/nri-grpc-client:latest"
docker build -f Dockerfile.nri-grpc-client -t acnpublic.azurecr.io/nri-grpc-client:latest .

echo "Pushing image to acnpublic.azurecr.io..."
docker push acnpublic.azurecr.io/nri-grpc-client:latest

echo "NRI gRPC plugin build completed successfully!"
echo ""
echo "Architecture: NRI Plugin (gRPC Client) -> DRA Driver (gRPC Server)"
echo "Communication: gRPC calls on port 50051"
echo ""
echo "To deploy the NRI gRPC plugin:"
echo "  kubectl apply -f nri-grpc-plugin-ds.yaml"
echo ""
echo "Note: Make sure the DRA driver with gRPC server is deployed first!"
echo "  cd main && ./build.sh"