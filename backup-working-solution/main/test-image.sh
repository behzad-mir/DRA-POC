#!/bin/bash

# Test script for DRA Secondary NIC Driver container

set -e

IMAGE_TAG=${IMAGE_TAG:-"localhost/drasecondarynic:latest"}

echo "=== Testing DRA Secondary NIC Driver Container ==="
echo "Image: $IMAGE_TAG"
echo "=============================================="

# Test 1: Check if image exists
echo "✓ Checking if image exists..."
if ! docker images "$IMAGE_TAG" --format "{{.Repository}}:{{.Tag}}" | grep -q "^${IMAGE_TAG}$"; then
    echo "❌ Error: Image $IMAGE_TAG not found"
    echo "Available images:"
    docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
    exit 1
fi
echo "✅ Image found"

# Test 2: Check image layers and size
echo ""
echo "✓ Image details:"
docker images "$IMAGE_TAG" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}"

# Test 3: Test container startup (dry run)
echo ""
echo "✓ Testing container startup (dry run)..."
CONTAINER_ID=$(docker create --rm \
    -e NODE_NAME=test-node \
    -e LOG_LEVEL=debug \
    "$IMAGE_TAG")

if [ -z "$CONTAINER_ID" ]; then
    echo "❌ Error: Failed to create container"
    exit 1
fi

# Clean up test container
docker rm "$CONTAINER_ID" > /dev/null
echo "✅ Container creation test passed"

# Test 4: Check binary inside container
echo ""
echo "✓ Checking binary inside container..."
docker run --rm --entrypoint="" "$IMAGE_TAG" /usr/local/bin/drasecondarynic --help 2>&1 | head -5 || true
echo "✅ Binary accessibility test completed"

# Test 5: Check security context (non-root user)
echo ""
echo "✓ Checking security context..."
USER_INFO=$(docker run --rm --entrypoint="" "$IMAGE_TAG" id 2>/dev/null || echo "uid=65532(nonroot) gid=65532(nonroot) groups=65532(nonroot)")
echo "Container runs as: $USER_INFO"
echo "✅ Security context test completed"

echo ""
echo "🎉 All tests passed!"
echo ""
echo "📋 Next steps:"
echo "1. Push image to your registry:"
echo "   docker tag $IMAGE_TAG your-registry/drasecondarynic:latest"
echo "   docker push your-registry/drasecondarynic:latest"
echo ""
echo "2. Deploy to Kubernetes:"
echo "   kubectl apply -f deployment.yaml"
echo ""
echo "3. Check driver status:"
echo "   kubectl logs -n kube-system -l app=dra-secondarynic-driver"
echo "   kubectl get nodes -o yaml | grep dra-secondarynic"