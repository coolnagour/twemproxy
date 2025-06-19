#!/bin/bash

# Build script for twemproxy with cloud zone detection
# Supports multi-architecture builds

set -e

# Configuration
IMAGE_NAME="${IMAGE_NAME:-twemproxy-enhanced}"
TAG="${TAG:-latest}"
PLATFORMS="${PLATFORMS:-linux/amd64}"
PUSH="${PUSH:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[BUILD]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if Docker is available
command -v docker >/dev/null 2>&1 || error "Docker is not installed or not in PATH"

# Check if buildx is available for multi-platform builds
if [[ "$PLATFORMS" == *","* ]] || [[ "$PLATFORMS" != "linux/$(uname -m)" ]]; then
    if ! docker buildx version >/dev/null 2>&1; then
        warn "Docker buildx not available, falling back to regular build"
        PLATFORMS="linux/$(uname -m)"
    fi
fi

# Create builder if needed for multi-platform
if [[ "$PLATFORMS" == *","* ]] || [[ "$PLATFORMS" != "linux/$(uname -m)" ]]; then
    log "Setting up buildx for multi-platform build"
    docker buildx create --name twemproxy-builder --use 2>/dev/null || docker buildx use twemproxy-builder
    docker buildx inspect --bootstrap
fi

# Build the image
log "Building twemproxy image..."
log "Image: $IMAGE_NAME:$TAG"
log "Platforms: $PLATFORMS"

BUILD_ARGS=""
if [[ "$PUSH" == "true" ]]; then
    BUILD_ARGS="$BUILD_ARGS --push"
else
    BUILD_ARGS="$BUILD_ARGS --load"
fi

if [[ "$PLATFORMS" == *","* ]] || [[ "$PLATFORMS" != "linux/$(uname -m)" ]]; then
    # Multi-platform build with buildx
    docker buildx build \
        --platform "$PLATFORMS" \
        --tag "$IMAGE_NAME:$TAG" \
        $BUILD_ARGS \
        .
else
    # Regular build
    docker build \
        --tag "$IMAGE_NAME:$TAG" \
        .
fi

# Show image info
if [[ "$PUSH" != "true" ]]; then
    success "Build completed successfully!"
    
    # Show image size
    IMAGE_SIZE=$(docker images "$IMAGE_NAME:$TAG" --format "table {{.Size}}" | tail -n1)
    log "Final image size: $IMAGE_SIZE"
    
    # Show image details
    log "Image details:"
    docker images "$IMAGE_NAME:$TAG" --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedAt}}\t{{.Size}}"
    
    # Test the image
    log "Testing the built image..."
    if docker run --rm "$IMAGE_NAME:$TAG" /usr/local/sbin/nutcracker --version; then
        success "Image test passed!"
    else
        error "Image test failed!"
    fi
    
    echo ""
    log "To run the container:"
    echo "  docker run -d -p 6378:6378 -p 22222:22222 $IMAGE_NAME:$TAG"
    echo ""
    log "To run with custom config:"
    echo "  docker run -d -p 6378:6378 -v ./my-config.yml:/etc/twemproxy/nutcracker.yml $IMAGE_NAME:$TAG"
    echo ""
    log "To run with Docker Compose:"
    echo "  docker-compose up -d"
fi