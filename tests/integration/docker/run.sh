#!/bin/bash
# Build the test image and run integration tests.
# Usage: ./tests/integration/docker/run.sh [pytest args...]
set -e

cd "$(git rev-parse --show-toplevel)"

IMAGE="snaffler-ng-integration"

echo "Building test image (deb build + install + samba + playwright)..."
docker build -t "$IMAGE" -f tests/integration/docker/Dockerfile .

echo "Running integration tests..."
docker run --rm --privileged "$IMAGE" python3 -m pytest -v --tb=short "$@"
