#!/bin/bash
# Build the deb test image and run integration tests.
# Usage: ./tests/deb/run.sh [pytest args...]
set -e

cd "$(git rev-parse --show-toplevel)"

IMAGE="snaffler-ng-deb-test"

echo "Building test image (deb build + install + playwright)..."
docker build -t "$IMAGE" -f tests/deb/Dockerfile .

echo "Running integration tests..."
docker run --rm "$IMAGE" python3 -m pytest -v --tb=short "$@"
