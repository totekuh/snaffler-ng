#!/bin/bash
# Build test images and run integration tests via Docker Compose.
# Usage: ./tests/docker/run.sh [pytest args...]
#   With AD:  ./tests/docker/run.sh --profile ad [pytest args...]
set -e

cd "$(git rev-parse --show-toplevel)"
COMPOSE="tests/docker/docker-compose.yml"

PROFILES=()
PYTEST_ARGS=()
for arg in "$@"; do
    if [[ "$arg" == "--profile" ]]; then
        PROFILES+=("$arg")
        continue
    fi
    if [[ ${#PROFILES[@]} -gt 0 && "${PROFILES[-1]}" == "--profile" ]]; then
        PROFILES+=("$arg")
        continue
    fi
    PYTEST_ARGS+=("$arg")
done

PROFILE_FLAGS="${PROFILES[@]}"

echo "Building integration test images..."
docker compose -f "$COMPOSE" $PROFILE_FLAGS build

echo "Running integration tests..."
docker compose -f "$COMPOSE" $PROFILE_FLAGS run --rm testrunner \
    python3 -m pytest -v --tb=short "${PYTEST_ARGS[@]}"

docker compose -f "$COMPOSE" $PROFILE_FLAGS down
