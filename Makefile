.PHONY: test-all test-unit test-integration test-integration-ad build-deb clean

test-all: test-unit test-integration

test-unit:
	python -m pytest tests/unit/ -v --tb=short

test-integration:
	./tests/docker/run.sh

test-integration-ad:
	./tests/docker/run.sh --profile ad

build-deb:
	docker compose -f tests/docker-compose.yml build testrunner

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
