.PHONY: test test-all test-unit test-integration build-deb clean

test: test-unit

test-all: test-unit test-integration

test-unit:
	python -m pytest tests/unit/ -v --tb=short

test-integration:
	./tests/integration/docker/run.sh

build-deb:
	docker build -t snaffler-ng-integration -f tests/integration/docker/Dockerfile .

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
