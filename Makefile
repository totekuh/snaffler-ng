.PHONY: test-all test-unit test-integration test-integration-ad test-windows setup-windows build-deb clean

test-all: test-unit test-integration

test-unit:
	python -m pytest tests/unit/ -v --tb=short

test-integration:
	./tests/docker/run.sh

test-integration-ad:
	./tests/docker/run.sh --profile ad

setup-windows:
	uv pip install -e /home/witchtape/tools/winbox
	uv pip install "mcp>=1.29.1,<2"
	winbox up

test-windows:
	python -m pytest tests/windows/ -v --tb=short

build-deb:
	docker compose -f tests/docker-compose.yml build testrunner

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
