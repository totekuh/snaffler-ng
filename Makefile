.PHONY: test test-unit test-integration build-deb clean

test: test-unit

test-unit:
	python -m pytest tests/unit/ -v --tb=short

test-integration:
	./tests/deb/run.sh

build-deb:
	docker build -t snaffler-ng-deb-test -f tests/deb/Dockerfile .

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
