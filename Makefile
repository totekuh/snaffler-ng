.PHONY: test-all test-unit test-e2e test-e2e-ad test-e2e-socks test-e2e-full test-ad-scan test-windows setup-windows clean

test-all: test-unit test-e2e-ad

test-unit:
	python -m pytest tests/unit/ -v --tb=short

# Build .deb, install in clean container, run e2e tests against installed package
test-e2e:
	python tests/docker/run.py

test-e2e-ad:
	python tests/docker/run.py --ad

test-e2e-socks:
	python tests/docker/run.py --socks

test-e2e-full:
	python tests/docker/run.py --all

# Host-side AD scan tests (requires running DC container + AD_DC_HOST env)
test-ad-scan:
	python -m pytest tests/integration/test_ad_scan.py -v --tb=short

setup-windows:
	uv pip install -e /home/witchtape/tools/winbox
	uv pip install "mcp>=1.29.1,<2"
	winbox up

test-windows:
	python -m pytest tests/windows/ -v --tb=short

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
