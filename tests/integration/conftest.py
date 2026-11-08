"""Integration test fixtures.

- AD fixtures: imported from tests.ad_env when available
- Deb/web fixtures: activate when running inside Docker (scan DB exists)
"""

import os
import signal
import sqlite3
import subprocess
import time

import pytest

# AD fixtures (skip gracefully if not available)
try:
    from tests.ad_env.conftest import ad_dc, ad_cfg  # noqa: F401
except ImportError:
    pass

# ── Deb integration fixtures (Docker only) ──────────────────────

SCAN_DB = "/work/scan.db"
IN_DOCKER = os.path.exists(SCAN_DB)


@pytest.fixture(scope="session")
def scan_db():
    """Path to the real scan DB produced by entrypoint.sh."""
    if not IN_DOCKER:
        pytest.skip("Not in Docker — scan DB not available")
    conn = sqlite3.connect(SCAN_DB)
    count = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    conn.close()
    assert count > 0, "Scan DB has no findings — snaffler scan may have failed"
    return SCAN_DB


@pytest.fixture(scope="session")
def web_server(scan_db):
    """Start snaffler results --web and yield (process, port). Kills on teardown."""
    requests = pytest.importorskip("requests")
    port = 18923
    proc = subprocess.Popen(
        ["snaffler", "results", "--web", "--web-port", str(port), "-s", scan_db],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/", timeout=1)
            if r.status_code == 200:
                break
        except requests.ConnectionError:
            time.sleep(0.2)
    else:
        proc.kill()
        out = proc.stdout.read().decode(errors="replace")
        pytest.fail(f"Web server did not start in 10s. Output:\n{out}")

    yield proc, port

    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
