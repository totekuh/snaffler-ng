"""Shared fixtures for deb integration tests.

All tests run against the *installed* snaffler-ng package, not source tree.
The scan DB at /tests/scan.db is produced by a real snaffler scan against
a Samba share serving tests/data/ — created by entrypoint.sh before pytest.
"""

import os
import signal
import sqlite3
import subprocess
import time

import pytest
import requests

SCAN_DB = "/tests/scan.db"


@pytest.fixture(scope="session")
def scan_db():
    """Path to the real scan DB produced by entrypoint.sh."""
    assert os.path.exists(SCAN_DB), f"Scan DB not found at {SCAN_DB} — did entrypoint.sh run?"
    conn = sqlite3.connect(SCAN_DB)
    count = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    conn.close()
    assert count > 0, "Scan DB has no findings — snaffler scan may have failed"
    return SCAN_DB


@pytest.fixture(scope="session")
def web_server(scan_db):
    """Start snaffler results --web and yield (process, port). Kills on teardown."""
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
