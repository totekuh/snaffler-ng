"""Integration test fixtures.

- AD fixtures: imported from tests.ad_env when available
- Scan fixtures: run snaffler against SMB_HOST inside Docker
- Packet capture: start_tcpdump() for DNS leak tests
"""

import os
import signal
import sqlite3
import subprocess
import time

import pytest

# AD fixtures (skip gracefully if not available)
try:
    from tests.ad_env.conftest import ad_cfg, ad_dc  # noqa: F401
except ImportError:
    pass

# ── Packet capture ───────────────────────────────────────────────


def start_tcpdump(pcap_path: str) -> subprocess.Popen:
    """Start tcpdump and block until it is actively capturing.

    Captures all traffic (no BPF capture filter) because Docker's
    iptables DNAT rewrites port numbers before the kernel BPF sees
    them, making ``port 53`` miss DNS packets whose destination was
    rewritten.  Filtering happens at read time via ``read_pcap_packets``.

    Uses ``--immediate-mode`` so packets are delivered to userspace
    without buffering delay, and polls a sentinel pcap file to confirm
    readiness instead of reading stderr.

    Returns the Popen handle — caller must ``terminate()`` + ``wait()``
    when done.
    """
    proc = subprocess.Popen(
        ["tcpdump", "-i", "any", "--immediate-mode", "-U", "-w", pcap_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if os.path.exists(pcap_path) and os.path.getsize(pcap_path) >= 24:
            return proc
        time.sleep(0.1)

    proc.kill()
    proc.wait()
    pytest.fail("tcpdump did not start capturing within 5s")


def read_pcap_packets(pcap_path: str, bpf_filter: str = "port 53") -> list[str]:
    """Read a pcap file with tcpdump and return matching packet lines."""
    result = subprocess.run(
        ["tcpdump", "-r", pcap_path, "-nn", bpf_filter],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip().splitlines()


# ── Docker detection ──────────────────────────────────────────────

SMB_HOST = os.environ.get("SMB_HOST", "samba")
IN_DOCKER = os.environ.get("SNAFFLER_TEST_DOCKER") == "1"


def _run_scan(db_path, extra_args=None):
    cmd = [
        "snaffler",
        "--unc", f"\\\\{SMB_HOST}\\testdata",
        "--state", db_path,
        "--fresh", "--no-banner", "--log-level", "data",
    ]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"snaffler scan failed (exit {result.returncode}):\n{result.stderr}"
        )
    return db_path


@pytest.fixture(scope="session")
def scan_db():
    """Run snaffler against Samba share, return path to scan DB."""
    if not IN_DOCKER:
        pytest.skip("Not in Docker — SMB target not available")
    db_path = "/work/scan.db"
    _run_scan(db_path)
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
    conn.close()
    assert count > 0, "Scan DB has no findings — snaffler scan may have failed"
    return db_path


@pytest.fixture(scope="session")
def scan_db_skip_binary():
    """Run snaffler with --skip-binary against Samba share."""
    if not IN_DOCKER:
        pytest.skip("Not in Docker — SMB target not available")
    db_path = "/work/scan_skipbin.db"
    _run_scan(db_path, extra_args=["--skip-binary"])
    return db_path


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
