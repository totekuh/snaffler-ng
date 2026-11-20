"""Windows VM end-to-end test fixtures.

Requires winbox >= 2.0.0 and a Windows VM (auto-started if off).
Skips when winbox not installed or VM does not exist.
"""

import json
import os
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

wb = pytest.importorskip("winbox")

from winbox.config import Config as WinboxConfig
from winbox.mcp._shares import share_create, share_delete, user_create, user_delete
from winbox.mcp._shares_io import share_mkdir, share_write
from winbox.vm import VM, GuestAgent

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.runner import SnafflerRunner
from snaffler.utils.logger import set_finding_store

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_SNAPSHOT_NAME = "snaffler_test_pre"

# ---------------------------------------------------------------------------
# Boot and verify
# ---------------------------------------------------------------------------


def _ensure_vm_ready():
    """Start VM if needed, wait for agent, verify SMB. Return (ip, cfg) or skip."""
    if os.environ.get("SNAFFLER_WIN_TESTS", "").lower() in ("0", "false", "no", "off"):
        pytest.skip("SNAFFLER_WIN_TESTS explicitly disabled")

    try:
        cfg = WinboxConfig.load()
    except Exception as exc:
        pytest.skip(f"winbox config not found: {exc}")

    vm = VM(cfg)
    ga = GuestAgent(cfg)

    if not vm.exists():
        pytest.skip("Windows VM does not exist — run 'winbox setup' first")

    if not vm.is_running():
        vm.start()
        ga.wait(timeout=180)

    assert vm.is_running(), "VM failed to start"
    assert ga.ping(), "Guest agent not responding"

    ip = vm.ip()
    assert ip, "VM has no IP — check libvirt network"

    for attempt in range(3):
        try:
            with socket.create_connection((ip, 445), timeout=10):
                break
        except OSError:
            if attempt == 2:
                pytest.fail(f"SMB port 445 unreachable on {ip} after 3 attempts")
            import time
            time.sleep(5)

    return ip, cfg, vm, ga


_VM_IP, _WINBOX_CFG, _VM, _GA = (None, None, None, None)


def _boot():
    global _VM_IP, _WINBOX_CFG, _VM, _GA
    _VM_IP, _WINBOX_CFG, _VM, _GA = _ensure_vm_ready()


_boot()

pytestmark = [
    pytest.mark.windows,
]

# ---------------------------------------------------------------------------
# Test accounts and shares
# ---------------------------------------------------------------------------

USERS = {
    "fulluser": {"password": "SnaffFull1!", "access": "full"},
    "readuser": {"password": "SnaffRead1!", "access": "read"},
    "noaccess": {"password": "SnaffNone1!", "access": None},
}

SHARES = {
    "SnaffTest": {"full_access": ["fulluser"], "read_access": ["readuser"]},
    "SnaffSensitive": {"full_access": ["fulluser"]},
    "SnaffEmpty": {"full_access": ["Everyone"]},
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snapshot_create_offline(vm, ga, name):
    """Shut down VM, create snapshot, restart and wait for agent.

    pflash/UEFI VMs require offline snapshots — virsh refuses them live.
    """
    if vm.is_running():
        vm.shutdown()
        if not vm.wait_shutdown(timeout=120):
            vm.force_stop()
    vm.snapshot_create(name)
    vm.start()
    ga.wait(timeout=120)


def _seed_directory(share_name, local_dir):
    """Walk a local directory and upload all files to a Windows share."""
    local_dir = Path(local_dir)
    for dirpath, _dirnames, filenames in os.walk(local_dir):
        rel_dir = Path(dirpath).relative_to(local_dir)
        if rel_dir != Path("."):
            share_mkdir(name=share_name, path=str(rel_dir).replace(os.sep, "/"))
        for fname in filenames:
            local_path = Path(dirpath) / fname
            rel_path = (rel_dir / fname) if rel_dir != Path(".") else Path(fname)
            share_write(
                name=share_name,
                path=str(rel_path).replace(os.sep, "/"),
                source=str(local_path),
            )


def make_cfg(vm_ip, username="", password="", unc_targets=None, share="SnaffTest"):
    """Build a real SnafflerConfiguration targeting the Windows VM."""
    if unc_targets is None:
        unc_targets = [f"//{vm_ip}/{share}"]
    c = SnafflerConfiguration()
    c.targets.unc_targets = unc_targets
    c.auth.username = username
    c.auth.password = password
    c.auth.smb_timeout = 30
    c.auth.smb_port = 445
    c.scanning.max_read_bytes = 2 * 1024 * 1024
    c.scanning.max_file_bytes = 10 * 1024 * 1024
    c.scanning.match_context_bytes = 200
    c.scanning.min_interest = 0
    c.advanced.share_threads = 2
    c.advanced.tree_threads = 4
    c.advanced.file_threads = 4
    c.state.state_db = ":memory:"
    RuleLoader.load(c)
    return c


def run_scan(cfg):
    """Execute a full snaffler scan, return (runner, progress)."""
    runner = SnafflerRunner(cfg)
    runner.execute()
    return runner, runner.progress


no_auth_check = patch.object(SnafflerRunner, "_validate_credentials")

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def windows_env():
    """One-time setup: snapshot VM, create users/shares, seed test data."""
    cfg = _WINBOX_CFG
    vm = _VM
    ga = _GA
    ip = _VM_IP

    assert _DATA_DIR.is_dir(), f"Test data directory missing: {_DATA_DIR}"
    assert any(_DATA_DIR.iterdir()), f"Test data directory empty: {_DATA_DIR}"

    # -- Snapshot clean state (delete stale one from interrupted runs) --
    if _SNAPSHOT_NAME in vm.snapshot_list():
        if vm.is_running():
            vm.shutdown()
            if not vm.wait_shutdown(timeout=120):
                vm.force_stop()
        vm.snapshot_revert(_SNAPSHOT_NAME)
        from winbox.vm.virsh import virsh_run
        virsh_run("snapshot-delete", vm.name, _SNAPSHOT_NAME)

    try:
        _snapshot_create_offline(vm, ga, _SNAPSHOT_NAME)
    except RuntimeError as exc:
        pytest.fail(f"VM snapshot failed: {exc}")

    assert vm.is_running(), "VM did not restart after snapshot"
    assert ga.ping(), "Guest agent not responding after snapshot restart"

    # Wait for SMB service to be ready after boot
    import time
    for attempt in range(6):
        try:
            with socket.create_connection((ip, 445), timeout=5):
                break
        except OSError:
            if attempt == 5:
                pytest.fail(f"SMB port 445 not ready on {ip} after snapshot restart")
            time.sleep(5)

    try:
        # -- Clean stale state from interrupted runs --
        for share_name in SHARES:
            share_delete(name=share_name, purge=True, confirm=True)
        for username in USERS:
            user_delete(username=username, confirm=True)

        # -- Create test users --
        for username, info in USERS.items():
            result = user_create(username=username, password=info["password"])
            try:
                parsed = json.loads(result)
                assert parsed.get("created"), f"Failed to create user {username}: {result}"
            except json.JSONDecodeError:
                pytest.fail(f"user_create({username}) returned non-JSON: {result}")

        # -- Create test shares with ACLs --
        for share_name, acl in SHARES.items():
            result = share_create(
                name=share_name,
                full_access=acl.get("full_access"),
                read_access=acl.get("read_access"),
            )
            try:
                parsed = json.loads(result)
                assert parsed.get("name") == share_name, f"Failed to create share {share_name}: {result}"
            except json.JSONDecodeError:
                pytest.fail(f"share_create({share_name}) returned non-JSON: {result}")

        # -- Verify shares reachable over SMB --
        from impacket.smbconnection import SMBConnection
        smb = SMBConnection(ip, ip)
        smb.login(cfg.vm_user, cfg.vm_password)
        remote_shares = [s["shi1_netname"][:-1] for s in smb.listShares()]
        smb.close()
        for name in SHARES:
            assert name in remote_shares, f"Share {name} not visible over SMB. Got: {remote_shares}"

        # -- Seed test data --
        _seed_directory("SnaffTest", _DATA_DIR)

        share_write(
            name="SnaffSensitive",
            path="deploy.ps1",
            source=str(_DATA_DIR / "test-inline-password.ps1"),
        )

        yield {
            "vm_ip": ip,
            "users": USERS,
            "shares": SHARES,
            "cfg": cfg,
        }

    finally:
        if vm.is_running():
            vm.shutdown()
            if not vm.wait_shutdown(timeout=120):
                vm.force_stop()
        vm.snapshot_revert(_SNAPSHOT_NAME)
        vm.start()
        ga.wait(timeout=120)


@pytest.fixture(autouse=True)
def _reset_finding_store():
    yield
    set_finding_store(None)
