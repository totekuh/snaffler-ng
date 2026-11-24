"""Windows AD DC end-to-end test fixtures.

Requires winbox >= 2.1.0 and a Windows Server VM (auto-started if off).
Lazy snapshot provisioning: promotes to DC and configures DFS on first
run, snapshots the result. Subsequent runs restore from snapshot.

Delete the snapshot to force re-provisioning:
    virsh snapshot-delete winbox snaffler-windows-ad
"""

import json
import os
import socket
import time

import pytest

wb = pytest.importorskip("winbox")

from winbox.config import Config as WinboxConfig
from winbox.mcp._ad import ad_promote, ad_status
from winbox.mcp._ad_dfs import ad_dfs_create, ad_dfs_add_target, ad_dfs_list
from winbox.mcp._shares import share_create
from winbox.mcp._shares_io import share_write
from winbox.vm import VM, GuestAgent

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.utils.logger import set_finding_store

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SNAPSHOT_NAME = "snaffler-windows-ad"
_DOMAIN = "WINLAB.LOCAL"
_DSRM_PASSWORD = "SnaffAD1!"
_DFS_NAMESPACE = "lab-dfs"
_DFS_SHARE = "DFSRoot"

# ---------------------------------------------------------------------------
# Boot and verify
# ---------------------------------------------------------------------------


def _ensure_vm_ready():
    """Start VM if needed, wait for agent, verify connectivity."""
    if os.environ.get("SNAFFLER_WIN_AD_TESTS", "").lower() in ("0", "false", "no", "off"):
        pytest.skip("SNAFFLER_WIN_AD_TESTS explicitly disabled")

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

    return ip, cfg, vm, ga


_VM_IP, _WINBOX_CFG, _VM, _GA = (None, None, None, None)


def _boot():
    global _VM_IP, _WINBOX_CFG, _VM, _GA
    _VM_IP, _WINBOX_CFG, _VM, _GA = _ensure_vm_ready()


_boot()

pytestmark = [pytest.mark.windows_ad]

# ---------------------------------------------------------------------------
# Port / service readiness
# ---------------------------------------------------------------------------


def _wait_for_ports(ip, ports=(88, 389, 445), timeout=90):
    """Wait until all AD-related ports respond."""
    deadline = time.monotonic() + timeout
    for port in ports:
        while True:
            try:
                with socket.create_connection((ip, port), timeout=5):
                    break
            except (OSError, socket.timeout):
                if time.monotonic() > deadline:
                    pytest.fail(f"Port {port} on {ip} not ready after {timeout}s")
                time.sleep(3)


def _admin_password():
    """Domain admin password — the VM's original local admin password."""
    return _WINBOX_CFG.vm_password


def _validate_ad_services(ip):
    """Verify LDAP bind and SYSVOL share are healthy.

    AD services accept TCP connections before authentication works,
    so retry both LDAP bind and SMB share listing with generous timeouts.
    """
    from impacket.ldap.ldap import LDAPConnection
    from impacket.smbconnection import SMBConnection

    password = _admin_password()

    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            ldap = LDAPConnection(f"ldap://{ip}", _DOMAIN.lower())
            ldap.login("Administrator", password, _DOMAIN)
            ldap.close()
            break
        except Exception as exc:
            last_exc = exc
            time.sleep(5)
    else:
        pytest.fail(f"LDAP bind not ready after 90s: {last_exc}")

    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            smb = SMBConnection(ip, ip, timeout=5)
            smb.login("Administrator", password, _DOMAIN)
            shares = [s["shi1_netname"][:-1] for s in smb.listShares()]
            smb.close()
            assert "SYSVOL" in shares or "sysvol" in shares, f"SYSVOL missing: {shares}"
            return
        except Exception as exc:
            last_exc = exc
            time.sleep(3)
    pytest.fail(f"SMB services not ready after 60s: {last_exc}")


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------


def _snapshot_create_offline(vm, ga, name):
    """Shut down VM, create snapshot, restart and wait for agent."""
    if vm.is_running():
        vm.shutdown()
        if not vm.wait_shutdown(timeout=120):
            vm.force_stop()
    vm.snapshot_create(name)
    vm.start()
    ga.wait(timeout=180)


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------


def _provision_ad_dc(ip, vm, ga):
    """Promote to DC, create DFS namespace, take snapshot."""
    status = json.loads(ad_status())
    if not status.get("is_dc"):
        result = ad_promote(domain=_DOMAIN, password=_DSRM_PASSWORD)
        parsed = json.loads(result)
        if not parsed.get("success", parsed.get("promoted")):
            pytest.fail(f"AD promotion failed: {result}")

        ip = vm.ip()
        _wait_for_ports(ip, timeout=120)
        _validate_ad_services(ip)

    share_create(name=_DFS_SHARE, full_access=["Everyone"])
    share_write(name=_DFS_SHARE, path="dfs-test.txt", content="DFS discovery test")

    hostname = json.loads(ad_status()).get("hostname", "")
    target = f"\\\\{hostname}\\{_DFS_SHARE}"

    result = ad_dfs_create(namespace=_DFS_NAMESPACE, target=target)
    parsed = json.loads(result)
    if not parsed.get("created"):
        pytest.fail(f"DFS namespace creation failed: {result}")

    result = ad_dfs_add_target(
        namespace=_DFS_NAMESPACE,
        folder="Abteilungen",
        target=target,
    )
    parsed = json.loads(result)
    if not parsed.get("added"):
        pytest.fail(f"DFS folder target failed: {result}")

    dfs = json.loads(ad_dfs_list())
    assert dfs, "DFS namespace list empty after creation"

    _snapshot_create_offline(vm, ga, _SNAPSHOT_NAME)
    return ip


def _restore_snapshot(vm, ga):
    """Revert to AD snapshot and wait for services."""
    if vm.is_running():
        vm.shutdown()
        if not vm.wait_shutdown(timeout=120):
            vm.force_stop()
    vm.snapshot_revert(_SNAPSHOT_NAME)
    vm.start()
    ga.wait(timeout=180)

    ip = vm.ip()
    assert ip, "VM has no IP after snapshot restore"
    _wait_for_ports(ip, timeout=90)
    _validate_ad_services(ip)
    return ip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_ad_cfg(dc_ip, **overrides):
    """Build a SnafflerConfiguration targeting the Windows AD DC."""
    cfg = SnafflerConfiguration()
    cfg.auth.domain = _DOMAIN.lower()
    cfg.auth.dc_host = dc_ip
    cfg.auth.username = "Administrator"
    cfg.auth.password = _admin_password()
    cfg.auth.smb_timeout = 30
    cfg.auth.smb_port = 445
    cfg.scanning.max_read_bytes = 2 * 1024 * 1024
    cfg.scanning.max_file_bytes = 10 * 1024 * 1024
    cfg.scanning.match_context_bytes = 200
    cfg.scanning.min_interest = 0
    cfg.advanced.share_threads = 2
    cfg.advanced.tree_threads = 4
    cfg.advanced.file_threads = 4
    cfg.state.state_db = ":memory:"
    for k, v in overrides.items():
        parts = k.split(".")
        obj = cfg
        for p in parts[:-1]:
            obj = getattr(obj, p)
        setattr(obj, parts[-1], v)
    RuleLoader.load(cfg)
    return cfg


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def windows_ad_env():
    """Lazy-provision Windows AD DC. Restore from snapshot if available."""
    vm = _VM
    ga = _GA

    if _SNAPSHOT_NAME in vm.snapshot_list():
        ip = _restore_snapshot(vm, ga)
    else:
        ip = _provision_ad_dc(_VM_IP, vm, ga)

    yield {
        "domain": _DOMAIN,
        "realm": _DOMAIN,
        "dc_ip": ip,
        "admin_user": "Administrator",
        "admin_pass": _admin_password(),
        "dfs_namespace": _DFS_NAMESPACE,
        "dfs_share": _DFS_SHARE,
    }


@pytest.fixture(autouse=True)
def _reset_finding_store():
    yield
    set_finding_store(None)
