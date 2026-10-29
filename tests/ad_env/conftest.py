"""Fixtures for Samba AD DC integration tests."""

import os
import socket

import pytest


def _ad_available():
    """Check if AD DC container is reachable on LDAP and SMB ports."""
    if os.environ.get("SNAFFLER_AD_TESTS", "").lower() in ("0", "false", "no", "off"):
        return False
    host = os.environ.get("AD_DC_HOST", "127.0.0.1")
    for port in (389, 445):
        try:
            with socket.create_connection((host, port), timeout=2):
                pass
        except (OSError, socket.timeout):
            return False
    return True


AD_ENABLED = _ad_available()

AD_CONFIG = {
    "domain": "testlab.local",
    "realm": "TESTLAB.LOCAL",
    "dc_host": os.environ.get("AD_DC_HOST", "127.0.0.1"),
    "admin_user": "Administrator",
    "admin_pass": os.environ.get("AD_ADMIN_PASS", "Passw0rd!Testing"),
    "test_user": "testrunner",
    "test_pass": "TestRunner1!",
    "test_nthash": "a816f97042854c6ca6e650e6d9b7a64e",
}


def _make_cfg(**overrides):
    from snaffler.config.configuration import SnafflerConfiguration
    cfg = SnafflerConfiguration()
    cfg.auth.domain = AD_CONFIG["domain"]
    cfg.auth.dc_host = AD_CONFIG["dc_host"]
    cfg.auth.username = AD_CONFIG["admin_user"]
    cfg.auth.password = AD_CONFIG["admin_pass"]
    for k, v in overrides.items():
        parts = k.split(".")
        obj = cfg
        for p in parts[:-1]:
            obj = getattr(obj, p)
        setattr(obj, parts[-1], v)
    return cfg


def _validate_ad_services():
    """Verify AD DC services respond correctly. Called once per session."""
    from impacket.ldap.ldap import LDAPConnection
    from impacket.smbconnection import SMBConnection

    host = AD_CONFIG["dc_host"]

    ldap = LDAPConnection(f"ldap://{host}", AD_CONFIG["domain"])
    ldap.login(AD_CONFIG["admin_user"], AD_CONFIG["admin_pass"], AD_CONFIG["realm"])
    ldap.close()

    smb = SMBConnection(host, host)
    smb.login(AD_CONFIG["admin_user"], AD_CONFIG["admin_pass"], AD_CONFIG["realm"])
    server = smb.getServerName()
    shares = [s["shi1_netname"][:-1] for s in smb.listShares()]
    smb.close()

    assert server, "SMB server name empty"
    assert "sysvol" in shares, f"SYSVOL not in shares: {shares}"


@pytest.fixture(scope="session")
def ad_dc():
    if not AD_ENABLED:
        pytest.skip("AD DC not available (LDAP/SMB ports unreachable on 127.0.0.1)")
    _validate_ad_services()
    return AD_CONFIG


@pytest.fixture()
def ad_cfg(ad_dc):
    return _make_cfg()
