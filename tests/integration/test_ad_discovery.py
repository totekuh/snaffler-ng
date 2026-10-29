"""Integration tests: LDAP discovery against a real Samba AD DC."""

import pytest

from snaffler.discovery.ad import ADDiscovery
from snaffler.config.configuration import SnafflerConfiguration
from tests.ad_env.conftest import AD_ENABLED, AD_CONFIG

pytestmark = pytest.mark.skipif(not AD_ENABLED, reason="AD DC not available")

_DC_HOST = AD_CONFIG["dc_host"]
_ADMIN_PASS = AD_CONFIG["admin_pass"]


def _make_cfg(**overrides):
    cfg = SnafflerConfiguration()
    cfg.auth.domain = "testlab.local"
    cfg.auth.dc_host = _DC_HOST
    cfg.auth.username = "Administrator"
    cfg.auth.password = _ADMIN_PASS
    for k, v in overrides.items():
        parts = k.split(".")
        obj = cfg
        for p in parts[:-1]:
            obj = getattr(obj, p)
        setattr(obj, parts[-1], v)
    return cfg

EXPECTED_ENABLED = {"DBSERVER1.TESTLAB.LOCAL", "DC01.TESTLAB.LOCAL",
                    "FILESERVER1.TESTLAB.LOCAL", "WEBSERVER1.TESTLAB.LOCAL"}
EXPECTED_ALL = EXPECTED_ENABLED | {"DISABLED-PC.TESTLAB.LOCAL"}


# ── Computer discovery ───────────────────────────────────────────────

class TestComputerDiscovery:

    def test_discover_computers_default(self):
        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        computers = set(ad.get_domain_computers())
        assert EXPECTED_ENABLED <= computers
        assert "DISABLED-PC.TESTLAB.LOCAL" not in computers

    def test_discover_computers_include_disabled(self):
        cfg = _make_cfg(**{"targets.skip_disabled_computers": False})
        ad = ADDiscovery(cfg)
        computers = set(ad.get_domain_computers())
        assert EXPECTED_ALL <= computers

    def test_disabled_pc_filtered(self):
        cfg_skip = _make_cfg()
        cfg_all = _make_cfg(**{"targets.skip_disabled_computers": False})
        skip = set(ADDiscovery(cfg_skip).get_domain_computers())
        full = set(ADDiscovery(cfg_all).get_domain_computers())
        diff = full - skip
        assert "DISABLED-PC.TESTLAB.LOCAL" in diff

    def test_computer_hostnames_are_fqdn(self):
        cfg = _make_cfg(**{"targets.skip_disabled_computers": False})
        ad = ADDiscovery(cfg)
        for host in ad.get_domain_computers():
            assert host.endswith(".TESTLAB.LOCAL"), f"{host} not FQDN"

    def test_discovery_complete_flag(self):
        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        ad.get_domain_computers()
        assert ad.discovery_complete is True

    def test_stealth_mode(self):
        cfg = _make_cfg(**{"advanced.stealth": True,
                           "targets.skip_disabled_computers": False})
        ad = ADDiscovery(cfg)
        computers = set(ad.get_domain_computers())
        assert EXPECTED_ALL <= computers


# ── User discovery ───────────────────────────────────────────────────

class TestUserDiscovery:

    def test_discover_users_default_keywords(self):
        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        users = {u.lower() for u in ad.get_domain_users()}
        assert "svc_sql" in users
        assert "admin_backup" in users
        assert "scom_monitor" in users

    def test_discover_users_excludes_normal(self):
        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        users = {u.lower() for u in ad.get_domain_users()}
        assert "normal_user" not in users

    def test_discover_users_custom_keyword(self):
        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        users = {u.lower() for u in ad.get_domain_users(match_strings=["normal"])}
        assert "normal_user" in users

    def test_discover_users_min_length(self):
        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        users = {u.lower() for u in ad.get_domain_users(
            match_strings=["short", "svc", "admin", "scom", "backup"],
            min_len=6,
        )}
        assert "short" not in users
        assert "svc_sql" in users


# ── DFS discovery ────────────────────────────────────────────────────

class TestDFSDiscovery:

    def test_dfs_targets_empty(self):
        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        targets = ad.get_dfs_targets()
        assert targets == []


# ── Error handling ───────────────────────────────────────────────────

class TestErrorHandling:

    def test_bad_credentials_handled(self):
        cfg = _make_cfg()
        cfg.auth.password = "wrong_password"
        ad = ADDiscovery(cfg)
        result = ad.get_domain_computers()
        assert result == []
