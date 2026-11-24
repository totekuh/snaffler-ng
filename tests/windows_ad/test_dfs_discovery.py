"""DFS v2 discovery against real Windows AD DC.

Regression test for the UTF-16 msDFS-TargetListv2 bug:
  str(val) on Impacket ASN.1 value assumed UTF-8, but Windows AD
  stores DFS v2 XML as UTF-16 with BOM. This caused
  PyAsn1UnicodeDecodeError during DFS discovery.

Fix: bytes(val) — ET.fromstring() auto-detects encoding.
"""

import logging

import pytest

from snaffler.discovery.ad import ADDiscovery

from tests.windows_ad.conftest import make_ad_cfg


class TestDFSv2Discovery:
    """Verify DFS v2 target discovery works against real Windows AD."""

    def test_get_dfs_targets_no_exception(self, windows_ad_env):
        """The original bug raised PyAsn1UnicodeDecodeError here."""
        cfg = make_ad_cfg(windows_ad_env["dc_ip"])
        ad = ADDiscovery(cfg)
        targets = ad.get_dfs_targets()
        assert isinstance(targets, list)

    def test_dfs_targets_found(self, windows_ad_env):
        """DFS namespace configured during provisioning should be discovered."""
        cfg = make_ad_cfg(windows_ad_env["dc_ip"])
        ad = ADDiscovery(cfg)
        targets = ad.get_dfs_targets()
        assert len(targets) > 0, (
            "No DFS targets found — DFS namespace may not have been provisioned"
        )

    def test_dfs_targets_contain_share(self, windows_ad_env):
        """Discovered targets should include the DFS share we configured."""
        cfg = make_ad_cfg(windows_ad_env["dc_ip"])
        ad = ADDiscovery(cfg)
        targets = ad.get_dfs_targets()
        share = windows_ad_env["dfs_share"]
        matching = [t for t in targets if share.lower() in t.lower()]
        assert matching, f"No target contains '{share}'. Got: {targets}"

    def test_dfs_targets_normalized_unc(self, windows_ad_env):
        """All targets should be forward-slash UNC paths."""
        cfg = make_ad_cfg(windows_ad_env["dc_ip"])
        ad = ADDiscovery(cfg)
        targets = ad.get_dfs_targets()
        for t in targets:
            assert t.startswith("//"), f"Target not UNC: {t}"
            assert "\\" not in t, f"Backslash in target: {t}"
            parts = t[2:].split("/")
            assert len(parts) >= 2, f"Target missing host/share: {t}"

    def test_dfs_targets_no_duplicates(self, windows_ad_env):
        cfg = make_ad_cfg(windows_ad_env["dc_ip"])
        ad = ADDiscovery(cfg)
        targets = ad.get_dfs_targets()
        assert len(targets) == len(set(targets))


class TestDFSv2UTF16Regression:
    """Explicit regression tests for the PyAsn1UnicodeDecodeError bug."""

    def test_no_unicode_decode_error(self, windows_ad_env):
        """bytes(val) must handle UTF-16 BOM without raising."""
        cfg = make_ad_cfg(windows_ad_env["dc_ip"])
        ad = ADDiscovery(cfg)
        try:
            ad.get_dfs_targets()
        except UnicodeDecodeError:
            pytest.fail("UnicodeDecodeError raised — UTF-16 fix regressed")
        except Exception as exc:
            if "PyAsn1UnicodeDecodeError" in type(exc).__name__:
                pytest.fail(f"PyAsn1UnicodeDecodeError raised — UTF-16 fix regressed: {exc}")
            raise

    def test_no_dfs_error_in_logs(self, windows_ad_env, caplog):
        """No ERROR-level log messages about DFS v2 discovery."""
        cfg = make_ad_cfg(windows_ad_env["dc_ip"])
        ad = ADDiscovery(cfg)
        with caplog.at_level(logging.ERROR, logger="snaffler"):
            ad.get_dfs_targets()
        dfs_errors = [r for r in caplog.records if "DFS v2" in r.message or "dfs" in r.message.lower()]
        assert not dfs_errors, f"DFS error logged: {[r.message for r in dfs_errors]}"


class TestADServicesHealth:
    """Sanity checks that the DC is operational."""

    def test_ldap_bind(self, windows_ad_env):
        """LDAP bind to DC should succeed."""
        from snaffler.transport.ldap import LDAPTransport

        cfg = make_ad_cfg(windows_ad_env["dc_ip"])
        transport = LDAPTransport(cfg)
        ldap = transport.connect()
        ldap.close()

    def test_domain_computers_includes_dc(self, windows_ad_env):
        """Computer discovery should find at least the DC itself."""
        cfg = make_ad_cfg(windows_ad_env["dc_ip"])
        ad = ADDiscovery(cfg)
        computers = ad.get_domain_computers()
        assert len(computers) >= 1, "No computers found — DC should appear"
