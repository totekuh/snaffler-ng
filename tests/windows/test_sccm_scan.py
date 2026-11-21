"""SCCM ContentLib basic scan tests against Windows VM.

Verifies the ContentLib walker resolves DataLib INI pointers to
FileLib hash blobs and produces findings from the resolved content.
"""

import pytest

from tests.windows.conftest import make_cfg, run_scan, no_auth_check

pytestmark = pytest.mark.windows


class TestSCCMBasicScan:

    def test_contentlib_produces_findings(self, windows_env):
        cfg = make_cfg(
            windows_env["vm_ip"],
            username="fulluser",
            password="SnaffFull1!",
            share="SCCMContentLib$",
        )
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.scan_complete is True
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_dollar_share_accessible(self, windows_env):
        """Hidden $ share is reachable and scannable (Windows-specific)."""
        cfg = make_cfg(
            windows_env["vm_ip"],
            username="fulluser",
            password="SnaffFull1!",
            share="SCCMContentLib$",
        )
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.scan_complete is True
        assert p.files_scanned > 0

    def test_multiple_findings_from_contentlib(self, windows_env):
        """At least 2 distinct findings — proves multiple INIs resolved."""
        cfg = make_cfg(
            windows_env["vm_ip"],
            username="fulluser",
            password="SnaffFull1!",
            share="SCCMContentLib$",
        )
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.files_matched >= 2
