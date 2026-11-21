"""SCCM ContentLib coexistence tests against Windows VM.

Verifies SCCM ContentLib scanning works alongside normal share scanning
without interference.
"""

import tempfile
from pathlib import Path

import pytest

from snaffler.resume.scan_state import SQLiteStateStore
from tests.windows.conftest import make_cfg, run_scan, no_auth_check

pytestmark = pytest.mark.windows


class TestSCCMCoexistence:

    def test_sccm_alongside_normal_share(self, windows_env):
        """Scan SnaffTest + SCCMContentLib$ together, findings from both."""
        ip = windows_env["vm_ip"]
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = make_cfg(
                ip,
                username="fulluser",
                password="SnaffFull1!",
                unc_targets=[f"//{ip}/SnaffTest", f"//{ip}/SCCMContentLib$"],
            )
            cfg.state.state_db = db_path
            with no_auth_check:
                _, p = run_scan(cfg)
            assert p.scan_complete is True
            assert p.files_scanned >= 3

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()
            paths = [f["file_path"] for f in findings]

            has_sccm = any("SCCMContentLib" in fp for fp in paths)
            assert has_sccm, f"Missing SCCM findings. Paths: {paths}"
            assert p.files_matched >= 2
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_sccm_does_not_affect_normal_scan_counts(self, windows_env):
        """Normal share scan produces same finding count with or without SCCM."""
        ip = windows_env["vm_ip"]

        cfg_normal = make_cfg(ip, username="fulluser", password="SnaffFull1!", share="SnaffTest")
        with no_auth_check:
            _, p_normal = run_scan(cfg_normal)

        cfg_both = make_cfg(
            ip,
            username="fulluser",
            password="SnaffFull1!",
            unc_targets=[f"//{ip}/SnaffTest", f"//{ip}/SCCMContentLib$"],
        )
        with no_auth_check:
            _, p_both = run_scan(cfg_both)

        assert p_both.files_matched >= p_normal.files_matched, (
            f"Adding SCCM share should not reduce normal findings: "
            f"normal={p_normal.files_matched} both={p_both.files_matched}"
        )

    def test_sccm_scan_completes_without_timeout(self, windows_env):
        """ContentLib scan completes within normal timeout — no infinite loops."""
        cfg = make_cfg(
            windows_env["vm_ip"],
            username="fulluser",
            password="SnaffFull1!",
            share="SCCMContentLib$",
        )
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.scan_complete is True
