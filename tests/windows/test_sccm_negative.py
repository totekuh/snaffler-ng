"""SCCM ContentLib negative tests against Windows VM.

Verifies benign files don't produce findings and fast mode skips ContentLib.
"""

import tempfile
from pathlib import Path

import pytest

from snaffler.config.configuration import FAST_MODE_EXCLUSIONS
from snaffler.resume.scan_state import SQLiteStateStore
from tests.windows.conftest import make_cfg, run_scan, no_auth_check

pytestmark = pytest.mark.windows


class TestSCCMNegative:

    def test_benign_file_no_finding(self, windows_env):
        """readme.txt blob has benign content — no findings expected for it."""
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = make_cfg(
                windows_env["vm_ip"],
                username="fulluser",
                password="SnaffFull1!",
                share="SCCMContentLib",
            )
            cfg.state.state_db = db_path
            with no_auth_check:
                _, p = run_scan(cfg)

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            for f in findings:
                assert "readme" not in f["file_path"].lower(), (
                    f"Benign readme.txt should not produce findings: {f}"
                )
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_fast_mode_skips_contentlib(self, windows_env):
        """FAST_MODE_EXCLUSIONS prevent ContentLib directory from being entered."""
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = make_cfg(
                windows_env["vm_ip"],
                username="fulluser",
                password="SnaffFull1!",
                share="SCCMContentLib",
            )
            cfg.state.state_db = db_path
            cfg.targets.exclude_unc = list(FAST_MODE_EXCLUSIONS) + cfg.targets.exclude_unc
            with no_auth_check:
                _, p = run_scan(cfg)
            assert p.scan_complete is True

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            contentlib_findings = [
                f for f in findings if "SCCMContentLib" in f["file_path"]
            ]
            assert len(contentlib_findings) == 0, (
                f"Fast mode should skip ContentLib: "
                f"{[(f['file_path'], f['rule_name']) for f in contentlib_findings]}"
            )
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_no_ini_files_in_findings(self, windows_env):
        """DataLib .INI files themselves should not appear as findings."""
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = make_cfg(
                windows_env["vm_ip"],
                username="fulluser",
                password="SnaffFull1!",
                share="SCCMContentLib",
            )
            cfg.state.state_db = db_path
            with no_auth_check:
                _, p = run_scan(cfg)

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            for f in findings:
                assert "DataLib" not in f["file_path"], (
                    f"DataLib INI files should not appear as findings: {f['file_path']}"
                )
        finally:
            Path(db_path).unlink(missing_ok=True)
