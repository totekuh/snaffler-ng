"""Subpath scanning tests."""

import tempfile
from pathlib import Path

from snaffler.resume.scan_state import SQLiteStateStore
from tests.smb_shared.target import make_cfg, run_scan


class TestSubpath:

    def test_subpath_scans_only_subtree(self, smb_target):
        cfg = make_cfg(smb_target, subpath="/home")
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        cfg.state.state_db = db_path

        try:
            run_scan(cfg)
            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            assert len(findings) > 0
            for finding in findings:
                assert "/home/" in finding["file_path"], f"Finding outside /home: {finding['file_path']}"
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_subpath_fewer_findings_than_root(self, smb_target):
        cfg_root = make_cfg(smb_target)
        _, p_root = run_scan(cfg_root)

        cfg_sub = make_cfg(smb_target, subpath="/home")
        _, p_sub = run_scan(cfg_sub)

        assert p_sub.files_scanned < p_root.files_scanned

    def test_deep_subpath(self, smb_target):
        cfg = make_cfg(smb_target, subpath="/home/user/.ssh")
        _, p = run_scan(cfg)
        assert p.files_scanned >= 1
