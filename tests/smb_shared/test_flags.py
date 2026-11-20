"""Configuration flag tests."""

import tempfile
from pathlib import Path

from snaffler.resume.scan_state import SQLiteStateStore
from tests.smb_shared.target import make_cfg, run_scan


class TestFlags:

    def test_exclude_path(self, smb_target):
        cfg = make_cfg(smb_target)
        _, p_full = run_scan(cfg)

        cfg_excl = make_cfg(smb_target)
        cfg_excl.targets.exclude_unc = ["*/home/*"]
        _, p_excl = run_scan(cfg_excl)

        assert p_excl.files_scanned < p_full.files_scanned

    def test_min_interest_filters(self, smb_target):
        cfg = make_cfg(smb_target, scanning__min_interest=2)
        _, p = run_scan(cfg)
        assert p.severity_green == 0
        assert p.severity_yellow == 0
        assert p.files_matched > 0

    def test_max_depth_zero(self, smb_target):
        cfg = make_cfg(smb_target, scanning__max_depth=0)
        _, p = run_scan(cfg)

        cfg_full = make_cfg(smb_target)
        _, p_full = run_scan(cfg_full)
        assert p.files_scanned < p_full.files_scanned

    def test_match_filter(self, smb_target):
        cfg = make_cfg(smb_target, scanning__match_filter=r"\.pem")
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
                assert ".pem" in finding["file_path"].lower(), f"Non-pem finding: {finding['file_path']}"
        finally:
            Path(db_path).unlink(missing_ok=True)
