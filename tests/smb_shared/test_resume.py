"""Resume / state_db tests."""

import tempfile
from pathlib import Path

from snaffler.resume.scan_state import SQLiteStateStore
from tests.smb_shared.target import make_cfg, run_scan


class TestResume:

    def test_resume_no_new_findings(self, smb_target):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg = make_cfg(smb_target)
            cfg.state.state_db = db_path
            run_scan(cfg)

            store = SQLiteStateStore(db_path)
            count1 = store.count_findings()
            store.close()

            cfg2 = make_cfg(smb_target)
            cfg2.state.state_db = db_path
            run_scan(cfg2)

            store = SQLiteStateStore(db_path)
            count2 = store.count_findings()
            store.close()

            assert count1 > 0
            assert count2 == count1
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_resume_restores_finding_counts(self, smb_target):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg = make_cfg(smb_target)
            cfg.state.state_db = db_path
            _, p1 = run_scan(cfg)

            cfg2 = make_cfg(smb_target)
            cfg2.state.state_db = db_path
            _, p2 = run_scan(cfg2)

            assert p2.files_matched >= p1.files_matched
        finally:
            Path(db_path).unlink(missing_ok=True)
