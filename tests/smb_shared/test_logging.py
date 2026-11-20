"""Logging assertion tests."""

import logging

from tests.smb_shared.target import make_cfg, run_scan


class TestLogging:

    def test_findings_logged(self, smb_target, caplog):
        cfg = make_cfg(smb_target)
        with caplog.at_level(logging.WARNING, logger="snaffler"):
            run_scan(cfg)
        findings = [r for r in caplog.records if "[Red]" in r.message or "[Black]" in r.message]
        assert len(findings) > 0

    def test_finding_paths_are_unc(self, smb_target, caplog):
        cfg = make_cfg(smb_target)
        with caplog.at_level(logging.WARNING, logger="snaffler"):
            run_scan(cfg)
        unc_findings = [
            r for r in caplog.records
            if hasattr(r, "file_path") and r.file_path.startswith("//")
        ]
        assert len(unc_findings) > 0
