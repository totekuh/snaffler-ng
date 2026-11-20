"""Core scan assertions: results, severity, consistency."""

import pytest

from snaffler import Snaffler
from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.analysis.model.file_result import FileResult
from snaffler.discovery.smb_tree_walker import SMBTreeWalker
from tests.smb_shared.target import SMBTarget, make_cfg, no_auth_check, run_scan


class TestCoreScan:

    def test_produces_findings(self, smb_target):
        cfg = make_cfg(smb_target)
        _, p = run_scan(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_scan_complete_flag(self, smb_target):
        cfg = make_cfg(smb_target)
        _, p = run_scan(cfg)
        assert p.scan_complete is True

    def test_severity_counts_sum(self, smb_target):
        cfg = make_cfg(smb_target)
        _, p = run_scan(cfg)
        total = p.severity_black + p.severity_red + p.severity_yellow + p.severity_green
        assert total == p.files_matched

    def test_finds_black_severity(self, smb_target):
        cfg = make_cfg(smb_target)
        _, p = run_scan(cfg)
        assert p.severity_black > 0

    def test_finds_red_severity(self, smb_target):
        cfg = make_cfg(smb_target)
        _, p = run_scan(cfg)
        assert p.severity_red > 0

    def test_scans_more_than_matches(self, smb_target):
        cfg = make_cfg(smb_target)
        _, p = run_scan(cfg)
        assert p.files_scanned > p.files_matched

    def test_wrong_creds_no_findings(self, smb_target):
        if not smb_target.enforces_auth:
            pytest.skip("backend does not enforce authentication")
        bad = SMBTarget(
            ip=smb_target.ip, port=smb_target.port, share=smb_target.share,
            username="wrong", password="wrong",
        )
        cfg = make_cfg(bad)
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.files_scanned == 0

    def test_consistent_results_across_runs(self, smb_target):
        cfg1 = make_cfg(smb_target)
        _, p1 = run_scan(cfg1)
        cfg2 = make_cfg(smb_target)
        _, p2 = run_scan(cfg2)
        assert p1.files_matched == p2.files_matched
        assert p1.severity_black == p2.severity_black
        assert p1.severity_red == p2.severity_red


class TestLibraryAPICore:

    def test_walk_produces_findings(self, smb_target):
        cfg = make_cfg(smb_target)
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)
        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(smb_target.unc))
        assert len(findings) > 0
        assert all(isinstance(f, FileResult) for f in findings)

    def test_walk_matches_runner_count(self, smb_target):
        cfg1 = make_cfg(smb_target)
        _, p = run_scan(cfg1)

        cfg2 = make_cfg(smb_target)
        walker = SMBTreeWalker(cfg2)
        reader = SMBFileAccessor(cfg2)
        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(smb_target.unc))
        assert len(findings) == p.files_matched
