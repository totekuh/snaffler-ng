"""Full snaffler scan against a Windows VM share seeded with tests/data/."""

from snaffler import Snaffler
from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.analysis.model.file_result import FileResult
from snaffler.discovery.smb_tree_walker import SMBTreeWalker
from tests.windows.conftest import USERS, make_cfg, no_auth_check, run_scan


class TestFullScanAuthenticated:

    def test_produces_findings(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"])
        _, p = run_scan(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_scan_complete(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"])
        _, p = run_scan(cfg)
        assert p.scan_complete is True

    def test_severity_counts_sum(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"])
        _, p = run_scan(cfg)
        total = p.severity_black + p.severity_red + p.severity_yellow + p.severity_green
        assert total == p.files_matched

    def test_finds_black_severity(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"])
        _, p = run_scan(cfg)
        assert p.severity_black > 0

    def test_finds_red_severity(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"])
        _, p = run_scan(cfg)
        assert p.severity_red > 0

    def test_scans_more_than_matches(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"])
        _, p = run_scan(cfg)
        assert p.files_scanned > p.files_matched

    def test_wrong_creds_no_findings(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password="WrongPassword123!")
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.files_scanned == 0

    def test_consistent_results(self, windows_env):
        u, pw = "fulluser", USERS["fulluser"]["password"]
        cfg1 = make_cfg(windows_env["vm_ip"], username=u, password=pw)
        _, p1 = run_scan(cfg1)
        cfg2 = make_cfg(windows_env["vm_ip"], username=u, password=pw)
        _, p2 = run_scan(cfg2)
        assert p1.files_matched == p2.files_matched


class TestLibraryAPIWindows:

    def test_walk_produces_findings(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"])
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)
        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"//{windows_env['vm_ip']}/SnaffTest"))
        assert len(findings) > 0
        assert all(isinstance(f, FileResult) for f in findings)

    def test_walk_matches_runner_count(self, windows_env):
        u, pw = "fulluser", USERS["fulluser"]["password"]

        cfg1 = make_cfg(windows_env["vm_ip"], username=u, password=pw)
        _, p = run_scan(cfg1)

        cfg2 = make_cfg(windows_env["vm_ip"], username=u, password=pw)
        walker = SMBTreeWalker(cfg2)
        reader = SMBFileAccessor(cfg2)
        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"//{windows_env['vm_ip']}/SnaffTest"))
        assert len(findings) == p.files_matched
