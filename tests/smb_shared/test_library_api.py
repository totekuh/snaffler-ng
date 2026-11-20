"""Library API (Snaffler.walk()) tests."""

from snaffler import Snaffler
from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.classifiers.rules import Triage
from snaffler.discovery.smb_tree_walker import SMBTreeWalker
from tests.smb_shared.target import make_cfg


class TestLibraryAPI:

    def test_walk_paths_are_unc(self, smb_target):
        cfg = make_cfg(smb_target)
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(smb_target.unc))

        for f in findings:
            base = f.file_path.split("→")[0]
            assert base.startswith("//"), f"Non-UNC path: {f.file_path}"

    def test_walk_subpath(self, smb_target):
        cfg = make_cfg(smb_target, subpath="/home")
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(smb_target.unc_with_subpath("/home")))

        assert len(findings) > 0
        for f in findings:
            base = f.file_path.split("→")[0]
            assert "/home/" in base, f"Finding outside /home: {f.file_path}"

    def test_walk_severity_distribution(self, smb_target):
        cfg = make_cfg(smb_target)
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(smb_target.unc))

        black = [f for f in findings if f.triage == Triage.BLACK]
        red = [f for f in findings if f.triage == Triage.RED]
        assert len(black) > 0
        assert len(red) > 0
