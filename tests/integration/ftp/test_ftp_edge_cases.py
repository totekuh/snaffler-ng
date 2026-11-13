"""
FTP edge case integration tests: subpaths, symlinks, concurrency, unicode.

Module-scoped server — one server for all tests in this file.
Connection drop test is in test_ftp_connection_drop.py (needs its own server).
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)

pyftpdlib = pytest.importorskip("pyftpdlib")

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration

from tests.integration.ftp.conftest import (
    free_port,
    make_cfg,
    run,
    start_ftp_server,
    stop_ftp_server,
)


@pytest.fixture(scope="module")
def ftp_server():
    root = tempfile.mkdtemp()

    # 50 dirs x 5 files for stress tests
    for i in range(50):
        d = Path(root, f"dir_{i:03d}")
        d.mkdir()
        for j in range(5):
            (d / f"file_{j}.txt").write_text(f"content {i}-{j}")

    # Subpath data
    sub_a = Path(root, "sub_a")
    sub_b = Path(root, "sub_b")
    sub_a.mkdir()
    sub_b.mkdir()
    (sub_a / "id_rsa").write_text("KEY A")
    (sub_b / "id_dsa").write_text("KEY B")

    # Symlink (may fail on some FS)
    try:
        os.symlink(root, str(Path(root, "dir_000", "link_to_parent")))
    except OSError:
        pass

    # Unicode filenames
    Path(root, "Passwörter.csv").write_text("data")
    Path(root, "contraseñas.txt").write_text("data")
    Path(root, "mot_de_passe.doc").write_text("data")

    port = free_port()
    server, thread = start_ftp_server(root, port)
    yield port, root
    stop_ftp_server(server)
    shutil.rmtree(root, ignore_errors=True)


class TestSubpaths:

    def test_sub_a_finds_key(self, ftp_server):
        port, _root = ftp_server
        cfg = make_cfg(port, subpath="/sub_a")
        _, p = run(cfg)
        assert p.scan_complete
        assert p.files_scanned >= 1
        assert p.files_matched >= 1

    def test_sub_b_finds_key(self, ftp_server):
        port, _root = ftp_server
        cfg = make_cfg(port, subpath="/sub_b")
        _, p = run(cfg)
        assert p.scan_complete
        assert p.files_scanned >= 1
        assert p.files_matched >= 1

    def test_full_scan_finds_both_subpaths(self, ftp_server):
        """Full scan discovers files from both sub_a and sub_b."""
        port, _root = ftp_server
        from snaffler import Snaffler
        from snaffler.accessors.ftp_file_accessor import FTPFileAccessor
        from snaffler.discovery.ftp_tree_walker import FTPTreeWalker

        cfg = make_cfg(port)
        walker = FTPTreeWalker(cfg)
        reader = FTPFileAccessor(cfg)
        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"ftp://127.0.0.1:{port}"))

        paths = [f.file_path for f in findings]
        has_a = any("sub_a" in p for p in paths)
        has_b = any("sub_b" in p for p in paths)
        assert has_a, "No findings from sub_a"
        assert has_b, "No findings from sub_b"


class TestSymlinkLoop:

    def test_symlink_does_not_hang(self, ftp_server):
        """Symlink to parent in dir_000 doesn't cause infinite recursion."""
        port, root = ftp_server
        symlink = Path(root, "dir_000", "link_to_parent")
        if not symlink.exists():
            pytest.skip("Symlink not created (filesystem limitation)")

        cfg = make_cfg(port)
        _, p = run(cfg)
        assert p.scan_complete


class TestConcurrentThreads:

    def test_high_thread_count_stress(self, ftp_server):
        """250 files with tree_threads=8, file_threads=8 — no deadlock."""
        port, _root = ftp_server
        cfg = make_cfg(port)
        cfg.advanced.tree_threads = 8
        cfg.advanced.file_threads = 8
        _, p = run(cfg)
        assert p.scan_complete
        assert p.files_scanned > 100


class TestUnicodeFilenames:

    def test_multilingual_rules_fire(self, ftp_server):
        """Multilingual filename rules trigger over FTP."""
        port, _root = ftp_server
        cfg = make_cfg(port)
        _, p = run(cfg)
        # Passwörter, contraseñas, mot_de_passe trigger rules
        assert p.files_matched >= 3
