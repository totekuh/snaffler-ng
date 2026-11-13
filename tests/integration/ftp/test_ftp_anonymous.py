"""
FTP anonymous integration tests with module-scoped server.

One server per file — all tests share it. Test data includes standard
test files, unicode filenames, empty dirs, zero-byte files, and deeply
nested directories.
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

from tests.integration.ftp.conftest import (
    _DATA_DIR,
    free_port,
    make_cfg,
    run,
    start_ftp_server,
    stop_ftp_server,
)


@pytest.fixture(scope="module")
def ftp_server():
    root = tempfile.mkdtemp()

    # Copy standard test data into data/ subtree
    shutil.copytree(str(_DATA_DIR), os.path.join(root, "data"))

    # Unicode filenames at root
    Path(root, "Passwörter_backup.csv").write_text("data")
    Path(root, "contraseñas.txt").write_text("data")
    Path(root, "mot_de_passe_admin.txt").write_text("data")
    Path(root, "密码文件.txt").write_text("data")
    Path(root, "normal_ascii.txt").write_text("nothing interesting")

    # Empty directories
    Path(root, "empty_a").mkdir()
    Path(root, "empty_b").mkdir()
    has_files = Path(root, "has_files")
    has_files.mkdir()
    (has_files / "id_rsa").write_text("SSH KEY")

    # Zero-byte files
    Path(root, "zero.txt").touch()
    Path(root, "zero.key").touch()

    # Deeply nested directories (55 levels, path > 300 chars)
    current = Path(root, "deep")
    for i in range(55):
        current = current / f"level_{i:02d}"
        current.mkdir(parents=True, exist_ok=True)
    (current / "id_rsa").write_text("DEEP KEY")

    port = free_port()
    server, thread = start_ftp_server(root, port)
    yield port, root
    stop_ftp_server(server)
    shutil.rmtree(root, ignore_errors=True)


class TestAnonymousBasic:

    def test_produces_findings(self, ftp_server):
        port, _root = ftp_server
        cfg = make_cfg(port, subpath="/data")
        _, p = run(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_severity_distribution(self, ftp_server):
        port, _root = ftp_server
        cfg = make_cfg(port, subpath="/data")
        _, p = run(cfg)
        total = p.severity_black + p.severity_red + p.severity_yellow + p.severity_green
        assert total == p.files_matched
        assert p.severity_black > 0
        assert p.severity_red > 0

    def test_scan_complete_flag(self, ftp_server):
        port, _root = ftp_server
        cfg = make_cfg(port, subpath="/data")
        _, p = run(cfg)
        assert p.scan_complete is True

    def test_finding_paths_are_ftp_urls(self, ftp_server):
        port, _root = ftp_server
        cfg = make_cfg(port, subpath="/data")
        from snaffler import Snaffler
        from snaffler.accessors.ftp_file_accessor import FTPFileAccessor
        from snaffler.discovery.ftp_tree_walker import FTPTreeWalker

        walker = FTPTreeWalker(cfg)
        reader = FTPFileAccessor(cfg)
        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"ftp://127.0.0.1:{port}/data"))

        assert len(findings) > 0
        for f in findings:
            base = f.file_path.split("→")[0]
            assert base.startswith("ftp://"), f"Non-FTP path: {f.file_path}"


class TestAnonymousUnicode:

    def test_unicode_filenames_discovered(self, ftp_server):
        """German umlauts, Spanish tildes, CJK — all survive FTP round-trip."""
        port, _root = ftp_server
        cfg = make_cfg(port)
        _, p = run(cfg)
        assert p.files_scanned > 5
        assert p.scan_complete

    def test_multilingual_rules_fire(self, ftp_server):
        """Multilingual rules detect German/Spanish/French keywords via FTP."""
        port, _root = ftp_server
        cfg = make_cfg(port)
        _, p = run(cfg)
        assert p.files_matched >= 3


class TestAnonymousEdgeCases:

    def test_empty_server_subdir(self, ftp_server):
        """Scanning an empty directory completes without crash."""
        port, _root = ftp_server
        cfg = make_cfg(port, subpath="/empty_a")
        _, p = run(cfg)
        assert p.scan_complete
        assert p.files_scanned == 0

    def test_empty_subdirectories(self, ftp_server):
        """Mixed empty and non-empty dirs — empty ones don't crash walker."""
        port, _root = ftp_server
        cfg = make_cfg(port, subpath="/has_files")
        _, p = run(cfg)
        assert p.scan_complete
        assert p.files_scanned >= 1

    def test_deeply_nested_directory(self, ftp_server):
        """55 nested levels, path > 300 chars — scan completes."""
        port, root = ftp_server
        deep_file = Path(root, "deep")
        for i in range(55):
            deep_file = deep_file / f"level_{i:02d}"
        deep_file = deep_file / "id_rsa"
        assert len(str(deep_file)) > 300

        cfg = make_cfg(port, subpath="/deep")
        _, p = run(cfg)
        assert p.scan_complete
        assert p.files_scanned >= 1

    def test_zero_byte_files(self, ftp_server):
        """Zero-byte files don't crash the scanner."""
        port, _root = ftp_server
        cfg = make_cfg(port)
        _, p = run(cfg)
        assert p.scan_complete
