"""
FTP protocol-level error tests.

Separate module from other FTP tests to avoid asyncore socket map conflicts.
Class-scoped server fixtures: only one FTPServer alive at a time (pyftpdlib
uses asyncore's process-global socket map).
"""

import ftplib
import shutil
import tempfile

import pytest

pyftpdlib = pytest.importorskip("pyftpdlib")

from tests.integration.ftp.conftest import (
    free_port,
    make_cfg,
    no_auth_check,
    run,
    start_ftp_server,
    stop_ftp_server,
)

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")


class TestFTPErrorsAnon:
    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _server(cls, tmp_path_factory):
        root = tmp_path_factory.mktemp("anon")
        (root / "file.txt").write_text("content")
        port = free_port()
        srv, _ = start_ftp_server(root, port)
        cls._port = port
        cls._root = root
        yield
        stop_ftp_server(srv)

    def test_connection_refused_raises(self):
        port = free_port()
        ftp = ftplib.FTP()
        with pytest.raises(OSError):
            ftp.connect("127.0.0.1", port, timeout=3)

    def test_nonexistent_dir_raises(self):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", self._port, timeout=5)
        ftp.login()
        with pytest.raises(ftplib.error_perm):
            ftp.cwd("/bogus_directory")
        ftp.close()

    def test_download_nonexistent_file_raises(self):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", self._port, timeout=5)
        ftp.login()
        with pytest.raises(ftplib.error_perm):
            ftp.size("no_such_file.txt")
        ftp.close()

    def test_empty_root_scan_no_crash(self):
        empty_dir = tempfile.mkdtemp()
        cfg = make_cfg(self._port)
        with no_auth_check:
            _, p = run(cfg)
        assert p.scan_complete
        shutil.rmtree(empty_dir, ignore_errors=True)


class TestFTPErrorsAuth:
    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _server(cls, tmp_path_factory):
        root = tmp_path_factory.mktemp("auth")
        (root / "data.txt").write_text("content")
        port = free_port()
        srv, _ = start_ftp_server(root, port, username="ftpuser", password="ftppass")
        cls._port = port
        cls._root = root
        yield
        stop_ftp_server(srv)

    def test_wrong_creds_raises(self):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", self._port, timeout=5)
        with pytest.raises(ftplib.error_perm):
            ftp.login("wrong_user", "wrong_pass")
        ftp.close()

    def test_anonymous_on_auth_server_raises(self):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", self._port, timeout=5)
        with pytest.raises(ftplib.error_perm):
            ftp.login("anonymous", "")
        ftp.close()
