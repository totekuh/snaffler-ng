"""
FTP protocol-level error tests.

Separate module from other FTP tests to avoid asyncore socket map conflicts.
Single module-scoped server pair (anon + auth on different ports).
"""

import asyncore
import ftplib
import shutil
import tempfile
import threading
import time
import warnings

import pytest

pyftpdlib = pytest.importorskip("pyftpdlib")

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from tests.integration.ftp.conftest import free_port, make_cfg, no_auth_check, run

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")


def _fresh_range():
    _fresh_range.base = getattr(_fresh_range, "base", 61000) + 200
    return range(_fresh_range.base, _fresh_range.base + 100)


@pytest.fixture(scope="module")
def ftp_servers(tmp_path_factory):
    asyncore.socket_map.clear()

    anon_root = tmp_path_factory.mktemp("anon")
    (anon_root / "file.txt").write_text("content")
    auth_root = tmp_path_factory.mktemp("auth")
    (auth_root / "data.txt").write_text("content")

    anon_port = free_port()
    auth_port = free_port()

    anon_auth = DummyAuthorizer()
    anon_auth.add_anonymous(str(anon_root))

    auth_auth = DummyAuthorizer()
    auth_auth.add_user("ftpuser", "ftppass", str(auth_root), perm="elradfmw")

    class AnonHandler(FTPHandler):
        passive_ports = _fresh_range()
        banner = "anon-errors"

    AnonHandler.authorizer = anon_auth

    class AuthHandler(FTPHandler):
        passive_ports = _fresh_range()
        banner = "auth-errors"

    AuthHandler.authorizer = auth_auth

    anon_srv = FTPServer(("127.0.0.1", anon_port), AnonHandler)
    auth_srv = FTPServer(("127.0.0.1", auth_port), AuthHandler)

    t1 = threading.Thread(target=anon_srv.serve_forever, daemon=True)
    t2 = threading.Thread(target=auth_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()
    time.sleep(0.5)

    yield {"anon_port": anon_port, "auth_port": auth_port}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        anon_srv.close_all()
        auth_srv.close_all()
    asyncore.socket_map.clear()


class TestFTPErrors:
    def test_connection_refused_raises(self):
        port = free_port()
        ftp = ftplib.FTP()
        with pytest.raises(OSError):
            ftp.connect("127.0.0.1", port, timeout=3)

    def test_wrong_creds_raises(self, ftp_servers):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", ftp_servers["auth_port"], timeout=5)
        with pytest.raises(ftplib.error_perm):
            ftp.login("wrong_user", "wrong_pass")
        ftp.close()

    def test_anonymous_on_auth_server_raises(self, ftp_servers):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", ftp_servers["auth_port"], timeout=5)
        with pytest.raises(ftplib.error_perm):
            ftp.login("anonymous", "")
        ftp.close()

    def test_nonexistent_dir_raises(self, ftp_servers):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", ftp_servers["anon_port"], timeout=5)
        ftp.login()
        with pytest.raises(ftplib.error_perm):
            ftp.cwd("/bogus_directory")
        ftp.close()

    def test_download_nonexistent_file_raises(self, ftp_servers):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", ftp_servers["anon_port"], timeout=5)
        ftp.login()
        with pytest.raises(ftplib.error_perm):
            ftp.size("no_such_file.txt")
        ftp.close()

    def test_empty_root_scan_no_crash(self, ftp_servers):
        empty_dir = tempfile.mkdtemp()
        port = ftp_servers["anon_port"]
        cfg = make_cfg(port)
        with no_auth_check:
            _, p = run(cfg)
        assert p.scan_complete
        shutil.rmtree(empty_dir, ignore_errors=True)
