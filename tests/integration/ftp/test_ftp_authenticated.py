"""
FTP authenticated integration tests.

Module-scoped auth server — one server for all tests in this file.
"""

import pytest

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)

pyftpdlib = pytest.importorskip("pyftpdlib")

from tests.integration.ftp.conftest import (
    _DATA_DIR,
    free_port,
    make_cfg,
    no_auth_check,
    run,
    start_ftp_server,
    stop_ftp_server,
)


@pytest.fixture(scope="module")
def ftp_server():
    port = free_port()
    server, thread = start_ftp_server(
        _DATA_DIR, port, username="ftpuser", password="ftppass",
    )
    yield port
    stop_ftp_server(server)


class TestFTPAuthenticated:

    def test_correct_creds_produce_findings(self, ftp_server):
        cfg = make_cfg(ftp_server, username="ftpuser", password="ftppass")
        _, p = run(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_wrong_creds_no_findings(self, ftp_server):
        cfg = make_cfg(ftp_server, username="wrong", password="wrong")
        with no_auth_check:
            _, p = run(cfg)
        assert p.files_scanned == 0

    def test_anonymous_rejected_on_auth_server(self, ftp_server):
        cfg = make_cfg(ftp_server)
        with no_auth_check:
            _, p = run(cfg)
        assert p.files_scanned == 0

    def test_consistent_across_runs(self, ftp_server):
        cfg1 = make_cfg(ftp_server, username="ftpuser", password="ftppass")
        _, p1 = run(cfg1)

        cfg2 = make_cfg(ftp_server, username="ftpuser", password="ftppass")
        _, p2 = run(cfg2)

        assert p1.files_matched == p2.files_matched
        assert p1.severity_black == p2.severity_black
        assert p1.severity_red == p2.severity_red
