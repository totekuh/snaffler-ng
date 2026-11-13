"""
FTPS (FTP over TLS) integration tests.

Module-scoped FTPS server with self-signed cert — one server for all tests.
"""

import pytest

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)

pyftpdlib = pytest.importorskip("pyftpdlib")

from tests.integration.ftp.conftest import (
    _DATA_DIR,
    free_port,
    generate_test_cert,
    make_cfg,
    run,
    start_ftps_server,
    stop_ftp_server,
)


@pytest.fixture(scope="module")
def ftps_server(tmp_path_factory):
    cert_dir = tmp_path_factory.mktemp("certs")
    certfile, keyfile = generate_test_cert(cert_dir)
    port = free_port()
    server, thread = start_ftps_server(_DATA_DIR, port, certfile, keyfile)
    yield port
    stop_ftp_server(server)


class TestFTPS:

    def test_ftps_produces_findings(self, ftps_server):
        cfg = make_cfg(ftps_server, tls=True)
        _, p = run(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0
        assert p.scan_complete

    def test_ftps_severity_distribution(self, ftps_server):
        cfg = make_cfg(ftps_server, tls=True)
        _, p = run(cfg)
        assert p.severity_black > 0
        assert p.severity_red > 0
        total = p.severity_black + p.severity_red + p.severity_yellow + p.severity_green
        assert total == p.files_matched

    def test_ftps_scan_complete(self, ftps_server):
        cfg = make_cfg(ftps_server, tls=True)
        _, p = run(cfg)
        assert p.scan_complete is True
