"""
FTP flag/config integration tests: exclude paths, min interest, max depth,
match filters, subpath scanning.

Module-scoped anonymous server — one server for all tests in this file.
"""

import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)

pyftpdlib = pytest.importorskip("pyftpdlib")

from snaffler.resume.scan_state import SQLiteStateStore

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
    port = free_port()
    server, thread = start_ftp_server(_DATA_DIR, port)
    yield port
    stop_ftp_server(server)


class TestExcludePath:

    def test_exclude_path_works(self, ftp_server):
        cfg = make_cfg(ftp_server)
        cfg.targets.exclude_unc = ["*/home/*"]
        _, p = run(cfg)
        assert p.scan_complete
        assert p.files_scanned > 0


class TestMinInterest:

    def test_min_interest_filters_low_severity(self, ftp_server):
        cfg = make_cfg(ftp_server)
        cfg.scanning.min_interest = 2
        _, p = run(cfg)
        assert p.severity_green == 0
        assert p.severity_yellow == 0
        assert p.files_matched > 0


class TestMaxDepth:

    def test_depth_zero_scans_root_only(self, ftp_server):
        cfg = make_cfg(ftp_server)
        cfg.scanning.max_depth = 0
        _, p = run(cfg)
        assert p.scan_complete
        assert p.files_scanned < 50


class TestMatchFilter:

    def test_match_regex_pem_only(self, ftp_server):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg = make_cfg(ftp_server)
            cfg.scanning.match_filter = r"\.pem"
            cfg.state.state_db = db_path
            run(cfg)

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            assert len(findings) > 0
            for f in findings:
                assert ".pem" in f["file_path"].lower(), (
                    f"Non-pem finding: {f['file_path']}"
                )
        finally:
            Path(db_path).unlink(missing_ok=True)


class TestSubpath:

    def test_subpath_only_finds_subtree(self, ftp_server):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg = make_cfg(ftp_server, subpath="/home")
            cfg.state.state_db = db_path
            run(cfg)

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            assert len(findings) > 0
            for f in findings:
                assert "/home/" in f["file_path"], (
                    f"Finding outside /home: {f['file_path']}"
                )
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_subpath_scans_subset(self, ftp_server):
        cfg = make_cfg(ftp_server, subpath="/home")
        _, p = run(cfg)
        assert p.scan_complete
        assert p.files_scanned >= 1
        assert p.files_scanned < 50
