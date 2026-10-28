"""
Integration test: SMB snaffling against a real in-process SMB server.

Uses impacket's SimpleSMBServer to serve tests/data/ over SMB, then runs:
  1. SnafflerRunner (full pipeline) — anonymous + authenticated
  2. Snaffler library API with injected SMB walker/reader
  3. Subpath scanning (start from a subdirectory, not root)
  4. Resume across two runs
  5. --exclude-path, --match, --max-depth, --min-interest flags

No mocking — real SMB server, real rules, real classification engine.
"""

import hashlib
import logging
import socket
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)

smbserver = pytest.importorskip("impacket.smbserver")

from impacket.smbserver import SimpleSMBServer

from snaffler import Snaffler
from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.loader import RuleLoader
from snaffler.classifiers.rules import Triage
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.smb_tree_walker import SMBTreeWalker
from snaffler.engine.runner import SnafflerRunner
from snaffler.resume.scan_state import SQLiteStateStore
from snaffler.utils.logger import set_finding_store

_no_auth_check = patch.object(SnafflerRunner, "_validate_credentials")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


# ---------------------------------------------------------------------------
# SMB server helpers
# ---------------------------------------------------------------------------

def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _nt_hash(password):
    return hashlib.new("md4", password.encode("utf-16le")).hexdigest()


def _start_smb_server(root, port, share_name="TESTDATA", username=None, password=None):
    """Start an impacket SMB server in a daemon thread. Returns (server, thread)."""
    server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=port)
    server.setSMB2Support(True)
    # Make per-connection handler threads daemon so they don't block process exit
    server.getServer().daemon_threads = True
    server.addShare(share_name, str(root), "Test share")

    if username and password:
        nthash = _nt_hash(password)
        server.addCredential(username, 0, "", nthash)

    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    time.sleep(0.5)
    return server, thread


def _stop_smb_server(server, thread):
    try:
        server.getServer().shutdown()
    except Exception:
        pass
    try:
        server.stop()
    except Exception:
        pass
    thread.join(timeout=5)


@pytest.fixture()
def anon_smb():
    """Anonymous SMB server serving tests/data/ as TESTDATA share."""
    port = _free_port()
    server, thread = _start_smb_server(_DATA_DIR, port)
    yield port
    _stop_smb_server(server, thread)


@pytest.fixture()
def auth_smb():
    """Authenticated SMB server (smbuser/smbpass) serving tests/data/."""
    port = _free_port()
    server, thread = _start_smb_server(
        _DATA_DIR, port, username="smbuser", password="smbpass",
    )
    yield port
    _stop_smb_server(server, thread)


@pytest.fixture(autouse=True)
def _reset_finding_store():
    yield
    set_finding_store(None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cfg(port, subpath="", share="TESTDATA", username="", password=""):
    """Build SnafflerConfiguration targeting an SMB server."""
    unc = f"//127.0.0.1/{share}{subpath}"
    c = SnafflerConfiguration()
    c.targets.unc_targets = [unc]
    c.auth.username = username
    c.auth.password = password
    c.auth.smb_timeout = 10
    c.auth.smb_port = port
    c.scanning.max_read_bytes = 2 * 1024 * 1024
    c.scanning.max_file_bytes = 10 * 1024 * 1024
    c.scanning.match_context_bytes = 200
    c.scanning.min_interest = 0
    c.advanced.share_threads = 2
    c.advanced.tree_threads = 4
    c.advanced.file_threads = 4
    c.state.state_db = ":memory:"
    RuleLoader.load(c)
    return c


def _run(cfg):
    """Execute SnafflerRunner and return (runner, progress)."""
    runner = SnafflerRunner(cfg)
    runner.execute()
    return runner, runner.progress


# ---------------------------------------------------------------------------
# Runner: anonymous SMB
# ---------------------------------------------------------------------------

class TestRunnerAnonymous:

    def test_produces_findings(self, anon_smb):
        cfg = _make_cfg(anon_smb)
        _, p = _run(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_scans_more_than_matches(self, anon_smb):
        cfg = _make_cfg(anon_smb)
        _, p = _run(cfg)
        assert p.files_scanned > p.files_matched

    def test_severity_counts_sum(self, anon_smb):
        cfg = _make_cfg(anon_smb)
        _, p = _run(cfg)
        total = p.severity_black + p.severity_red + p.severity_yellow + p.severity_green
        assert total == p.files_matched

    def test_finds_black_severity(self, anon_smb):
        cfg = _make_cfg(anon_smb)
        _, p = _run(cfg)
        assert p.severity_black > 0

    def test_finds_red_severity(self, anon_smb):
        cfg = _make_cfg(anon_smb)
        _, p = _run(cfg)
        assert p.severity_red > 0

    def test_scan_complete_flag(self, anon_smb):
        cfg = _make_cfg(anon_smb)
        _, p = _run(cfg)
        assert p.scan_complete is True

    def test_findings_logged(self, anon_smb, caplog):
        cfg = _make_cfg(anon_smb)
        with caplog.at_level(logging.WARNING, logger="snaffler"):
            _run(cfg)
        findings = [r for r in caplog.records if "[Red]" in r.message or "[Black]" in r.message]
        assert len(findings) > 0

    def test_finding_paths_are_unc(self, anon_smb, caplog):
        """Finding paths in log output should be UNC paths."""
        cfg = _make_cfg(anon_smb)
        with caplog.at_level(logging.WARNING, logger="snaffler"):
            _run(cfg)
        unc_findings = [
            r for r in caplog.records
            if hasattr(r, "file_path") and r.file_path.startswith("//")
        ]
        assert len(unc_findings) > 0


# ---------------------------------------------------------------------------
# Runner: authenticated SMB
# ---------------------------------------------------------------------------

class TestRunnerAuthenticated:

    def test_produces_findings_with_creds(self, auth_smb):
        cfg = _make_cfg(auth_smb, username="smbuser", password="smbpass")
        _, p = _run(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_severity_counts_match(self, auth_smb):
        cfg = _make_cfg(auth_smb, username="smbuser", password="smbpass")
        _, p = _run(cfg)
        total = p.severity_black + p.severity_red + p.severity_yellow + p.severity_green
        assert total == p.files_matched

    def test_wrong_creds_no_findings(self, auth_smb):
        """Wrong credentials should produce zero findings."""
        cfg = _make_cfg(auth_smb, username="wrong", password="wrong")
        with _no_auth_check:
            _, p = _run(cfg)
        assert p.files_scanned == 0

    def test_consistent_results_across_runs(self, auth_smb):
        """Two authenticated scans of same data should find the same findings."""
        cfg1 = _make_cfg(auth_smb, username="smbuser", password="smbpass")
        _, p1 = _run(cfg1)

        cfg2 = _make_cfg(auth_smb, username="smbuser", password="smbpass")
        _, p2 = _run(cfg2)

        assert p1.files_matched == p2.files_matched
        assert p1.severity_black == p2.severity_black
        assert p1.severity_red == p2.severity_red


# ---------------------------------------------------------------------------
# Runner: subpath scanning
# ---------------------------------------------------------------------------

class TestRunnerSubpath:

    def test_subpath_scans_only_subtree(self, anon_smb):
        """Scanning from /home should only find files under /home."""
        cfg = _make_cfg(anon_smb, subpath="/home")
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        cfg.state.state_db = db_path

        try:
            _run(cfg)
            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            assert len(findings) > 0
            for f in findings:
                assert "/home/" in f["file_path"], f"Finding outside /home: {f['file_path']}"
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_subpath_fewer_findings_than_root(self, anon_smb):
        """Scanning a subpath should find fewer files than scanning root."""
        cfg_root = _make_cfg(anon_smb)
        _, p_root = _run(cfg_root)

        cfg_sub = _make_cfg(anon_smb, subpath="/home")
        _, p_sub = _run(cfg_sub)

        assert p_sub.files_scanned < p_root.files_scanned

    def test_deep_subpath(self, anon_smb):
        """Scanning a deep subpath like /home/user/.ssh should still work."""
        cfg = _make_cfg(anon_smb, subpath="/home/user/.ssh")
        _, p = _run(cfg)
        assert p.files_scanned >= 1


# ---------------------------------------------------------------------------
# Runner: flags
# ---------------------------------------------------------------------------

class TestRunnerFlags:

    def test_exclude_path(self, anon_smb):
        """--exclude-path should skip matching directories."""
        cfg = _make_cfg(anon_smb)
        _, p_full = _run(cfg)

        cfg_excl = _make_cfg(anon_smb)
        cfg_excl.targets.exclude_unc = ["*/home/*"]
        _, p_excl = _run(cfg_excl)

        assert p_excl.files_scanned < p_full.files_scanned

    def test_min_interest_filters(self, anon_smb):
        """--min-interest 2 should only report Red and Black."""
        cfg = _make_cfg(anon_smb)
        cfg.scanning.min_interest = 2
        _, p = _run(cfg)
        assert p.severity_green == 0
        assert p.severity_yellow == 0
        assert p.files_matched > 0

    def test_max_depth_zero(self, anon_smb):
        """--max-depth 0 scans only the root directory (no subdirs)."""
        cfg = _make_cfg(anon_smb)
        cfg.scanning.max_depth = 0
        _, p = _run(cfg)

        cfg_full = _make_cfg(anon_smb)
        _, p_full = _run(cfg_full)
        assert p.files_scanned < p_full.files_scanned

    def test_match_filter(self, anon_smb):
        """--match regex should only report findings matching the pattern."""
        cfg = _make_cfg(anon_smb)
        cfg.scanning.match_filter = r"\.pem"
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        cfg.state.state_db = db_path

        try:
            _run(cfg)
            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            assert len(findings) > 0
            for f in findings:
                assert ".pem" in f["file_path"].lower(), f"Non-pem finding: {f['file_path']}"
        finally:
            Path(db_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Runner: resume
# ---------------------------------------------------------------------------

class TestRunnerResume:

    def test_resume_no_new_findings(self, anon_smb):
        """Second run with same DB should not produce new findings."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg = _make_cfg(anon_smb)
            cfg.state.state_db = db_path
            _run(cfg)

            store = SQLiteStateStore(db_path)
            count1 = store.count_findings()
            store.close()

            cfg2 = _make_cfg(anon_smb)
            cfg2.state.state_db = db_path
            _run(cfg2)

            store = SQLiteStateStore(db_path)
            count2 = store.count_findings()
            store.close()

            assert count1 > 0
            assert count2 == count1
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_resume_restores_finding_counts(self, anon_smb):
        """On resume, progress should reflect findings from previous run."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg = _make_cfg(anon_smb)
            cfg.state.state_db = db_path
            _, p1 = _run(cfg)

            cfg2 = _make_cfg(anon_smb)
            cfg2.state.state_db = db_path
            _, p2 = _run(cfg2)

            assert p2.files_matched >= p1.files_matched
        finally:
            Path(db_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Library API with SMB transport
# ---------------------------------------------------------------------------

class TestLibraryAPI:

    def test_walk_produces_findings(self, anon_smb):
        """Snaffler.walk() with SMB walker/reader produces findings."""
        cfg = _make_cfg(anon_smb)
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"//127.0.0.1/TESTDATA"))

        assert len(findings) > 0
        assert all(isinstance(f, FileResult) for f in findings)

    def test_walk_paths_are_unc(self, anon_smb):
        cfg = _make_cfg(anon_smb)
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"//127.0.0.1/TESTDATA"))

        for f in findings:
            base = f.file_path.split("→")[0]
            assert base.startswith("//"), f"Non-UNC path: {f.file_path}"

    def test_walk_subpath(self, anon_smb):
        """walk() starting from a subpath only finds files under that path."""
        cfg = _make_cfg(anon_smb, subpath="/home")
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"//127.0.0.1/TESTDATA/home"))

        assert len(findings) > 0
        for f in findings:
            base = f.file_path.split("→")[0]
            assert "/home/" in base, f"Finding outside /home: {f.file_path}"

    def test_walk_with_auth(self, auth_smb):
        cfg = _make_cfg(auth_smb, username="smbuser", password="smbpass")
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"//127.0.0.1/TESTDATA"))

        assert len(findings) > 0

    def test_walk_severity_distribution(self, anon_smb):
        cfg = _make_cfg(anon_smb)
        walker = SMBTreeWalker(cfg)
        reader = SMBFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"//127.0.0.1/TESTDATA"))

        black = [f for f in findings if f.triage == Triage.BLACK]
        red = [f for f in findings if f.triage == Triage.RED]
        assert len(black) > 0
        assert len(red) > 0

    def test_walk_matches_runner_count(self, anon_smb):
        """Library API and runner should find the same number of findings."""
        cfg = _make_cfg(anon_smb)
        _, p = _run(cfg)

        cfg2 = _make_cfg(anon_smb)
        walker = SMBTreeWalker(cfg2)
        reader = SMBFileAccessor(cfg2)
        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"//127.0.0.1/TESTDATA"))

        assert len(findings) == p.files_matched
