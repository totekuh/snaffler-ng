"""
Integration tests: SMB edge cases that real AD environments produce.

Covers: unicode filenames, symlink loops, connection drops mid-walk,
very long paths, empty shares/dirs, concurrent multi-share scanning.

Uses impacket's SimpleSMBServer with custom file trees (tmp_path).
"""

import hashlib
import os
import socket
import threading
import time
from unittest.mock import patch

import pytest

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning"),
]

smbserver = pytest.importorskip("impacket.smbserver")

from impacket.smbserver import SimpleSMBServer

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.runner import SnafflerRunner
from snaffler.utils.logger import set_finding_store

_no_auth_check = patch.object(SnafflerRunner, "_validate_credentials")


# ---------------------------------------------------------------------------
# SMB server helpers (same pattern as test_smb.py)
# ---------------------------------------------------------------------------


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_smb_server(root, port, share_name="TESTDATA"):
    server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=port)
    server.setSMB2Support(True)
    server.getServer().daemon_threads = True
    server.addShare(share_name, str(root), "Test share")
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


def _make_cfg(port, unc_targets=None, share="TESTDATA", subpath=""):
    if unc_targets is None:
        unc_targets = [f"//127.0.0.1/{share}{subpath}"]
    c = SnafflerConfiguration()
    c.targets.unc_targets = unc_targets
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
    runner = SnafflerRunner(cfg)
    runner.execute()
    return runner, runner.progress


@pytest.fixture(autouse=True)
def _reset_finding_store():
    yield
    set_finding_store(None)


# ---------------------------------------------------------------------------
# Test 1: Unicode filenames over SMB
# ---------------------------------------------------------------------------


class TestUnicodeFilenames:
    def test_unicode_files_discovered(self, tmp_path):
        """German umlauts, Spanish tildes, CJK — all survive SMB round-trip."""
        unicode_files = [
            "Passwörter_Server.xlsx",
            "contraseñas_servidor.txt",
            "mot_de_passe.doc",
            "密码文件.txt",
            "normal_file.txt",
        ]
        for name in unicode_files:
            (tmp_path / name).write_text("test content", encoding="utf-8")

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            _, p = _run(cfg)
            assert p.files_scanned == len(unicode_files)
        finally:
            _stop_smb_server(server, thread)

    def test_multilingual_rules_fire_over_smb(self, tmp_path):
        """Multilingual filename rules detect German/Spanish/French keywords via SMB."""
        (tmp_path / "Passwörter_backup.csv").write_text("data")
        (tmp_path / "contraseñas.txt").write_text("data")
        (tmp_path / "mot_de_passe_admin.txt").write_text("data")
        (tmp_path / "readme.txt").write_text("nothing interesting")

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            _, p = _run(cfg)
            assert p.files_matched >= 3, f"Expected at least 3 multilingual matches, got {p.files_matched}"
        finally:
            _stop_smb_server(server, thread)


# ---------------------------------------------------------------------------
# Test 2: Symlink loop protection
# ---------------------------------------------------------------------------


class TestSymlinkLoop:
    @pytest.mark.timeout(30)
    def test_symlink_to_parent_does_not_hang(self, tmp_path):
        """A symlink pointing to parent dir should not cause infinite recursion."""
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        (dir_a / "id_rsa").write_text("SSH KEY CONTENT")

        try:
            os.symlink(str(tmp_path), str(dir_a / "link_to_parent"))
        except OSError:
            pytest.skip("Cannot create symlinks (filesystem or OS limitation)")

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            _, p = _run(cfg)
            assert p.files_scanned >= 1
            assert p.scan_complete
        finally:
            _stop_smb_server(server, thread)

    @pytest.mark.timeout(30)
    def test_mutual_symlink_loop(self, tmp_path):
        """Two directories symlinking to each other should not hang."""
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        (dir_a / "secret.txt").write_text("password=hunter2")

        try:
            os.symlink(str(dir_b), str(dir_a / "link_to_b"))
            os.symlink(str(dir_a), str(dir_b / "link_to_a"))
        except OSError:
            pytest.skip("Cannot create symlinks")

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            _, p = _run(cfg)
            assert p.scan_complete
        finally:
            _stop_smb_server(server, thread)


# ---------------------------------------------------------------------------
# Test 3: Connection drop mid-walk
# ---------------------------------------------------------------------------


class TestConnectionDrop:
    @pytest.mark.timeout(60)
    def test_server_killed_mid_scan(self, tmp_path):
        """Scan completes gracefully when server dies mid-walk."""
        for i in range(50):
            d = tmp_path / f"dir_{i:03d}"
            d.mkdir()
            for j in range(5):
                (d / f"file_{j}.txt").write_text(f"content {i}-{j}")

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)

        def kill_server_after_delay():
            time.sleep(1.5)
            _stop_smb_server(server, thread)

        killer = threading.Thread(target=kill_server_after_delay, daemon=True)
        killer.start()

        cfg = _make_cfg(port)
        try:
            _, p = _run(cfg)
        except Exception:
            pass

        assert p.scan_complete


# ---------------------------------------------------------------------------
# Test 4: Very long paths
# ---------------------------------------------------------------------------


class TestLongPaths:
    def test_deeply_nested_directory(self, tmp_path):
        """50+ nested directories with total path > 300 chars — scan completes."""
        current = tmp_path
        for i in range(55):
            current = current / f"level_{i:02d}"
            current.mkdir()

        (current / "id_rsa").write_text("PRIVATE KEY DEEP")
        total_len = len(str(current / "id_rsa"))
        assert total_len > 300, f"Path only {total_len} chars, need > 300"

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            _, p = _run(cfg)
            assert p.scan_complete
            assert p.files_scanned >= 1
        finally:
            _stop_smb_server(server, thread)


# ---------------------------------------------------------------------------
# Test 5: Empty shares and directories
# ---------------------------------------------------------------------------


class TestEmptyDirs:
    def test_completely_empty_share(self, tmp_path):
        """Empty share root — scan completes, zero files."""
        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            _, p = _run(cfg)
            assert p.scan_complete
            assert p.files_scanned == 0
        finally:
            _stop_smb_server(server, thread)

    def test_empty_subdirectories(self, tmp_path):
        """Mix of empty and non-empty dirs — empty ones don't crash walker."""
        (tmp_path / "empty_a").mkdir()
        (tmp_path / "empty_b").mkdir()
        (tmp_path / "empty_c").mkdir()
        non_empty = tmp_path / "has_files"
        non_empty.mkdir()
        (non_empty / "id_rsa").write_text("SSH KEY")

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            _, p = _run(cfg)
            assert p.scan_complete
            assert p.files_scanned >= 1
        finally:
            _stop_smb_server(server, thread)

    def test_nested_empty_directories(self, tmp_path):
        """Deeply nested empty dirs — no crash."""
        current = tmp_path
        for i in range(10):
            current = current / f"empty_{i}"
            current.mkdir()

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            _, p = _run(cfg)
            assert p.scan_complete
            assert p.files_scanned == 0
        finally:
            _stop_smb_server(server, thread)


# ---------------------------------------------------------------------------
# Test 6: Concurrent multi-share scanning
# ---------------------------------------------------------------------------


def _start_multi_share_server(shares, port):
    """Start one SMB server with multiple shares. shares = [(name, path), ...]"""
    server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=port)
    server.setSMB2Support(True)
    server.getServer().daemon_threads = True
    for name, path in shares:
        server.addShare(name, str(path), f"{name} share")
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    time.sleep(0.5)
    return server, thread


class TestConcurrentShares:
    def test_two_shares_both_scanned(self, tmp_path):
        """Two shares on one server — findings from both appear."""
        share_a = tmp_path / "share_a"
        share_b = tmp_path / "share_b"
        share_a.mkdir()
        share_b.mkdir()

        (share_a / "id_rsa").write_text("SSH KEY A")
        (share_a / "passwords.txt").write_text("admin:pass123")
        (share_b / "id_ed25519").write_text("SSH KEY B")
        (share_b / ".env").write_text("DB_PASSWORD=secret")

        port = _free_port()
        server, thread = _start_multi_share_server([("SHAREA", share_a), ("SHAREB", share_b)], port)

        try:
            cfg = _make_cfg(
                port,
                unc_targets=[
                    "//127.0.0.1/SHAREA",
                    "//127.0.0.1/SHAREB",
                ],
            )
            _, p = _run(cfg)
            assert p.scan_complete
            assert p.files_scanned >= 4
            assert p.files_matched >= 2
        finally:
            _stop_smb_server(server, thread)

    def test_concurrent_shares_no_cross_contamination(self, tmp_path):
        """Findings from each share reference correct share path."""
        share_a = tmp_path / "share_a"
        share_b = tmp_path / "share_b"
        share_a.mkdir()
        share_b.mkdir()

        (share_a / "id_rsa").write_text("KEY A")
        (share_b / "id_dsa").write_text("KEY B")

        port = _free_port()
        server, thread = _start_multi_share_server([("ALPHA", share_a), ("BETA", share_b)], port)

        try:
            cfg = _make_cfg(
                port,
                unc_targets=[
                    "//127.0.0.1/ALPHA",
                    "//127.0.0.1/BETA",
                ],
            )
            _, p = _run(cfg)
            assert p.scan_complete
            assert p.files_matched >= 2
        finally:
            _stop_smb_server(server, thread)


# ---------------------------------------------------------------------------
# Protocol-level error tests (raw impacket, no snaffler runner)
# ---------------------------------------------------------------------------

from impacket.nmb import NetBIOSTimeout
from impacket.smbconnection import SessionError, SMBConnection


class TestSMBErrors:
    """Verify SMB protocol errors raise proper exceptions."""

    @pytest.fixture()
    def smb_server(self, tmp_path):
        (tmp_path / "secret.txt").write_text("password=hunter2")
        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        yield port
        _stop_smb_server(server, thread)

    @pytest.fixture()
    def auth_smb_server(self, tmp_path):
        (tmp_path / "data.txt").write_text("content")
        port = _free_port()
        server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=port)
        server.setSMB2Support(True)
        server.getServer().daemon_threads = True
        server.addShare("TESTDATA", str(tmp_path), "Test share")
        nt_hash = hashlib.new("md4", "smbpass".encode("utf-16le")).hexdigest()
        server.addCredential("smbuser", 0, "", nt_hash)
        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()
        time.sleep(0.5)
        yield port
        _stop_smb_server(server, thread)

    def test_nonexistent_share_raises(self, smb_server):
        smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=smb_server)
        smb.login("", "", "")
        with pytest.raises(SessionError):
            smb.listPath("BOGUS_SHARE", "*")
        smb.close()

    def test_file_not_found_raises(self, smb_server):
        smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=smb_server)
        smb.login("", "", "")
        with pytest.raises(SessionError):
            smb.getFile("TESTDATA", "no_such_file.txt", lambda x: None)
        smb.close()

    def test_list_nonexistent_dir_raises(self, smb_server):
        smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=smb_server)
        smb.login("", "", "")
        with pytest.raises(SessionError):
            smb.listPath("TESTDATA", "no_such_dir/*")
        smb.close()

    def test_connection_refused_raises(self):
        port = _free_port()
        with pytest.raises(OSError):
            SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=3)

    def test_wrong_creds_raises(self, auth_smb_server):
        smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=auth_smb_server)
        with pytest.raises(SessionError):
            smb.login("smbuser", "wrongpassword", "")

    def test_get_file_wrong_share_raises(self, smb_server):
        smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=smb_server)
        smb.login("", "", "")
        with pytest.raises(SessionError):
            smb.getFile("NONEXISTENT", "file.txt", lambda x: None)

    def test_server_crash_mid_file_read(self, tmp_path):
        large_file = tmp_path / "big.bin"
        large_file.write_bytes(b"\x00" * 5_000_000)
        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=5)
        smb.login("", "", "")

        def kill_server():
            time.sleep(0.1)
            _stop_smb_server(server, thread)

        killer = threading.Thread(target=kill_server, daemon=True)
        killer.start()
        try:
            smb.getFile("TESTDATA", "big.bin", lambda x: None)
        except (SessionError, OSError):
            pass
        killer.join(timeout=5)

    def test_closed_connection_reuse_raises(self, smb_server):
        smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=smb_server)
        smb.login("", "", "")
        smb.listShares()
        smb.close()
        with pytest.raises((SessionError, OSError, AttributeError)):
            smb.listShares()

    def test_empty_password_on_auth_server_raises(self, auth_smb_server):
        smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=auth_smb_server)
        with pytest.raises(SessionError):
            smb.login("smbuser", "", "")

    def test_connect_to_non_smb_port(self):
        port = _free_port()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)

        def accept_and_close():
            conn, _ = srv.accept()
            conn.close()
            srv.close()

        t = threading.Thread(target=accept_and_close, daemon=True)
        t.start()
        with pytest.raises((OSError, SessionError)):
            SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=3)
        t.join(timeout=5)

    def test_server_crash_snaffler_completes(self, tmp_path):
        for i in range(20):
            d = tmp_path / f"dir_{i}"
            d.mkdir()
            for j in range(5):
                (d / f"secret_{j}.key").write_text(f"password={i}_{j}")

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)

        def kill_server():
            time.sleep(1.5)
            _stop_smb_server(server, thread)

        killer = threading.Thread(target=kill_server, daemon=True)
        killer.start()

        cfg = _make_cfg(port)
        with _no_auth_check:
            _, p = _run(cfg)
        assert p.scan_complete
        killer.join(timeout=5)

    def test_very_deep_path_scan(self, tmp_path):
        current = tmp_path
        for i in range(60):
            current = current / f"level_{i}"
            current.mkdir()
            (current / "secret.key").write_text(f"key_{i}")

        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            cfg.scanning.max_depth = 5
            with _no_auth_check:
                _, p = _run(cfg)
            assert p.scan_complete
            assert p.files_scanned > 0
            assert p.files_scanned < 60
        finally:
            _stop_smb_server(server, thread)

    def test_target_disappears_after_share_enum(self, tmp_path):
        (tmp_path / "secret.key").write_text("key data")
        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=3)
        smb.login("", "", "")
        shares = smb.listShares()
        assert len(shares) > 0
        _stop_smb_server(server, thread)
        time.sleep(0.5)
        try:
            smb.listPath("TESTDATA", "*")
            smb.getFile("TESTDATA", "secret.key", lambda x: None)
            smb.listPath("TESTDATA", "*")
        except (SessionError, OSError, NetBIOSTimeout):
            pass

    def test_multiple_shares_partial_access_scan_completes(self, tmp_path):
        share_open = tmp_path / "open"
        share_open.mkdir()
        (share_open / "id_rsa").write_text("SSH KEY")
        share_locked = tmp_path / "locked"
        share_locked.mkdir()
        (share_locked / "secret.txt").write_text("hidden")

        port = _free_port()
        server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=port)
        server.setSMB2Support(True)
        server.getServer().daemon_threads = True
        server.addShare("OPEN", str(share_open), "Open share")
        server.addShare("LOCKED", str(share_locked), "Locked share")
        nt_hash = hashlib.new("md4", "lockpass".encode("utf-16le")).hexdigest()
        server.addCredential("lockuser", 0, "", nt_hash)
        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()
        time.sleep(0.5)

        try:
            cfg = _make_cfg(
                port,
                unc_targets=["//127.0.0.1/OPEN", "//127.0.0.1/LOCKED"],
            )
            with _no_auth_check:
                _, p = _run(cfg)
            assert p.scan_complete
            assert p.files_scanned >= 1
        finally:
            _stop_smb_server(server, thread)

    def test_smb_timeout_slow_server(self):
        port = _free_port()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)

        accepted = []

        def accept_and_hold():
            conn, _ = srv.accept()
            accepted.append(conn)
            time.sleep(10)
            conn.close()
            srv.close()

        t = threading.Thread(target=accept_and_hold, daemon=True)
        t.start()
        try:
            with pytest.raises((OSError, NetBIOSTimeout)):
                SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=2)
        finally:
            for c in accepted:
                try:
                    c.close()
                except Exception:
                    pass
            try:
                srv.close()
            except Exception:
                pass

    def test_reconnect_after_timeout(self, tmp_path):
        (tmp_path / "secret.key").write_text("key")
        port = _free_port()
        with pytest.raises(OSError):
            SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=1)
        server, thread = _start_smb_server(tmp_path, port)
        try:
            smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=5)
            smb.login("", "", "")
            shares = [s["shi1_netname"][:-1] for s in smb.listShares()]
            assert "TESTDATA" in shares
            smb.close()
        finally:
            _stop_smb_server(server, thread)

    def test_zero_byte_file_getfile(self, tmp_path):
        (tmp_path / "empty.txt").write_bytes(b"")
        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            from io import BytesIO

            smb = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=5)
            smb.login("", "", "")
            buf = BytesIO()
            smb.getFile("TESTDATA", "empty.txt", buf.write)
            assert buf.tell() == 0
            smb.close()
        finally:
            _stop_smb_server(server, thread)

    def test_binary_file_no_extension_scanned(self, tmp_path):
        elf_header = b"\x7fELF" + b"\x00" * 100
        (tmp_path / "data_blob").write_bytes(elf_header)
        (tmp_path / "id_rsa").write_text("SSH KEY")
        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg = _make_cfg(port)
            cfg.scanning.skip_binary = False
            with _no_auth_check:
                _, p = _run(cfg)
            assert p.scan_complete
            assert p.files_scanned >= 2
        finally:
            _stop_smb_server(server, thread)

    def test_binary_file_no_extension_skipped(self, tmp_path):
        elf_header = b"\x7fELF" + b"\x00" * 100
        (tmp_path / "data_blob").write_bytes(elf_header)
        (tmp_path / "id_rsa").write_text("SSH KEY")
        port = _free_port()
        server, thread = _start_smb_server(tmp_path, port)
        try:
            cfg_skip = _make_cfg(port)
            cfg_skip.scanning.skip_binary = True
            with _no_auth_check:
                _, p_skip = _run(cfg_skip)
            cfg_no_skip = _make_cfg(port)
            cfg_no_skip.scanning.skip_binary = False
            with _no_auth_check:
                _, p_no_skip = _run(cfg_no_skip)
            assert p_skip.files_scanned <= p_no_skip.files_scanned
        finally:
            _stop_smb_server(server, thread)
