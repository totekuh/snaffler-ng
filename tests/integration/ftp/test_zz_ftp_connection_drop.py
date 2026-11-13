"""
FTP connection drop test — separate file, fully self-contained.

Does NOT use conftest's start/stop to avoid poisoning asyncore for other files.
"""

import asyncore
import shutil
import socket
import tempfile
import threading
import time
import warnings
from pathlib import Path

import pytest

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)

pyftpdlib = pytest.importorskip("pyftpdlib")

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.runner import SnafflerRunner
from snaffler.utils.logger import set_finding_store


class TestConnectionDrop:

    def test_server_killed_mid_scan(self):
        """Scan returns gracefully when FTP server dies mid-walk."""
        root = tempfile.mkdtemp()
        try:
            for i in range(50):
                d = Path(root, f"dir_{i:03d}")
                d.mkdir()
                for j in range(5):
                    (d / f"file_{j}.txt").write_text(f"content {i}-{j}")

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()

            authorizer = DummyAuthorizer()
            authorizer.add_anonymous(root, perm="elr")
            handler = type("_H", (FTPHandler,), {
                "authorizer": authorizer,
                "passive_ports": range(60900, 61000),
                "banner": "drop-test",
            })
            asyncore.socket_map.clear()
            server = FTPServer(("127.0.0.1", port), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            time.sleep(0.3)

            def kill_after_delay():
                time.sleep(1.5)
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    server.close_all()

            killer = threading.Thread(target=kill_after_delay, daemon=True)
            killer.start()

            url = f"ftp://127.0.0.1:{port}/"
            c = SnafflerConfiguration()
            c.targets.ftp_targets = [url]
            c.targets.ftp_tls = False
            c.auth.smb_timeout = 10
            c.scanning.max_read_bytes = 2 * 1024 * 1024
            c.scanning.max_file_bytes = 10 * 1024 * 1024
            c.scanning.match_context_bytes = 200
            c.scanning.min_interest = 0
            c.advanced.share_threads = 2
            c.advanced.tree_threads = 4
            c.advanced.file_threads = 4
            c.state.state_db = ":memory:"
            RuleLoader.load(c)

            runner = SnafflerRunner(c)
            try:
                runner.execute()
            except SystemExit:
                pass

            assert runner.progress is not None
        finally:
            set_finding_store(None)
            asyncore.socket_map.clear()
            shutil.rmtree(root, ignore_errors=True)
