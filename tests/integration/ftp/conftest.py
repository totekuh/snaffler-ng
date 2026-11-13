"""Shared FTP test infrastructure.

pyftpdlib uses asyncore's process-global socket map. Only ONE FTPServer
can be alive per process at a time. Each test FILE gets a module-scoped
fixture that starts a server on setup and tears it down on module exit.
No inline server creation inside tests.
"""

import asyncore
import ipaddress
import os
import socket
import threading
import time
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest

pyftpdlib = pytest.importorskip("pyftpdlib")

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.runner import SnafflerRunner
from snaffler.utils.logger import set_finding_store

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"

_next_passive_base = [61000]


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fresh_passive_range():
    base = _next_passive_base[0]
    _next_passive_base[0] += 100
    return range(base, base + 100)


def _nuke_asyncore():
    asyncore.socket_map.clear()


def start_ftp_server(root, port, username=None, password=None):
    _nuke_asyncore()

    authorizer = DummyAuthorizer()
    if username:
        authorizer.add_user(username, password, str(root), perm="elr")
    else:
        authorizer.add_anonymous(str(root), perm="elr")

    handler = type("_FTPHandler", (FTPHandler,), {
        "authorizer": authorizer,
        "passive_ports": _fresh_passive_range(),
        "banner": "test-ftp-server",
    })

    server = FTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    server._test_thread = thread
    return server, thread


def start_ftps_server(root, port, certfile, keyfile, username=None, password=None):
    _nuke_asyncore()

    authorizer = DummyAuthorizer()
    if username:
        authorizer.add_user(username, password, str(root), perm="elr")
    else:
        authorizer.add_anonymous(str(root), perm="elr")

    handler = type("_TLSHandler", (TLS_FTPHandler,), {
        "authorizer": authorizer,
        "passive_ports": _fresh_passive_range(),
        "banner": "test-ftps-server",
        "certfile": str(certfile),
        "keyfile": str(keyfile),
        "tls_control_required": False,
        "tls_data_required": False,
    })

    server = FTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    server._test_thread = thread
    return server, thread


def stop_ftp_server(server):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            server.close_all()
        except Exception:
            pass
    thread = getattr(server, "_test_thread", None)
    if thread:
        thread.join(timeout=2)


def make_cfg(port, subpath="/", username="", password="", tls=False):
    url = f"ftp://127.0.0.1:{port}{subpath}"
    c = SnafflerConfiguration()
    c.targets.ftp_targets = [url]
    c.targets.ftp_tls = tls
    c.auth.username = username
    c.auth.password = password
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
    return c


def run(cfg):
    runner = SnafflerRunner(cfg)
    runner.execute()
    return runner, runner.progress


def generate_test_cert(cert_dir):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    certfile = Path(cert_dir) / "server.crt"
    keyfile = Path(cert_dir) / "server.key"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return certfile, keyfile


no_auth_check = patch.object(SnafflerRunner, "_validate_credentials")


@pytest.fixture(autouse=True)
def _reset_state():
    yield
    set_finding_store(None)
