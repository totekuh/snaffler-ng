"""Impacket SimpleSMBServer backend factory."""

import socket
import threading
import time
from pathlib import Path

from tests.smb_shared.target import SMBTarget

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _nt_hash(password):
    from impacket.ntlm import compute_nthash
    return compute_nthash(password).hex()


def _start_smb_server(root, port, share_name="TESTDATA", username=None, password=None):
    from impacket.smbserver import SimpleSMBServer

    server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=port)
    server.setSMB2Support(True)
    server.getServer().daemon_threads = True
    server.addShare(share_name, str(root), "Test share")

    if username and password:
        server.addCredential(username, 0, "", _nt_hash(password))

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


def impacket_smb_target():
    port = _free_port()
    server, thread = _start_smb_server(_DATA_DIR, port)
    yield SMBTarget(ip="127.0.0.1", port=port, share="TESTDATA")
    _stop_smb_server(server, thread)
