"""SOCKS proxy integration tests with network isolation.

Requires Docker containers started with --profile socks:
  - socks-proxy: microsocks SOCKS5 server bridging external_net and internal_net
  - socks-target: Samba file server on internal_net only

The test host must be able to reach socks-proxy but NOT socks-target
directly (when running inside Docker testrunner). Set env vars
SOCKS_PROXY_HOST and SOCKS_TARGET_HOST.
"""

import os
import socket
from io import BytesIO

import pytest
import socks as pysocks
from impacket.smbconnection import SessionError, SMBConnection

from snaffler.transport.socks import setup_socks_proxy

PROXY_HOST = os.environ.get("SOCKS_PROXY_HOST")
PROXY4_HOST = os.environ.get("SOCKS4_PROXY_HOST")
PROXY_PORT = int(os.environ.get("SOCKS_PROXY_PORT", "1080"))
TARGET_HOST = os.environ.get("SOCKS_TARGET_HOST")
TARGET_IP = os.environ.get("SOCKS_TARGET_IP", "10.56.0.2")


def _socks_available():
    if not PROXY_HOST or not TARGET_HOST:
        return False
    try:
        with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=2):
            return True
    except (OSError, socket.timeout):
        return False


pytestmark = pytest.mark.skipif(
    not _socks_available(),
    reason="SOCKS proxy not available (set SOCKS_PROXY_HOST and SOCKS_TARGET_HOST)",
)


@pytest.fixture(autouse=True)
def restore_socket():
    original_socket = socket.socket
    original_getaddrinfo = socket.getaddrinfo
    yield
    socket.socket = original_socket
    socket.getaddrinfo = original_getaddrinfo


_original_getaddrinfo = socket.getaddrinfo


def _socks_getaddrinfo(host, port, family=0, type_=0, proto=0, flags=0):
    """When SOCKS is active, return the hostname as-is so PySocks
    resolves it via the proxy (rdns). getaddrinfo can't resolve
    hosts on the internal network, but PySocks connect() can."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]


def _connect_smb(proxy_url):
    setup_socks_proxy(proxy_url)
    socket.getaddrinfo = _socks_getaddrinfo
    smb = SMBConnection(TARGET_HOST, TARGET_HOST, sess_port=445, timeout=10)
    smb.login("", "", "")
    return smb


class TestNetworkIsolation:
    def test_proxy_reachable(self):
        with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=3):
            pass

    def test_target_not_directly_reachable_dns(self):
        """Target hostname must not resolve from runner's network."""
        with pytest.raises((OSError, socket.gaierror)):
            socket.getaddrinfo(TARGET_HOST, 445)

    def test_target_not_directly_reachable_ip(self):
        """TCP connect to target's known IP on internal_net must fail.
        This proves L3 routing isolation, not just DNS."""
        with pytest.raises((OSError, socket.timeout)):
            socket.create_connection((TARGET_IP, 445), timeout=3)

    def test_target_reachable_through_proxy(self):
        s = pysocks.socksocket()
        s.set_proxy(pysocks.SOCKS5, PROXY_HOST, PROXY_PORT)
        s.settimeout(5)
        s.connect((TARGET_HOST, 445))
        s.close()

    def test_proxy_on_different_network_than_target(self):
        """Verify the proxy has connectivity to both networks by
        successfully proxying a connection to the target."""
        s = pysocks.socksocket()
        s.set_proxy(pysocks.SOCKS5, PROXY_HOST, PROXY_PORT)
        s.settimeout(5)
        s.connect((TARGET_HOST, 445))
        s.close()


class TestSocksSMB:
    def test_socks5_share_enumeration(self):
        smb = _connect_smb(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert "testdata" in shares
        smb.close()

    def test_socks5_directory_listing(self):
        smb = _connect_smb(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        files = smb.listPath("testdata", "*")
        filenames = [f.get_longname() for f in files]
        assert len(filenames) > 0
        smb.close()

    def test_socks5_file_read(self):
        smb = _connect_smb(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        buf = BytesIO()
        files = smb.listPath("testdata", "*")
        regular_files = [
            f.get_longname() for f in files if not f.is_directory() and f.get_longname() not in (".", "..")
        ]
        assert len(regular_files) > 0
        smb.getFile("testdata", regular_files[0], buf.write)
        assert buf.tell() > 0
        smb.close()

    def test_bare_url_defaults_socks5(self):
        smb = _connect_smb(f"{PROXY_HOST}:{PROXY_PORT}")
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert "testdata" in shares
        smb.close()

    def test_multiple_shares_listed(self):
        smb = _connect_smb(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert "testdata" in shares
        assert "ipc$" in shares
        smb.close()

    def test_reconnect_after_close(self):
        smb = _connect_smb(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        smb.listShares()
        smb.close()
        smb2 = _connect_smb(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        shares = [s["shi1_netname"][:-1].lower() for s in smb2.listShares()]
        assert "testdata" in shares
        smb2.close()


class TestSocksErrors:
    def _setup_with_getaddrinfo(self, proxy_url):
        setup_socks_proxy(proxy_url)
        socket.getaddrinfo = _socks_getaddrinfo

    def test_unreachable_proxy_fails(self):
        self._setup_with_getaddrinfo("socks5://192.0.2.1:1080")
        with pytest.raises(OSError):
            SMBConnection(TARGET_HOST, TARGET_HOST, sess_port=445, timeout=3)

    def test_wrong_proxy_port_fails(self):
        self._setup_with_getaddrinfo(f"socks5://{PROXY_HOST}:9999")
        with pytest.raises(OSError):
            SMBConnection(TARGET_HOST, TARGET_HOST, sess_port=445, timeout=3)

    def test_target_wrong_port_fails(self):
        self._setup_with_getaddrinfo(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        with pytest.raises(OSError):
            SMBConnection(TARGET_HOST, TARGET_HOST, sess_port=12345, timeout=3)

    def test_target_nonexistent_host_fails(self):
        self._setup_with_getaddrinfo(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        with pytest.raises(OSError):
            SMBConnection("192.0.2.99", "192.0.2.99", sess_port=445, timeout=5)

    def test_nonexistent_share_fails(self):
        smb = _connect_smb(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        with pytest.raises(SessionError):
            smb.listPath("nonexistent_share_xyz", "*")
        smb.close()

    def test_socket_restored_after_fixture(self):
        original = socket.socket
        setup_socks_proxy(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        assert socket.socket is not original


# ------------------------------------------------------------------
# SOCKS4 tests (Dante proxy)
# ------------------------------------------------------------------


def _socks4_available():
    if not PROXY4_HOST:
        return False
    try:
        with socket.create_connection((PROXY4_HOST, PROXY_PORT), timeout=2):
            return True
    except (OSError, socket.timeout):
        return False


def _connect_smb_socks4(proxy_url):
    setup_socks_proxy(proxy_url)
    socket.getaddrinfo = _socks_getaddrinfo
    smb = SMBConnection(TARGET_IP, TARGET_IP, sess_port=445, timeout=10)
    smb.login("", "", "")
    return smb


@pytest.mark.skipif(
    not _socks4_available(),
    reason="SOCKS4 proxy not available (set SOCKS4_PROXY_HOST)",
)
class TestSocks4:
    def test_socks4_share_enumeration(self):
        smb = _connect_smb_socks4(f"socks4://{PROXY4_HOST}:{PROXY_PORT}")
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert "testdata" in shares
        smb.close()

    def test_socks4_directory_listing(self):
        smb = _connect_smb_socks4(f"socks4://{PROXY4_HOST}:{PROXY_PORT}")
        files = smb.listPath("testdata", "*")
        filenames = [f.get_longname() for f in files]
        assert len(filenames) > 0
        smb.close()

    def test_socks4_file_read(self):
        smb = _connect_smb_socks4(f"socks4://{PROXY4_HOST}:{PROXY_PORT}")
        buf = BytesIO()
        files = smb.listPath("testdata", "*")
        regular_files = [
            f.get_longname() for f in files if not f.is_directory() and f.get_longname() not in (".", "..")
        ]
        assert len(regular_files) > 0
        smb.getFile("testdata", regular_files[0], buf.write)
        assert buf.tell() > 0
        smb.close()

    def test_socks4_nonexistent_share_fails(self):
        smb = _connect_smb_socks4(f"socks4://{PROXY4_HOST}:{PROXY_PORT}")
        with pytest.raises(SessionError):
            smb.listPath("nonexistent_share_xyz", "*")
        smb.close()

    def test_socks4_connection_refused_fails(self):
        setup_socks_proxy(f"socks4://{PROXY4_HOST}:9999")
        socket.getaddrinfo = _socks_getaddrinfo
        with pytest.raises(OSError):
            SMBConnection(TARGET_IP, TARGET_IP, sess_port=445, timeout=3)
