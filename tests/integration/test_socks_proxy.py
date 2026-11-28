"""SOCKS proxy integration tests with network isolation.

Requires Docker containers started with --profile socks:
  - socks-proxy: microsocks SOCKS5 server bridging external_net and internal_net
  - socks-target: Samba file server on internal_net only

The test host must be able to reach socks-proxy but NOT socks-target
directly (when running inside Docker testrunner). Set env vars
SOCKS_PROXY_HOST and SOCKS_TARGET_HOST.
"""

import os
import re
import socket
import subprocess
from io import BytesIO
from unittest.mock import MagicMock

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


class TestDnsLeak:
    def test_no_dns_leak_to_system_resolver(self):
        """System resolver must never be called with the target hostname."""
        real_getaddrinfo = socket.getaddrinfo
        spy = MagicMock(wraps=real_getaddrinfo)
        socket.getaddrinfo = spy

        setup_socks_proxy(f"socks5://{PROXY_HOST}:{PROXY_PORT}")

        smb = SMBConnection(TARGET_HOST, TARGET_HOST, sess_port=445, timeout=10)
        smb.login("", "", "")
        smb.listShares()
        smb.close()

        leaked_hosts = [call.args[0] for call in spy.call_args_list if call.args and call.args[0] == TARGET_HOST]
        assert leaked_hosts == [], f"DNS leaked TARGET_HOST to system resolver: {spy.call_args_list}"

    def test_production_patch_enables_proxy_connection(self):
        """Production getaddrinfo patch alone (no test shim) must enable SMB through proxy."""
        setup_socks_proxy(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        smb = SMBConnection(TARGET_HOST, TARGET_HOST, sess_port=445, timeout=10)
        smb.login("", "", "")
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert "testdata" in shares
        smb.close()

    def test_hostname_passthrough_tuple_format(self):
        """After setup_socks_proxy(), getaddrinfo must return hostname passthrough, not an IP."""
        setup_socks_proxy(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
        result = socket.getaddrinfo(TARGET_HOST, 445)
        assert len(result) == 1
        assert result[0] == (socket.AF_INET, socket.SOCK_STREAM, 6, "", (TARGET_HOST, 445))


class TestDnsLeakWireLevel:
    """Packet-capture proof that no DNS queries leave the client."""

    @staticmethod
    def _tcpdump_packet_count(stderr_output: str) -> int:
        match = re.search(r"(\d+) packets? captured", stderr_output)
        return int(match.group(1)) if match else -1

    def test_no_dns_packets_on_client(self):
        """tcpdump on port 53 must capture zero packets during proxied SMB."""
        pcap = "/tmp/dns_leak_test.pcap"
        proc = subprocess.Popen(
            ["tcpdump", "-i", "any", "-w", pcap, "-c", "1", "port", "53"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            setup_socks_proxy(f"socks5://{PROXY_HOST}:{PROXY_PORT}")
            smb = SMBConnection(TARGET_HOST, TARGET_HOST, sess_port=445, timeout=10)
            smb.login("", "", "")
            smb.listShares()
            smb.close()
        finally:
            proc.terminate()
            _, stderr = proc.communicate(timeout=5)

        count = self._tcpdump_packet_count(stderr.decode(errors="replace"))
        assert count == 0, f"DNS leak detected: {count} packet(s) on port 53. stderr: {stderr.decode(errors='replace')}"


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

    def test_socks4_multiple_shares(self):
        smb = _connect_smb_socks4(f"socks4://{PROXY4_HOST}:{PROXY_PORT}")
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert "testdata" in shares
        assert "ipc$" in shares
        smb.close()

    def test_socks4_reconnect(self):
        smb1 = _connect_smb_socks4(f"socks4://{PROXY4_HOST}:{PROXY_PORT}")
        smb1.listShares()
        smb1.close()
        smb2 = _connect_smb_socks4(f"socks4://{PROXY4_HOST}:{PROXY_PORT}")
        shares = [s["shi1_netname"][:-1].lower() for s in smb2.listShares()]
        assert "testdata" in shares
        smb2.close()

    def test_socks4_unreachable_proxy_fails(self):
        setup_socks_proxy("socks4://192.0.2.1:1080")
        socket.getaddrinfo = _socks_getaddrinfo
        with pytest.raises(OSError):
            SMBConnection(TARGET_IP, TARGET_IP, sess_port=445, timeout=3)

    def test_socks4_wrong_proxy_port_fails(self):
        setup_socks_proxy(f"socks4://{PROXY4_HOST}:9999")
        socket.getaddrinfo = _socks_getaddrinfo
        with pytest.raises(OSError):
            SMBConnection(TARGET_IP, TARGET_IP, sess_port=445, timeout=3)

    def test_socks4_target_wrong_port_fails(self):
        setup_socks_proxy(f"socks4://{PROXY4_HOST}:{PROXY_PORT}")
        socket.getaddrinfo = _socks_getaddrinfo
        try:
            SMBConnection(TARGET_IP, TARGET_IP, sess_port=12345, timeout=3)
            pytest.fail("Expected connection to wrong port to raise")
        except OSError:
            pass
        except Exception as e:
            assert "answer" in str(e).lower() or "refused" in str(e).lower()

    def test_socks4_nonexistent_host_fails(self):
        setup_socks_proxy(f"socks4://{PROXY4_HOST}:{PROXY_PORT}")
        socket.getaddrinfo = _socks_getaddrinfo
        with pytest.raises(OSError):
            SMBConnection("192.0.2.99", "192.0.2.99", sess_port=445, timeout=5)
