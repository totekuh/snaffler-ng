"""SOCKS + AD DNS leak tests.

Verifies that AD discovery (LDAP, Kerberos) through a SOCKS proxy
produces zero DNS queries on the client side. Requires Docker
containers started with --profile socks-ad.
"""

import os
import socket
import subprocess
from unittest.mock import MagicMock

import pytest
from impacket.smbconnection import SMBConnection

from snaffler.transport.socks import setup_socks_proxy

PROXY_HOST = os.environ.get("SOCKS_PROXY_HOST")
DC_HOST = os.environ.get("AD_DC_HOST")
DOMAIN = os.environ.get("AD_DOMAIN")
USERNAME = os.environ.get("AD_USER")
PASSWORD = os.environ.get("AD_PASS")


def _env_available():
    return all([PROXY_HOST, DC_HOST, DOMAIN, USERNAME, PASSWORD])


pytestmark = pytest.mark.skipif(
    not _env_available(),
    reason="SOCKS+AD env vars not set (need SOCKS_PROXY_HOST, AD_DC_HOST, AD_DOMAIN, AD_USER, AD_PASS)",
)


@pytest.fixture(autouse=True)
def restore_socket():
    original_socket = socket.socket
    original_getaddrinfo = socket.getaddrinfo
    yield
    socket.socket = original_socket
    socket.getaddrinfo = original_getaddrinfo


class TestSocksAdDnsLeak:
    def test_ad_scan_no_dns_leak(self):
        """Full snaffler AD scan through SOCKS must produce zero DNS packets."""
        pcap = "/tmp/ad_dns_leak.pcap"
        capture = subprocess.Popen(
            ["tcpdump", "-i", "any", "-w", pcap, "port", "53"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            subprocess.run(
                [
                    "snaffler",
                    "-d",
                    DOMAIN,
                    "--dc-host",
                    DC_HOST,
                    "-u",
                    USERNAME,
                    "-p",
                    PASSWORD,
                    "--socks",
                    f"socks5://{PROXY_HOST}:1080",
                    "--fast",
                    "--max-depth",
                    "1",
                ],
                timeout=60,
                capture_output=True,
            )
        finally:
            capture.terminate()
            capture.wait(timeout=5)

        assert os.path.exists(pcap), "pcap file not created"
        result = subprocess.run(
            ["tcpdump", "-r", pcap, "-nn", "port 53"],
            capture_output=True,
            text=True,
        )
        dns_packets = result.stdout.strip().splitlines()
        assert not dns_packets, f"DNS leak: {len(dns_packets)} packet(s):\n" + "\n".join(dns_packets)

    def test_ad_ldap_discovery_through_socks(self):
        """AD discovery through SOCKS must find provisioned computers."""
        from snaffler.config.configuration import SnafflerConfiguration
        from snaffler.discovery.ad import ADDiscovery

        setup_socks_proxy(f"socks5://{PROXY_HOST}:1080")

        cfg = SnafflerConfiguration()
        cfg.auth.domain = DOMAIN
        cfg.auth.dc_host = DC_HOST
        cfg.auth.username = USERNAME
        cfg.auth.password = PASSWORD
        cfg.auth.socks_proxy = f"socks5://{PROXY_HOST}:1080"
        cfg.targets.domain_users = False

        ad = ADDiscovery(cfg)
        computers = ad.get_domain_computers()
        hostnames = [c.upper() for c in computers]
        assert any("FILESERVER1" in h for h in hostnames)

    def test_ad_ldap_no_dns_leak_spy(self):
        """System resolver must not be called with DC hostname during AD discovery."""
        from snaffler.config.configuration import SnafflerConfiguration
        from snaffler.discovery.ad import ADDiscovery

        real_getaddrinfo = socket.getaddrinfo
        spy = MagicMock(wraps=real_getaddrinfo)
        socket.getaddrinfo = spy

        setup_socks_proxy(f"socks5://{PROXY_HOST}:1080")

        cfg = SnafflerConfiguration()
        cfg.auth.domain = DOMAIN
        cfg.auth.dc_host = DC_HOST
        cfg.auth.username = USERNAME
        cfg.auth.password = PASSWORD
        cfg.auth.socks_proxy = f"socks5://{PROXY_HOST}:1080"
        cfg.targets.domain_users = False

        ad = ADDiscovery(cfg)
        ad.get_domain_computers()

        leaked = [call.args[0] for call in spy.call_args_list if call.args and call.args[0] == DC_HOST]
        assert not leaked, f"DNS leaked DC hostname to system resolver: {spy.call_args_list}"


