"""Verify snaffler generates real DNS traffic when running without SOCKS.

Counterpart to the SOCKS DNS leak tests: proves DNS resolution works
normally when no proxy is configured. Requires the AD profile (DC
directly reachable) and tcpdump with NET_RAW capability.
"""

import subprocess

import pytest

from tests.ad_env.conftest import AD_CONFIG, AD_ENABLED
from tests.integration.conftest import read_pcap_packets, start_tcpdump

pytestmark = pytest.mark.skipif(not AD_ENABLED, reason="AD DC not available")

DC_HOST = AD_CONFIG["dc_host"]
DOMAIN = AD_CONFIG["domain"]
USERNAME = AD_CONFIG["admin_user"]
PASSWORD = AD_CONFIG["admin_pass"]


class TestDnsNormalWithoutSocks:
    def test_ad_scan_generates_dns_traffic(self):
        """Snaffler AD scan without --socks must produce DNS packets on the client."""
        pcap = "/tmp/ad_dns_normal.pcap"
        capture = start_tcpdump(pcap)

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

        dns_packets = read_pcap_packets(pcap)
        assert dns_packets, "No DNS packets — without SOCKS, snaffler should generate real DNS traffic"
