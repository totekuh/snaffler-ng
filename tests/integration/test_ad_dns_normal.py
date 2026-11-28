"""Verify snaffler generates real DNS traffic when running without SOCKS.

Counterpart to the SOCKS DNS leak tests: proves DNS resolution works
normally when no proxy is configured. Requires the AD profile (DC
directly reachable) and tcpdump with NET_RAW capability.
"""

import os
import subprocess

import pytest

from tests.ad_env.conftest import AD_CONFIG, AD_ENABLED

pytestmark = pytest.mark.skipif(not AD_ENABLED, reason="AD DC not available")

DC_HOST = AD_CONFIG["dc_host"]
DOMAIN = AD_CONFIG["domain"]
USERNAME = AD_CONFIG["admin_user"]
PASSWORD = AD_CONFIG["admin_pass"]


class TestDnsNormalWithoutSocks:
    def test_ad_scan_generates_dns_traffic(self):
        """Snaffler AD scan without --socks must produce DNS packets on the client."""
        pcap = "/tmp/ad_dns_normal.pcap"
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

        # Diagnostic: dump all captured packets and iptables nat rules
        all_pkts = subprocess.run(
            ["tcpdump", "-r", pcap, "-nn"],
            capture_output=True,
            text=True,
        )
        iptables = subprocess.run(
            ["iptables", "-t", "nat", "-L", "OUTPUT", "-n"],
            capture_output=True,
            text=True,
        )
        resolv = subprocess.run(
            ["cat", "/etc/resolv.conf"],
            capture_output=True,
            text=True,
        )

        result = subprocess.run(
            ["tcpdump", "-r", pcap, "-nn", "port 53"],
            capture_output=True,
            text=True,
        )
        dns_packets = result.stdout.strip().splitlines()
        diag = (
            f"\n--- all packets ---\n{all_pkts.stdout or '(none)'}"
            f"\n--- iptables nat OUTPUT ---\n{iptables.stdout or iptables.stderr}"
            f"\n--- resolv.conf ---\n{resolv.stdout}"
        )
        assert dns_packets, f"No DNS packets on port 53.{diag}"
