"""Integration tests for custom DNS resolution via a real dnslib server."""

import socket
import time
from unittest.mock import patch

import pytest
from dnslib import RR, A, QTYPE, RCODE
from dnslib.server import DNSServer, BaseResolver

from snaffler.transport.dns import setup_custom_dns, _original_getaddrinfo


# ── Test DNS server ──────────────────────────────────────────────────

DNS_RECORDS = {
    "testhost.lab": "10.99.99.1",
    "dc01.corp.local": "192.168.1.10",
    "multi.lab": ["10.0.0.1", "10.0.0.2"],
}


class LabResolver(BaseResolver):
    def __init__(self, records):
        self.records = records

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        if qname in self.records:
            val = self.records[qname]
            if isinstance(val, list):
                for ip in val:
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))
            else:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(val), ttl=60))
        else:
            reply.header.rcode = getattr(RCODE, "NXDOMAIN", 3)
        return reply


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def dns_server():
    port = _free_port()
    resolver = LabResolver(DNS_RECORDS)
    server = DNSServer(resolver, port=port, address="127.0.0.1", tcp=True)
    server.start_thread()
    time.sleep(0.3)
    yield port
    server.stop()


@pytest.fixture(autouse=True)
def _restore_getaddrinfo():
    original = socket.getaddrinfo
    yield
    socket.getaddrinfo = original


# ── Server lifecycle ─────────────────────────────────────────────────

def test_dns_server_starts_and_stops(dns_server):
    import dns.resolver
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ["127.0.0.1"]
    r.port = dns_server

    answers = r.resolve("testhost.lab", "A", tcp=True)
    ips = [str(rdata) for rdata in answers]
    assert "10.99.99.1" in ips


# ── setup_custom_dns() validation ────────────────────────────────────

def test_setup_rejects_hostname(dns_server):
    with pytest.raises(ValueError, match="must be an IP address"):
        setup_custom_dns("not-an-ip", port=dns_server)


def test_setup_rejects_missing_dnspython(dns_server):
    with patch.dict("sys.modules", {"dns.resolver": None, "dns": None}):
        with pytest.raises(ImportError, match="dnspython"):
            setup_custom_dns("127.0.0.1", port=dns_server)


def test_setup_accepts_ipv4(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)


def test_setup_accepts_ipv6(dns_server):
    setup_custom_dns("::1", port=dns_server)


# ── Monkey-patched getaddrinfo — real DNS queries ────────────────────

def test_resolves_known_host(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)

    results = socket.getaddrinfo("testhost.lab", 445)
    assert len(results) >= 1
    family, socktype, proto, canonname, sockaddr = results[0]
    assert sockaddr[0] == "10.99.99.1"
    assert sockaddr[1] == 445


def test_passthrough_none_host(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)

    results = socket.getaddrinfo(None, 80, socket.AF_INET, socket.SOCK_STREAM)
    assert len(results) >= 1


def test_passthrough_ip_address(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)

    results = socket.getaddrinfo("1.2.3.4", 445, socket.AF_INET, socket.SOCK_STREAM)
    assert len(results) >= 1
    assert results[0][4][0] == "1.2.3.4"


def test_unknown_host_raises_gaierror(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)

    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("nonexistent.invalid.lab", 445)


def test_string_port_service_name(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)

    results = socket.getaddrinfo("testhost.lab", "http")
    assert len(results) >= 1
    assert results[0][4][0] == "10.99.99.1"
    assert results[0][4][1] == 80


def test_none_port_becomes_zero(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)

    results = socket.getaddrinfo("testhost.lab", None)
    assert len(results) >= 1
    assert results[0][4][1] == 0


def test_multiple_records(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)

    results = socket.getaddrinfo("multi.lab", 80)
    ips = {r[4][0] for r in results}
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips


def test_second_known_host(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)

    results = socket.getaddrinfo("dc01.corp.local", 445)
    assert results[0][4][0] == "192.168.1.10"


# ── Edge cases ───────────────────────────────────────────────────────

def test_dns_server_unreachable():
    port = _free_port()
    setup_custom_dns("127.0.0.1", port=port)

    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("testhost.lab", 445)


def test_gaierror_passthrough(dns_server):
    setup_custom_dns("127.0.0.1", port=dns_server)

    import dns.resolver as _dns_mod
    original_resolve = _dns_mod.Resolver.resolve

    def raise_gaierror(self, *args, **kwargs):
        raise socket.gaierror(8, "network unreachable")

    with patch.object(_dns_mod.Resolver, "resolve", raise_gaierror):
        with pytest.raises(socket.gaierror, match="network unreachable"):
            socket.getaddrinfo("testhost.lab", 445)
