"""
SOCKS proxy support for tunneling SMB/LDAP connections through a pivot host.

Uses PySocks to monkey-patch socket.socket globally so all TCP connections
(SMB, LDAP, Kerberos) are routed through the proxy. Must be called once
at startup before any connections are made.
"""

import ipaddress
import socket
from urllib.parse import urlparse

# PySocks proxy type constants (avoids importing socks at module level)
SOCKS4 = 1
SOCKS5 = 2


def parse_socks_url(url: str) -> tuple[int, str, int, str | None, str | None]:
    """Parse a SOCKS proxy URL into (proxy_type, host, port, username, password).

    Accepted formats:
        socks5://host:port
        socks4://host:port
        socks5://user:pass@host:port
        host:port              (defaults to SOCKS5)

    Returns:
        Tuple of (proxy_type, host, port, username, password).
        username and password may be None.

    Raises:
        ValueError: If the URL is malformed or missing required components.
    """
    # Bare host:port (no scheme) — default to SOCKS5
    if "://" not in url:
        url = f"socks5://{url}"

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    if scheme == "socks5":
        proxy_type = SOCKS5
    elif scheme == "socks4":
        proxy_type = SOCKS4
    else:
        raise ValueError(f"Unsupported SOCKS scheme: {scheme!r} (use socks4 or socks5)")

    host = parsed.hostname
    if not host:
        raise ValueError(f"Missing host in SOCKS proxy URL: {url!r}")

    port = parsed.port
    if not port:
        raise ValueError(f"Missing port in SOCKS proxy URL: {url!r}")

    username = parsed.username or None
    password = parsed.password or None

    return (proxy_type, host, port, username, password)


def setup_socks_proxy(proxy_url: str) -> None:
    """Apply global SOCKS monkey-patch so all new sockets route through the proxy.

    Must be called before any SMB/LDAP connections are created.

    Raises:
        ImportError: If PySocks is not installed.
        ValueError: If proxy_url is malformed.
    """
    try:
        import socks
    except ImportError:
        raise ImportError("PySocks is required for --socks support. Install it with: pip install pysocks")

    proxy_type, host, port, username, password = parse_socks_url(proxy_url)

    socks.set_default_proxy(
        proxy_type=proxy_type,
        addr=host,
        port=port,
        rdns=True,
        username=username,
        password=password,
    )
    socket.socket = socks.socksocket  # type: ignore[misc,assignment]

    # Patch getaddrinfo so hostnames pass through unresolved to
    # socksocket.connect(), where rdns=True handles remote resolution.
    # Without this, getaddrinfo hits the local resolver which can't
    # reach internal AD hostnames behind the proxy.
    _original_getaddrinfo = socket.getaddrinfo

    def _socks_getaddrinfo(
        host: str | None, port: int | str | None, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        if host is None:
            return _original_getaddrinfo(host, port, family, type, proto, flags)
        try:
            ipaddress.ip_address(host)
            return _original_getaddrinfo(host, port, family, type, proto, flags)
        except ValueError:
            port_num = port if isinstance(port, int) and port is not None else 0
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port_num))]

    socket.getaddrinfo = _socks_getaddrinfo
