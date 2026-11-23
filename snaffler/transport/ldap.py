import ipaddress
import socket

from impacket.ldap.ldap import LDAPConnection

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.transport.auth import authenticate_ldap


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_or_self(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


class LDAPTransport:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.auth = cfg.auth

    def connect(self) -> LDAPConnection:
        if not self.auth.domain:
            raise ValueError("LDAP connection requires a domain")

        target = self.auth.dc_host or self.auth.domain

        if self.auth.kerberos and self.auth.dc_host:
            dst_ip = self.auth.dc_host if _is_ip(self.auth.dc_host) else _resolve_or_self(self.auth.dc_host)
            ldap = LDAPConnection(
                f"ldap://{self.auth.dc_host}",
                self.auth.domain,
                dstIp=dst_ip,
            )
        else:
            ldap = LDAPConnection(
                f"ldap://{target}",
                self.auth.domain,
            )

        authenticate_ldap(ldap, self.auth)
        return ldap
