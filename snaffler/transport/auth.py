"""Shared authentication helpers for SMB and LDAP transports."""

import logging

from snaffler.transport.kerberos import get_tgt_and_tgs

logger = logging.getLogger("snaffler")


def authenticate_smb(smb, auth):
    """Authenticate an SMBConnection using Kerberos or NTLM.

    Args:
        smb: An impacket SMBConnection instance.
        auth: Auth config object with username, password, domain, nthash,
              kerberos, dc_host, and use_kcache attributes.
    """
    if auth.kerberos:
        tgt = None
        tgs = None
        if not auth.use_kcache:
            remote_host = smb.getRemoteHost()
            spn = f"cifs/{smb.getRemoteName()}"
            tgt, tgs = get_tgt_and_tgs(auth, spn, remote_host)
        smb.kerberosLogin(
            user=auth.username or "",
            password=auth.password or "",
            domain=(auth.domain or "").upper(),
            lmhash="",
            nthash=auth.nthash or "",
            aesKey="",
            kdcHost=auth.dc_host,
            useCache=auth.use_kcache,
            TGT=tgt,
            TGS=tgs,
        )
    elif auth.nthash:
        smb.login(
            auth.username,
            "",
            auth.domain or "",
            "",
            auth.nthash,
        )
    else:
        smb.login(
            auth.username,
            auth.password or "",
            auth.domain or "",
        )


def authenticate_ldap(ldap_conn, auth):
    """Authenticate an LDAPConnection using Kerberos or NTLM.

    Args:
        ldap_conn: An impacket LDAPConnection instance.
        auth: Auth config object with username, password, domain, nthash,
              kerberos, dc_host, and use_kcache attributes.
    """
    if auth.kerberos:
        tgt = None
        tgs = None
        if not auth.use_kcache:
            dc_host = auth.dc_host or auth.domain
            spn = f"ldap/{dc_host}"
            tgt, tgs = get_tgt_and_tgs(auth, spn, dc_host)
        ldap_conn.kerberosLogin(
            user=auth.username or "",
            password=auth.password or "",
            domain=(auth.domain or "").upper(),
            lmhash="",
            nthash=auth.nthash or "",
            aesKey="",
            kdcHost=auth.dc_host,
            useCache=auth.use_kcache,
            TGT=tgt,
            TGS=tgs,
        )
    elif auth.nthash:
        ldap_conn.login(
            auth.username,
            "",
            auth.domain,
            "",
            auth.nthash,
        )
    else:
        ldap_conn.login(
            auth.username,
            auth.password or "",
            auth.domain,
        )
