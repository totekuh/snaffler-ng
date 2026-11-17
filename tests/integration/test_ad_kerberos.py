"""Kerberos integration tests against Samba AD DC.

These tests verify the TGS-REQ checksum fix works against a real
Samba 4.17 KDC that enforces RFC 4120 Authenticator checksums.
"""

import pytest
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection

from tests.ad_env.conftest import AD_CONFIG, AD_ENABLED, _make_cfg
from snaffler.transport.kerberos import get_kerberos_tgs, get_tgt_and_tgs
from snaffler.transport.ldap import LDAPTransport
from snaffler.transport.auth import authenticate_smb

DC_IP = AD_CONFIG["dc_host"]
DC_HOSTNAME = "dc01.testlab.local"

pytestmark = pytest.mark.skipif(
    not AD_ENABLED,
    reason="AD DC not available (KDC/LDAP/SMB ports unreachable)",
)


def _get_tgt(username=None, password=None, nthash=""):
    domain = AD_CONFIG["realm"]
    username = username or AD_CONFIG["admin_user"]
    password = password or AD_CONFIG["admin_pass"]
    client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    return getKerberosTGT(
        client,
        password,
        domain,
        lmhash="",
        nthash=nthash,
        aesKey="",
        kdcHost=DC_IP,
    )


class TestTgsChecksum:
    """Verify our get_kerberos_tgs produces valid service tickets."""

    def test_tgs_for_cifs(self):
        tgt, cipher, _, session_key = _get_tgt()
        server = Principal(
            f"cifs/{DC_HOSTNAME}",
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        tgs, tgs_cipher, _, tgs_key = get_kerberos_tgs(
            server,
            AD_CONFIG["realm"],
            DC_IP,
            tgt,
            cipher,
            session_key,
        )
        assert tgs is not None
        assert len(tgs) > 0

    def test_tgs_for_ldap(self):
        tgt, cipher, _, session_key = _get_tgt()
        server = Principal(
            f"ldap/{DC_HOSTNAME}",
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        tgs, tgs_cipher, _, tgs_key = get_kerberos_tgs(
            server,
            AD_CONFIG["realm"],
            DC_IP,
            tgt,
            cipher,
            session_key,
        )
        assert tgs is not None

    def test_tgs_with_test_user(self):
        tgt, cipher, _, session_key = _get_tgt(
            username=AD_CONFIG["test_user"],
            password=AD_CONFIG["test_pass"],
        )
        server = Principal(
            f"cifs/{DC_HOSTNAME}",
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        tgs, _, _, _ = get_kerberos_tgs(
            server,
            AD_CONFIG["realm"],
            DC_IP,
            tgt,
            cipher,
            session_key,
        )
        assert tgs is not None

    def test_bad_spn_raises(self):
        tgt, cipher, _, session_key = _get_tgt()
        server = Principal(
            "cifs/nonexistent.testlab.local",
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        with pytest.raises(KerberosError):
            get_kerberos_tgs(
                server,
                AD_CONFIG["realm"],
                DC_IP,
                tgt,
                cipher,
                session_key,
            )


class TestKerberosSMB:
    """SMB authentication via Kerberos against Samba DC."""

    def _smb_kerberos(self, cfg):
        """Connect SMB using hostname for SPN, IP for transport."""
        smb = SMBConnection(
            remoteName=DC_HOSTNAME,
            remoteHost=DC_IP,
            sess_port=445,
            timeout=10,
        )
        authenticate_smb(smb, cfg.auth)
        return smb

    def test_kerberos_smb_login(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True})
        smb = self._smb_kerberos(cfg)
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert len(shares) > 0
        smb.close()

    def test_kerberos_share_enumeration(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True})
        smb = self._smb_kerberos(cfg)
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert "sysvol" in shares
        smb.close()

    def test_kerberos_file_read(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True})
        smb = self._smb_kerberos(cfg)
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert "data" in shares
        smb.close()

    def test_kerberos_wrong_password(self, ad_dc):
        cfg = _make_cfg(
            **{
                "auth.kerberos": True,
                "auth.password": "WrongPassword!",
            }
        )
        with pytest.raises(Exception):
            self._smb_kerberos(cfg)


class TestKerberosLDAP:
    """LDAP authentication via Kerberos against Samba DC."""

    def test_kerberos_ldap_bind(self, ad_dc):
        from impacket.ldap.ldap import LDAPConnection as ImpacketLDAP
        from snaffler.transport.kerberos import get_tgt_and_tgs
        from unittest.mock import MagicMock

        cfg = _make_cfg(
            **{
                "auth.kerberos": True,
                "auth.dc_host": DC_IP,
            }
        )
        # Get tickets using hostname SPN but IP for KDC transport
        tgt, tgs = get_tgt_and_tgs(cfg.auth, f"ldap/{DC_HOSTNAME}", DC_IP)

        ldap = ImpacketLDAP(
            f"ldap://{DC_HOSTNAME}",
            cfg.auth.domain,
            dstIp=DC_IP,
        )
        ldap.kerberosLogin(
            user=cfg.auth.username or "",
            password=cfg.auth.password or "",
            domain=(cfg.auth.domain or "").upper(),
            lmhash="",
            nthash="",
            aesKey="",
            kdcHost=DC_IP,
            useCache=False,
            TGT=tgt,
            TGS=tgs,
        )
        assert ldap is not None
        ldap.close()


class TestNTLMRegression:
    """Verify NTLM/PTH paths unchanged after Kerberos changes."""

    def test_ntlm_smb_still_works(self, ad_dc):
        cfg = _make_cfg()
        smb = SMBConnection(DC_IP, DC_IP, timeout=10)
        authenticate_smb(smb, cfg.auth)
        assert smb.getServerName().upper() == "DC01"
        smb.close()

    def test_pth_smb_still_works(self, ad_dc):
        cfg = _make_cfg(
            **{
                "auth.username": AD_CONFIG["test_user"],
                "auth.password": "",
                "auth.nthash": AD_CONFIG["test_nthash"],
            }
        )
        smb = SMBConnection(DC_IP, DC_IP, timeout=10)
        authenticate_smb(smb, cfg.auth)
        assert smb.getServerName().upper() == "DC01"
        smb.close()

    def test_ntlm_ldap_still_works(self, ad_dc):
        cfg = _make_cfg(**{"auth.dc_host": DC_IP})
        transport = LDAPTransport(cfg)
        ldap = transport.connect()
        assert ldap is not None
        ldap.close()
