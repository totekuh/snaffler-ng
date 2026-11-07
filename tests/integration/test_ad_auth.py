"""Integration tests: authentication and SMB share operations against real Samba AD DC."""

import io

import pytest
from impacket.ldap.ldap import LDAPSessionError
from impacket.smbconnection import SMBConnection, SessionError

from snaffler.transport.ldap import LDAPTransport
from tests.ad_env.conftest import _make_cfg, AD_CONFIG, AD_ENABLED

pytestmark = pytest.mark.skipif(not AD_ENABLED, reason="AD DC not available")


def _smb_connect(user, password, domain, nthash=""):
    smb = SMBConnection(AD_CONFIG["dc_host"], AD_CONFIG["dc_host"])
    smb.login(user, password, domain, nthash=nthash)
    return smb


# ── LDAP auth ────────────────────────────────────────────────────────

class TestLDAPAuth:
    def test_ntlm_password_ldap(self, ad_dc):
        cfg = _make_cfg()
        transport = LDAPTransport(cfg)
        ldap = transport.connect()
        try:
            assert ldap is not None
        finally:
            ldap.close()

    def test_ntlm_password_ldap_test_user(self, ad_dc):
        cfg = _make_cfg(
            **{"auth.username": AD_CONFIG["test_user"],
               "auth.password": AD_CONFIG["test_pass"]}
        )
        transport = LDAPTransport(cfg)
        ldap = transport.connect()
        try:
            assert ldap is not None
        finally:
            ldap.close()

    def test_wrong_password_ldap(self, ad_dc):
        cfg = _make_cfg(**{"auth.password": "WrongPassword!"})
        transport = LDAPTransport(cfg)
        with pytest.raises((LDAPSessionError, Exception)):
            transport.connect()


# ── SMB auth ─────────────────────────────────────────────────────────

class TestSMBAuth:
    def test_ntlm_password_smb(self, ad_dc):
        smb = _smb_connect(
            AD_CONFIG["test_user"], AD_CONFIG["test_pass"], AD_CONFIG["realm"]
        )
        try:
            assert smb.getServerName().upper() == "DC01"
        finally:
            smb.close()

    def test_pth_smb(self, ad_dc):
        smb = _smb_connect(
            AD_CONFIG["test_user"], "", AD_CONFIG["realm"],
            nthash=AD_CONFIG["test_nthash"],
        )
        try:
            assert smb.getServerName().upper() == "DC01"
        finally:
            smb.close()

    def test_wrong_password_smb(self, ad_dc):
        with pytest.raises((SessionError, Exception)):
            _smb_connect(
                AD_CONFIG["test_user"], "WrongPassword!", AD_CONFIG["realm"]
            )


# ── Share operations ─────────────────────────────────────────────────

class TestShareOps:
    def _admin_smb(self):
        return _smb_connect(
            AD_CONFIG["admin_user"], AD_CONFIG["admin_pass"], AD_CONFIG["realm"]
        )

    def test_share_enumeration(self, ad_dc):
        smb = self._admin_smb()
        try:
            shares = smb.listShares()
            names = {s["shi1_netname"][:-1] for s in shares}
            for expected in ("sysvol", "netlogon", "data", "finance", "it"):
                assert expected in names, f"share '{expected}' missing, got {names}"
        finally:
            smb.close()

    def test_share_directory_listing(self, ad_dc):
        smb = self._admin_smb()
        try:
            entries = smb.listPath("data", "\\*")
            names = {e.get_longname() for e in entries}
            assert "config.ini" in names, f"config.ini missing, got {names}"
        finally:
            smb.close()

    def test_share_file_read(self, ad_dc):
        smb = self._admin_smb()
        try:
            buf = io.BytesIO()
            smb.getFile("data", "\\config.ini", buf.write)
            content = buf.getvalue().decode()
            assert "password=s3cret" in content
            assert "DB_HOST=prod-db.corp.local" in content
        finally:
            smb.close()

    def test_finance_share_has_passwords(self, ad_dc):
        smb = self._admin_smb()
        try:
            buf = io.BytesIO()
            smb.getFile("finance", "\\passwords.txt", buf.write)
            content = buf.getvalue().decode()
            assert "svc_sql" in content
        finally:
            smb.close()
