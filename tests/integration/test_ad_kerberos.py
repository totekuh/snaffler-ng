"""Kerberos integration tests against Samba AD DC.

Covers TGS-REQ checksum fix, SMB/LDAP Kerberos auth, AD discovery,
PTH+Kerberos, ccache config validation, multi-share access, and
resume with Kerberos auth. Each area has positive and negative tests.
"""

import os
import tempfile

import pytest
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
from impacket.krb5.types import Principal
from impacket.ldap.ldap import LDAPConnection as ImpacketLDAP
from impacket.smbconnection import SMBConnection

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.ad import ADDiscovery
from snaffler.transport.auth import authenticate_smb
from snaffler.transport.kerberos import get_kerberos_tgs, get_tgt_and_tgs
from snaffler.transport.ldap import LDAPTransport
from tests.ad_env.conftest import AD_CONFIG, AD_ENABLED, _make_cfg

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


def _smb_kerberos(cfg):
    smb = SMBConnection(
        remoteName=DC_HOSTNAME,
        remoteHost=DC_IP,
        sess_port=445,
        timeout=10,
    )
    authenticate_smb(smb, cfg.auth)
    return smb


# ------------------------------------------------------------------
# TGS checksum verification
# ------------------------------------------------------------------


class TestTgsChecksum:
    def test_tgs_for_cifs(self):
        tgt, cipher, _, session_key = _get_tgt()
        server = Principal(
            f"cifs/{DC_HOSTNAME}",
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        tgs, _, _, _ = get_kerberos_tgs(server, AD_CONFIG["realm"], DC_IP, tgt, cipher, session_key)
        assert tgs is not None
        assert len(tgs) > 0

    def test_tgs_for_ldap(self):
        tgt, cipher, _, session_key = _get_tgt()
        server = Principal(
            f"ldap/{DC_HOSTNAME}",
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        tgs, _, _, _ = get_kerberos_tgs(server, AD_CONFIG["realm"], DC_IP, tgt, cipher, session_key)
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
        tgs, _, _, _ = get_kerberos_tgs(server, AD_CONFIG["realm"], DC_IP, tgt, cipher, session_key)
        assert tgs is not None

    def test_bad_spn_raises(self):
        tgt, cipher, _, session_key = _get_tgt()
        server = Principal(
            "cifs/nonexistent.testlab.local",
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        with pytest.raises(KerberosError):
            get_kerberos_tgs(server, AD_CONFIG["realm"], DC_IP, tgt, cipher, session_key)

    def test_wrong_password_tgt_fails(self):
        with pytest.raises(KerberosError):
            _get_tgt(password="WrongPassword!")


# ------------------------------------------------------------------
# SMB Kerberos auth
# ------------------------------------------------------------------


class TestKerberosSMB:
    def test_kerberos_smb_login(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True})
        smb = _smb_kerberos(cfg)
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert len(shares) > 0
        smb.close()

    def test_kerberos_share_enumeration(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True})
        smb = _smb_kerberos(cfg)
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert "sysvol" in shares
        assert "data" in shares
        smb.close()

    def test_kerberos_directory_listing(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True})
        smb = _smb_kerberos(cfg)
        files = smb.listPath("data", "*")
        filenames = [f.get_longname() for f in files if f.get_longname() not in (".", "..")]
        assert len(filenames) > 0
        smb.close()

    def test_kerberos_file_read(self, ad_dc):
        from io import BytesIO

        cfg = _make_cfg(**{"auth.kerberos": True})
        smb = _smb_kerberos(cfg)
        buf = BytesIO()
        smb.getFile("data", "config.ini", buf.write)
        content = buf.getvalue().decode()
        assert "password" in content.lower() or "DB_HOST" in content
        smb.close()

    def test_kerberos_wrong_password(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True, "auth.password": "WrongPassword!"})
        with pytest.raises((KerberosError, OSError)):
            _smb_kerberos(cfg)

    def test_kerberos_test_user(self, ad_dc):
        cfg = _make_cfg(
            **{
                "auth.kerberos": True,
                "auth.username": AD_CONFIG["test_user"],
                "auth.password": AD_CONFIG["test_pass"],
            }
        )
        smb = _smb_kerberos(cfg)
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert len(shares) > 0
        smb.close()


# ------------------------------------------------------------------
# LDAP Kerberos auth (with dstIp fix)
# ------------------------------------------------------------------


def _dc_hostname_resolves():
    import socket

    try:
        socket.gethostbyname(DC_HOSTNAME)
        return True
    except socket.gaierror:
        return False


class TestKerberosLDAP:
    @pytest.mark.skipif(
        not _dc_hostname_resolves(),
        reason=f"{DC_HOSTNAME} not resolvable (run with DC DNS or in Docker)",
    )
    def test_kerberos_ldap_via_transport(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True, "auth.dc_host": DC_HOSTNAME})
        transport = LDAPTransport(cfg)
        ldap = transport.connect()
        assert ldap is not None
        ldap.close()

    def test_kerberos_ldap_manual_bind(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True, "auth.dc_host": DC_IP})
        tgt, tgs = get_tgt_and_tgs(cfg.auth, f"ldap/{DC_HOSTNAME}", DC_IP)
        ldap = ImpacketLDAP(f"ldap://{DC_HOSTNAME}", cfg.auth.domain, dstIp=DC_IP)
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

    @pytest.mark.skipif(
        not _dc_hostname_resolves(),
        reason=f"{DC_HOSTNAME} not resolvable (run with DC DNS or in Docker)",
    )
    def test_kerberos_ldap_wrong_password(self, ad_dc):
        cfg = _make_cfg(
            **{
                "auth.kerberos": True,
                "auth.dc_host": DC_HOSTNAME,
                "auth.password": "WrongPassword!",
            }
        )
        with pytest.raises((KerberosError, OSError)):
            transport = LDAPTransport(cfg)
            transport.connect()


# ------------------------------------------------------------------
# AD discovery with Kerberos
# ------------------------------------------------------------------


@pytest.mark.skipif(
    not _dc_hostname_resolves(),
    reason=f"{DC_HOSTNAME} not resolvable (run with DC DNS or in Docker)",
)
class TestKerberosDiscovery:
    def test_discover_computers_kerberos(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True, "auth.dc_host": DC_HOSTNAME})
        ad = ADDiscovery(cfg)
        computers = ad.get_domain_computers()
        assert len(computers) > 0
        ad.close()

    def test_discover_users_kerberos(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True, "auth.dc_host": DC_HOSTNAME})
        ad = ADDiscovery(cfg)
        users = ad.get_domain_users()
        assert len(users) > 0
        ad.close()

    def test_discover_computers_names_are_fqdn(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True, "auth.dc_host": DC_HOSTNAME})
        ad = ADDiscovery(cfg)
        computers = ad.get_domain_computers()
        for c in computers:
            assert "." in c, f"Computer {c} is not FQDN"
        ad.close()


# ------------------------------------------------------------------
# PTH + Kerberos (RC4 etype)
# ------------------------------------------------------------------


class TestKerberosPTH:
    @pytest.mark.xfail(reason="Samba may reject RC4 Kerberos (strict crypto policy)")
    def test_pth_kerberos_smb(self, ad_dc):
        cfg = _make_cfg(
            **{
                "auth.kerberos": True,
                "auth.username": AD_CONFIG["test_user"],
                "auth.password": "",
                "auth.nthash": AD_CONFIG["test_nthash"],
            }
        )
        smb = _smb_kerberos(cfg)
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        assert len(shares) > 0
        smb.close()

    def test_pth_kerberos_wrong_hash(self, ad_dc):
        cfg = _make_cfg(
            **{
                "auth.kerberos": True,
                "auth.username": AD_CONFIG["test_user"],
                "auth.password": "",
                "auth.nthash": "deadbeefdeadbeefdeadbeefdeadbeef",
            }
        )
        with pytest.raises((KerberosError, OSError)):
            _smb_kerberos(cfg)


# ------------------------------------------------------------------
# Kerberos ccache config validation
# ------------------------------------------------------------------


class TestKerberosCcache:
    def test_ccache_requires_krb5ccname(self):
        cfg = SnafflerConfiguration()
        cfg.auth.domain = "testlab.local"
        cfg.auth.kerberos = True
        cfg.auth.use_kcache = True
        cfg.auth.username = ""
        env_backup = os.environ.pop("KRB5CCNAME", None)
        try:
            with pytest.raises(ValueError, match=r"KRB5CCNAME"):
                cfg.validate()
        finally:
            if env_backup is not None:
                os.environ["KRB5CCNAME"] = env_backup

    def test_ccache_forbids_username(self):
        cfg = SnafflerConfiguration()
        cfg.auth.domain = "testlab.local"
        cfg.auth.kerberos = True
        cfg.auth.use_kcache = True
        cfg.auth.username = "admin"
        os.environ["KRB5CCNAME"] = "/tmp/krb5cc_test"
        try:
            with pytest.raises(ValueError, match=r"[Uu]sername"):
                cfg.validate()
        finally:
            del os.environ["KRB5CCNAME"]

    def test_ccache_valid_config(self):
        cfg = SnafflerConfiguration()
        cfg.auth.domain = "testlab.local"
        cfg.auth.kerberos = True
        cfg.auth.use_kcache = True
        cfg.auth.username = ""
        os.environ["KRB5CCNAME"] = "/tmp/krb5cc_test"
        try:
            cfg.validate()
        finally:
            del os.environ["KRB5CCNAME"]

    def test_kerberos_requires_domain(self):
        cfg = SnafflerConfiguration()
        cfg.auth.kerberos = True
        cfg.auth.domain = ""
        with pytest.raises(ValueError, match=r"[Dd]omain"):
            cfg.validate()


# ------------------------------------------------------------------
# Multi-share access with Kerberos
# ------------------------------------------------------------------


class TestKerberosMultiShare:
    def test_access_multiple_shares(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True})
        smb = _smb_kerberos(cfg)
        shares = [s["shi1_netname"][:-1].lower() for s in smb.listShares()]
        for share_name in ("data", "it"):
            assert share_name in shares
            files = smb.listPath(share_name, "*")
            assert len(files) > 0
        smb.close()

    def test_kerberos_file_content_match(self, ad_dc):
        from io import BytesIO

        cfg = _make_cfg(**{"auth.kerberos": True})
        smb = _smb_kerberos(cfg)
        buf = BytesIO()
        smb.getFile("finance", "passwords.txt", buf.write)
        content = buf.getvalue().decode()
        assert "svc_sql" in content
        smb.close()

    def test_kerberos_share_reconnect(self, ad_dc):
        cfg = _make_cfg(**{"auth.kerberos": True})
        smb1 = _smb_kerberos(cfg)
        smb1.listShares()
        smb1.close()
        smb2 = _smb_kerberos(cfg)
        shares = [s["shi1_netname"][:-1].lower() for s in smb2.listShares()]
        assert "data" in shares
        smb2.close()


# ------------------------------------------------------------------
# Resume with Kerberos auth
# ------------------------------------------------------------------


@pytest.mark.skipif(
    not _dc_hostname_resolves(),
    reason=f"{DC_HOSTNAME} not resolvable (run with DC DNS or in Docker)",
)
class TestKerberosResume:
    def test_scan_with_state_db(self, ad_dc):
        from snaffler.engine.file_pipeline import FilePipeline
        from snaffler.resume.scan_state import ScanState, SQLiteStateStore

        cfg = _make_cfg(**{"auth.kerberos": True})

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            state = ScanState(SQLiteStateStore(db_path))
            pipeline = FilePipeline(cfg, state=state)
            count = pipeline.run([f"//{DC_HOSTNAME}/data"])
            pipeline.close()
            state.store.close()
            assert count >= 0
        finally:
            os.unlink(db_path)

    def test_resume_skips_done_files(self, ad_dc):
        from snaffler.engine.file_pipeline import FilePipeline
        from snaffler.resume.scan_state import ScanState, SQLiteStateStore
        from snaffler.utils.progress import ProgressState

        cfg = _make_cfg(**{"auth.kerberos": True})
        target = f"//{DC_HOSTNAME}/data"

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            state1 = ScanState(SQLiteStateStore(db_path))
            progress1 = ProgressState()
            pipeline1 = FilePipeline(cfg, state=state1, progress=progress1)
            pipeline1.run([target])
            first_scanned = progress1.files_scanned
            pipeline1.close()
            state1.store.close()

            state2 = ScanState(SQLiteStateStore(db_path))
            progress2 = ProgressState()
            pipeline2 = FilePipeline(cfg, state=state2, progress=progress2)
            pipeline2.run([target])
            second_scanned = progress2.files_scanned
            pipeline2.close()
            state2.store.close()

            assert first_scanned > 0
            assert second_scanned == 0
        finally:
            os.unlink(db_path)


# ------------------------------------------------------------------
# NTLM/PTH regression
# ------------------------------------------------------------------


class TestNTLMRegression:
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
