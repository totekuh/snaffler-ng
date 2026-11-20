"""Scan-level integration tests against real Samba AD DC.

Exercises the full SnafflerRunner pipeline — credential validation,
share connection, tree walking, file scanning, rule matching — against
the TESTLAB.LOCAL Samba DC Docker container.
"""

import socket
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest

from snaffler.classifiers.loader import RuleLoader
from snaffler.engine.runner import SnafflerRunner
from snaffler.resume.scan_state import SQLiteStateStore
from tests.ad_env.conftest import _make_cfg, AD_CONFIG, AD_ENABLED

pytestmark = pytest.mark.skipif(not AD_ENABLED, reason="AD DC not available")

DC_HOST = AD_CONFIG["dc_host"]
DC_HOSTNAME = "dc01.testlab.local"


def _dc_hostname_resolves():
    try:
        socket.getaddrinfo(DC_HOSTNAME, 445)
        return True
    except socket.gaierror:
        return False


def _make_scan_cfg(unc_targets, **overrides):
    cfg = _make_cfg(**overrides)
    cfg.targets.unc_targets = unc_targets
    cfg.state.state_db = ":memory:"
    cfg.advanced.share_threads = 2
    cfg.advanced.tree_threads = 4
    cfg.advanced.file_threads = 4
    cfg.scanning.max_read_bytes = 2 * 1024 * 1024
    cfg.scanning.max_file_bytes = 10 * 1024 * 1024
    cfg.scanning.match_context_bytes = 200
    cfg.scanning.min_interest = 0
    RuleLoader.load(cfg)
    return cfg


def _run_scan(cfg):
    runner = SnafflerRunner(cfg)
    runner.execute()
    return runner, runner.progress


class TestNTLMScan:

    def test_ntlm_scan_produces_findings(self, ad_dc):
        cfg = _make_scan_cfg(
            unc_targets=[f"//{DC_HOST}/data", f"//{DC_HOST}/finance"],
        )
        _, p = _run_scan(cfg)
        assert p.scan_complete is True
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_sysvol_gpo_files_scanned(self, ad_dc):
        cfg = _make_scan_cfg(unc_targets=[f"//{DC_HOST}/sysvol"])
        _, p = _run_scan(cfg)
        assert p.scan_complete is True
        assert p.files_scanned > 0

    def test_nonexistent_share_completes_gracefully(self, ad_dc):
        cfg = _make_scan_cfg(unc_targets=[f"//{DC_HOST}/BOGUS_SHARE_XYZ"])
        _, p = _run_scan(cfg)
        assert p.scan_complete is True
        assert p.files_scanned == 0

    def test_wrong_password_rejected(self, ad_dc):
        cfg = _make_scan_cfg(
            unc_targets=[f"//{DC_HOST}/data"],
            **{"auth.password": "WrongPassword123!"},
        )
        with pytest.raises(SystemExit, match="authentication failed"):
            _run_scan(cfg)

    def test_wrong_domain_still_authenticates(self, ad_dc):
        # Samba AD DC accepts NTLM auth with wrong domain hint — this is
        # standard NTLMv2 behavior (domain is a hint, not enforced).
        # Verify scan completes without crash.
        cfg = _make_scan_cfg(
            unc_targets=[f"//{DC_HOST}/data"],
            **{"auth.domain": "FAKELAND.LOCAL"},
        )
        _, p = _run_scan(cfg)
        assert p.scan_complete is True

    def test_multi_share_scan(self, ad_dc):
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = _make_scan_cfg(unc_targets=[
                f"//{DC_HOST}/data",
                f"//{DC_HOST}/finance",
                f"//{DC_HOST}/it",
            ])
            cfg.state.state_db = db_path
            _, p = _run_scan(cfg)
            assert p.scan_complete is True
            assert p.files_scanned >= 3
            assert p.files_matched >= 1

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            paths = [f["file_path"] for f in findings]
            assert any("/finance/" in fp for fp in paths), (
                f"no finding from finance share, paths: {paths}"
            )
            store.close()
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_resume_no_new_findings(self, ad_dc):
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            targets = [f"//{DC_HOST}/data", f"//{DC_HOST}/finance"]

            cfg1 = _make_scan_cfg(unc_targets=targets)
            cfg1.state.state_db = db_path
            _, p1 = _run_scan(cfg1)
            assert p1.scan_complete is True
            assert p1.files_scanned > 0

            store = SQLiteStateStore(db_path)
            count1 = store.count_findings()
            store.close()
            assert count1 > 0

            cfg2 = _make_scan_cfg(unc_targets=targets)
            cfg2.state.state_db = db_path
            _, p2 = _run_scan(cfg2)
            assert p2.scan_complete is True

            store = SQLiteStateStore(db_path)
            count2 = store.count_findings()
            store.close()
            assert count2 == count1
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_insufficient_permissions_partial_results(self, ad_dc):
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = _make_scan_cfg(
                unc_targets=[f"//{DC_HOST}/data", f"//{DC_HOST}/finance"],
                **{
                    "auth.username": "normal_user",
                    "auth.password": "UserPass123!",
                },
            )
            cfg.state.state_db = db_path
            _, p = _run_scan(cfg)

            assert p.scan_complete is True
            assert p.files_scanned >= 1

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            paths = [f["file_path"] for f in findings]
            assert not any("/finance/" in fp for fp in paths), (
                f"normal_user should not access finance, but got: {paths}"
            )
            store.close()
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_concurrent_scans_both_complete(self, ad_dc):
        def scan_share(share):
            cfg = _make_scan_cfg(unc_targets=[f"//{DC_HOST}/{share}"])
            return _run_scan(cfg)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                pool.submit(scan_share, "data"): "data",
                pool.submit(scan_share, "it"): "it",
            }
            results = {}
            for future in as_completed(futures, timeout=30):
                name = futures[future]
                results[name] = future.result()

        assert results["data"][1].scan_complete is True
        assert results["it"][1].scan_complete is True
        assert results["data"][1].files_scanned > 0
        assert results["it"][1].files_scanned > 0


class TestKerberosScan:

    @pytest.mark.skipif(
        not _dc_hostname_resolves(),
        reason="DC hostname does not resolve",
    )
    def test_kerberos_scan_produces_findings(self, ad_dc):
        cfg = _make_scan_cfg(
            unc_targets=[
                f"//{DC_HOSTNAME}/data",
                f"//{DC_HOSTNAME}/finance",
            ],
            **{"auth.kerberos": True, "auth.dc_host": DC_HOSTNAME},
        )
        _, p = _run_scan(cfg)
        assert p.scan_complete is True
        assert p.files_scanned > 0
        assert p.files_matched > 0
