"""SCCM ContentLib display_name tests against Windows VM.

Verifies that filename-based rules fire via display_name on hash blobs,
and that findings reference the original filename instead of the hash.
"""

import tempfile
from pathlib import Path

import pytest

from snaffler.resume.scan_state import SQLiteStateStore
from tests.windows.conftest import make_cfg, run_scan, no_auth_check

pytestmark = pytest.mark.windows


class TestSCCMDisplayName:

    def test_ssh_key_matched_by_display_name(self, windows_env):
        """KeepSSHKeysByFileName fires on id_rsa via display_name."""
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = make_cfg(
                windows_env["vm_ip"],
                username="fulluser",
                password="SnaffFull1!",
                share="SCCMContentLib$",
            )
            cfg.state.state_db = db_path
            with no_auth_check:
                _, p = run_scan(cfg)

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            ssh_findings = [
                f for f in findings
                if "id_rsa" in (f.get("match_text") or "").lower()
                or "ssh" in (f.get("rule_name") or "").lower()
                or "private" in (f.get("rule_name") or "").lower()
            ]
            assert len(ssh_findings) > 0, (
                f"No SSH key finding via display_name. "
                f"All findings: {[(f['file_path'], f['rule_name']) for f in findings]}"
            )
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_ps_creds_content_match(self, windows_env):
        """KeepPsCredentials fires on deploy-script.ps1 content through ContentLib."""
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = make_cfg(
                windows_env["vm_ip"],
                username="fulluser",
                password="SnaffFull1!",
                share="SCCMContentLib$",
            )
            cfg.state.state_db = db_path
            with no_auth_check:
                _, p = run_scan(cfg)

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            ps_findings = [
                f for f in findings
                if "deploy-script" in (f.get("file_path") or "").lower()
                or "PsCredentials" in (f.get("rule_name") or "")
            ]
            assert len(ps_findings) > 0, (
                f"No PS credential finding from deploy-script.ps1. "
                f"All findings: {[(f['file_path'], f['rule_name']) for f in findings]}"
            )
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_display_name_in_finding_path(self, windows_env):
        """Finding file_path contains original filename, not just hash."""
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = make_cfg(
                windows_env["vm_ip"],
                username="fulluser",
                password="SnaffFull1!",
                share="SCCMContentLib$",
            )
            cfg.state.state_db = db_path
            with no_auth_check:
                _, p = run_scan(cfg)

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            for f in findings:
                fp = f["file_path"]
                has_original_name = (
                    "deploy-script.ps1" in fp
                    or "id_rsa" in fp
                    or "web.config" in fp
                )
                assert has_original_name, (
                    f"Finding should contain original filename: {fp}"
                )
                assert "SCCMContentLib" in fp, (
                    f"Finding should reference ContentLib path: {fp}"
                )
        finally:
            Path(db_path).unlink(missing_ok=True)
