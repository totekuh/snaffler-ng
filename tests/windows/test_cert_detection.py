"""DER private key detection and cert edge cases against Windows VM."""

import tempfile
from pathlib import Path

import pytest

from snaffler.resume.scan_state import SQLiteStateStore
from tests.windows.conftest import make_cfg, run_scan, no_auth_check

pytestmark = pytest.mark.windows


class TestCertDetection:

    def test_der_private_key_found(self, windows_env):
        """server.key (DER RSA private key) produces finding."""
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = db.name
        db.close()
        try:
            cfg = make_cfg(
                windows_env["vm_ip"],
                username="fulluser",
                password="SnaffFull1!",
                share="SnaffTest",
            )
            cfg.state.state_db = db_path
            with no_auth_check:
                _, p = run_scan(cfg)

            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            key_findings = [
                f for f in findings
                if "server.key" in f["file_path"].lower()
            ]
            assert len(key_findings) > 0, (
                f"No finding from DER private key server.key. "
                f"Cert-related findings: {[(f['file_path'], f['rule_name']) for f in findings if 'key' in f['file_path'].lower() or 'cert' in (f.get('rule_name') or '').lower()]}"
            )
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_empty_key_no_crash(self, windows_env):
        """empty.key (0 bytes) doesn't crash the scanner."""
        cfg = make_cfg(
            windows_env["vm_ip"],
            username="fulluser",
            password="SnaffFull1!",
            share="SnaffTest",
        )
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.scan_complete is True

    def test_garbage_der_no_crash(self, windows_env):
        """garbage.der (random bytes) doesn't crash the scanner."""
        cfg = make_cfg(
            windows_env["vm_ip"],
            username="fulluser",
            password="SnaffFull1!",
            share="SnaffTest",
        )
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.scan_complete is True
