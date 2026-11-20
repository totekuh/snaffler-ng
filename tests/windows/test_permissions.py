"""Permission-level tests: full, read-only, no-access users."""

from tests.windows.conftest import USERS, make_cfg, no_auth_check, run_scan


class TestFullAccessUser:

    def test_produces_findings(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"])
        _, p = run_scan(cfg)
        assert p.files_matched > 0

    def test_scans_seeded_files(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"])
        _, p = run_scan(cfg)
        assert p.files_scanned >= 10


class TestReadOnlyUser:

    def test_produces_findings(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="readuser",
                       password=USERS["readuser"]["password"])
        _, p = run_scan(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_same_findings_as_full(self, windows_env):
        ip = windows_env["vm_ip"]

        cfg_full = make_cfg(ip, username="fulluser",
                            password=USERS["fulluser"]["password"])
        _, p_full = run_scan(cfg_full)

        cfg_read = make_cfg(ip, username="readuser",
                            password=USERS["readuser"]["password"])
        _, p_read = run_scan(cfg_read)

        assert p_read.files_matched == p_full.files_matched


class TestNoAccessUser:

    def test_no_findings(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="noaccess",
                       password=USERS["noaccess"]["password"])
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.files_scanned == 0

    def test_still_completes(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="noaccess",
                       password=USERS["noaccess"]["password"])
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.scan_complete
