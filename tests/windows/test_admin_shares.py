"""Admin share access on real Windows SMB (C$, ADMIN$)."""

from tests.windows.conftest import USERS, make_cfg, no_auth_check, run_scan


class TestAdminShares:

    def test_c_dollar_accessible_as_admin(self, windows_env):
        cfg = make_cfg(
            windows_env["vm_ip"],
            username=windows_env["cfg"].vm_user,
            password=windows_env["cfg"].vm_password,
            share="C$",
        )
        cfg.scanning.max_depth = 2
        _, p = run_scan(cfg)
        assert p.scan_complete
        assert p.files_scanned > 0

    def test_c_dollar_denied_for_normal_user(self, windows_env):
        cfg = make_cfg(
            windows_env["vm_ip"],
            username="fulluser",
            password=USERS["fulluser"]["password"],
            share="C$",
        )
        with no_auth_check:
            _, p = run_scan(cfg)
        assert p.files_scanned == 0

    def test_admin_dollar_accessible(self, windows_env):
        cfg = make_cfg(
            windows_env["vm_ip"],
            username=windows_env["cfg"].vm_user,
            password=windows_env["cfg"].vm_password,
            share="ADMIN$",
        )
        cfg.scanning.max_depth = 1
        _, p = run_scan(cfg)
        assert p.scan_complete
        assert p.files_scanned > 0
