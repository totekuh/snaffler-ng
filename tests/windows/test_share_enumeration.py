"""Share enumeration against real Windows SMB."""

from tests.windows.conftest import USERS, make_cfg, run_scan


class TestShareDiscovery:

    def test_empty_share_completes(self, windows_env):
        cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                       password=USERS["fulluser"]["password"],
                       share="SnaffEmpty")
        _, p = run_scan(cfg)
        assert p.scan_complete
        assert p.files_scanned == 0

    def test_multi_share_scan(self, windows_env):
        ip = windows_env["vm_ip"]
        cfg = make_cfg(
            ip,
            username="fulluser",
            password=USERS["fulluser"]["password"],
            unc_targets=[f"//{ip}/SnaffTest", f"//{ip}/SnaffSensitive"],
        )
        _, p = run_scan(cfg)
        assert p.scan_complete
        assert p.files_matched > 0

    def test_multi_share_more_than_single(self, windows_env):
        ip = windows_env["vm_ip"]
        u, pw = "fulluser", USERS["fulluser"]["password"]

        cfg_single = make_cfg(ip, username=u, password=pw, share="SnaffTest")
        _, p_single = run_scan(cfg_single)

        cfg_multi = make_cfg(
            ip, username=u, password=pw,
            unc_targets=[f"//{ip}/SnaffTest", f"//{ip}/SnaffSensitive"],
        )
        _, p_multi = run_scan(cfg_multi)
        assert p_multi.files_scanned >= p_single.files_scanned

    def test_share_filter_isolates(self, windows_env):
        ip = windows_env["vm_ip"]
        u, pw = "fulluser", USERS["fulluser"]["password"]

        cfg_one = make_cfg(ip, username=u, password=pw, share="SnaffSensitive")
        _, p_one = run_scan(cfg_one)

        cfg_other = make_cfg(ip, username=u, password=pw, share="SnaffTest")
        _, p_other = run_scan(cfg_other)

        assert p_one.files_scanned != p_other.files_scanned
