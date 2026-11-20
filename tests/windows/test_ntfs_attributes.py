"""NTFS file attributes: hidden, system files on real Windows."""

from winbox.mcp._common import _ensure_vm_ready
from winbox.mcp._shares_io import share_rm, share_write

from tests.windows.conftest import USERS, make_cfg, run_scan


class TestHiddenFiles:

    def test_hidden_file_discovered(self, windows_env):
        share_write(
            name="SnaffTest", path="hidden_secret.key",
            content="-----BEGIN RSA PRIVATE KEY-----\nfakekey\n",
        )
        _, _, ga = _ensure_vm_ready()
        ga.exec_powershell(
            "$p = (Get-SmbShare -Name 'SnaffTest').Path; "
            "Set-ItemProperty (Join-Path $p 'hidden_secret.key') "
            "-Name Attributes -Value ([IO.FileAttributes]::Hidden)"
        )

        try:
            cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                           password=USERS["fulluser"]["password"])
            _, p = run_scan(cfg)
            assert p.files_scanned > 0
        finally:
            share_rm(name="SnaffTest", path="hidden_secret.key", confirm=True)

    def test_system_file_discovered(self, windows_env):
        share_write(
            name="SnaffTest", path="system_secret.key",
            content="-----BEGIN RSA PRIVATE KEY-----\nfakekey\n",
        )
        _, _, ga = _ensure_vm_ready()
        ga.exec_powershell(
            "$p = (Get-SmbShare -Name 'SnaffTest').Path; "
            "Set-ItemProperty (Join-Path $p 'system_secret.key') "
            "-Name Attributes -Value ([IO.FileAttributes]::System)"
        )

        try:
            cfg = make_cfg(windows_env["vm_ip"], username="fulluser",
                           password=USERS["fulluser"]["password"])
            _, p = run_scan(cfg)
            assert p.files_scanned > 0
        finally:
            share_rm(name="SnaffTest", path="system_secret.key", confirm=True)
