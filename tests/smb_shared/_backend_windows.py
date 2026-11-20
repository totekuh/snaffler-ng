"""Windows VM backend factory for shared SMB tests."""

import pytest

from tests.smb_shared.target import SMBTarget


def windows_smb_target():
    from tests.windows.conftest import _VM_IP, USERS

    if _VM_IP is None:
        pytest.skip("Windows VM not available")

    yield SMBTarget(
        ip=_VM_IP,
        port=445,
        share="SnaffTest",
        username="fulluser",
        password=USERS["fulluser"]["password"],
        enforces_auth=True,
    )
