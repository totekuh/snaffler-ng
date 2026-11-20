"""Parametrize shared SMB tests across available backends."""

import os

import pytest

from snaffler.utils.logger import set_finding_store

# ---------------------------------------------------------------------------
# Backend registry
# ---------------------------------------------------------------------------

_BACKENDS = {}


def _try_register_impacket():
    try:
        import impacket.smbserver  # noqa: F401

        from tests.smb_shared._backend_impacket import impacket_smb_target
        _BACKENDS["impacket"] = impacket_smb_target
    except ImportError:
        pass


def _try_register_windows():
    if os.environ.get("SNAFFLER_WIN_TESTS", "").lower() in ("0", "false", "no", "off"):
        return
    try:
        import winbox  # noqa: F401

        from tests.smb_shared._backend_windows import windows_smb_target
        _BACKENDS["windows"] = windows_smb_target
    except Exception:
        pass


_try_register_impacket()
_try_register_windows()

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)

# ---------------------------------------------------------------------------
# Parametrized fixture
# ---------------------------------------------------------------------------


@pytest.fixture(params=list(_BACKENDS.keys()))
def smb_target(request):
    factory = _BACKENDS[request.param]
    yield from factory()


@pytest.fixture(autouse=True)
def _reset_finding_store():
    yield
    set_finding_store(None)
