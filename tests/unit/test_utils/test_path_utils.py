"""Tests for snaffler.utils.path_utils."""

from datetime import datetime
from unittest.mock import MagicMock

from snaffler.utils.path_utils import (
    extract_share_root,
    extract_unc_host,
    extract_unc_share_name,
    get_modified_time,
)


def test_extract_share_root_smb_normal():
    assert extract_share_root("//server/share/sub/file.txt") == "//server/share"


def test_extract_share_root_backslash():
    assert extract_share_root("\\\\server\\share\\sub") == "//server/share"


def test_extract_share_root_ftp_url():
    result = extract_share_root("ftp://myhost:2121/pub/file.txt")
    assert result == "ftp://myhost:2121"


def test_extract_share_root_ftp_default_port():
    result = extract_share_root("ftp://myhost/pub/file.txt")
    assert result == "ftp://myhost"


def test_extract_share_root_single_component():
    assert extract_share_root("//server") == "//server"


def test_extract_share_root_local_path():
    assert extract_share_root("/local/path/file.txt") == "/local/path/file.txt"


def test_get_modified_time_success():
    info = MagicMock()
    info.get_mtime_epoch.return_value = 1700000000
    result = get_modified_time(info)
    assert isinstance(result, datetime)
    assert result == datetime.fromtimestamp(1700000000)


def test_get_modified_time_exception():
    info = MagicMock()
    info.get_mtime_epoch.side_effect = Exception("bad epoch")
    assert get_modified_time(info) is None
