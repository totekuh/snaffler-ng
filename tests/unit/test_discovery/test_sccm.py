"""Tests for SCCM ContentLib deep scan module."""

import fnmatch
from unittest.mock import MagicMock, patch

import pytest

from snaffler.config.configuration import FAST_MODE_EXCLUSIONS
from snaffler.discovery.sccm import is_contentlib_dir, parse_ini_hash, resolve_filelib_path, walk_contentlib


class TestIsContentLibDir:
    def test_exact_name(self):
        assert is_contentlib_dir("SCCMContentLib") is True

    def test_dollar_suffix(self):
        assert is_contentlib_dir("SCCMContentLib$") is True

    def test_lowercase(self):
        assert is_contentlib_dir("sccmcontentlib") is True

    def test_lowercase_dollar(self):
        assert is_contentlib_dir("sccmcontentlib$") is True

    def test_mixed_case(self):
        assert is_contentlib_dir("SccmContentLib$") is True

    def test_negative_data(self):
        assert is_contentlib_dir("data") is False

    def test_negative_sysvol(self):
        assert is_contentlib_dir("sysvol") is False

    def test_negative_contentlib_only(self):
        assert is_contentlib_dir("ContentLib") is False

    def test_negative_empty(self):
        assert is_contentlib_dir("") is False


class TestParseIniHash:
    def test_valid(self):
        assert parse_ini_hash("[File]\nHash=ab12cd34ef56") == "ab12cd34ef56"

    def test_whitespace(self):
        assert parse_ini_hash("[File]\nHash = ab12cd34ef56") == "ab12cd34ef56"

    def test_uppercase_hash(self):
        assert parse_ini_hash("[File]\nHash=AB12CD34EF56") == "AB12CD34EF56"

    def test_missing_hash(self):
        assert parse_ini_hash("[File]\nSomething=else") is None

    def test_empty(self):
        assert parse_ini_hash("") is None

    def test_hash_only_no_section(self):
        assert parse_ini_hash("Hash=abc123") == "abc123"

    def test_multiple_lines(self):
        content = "[File]\nSize=1234\nHash=deadbeef\nOther=value"
        assert parse_ini_hash(content) == "deadbeef"


class TestResolveFileLibPath:
    def test_basic(self):
        assert resolve_filelib_path("/base", "ab12cd34ef") == "/base/FileLib/ab12/ab12cd34ef"

    def test_long_hash(self):
        h = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        assert resolve_filelib_path("/path", h) == f"/path/FileLib/a1b2/{h}"

    def test_prefix_extraction(self):
        result = resolve_filelib_path("", "deadbeef1234")
        assert "/FileLib/dead/" in result


class TestShareLevelDetection:
    """Tests for ContentLib detection at share root (case 1: share IS ContentLib)."""

    def test_walk_directory_share_root_contentlib(self):
        from snaffler.discovery.smb_tree_walker import SMBTreeWalker

        cfg = MagicMock()
        cfg.rules.directory = []
        cfg.targets.exclude_unc = []

        walker = SMBTreeWalker(cfg)
        walker._cache = MagicMock()
        mock_smb = MagicMock()
        walker._cache.get.return_value = mock_smb

        with patch("snaffler.discovery.smb_tree_walker.walk_contentlib") as mock_walk:
            result = walker.walk_directory("//10.0.0.1/SCCMContentLib$", on_file=MagicMock())
            mock_walk.assert_called_once()
            assert result == []

    def test_walk_directory_share_root_contentlib_no_dollar(self):
        from snaffler.discovery.smb_tree_walker import SMBTreeWalker

        cfg = MagicMock()
        cfg.rules.directory = []
        cfg.targets.exclude_unc = []

        walker = SMBTreeWalker(cfg)
        walker._cache = MagicMock()
        walker._cache.get.return_value = MagicMock()

        with patch("snaffler.discovery.smb_tree_walker.walk_contentlib") as mock_walk:
            walker.walk_directory("//10.0.0.1/SCCMContentLib", on_file=MagicMock())
            mock_walk.assert_called_once()

    def test_walk_directory_share_root_normal_no_contentlib(self):
        from snaffler.discovery.smb_tree_walker import SMBTreeWalker

        cfg = MagicMock()
        cfg.rules.directory = []
        cfg.targets.exclude_unc = []

        walker = SMBTreeWalker(cfg)
        walker._cache = MagicMock()
        mock_smb = MagicMock()
        mock_smb.listPath.return_value = []
        walker._cache.get.return_value = mock_smb

        with patch("snaffler.discovery.smb_tree_walker.walk_contentlib") as mock_walk:
            walker.walk_directory("//10.0.0.1/data", on_file=MagicMock())
            mock_walk.assert_not_called()
            mock_smb.listPath.assert_called_once()

    def test_walk_directory_subdir_contentlib_still_triggers(self):
        """Case 2: ContentLib as subdirectory inside a normal share."""
        from snaffler.discovery.smb_tree_walker import SMBTreeWalker

        cfg = MagicMock()
        cfg.rules.directory = []
        cfg.targets.exclude_unc = []

        walker = SMBTreeWalker(cfg)
        walker._cache = MagicMock()
        mock_smb = MagicMock()
        walker._cache.get.return_value = mock_smb

        mock_entry = MagicMock()
        mock_entry.get_longname.return_value = "SCCMContentLib"
        mock_entry.is_directory.return_value = True
        mock_smb.listPath.return_value = [mock_entry]

        with patch("snaffler.discovery.smb_tree_walker.walk_contentlib") as mock_walk:
            walker.walk_directory("//10.0.0.1/data", on_file=MagicMock())
            mock_walk.assert_called_once()


class TestFastModeExclusions:
    """Verify FAST_MODE_EXCLUSIONS cover both ContentLib cases."""

    def test_fast_excludes_contentlib_share(self):
        """Case 1: share named SCCMContentLib matched by exclusion glob."""
        path = "//10.0.0.1/SCCMContentLib"
        assert any(
            fnmatch.fnmatch(path.lower(), p.lower()) for p in FAST_MODE_EXCLUSIONS
        ), f"FAST_MODE_EXCLUSIONS should match {path}"

    def test_fast_excludes_contentlib_dollar_share(self):
        path = "//10.0.0.1/SCCMContentLib$"
        assert any(
            fnmatch.fnmatch(path.lower(), p.lower()) for p in FAST_MODE_EXCLUSIONS
        ), f"FAST_MODE_EXCLUSIONS should match {path}"

    def test_fast_excludes_contentlib_subdir(self):
        """Case 2: ContentLib as subdirectory."""
        path = "//10.0.0.1/data/SCCMContentLib"
        assert any(
            fnmatch.fnmatch(path.lower(), p.lower()) for p in FAST_MODE_EXCLUSIONS
        ), f"FAST_MODE_EXCLUSIONS should match {path}"

    def test_fast_excludes_contentlib_subdir_dollar(self):
        path = "//10.0.0.1/data/SCCMContentLib$"
        assert any(
            fnmatch.fnmatch(path.lower(), p.lower()) for p in FAST_MODE_EXCLUSIONS
        ), f"FAST_MODE_EXCLUSIONS should match {path}"

    def test_fast_does_not_exclude_normal_share(self):
        path = "//10.0.0.1/data"
        assert not any(
            fnmatch.fnmatch(path.lower(), p.lower()) for p in FAST_MODE_EXCLUSIONS
        ), f"FAST_MODE_EXCLUSIONS should NOT match {path}"

    def test_fast_excludes_contentlib_children(self):
        """Files inside ContentLib dir also excluded."""
        path = "//10.0.0.1/data/SCCMContentLib/DataLib/something.ini"
        assert any(
            fnmatch.fnmatch(path.lower(), p.lower()) for p in FAST_MODE_EXCLUSIONS
        ), f"FAST_MODE_EXCLUSIONS should match {path}"


def _make_datalib_entry(name, is_dir=False):
    e = MagicMock()
    e.get_longname.return_value = name
    e.is_directory.return_value = is_dir
    return e


def _make_blob_entry(hash_name, size=100):
    e = MagicMock()
    e.get_longname.return_value = hash_name
    e.get_filesize.return_value = size
    e.get_mtime_epoch.return_value = 1700000000.0
    e.get_ctime_epoch.return_value = 1700000000.0
    e.get_atime_epoch.return_value = 1700000000.0
    return e


def _make_smb_with_ini(ini_name, ini_content, blob_hash, blob_size=100):
    """Build a mock SMB with one INI in DataLib and one blob in FileLib."""
    smb = MagicMock()

    datalib_entry = _make_datalib_entry(ini_name)
    blob_entry = _make_blob_entry(blob_hash, blob_size)

    def list_path(share, pattern):
        if "DataLib" in pattern:
            return [_make_datalib_entry("."), _make_datalib_entry(".."), datalib_entry]
        if "FileLib" in pattern:
            return [blob_entry]
        return []

    smb.listPath.side_effect = list_path

    def get_file(share, path, callback):
        callback(ini_content.encode())

    smb.getFile.side_effect = get_file
    return smb


class TestWalkContentLib:
    """Unit tests for walk_contentlib() function body."""

    def test_happy_path_calls_on_file(self):
        blob_hash = "ab12cd34ef567890"
        smb = _make_smb_with_ini(
            "deploy.ps1.INI", f"[File]\nHash={blob_hash}\n", blob_hash, 200,
        )
        on_file = MagicMock()
        walk_contentlib(smb, "10.0.0.1", "sccm", "", on_file)

        on_file.assert_called_once()
        args = on_file.call_args[0]
        assert args[0] == f"//10.0.0.1/sccm/FileLib/{blob_hash[:4]}/{blob_hash}"
        assert args[1] == 200
        assert args[5] == "deploy.ps1"

    def test_empty_datalib(self):
        smb = MagicMock()
        smb.listPath.return_value = [_make_datalib_entry("."), _make_datalib_entry("..")]
        on_file = MagicMock()
        walk_contentlib(smb, "10.0.0.1", "share", "", on_file)
        on_file.assert_not_called()

    def test_datalib_unreadable(self):
        smb = MagicMock()
        smb.listPath.side_effect = Exception("ACCESS_DENIED")
        on_file = MagicMock()
        walk_contentlib(smb, "10.0.0.1", "share", "", on_file)
        on_file.assert_not_called()

    def test_unreadable_ini_skipped(self):
        smb = MagicMock()
        good_hash = "deadbeef12345678"
        bad_entry = _make_datalib_entry("bad.ps1.INI")
        good_entry = _make_datalib_entry("good.ps1.INI")

        def list_path(share, pattern):
            if "DataLib" in pattern:
                return [_make_datalib_entry("."), _make_datalib_entry(".."), bad_entry, good_entry]
            if "FileLib" in pattern:
                return [_make_blob_entry(good_hash)]
            return []

        smb.listPath.side_effect = list_path

        call_count = [0]

        def get_file(share, path, callback):
            if "bad.ps1" in path:
                raise OSError("read failed")
            callback(f"[File]\nHash={good_hash}\n".encode())

        smb.getFile.side_effect = get_file
        on_file = MagicMock()
        walk_contentlib(smb, "10.0.0.1", "share", "", on_file)
        on_file.assert_called_once()
        assert on_file.call_args[0][5] == "good.ps1"

    def test_malformed_ini_no_hash(self):
        smb = MagicMock()
        entry = _make_datalib_entry("broken.txt.INI")
        smb.listPath.return_value = [_make_datalib_entry("."), _make_datalib_entry(".."), entry]
        smb.getFile.side_effect = lambda s, p, cb: cb(b"[File]\nNoHashHere=true\n")
        on_file = MagicMock()
        walk_contentlib(smb, "10.0.0.1", "share", "", on_file)
        on_file.assert_not_called()

    def test_non_ini_files_skipped(self):
        smb = MagicMock()
        entry = _make_datalib_entry("readme.txt")
        smb.listPath.return_value = [_make_datalib_entry("."), _make_datalib_entry(".."), entry]
        on_file = MagicMock()
        walk_contentlib(smb, "10.0.0.1", "share", "", on_file)
        on_file.assert_not_called()
        smb.getFile.assert_not_called()

    def test_directory_entries_skipped(self):
        smb = MagicMock()
        entry = _make_datalib_entry("subdir", is_dir=True)
        smb.listPath.return_value = [_make_datalib_entry("."), _make_datalib_entry(".."), entry]
        on_file = MagicMock()
        walk_contentlib(smb, "10.0.0.1", "share", "", on_file)
        on_file.assert_not_called()

    def test_missing_filelib_blob(self):
        smb = MagicMock()
        entry = _make_datalib_entry("secret.txt.INI")
        blob_hash = "abcdef1234567890"

        def list_path(share, pattern):
            if "DataLib" in pattern:
                return [_make_datalib_entry("."), _make_datalib_entry(".."), entry]
            if "FileLib" in pattern:
                return [_make_blob_entry("wrong_hash_name")]
            return []

        smb.listPath.side_effect = list_path
        smb.getFile.side_effect = lambda s, p, cb: cb(f"[File]\nHash={blob_hash}\n".encode())
        on_file = MagicMock()
        walk_contentlib(smb, "10.0.0.1", "share", "", on_file)
        on_file.assert_not_called()

    def test_filelib_stat_error(self):
        smb = MagicMock()
        entry = _make_datalib_entry("secret.txt.INI")
        blob_hash = "abcdef1234567890"

        def list_path(share, pattern):
            if "DataLib" in pattern:
                return [_make_datalib_entry("."), _make_datalib_entry(".."), entry]
            if "FileLib" in pattern:
                raise Exception("ACCESS_DENIED")
            return []

        smb.listPath.side_effect = list_path
        smb.getFile.side_effect = lambda s, p, cb: cb(f"[File]\nHash={blob_hash}\n".encode())
        on_file = MagicMock()
        walk_contentlib(smb, "10.0.0.1", "share", "", on_file)
        on_file.assert_not_called()
