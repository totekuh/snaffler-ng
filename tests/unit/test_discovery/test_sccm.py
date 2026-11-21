"""Tests for SCCM ContentLib deep scan module."""

import fnmatch
from unittest.mock import MagicMock, patch

import pytest

from snaffler.config.configuration import FAST_MODE_EXCLUSIONS
from snaffler.discovery.sccm import is_contentlib_dir, parse_ini_hash, resolve_filelib_path


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
