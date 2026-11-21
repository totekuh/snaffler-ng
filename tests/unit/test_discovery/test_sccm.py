"""Tests for SCCM ContentLib deep scan module."""

import pytest

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
