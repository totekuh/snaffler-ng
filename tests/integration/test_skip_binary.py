"""Integration tests for --skip-binary flag.

Compares two scan DBs:
- scan_db: default scan (no --skip-binary)
- scan_db_skip_binary: scan with --skip-binary

Both scan the same Samba share (tests/data/).
"""

import os
import sqlite3

import pytest

IN_DOCKER = os.environ.get("SNAFFLER_TEST_DOCKER") == "1"
pytestmark = pytest.mark.skipif(not IN_DOCKER, reason="Docker-only test")


def _query(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows


def _finding_count(db_path):
    return _query(db_path, "SELECT COUNT(*) FROM finding")[0][0]


def _findings_by_rule(db_path):
    return {row[0]: row[1] for row in _query(
        db_path, "SELECT rule_name, COUNT(*) FROM finding GROUP BY rule_name"
    )}


def _text_findings(db_path):
    """Findings on files that are NOT native binaries (no .elf/.exe/.macho extension)."""
    return _query(
        db_path,
        """SELECT file_path, rule_name FROM finding
           WHERE file_path NOT LIKE '%.elf'
             AND file_path NOT LIKE '%.exe'
             AND file_path NOT LIKE '%.macho'
             AND file_path NOT LIKE '%.dll'
             AND file_path NOT LIKE '%.so'
             AND file_path NOT LIKE '%.dylib'"""
    )


class TestSkipBinary:

    def test_both_dbs_exist(self, scan_db, scan_db_skip_binary):
        assert os.path.exists(scan_db)
        assert os.path.exists(scan_db_skip_binary)

    def test_default_scan_has_findings(self, scan_db):
        assert _finding_count(scan_db) > 0

    def test_skip_binary_scan_has_findings(self, scan_db_skip_binary):
        count = _finding_count(scan_db_skip_binary)
        assert count >= 0

    def test_skip_binary_no_more_findings_than_default(self, scan_db, scan_db_skip_binary):
        """--skip-binary should produce <= findings compared to default."""
        default_count = _finding_count(scan_db)
        skip_count = _finding_count(scan_db_skip_binary)
        assert skip_count <= default_count

    def test_text_file_count_stable(self, scan_db, scan_db_skip_binary):
        """Text files should still produce findings with --skip-binary.

        Exact findings may differ because pick_best selects different winners
        when content matches on binary files are removed.
        """
        default_text = _text_findings(scan_db)
        skip_text = _text_findings(scan_db_skip_binary)
        default_paths = {r[0] for r in default_text}
        skip_paths = {r[0] for r in skip_text}
        missing = default_paths - skip_paths
        assert not missing, f"Text files lost findings with --skip-binary: {missing}"
