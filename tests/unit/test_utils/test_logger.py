"""Regression tests for snaffler.utils.logger."""

import json
import logging
from unittest.mock import MagicMock, patch

from snaffler.utils import logger as logger_mod
from snaffler.utils.logger import log_file_result, setup_logging


# ---- BUG-NEW-1: _finding_store only called when suppress_log=False ----


class TestFindingStoreSuppressLog:
    """BUG-NEW-1: _finding_store must NOT be invoked when suppress_log=True."""

    def _make_logger(self):
        lg = logging.getLogger("snaffler.test.finding_store")
        lg.handlers.clear()
        lg.setLevel(logging.DEBUG)
        lg.addHandler(logging.NullHandler())
        return lg

    def test_finding_store_not_called_when_suppress_log_true(self):
        store = MagicMock()
        old = logger_mod._finding_store
        try:
            logger_mod._finding_store = store
            log_file_result(
                logger=self._make_logger(),
                file_path="//srv/share/secret.txt",
                triage="Red",
                rule_name="TestRule",
                match="password",
                context="password=hunter2",
                suppress_log=True,
            )
            store.assert_not_called()
        finally:
            logger_mod._finding_store = old

    def test_finding_store_called_when_suppress_log_false(self):
        store = MagicMock()
        old = logger_mod._finding_store
        try:
            logger_mod._finding_store = store
            log_file_result(
                logger=self._make_logger(),
                file_path="//srv/share/secret.txt",
                triage="Red",
                rule_name="TestRule",
                match="password",
                context="password=hunter2",
                suppress_log=False,
            )
            store.assert_called_once()
            kwargs = store.call_args[1]
            assert kwargs["file_path"] == "//srv/share/secret.txt"
            assert kwargs["triage"] == "Red"
            assert kwargs["rule_name"] == "TestRule"
        finally:
            logger_mod._finding_store = old


# ---- BUG-NEW-3: Ellipsis only appended when context > 200 chars ----


class TestContextEllipsis:
    """BUG-NEW-3: '...' must only appear when context exceeds 200 characters."""

    def _make_logger(self):
        lg = logging.getLogger("snaffler.test.ellipsis")
        lg.handlers.clear()
        lg.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        lg.addHandler(handler)
        return lg

    def test_no_ellipsis_for_exactly_200_chars(self, capsys):
        context_200 = "A" * 200
        lg = self._make_logger()

        with patch.object(logger_mod, "NO_COLOR", True):
            log_file_result(
                logger=lg,
                file_path="//srv/share/f.txt",
                triage="Green",
                rule_name="Rule",
                context=context_200,
            )

        captured = capsys.readouterr()
        # Context exactly 200 chars: no ellipsis
        assert "..." not in captured.err and "..." not in captured.out
        # But the full context IS present
        assert context_200 in (captured.out + captured.err)

    def test_ellipsis_for_201_chars(self, capsys):
        context_201 = "B" * 201
        lg = self._make_logger()

        with patch.object(logger_mod, "NO_COLOR", True):
            log_file_result(
                logger=lg,
                file_path="//srv/share/f.txt",
                triage="Green",
                rule_name="Rule",
                context=context_201,
            )

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "..." in output
        # Truncated to 200 chars + "..."
        assert "B" * 200 + "..." in output


# ---- BUG-F2: TSV file handler leak ----


class TestTSVFileHandlerLeak:
    """BUG-F2: setup_logging with log_type='tsv' must create exactly one FileHandler."""

    def test_tsv_creates_exactly_one_file_handler(self, tmp_path):
        from snaffler.utils.logger import setup_logging

        tsv_file = str(tmp_path / "test.tsv")
        lg = setup_logging(
            log_to_file=True,
            log_file_path=tsv_file,
            log_type="tsv",
            log_to_console=False,
        )
        try:
            file_handlers = [
                h for h in lg.handlers if isinstance(h, logging.FileHandler)
            ]
            assert len(file_handlers) == 1, (
                f"Expected exactly 1 FileHandler, got {len(file_handlers)}"
            )
        finally:
            for h in lg.handlers[:]:
                h.close()
            lg.handlers.clear()


# ---- created/accessed (ctime/atime) timestamp propagation ----


class TestCreatedAccessedOutput:
    """log_file_result must emit created/accessed in JSON / TSV / plain output."""

    def _emit(self, log_file_path, log_type, **extra):
        lg = setup_logging(
            log_to_file=True,
            log_file_path=log_file_path,
            log_type=log_type,
            log_to_console=False,
            log_level="data",
        )
        try:
            log_file_result(
                logger=lg,
                file_path="//srv/share/secret.txt",
                triage="Red",
                rule_name="TestRule",
                match="password",
                context="password=hunter2",
                size=100,
                modified="2024-01-03 00:00:00",
                created="2024-01-01 00:00:00",
                accessed="2024-01-02 00:00:00",
                **extra,
            )
        finally:
            for h in lg.handlers[:]:
                h.close()
            lg.handlers.clear()

    def test_json_emits_created_and_accessed(self, tmp_path):
        out = tmp_path / "out.json"
        self._emit(str(out), "json")

        lines = [l for l in out.read_text().splitlines() if l.strip()]
        record = json.loads(lines[-1])

        assert record["mtime"] == "2024-01-03 00:00:00"
        assert record["ctime"] == "2024-01-01 00:00:00"
        assert record["atime"] == "2024-01-02 00:00:00"

    def test_json_omits_created_accessed_when_absent(self, tmp_path):
        out = tmp_path / "out2.json"
        lg = setup_logging(
            log_to_file=True,
            log_file_path=str(out),
            log_type="json",
            log_to_console=False,
            log_level="data",
        )
        try:
            log_file_result(
                logger=lg,
                file_path="//srv/share/secret.txt",
                triage="Red",
                rule_name="TestRule",
                match="password",
                size=100,
            )
        finally:
            for h in lg.handlers[:]:
                h.close()
            lg.handlers.clear()

        lines = [l for l in out.read_text().splitlines() if l.strip()]
        record = json.loads(lines[-1])
        assert "ctime" not in record
        assert "atime" not in record

    def test_tsv_header_and_row_include_ctime_atime(self, tmp_path):
        out = tmp_path / "out.tsv"
        self._emit(str(out), "tsv")

        lines = [l for l in out.read_text().splitlines() if l.strip()]
        header = lines[0].split("\t")
        assert "ctime" in header
        assert "atime" in header

        row = lines[-1].split("\t")
        assert row[header.index("ctime")] == "2024-01-01 00:00:00"
        assert row[header.index("atime")] == "2024-01-02 00:00:00"

    def test_plain_text_includes_ctime_atime(self, tmp_path):
        out = tmp_path / "out.log"
        self._emit(str(out), "plain")

        text = out.read_text()
        assert "[ctime:2024-01-01 00:00:00]" in text
        assert "[atime:2024-01-02 00:00:00]" in text
