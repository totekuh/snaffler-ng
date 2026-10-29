"""Data types for file scanning results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from snaffler.analysis.model.file_context import FileContext
from snaffler.analysis.model.file_result import FileResult


class FileCheckStatus(Enum):
    """Outcome of a metadata-only file check."""
    DISCARD = "discard"
    SNAFFLE = "snaffle"
    NEEDS_CONTENT = "needs_content"
    CHECK_KEYS = "check_keys"
    PEEK_ARCHIVE = "peek_archive"


@dataclass
class FileCheckResult:
    """Result of :meth:`FileScanner.check_file`.

    For ``SNAFFLE`` status the finding is in *result*.
    For ``NEEDS_CONTENT`` / ``CHECK_KEYS`` / ``PEEK_ARCHIVE`` the caller
    should fetch bytes and call :meth:`FileScanner.scan_with_data`, passing
    this object as *prior* to avoid re-evaluating file rules.
    """
    status: FileCheckStatus
    result: Optional[FileResult] = None
    content_rule_names: list = field(default_factory=list)
    _ctx: Optional[FileContext] = None
    _best_result: Optional[FileResult] = None
    _needs_cert_check: bool = False
    _needs_archive_peek: bool = False
    _can_scan_content: bool = False
