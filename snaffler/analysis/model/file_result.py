#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime
from typing import Optional

from snaffler.classifiers.rules import Triage


class FileResult:
    __slots__ = (
        "accessed",
        "context",
        "created",
        "display_name",
        "file_path",
        "match",
        "modified",
        "rule_name",
        "size",
        "triage",
    )

    def __init__(
        self,
        file_path: str,
        size: int,
        modified: Optional[datetime],
        triage: Triage,
        rule_name: str,
        match: Optional[str] = None,
        context: Optional[str] = None,
        created: Optional[datetime] = None,
        accessed: Optional[datetime] = None,
        display_name: Optional[str] = None,
    ):
        self.file_path = file_path
        self.size = size
        self.modified = modified
        self.created = created
        self.accessed = accessed
        self.triage = triage
        self.rule_name = rule_name
        self.match = match
        self.context = context
        self.display_name = display_name

    def match_haystack(self) -> str:
        """Build the search string used by --match filter."""
        return "\n".join(filter(None, [self.file_path, self.rule_name, self.match, self.context]))

    @staticmethod
    def pick_best(
        current: Optional[FileResult],
        candidate: Optional[FileResult],
    ) -> Optional[FileResult]:
        if not candidate:
            return current
        if not current:
            return candidate
        if candidate.triage.more_severe_than(current.triage):
            return candidate
        return current
