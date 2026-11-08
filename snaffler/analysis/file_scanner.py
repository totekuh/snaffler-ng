#!/usr/bin/env python3
"""File scanner — two-phase evaluation (metadata then content)."""

import logging
import re
from typing import Optional

from snaffler.analysis.certificates import CertificateChecker
from snaffler.analysis.model.file_context import FileContext
from snaffler.analysis.model.file_result import FileResult
from snaffler.analysis.scanner_types import FileCheckStatus, FileCheckResult
from snaffler.analysis.binary_detect import read_magic
from snaffler.analysis.content_scanner import evaluate_content
from snaffler.analysis.archive_scanner import evaluate_archive, list_archive_members, MAX_ARCHIVE_MEMBERS
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.rules import MatchLocation, MatchAction, Triage
from snaffler.utils.fatal import check_fatal_os_error

logger = logging.getLogger("snaffler")

# Re-export for backward compatibility
__all__ = ["FileScanner", "FileCheckResult", "FileCheckStatus"]


class FileScanner:
    _MAX_ARCHIVE_MEMBERS = MAX_ARCHIVE_MEMBERS
    _list_archive_members = staticmethod(list_archive_members)

    def __init__(
            self,
            cfg,
            file_accessor=None,
            rule_evaluator: RuleEvaluator = None,
    ):
        self.cfg = cfg
        self.file_accessor = file_accessor
        self.rule_evaluator = rule_evaluator

        self.cert_checker = CertificateChecker(
            custom_passwords=cfg.scanning.cert_passwords
        )
        mf = getattr(cfg.scanning, 'match_filter', None)
        self._match_re = None
        if isinstance(mf, str):
            try:
                self._match_re = re.compile(mf, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Invalid --match regex '{mf}': {e}")
                raise SystemExit(1)
        self._max_read_bytes = cfg.scanning.max_read_bytes
        self._match_context_bytes = cfg.scanning.match_context_bytes
        self._skip_binary = getattr(cfg.scanning, 'skip_binary', False)

    def _filter_result(
            self,
            result: FileResult,
    ) -> Optional[FileResult]:
        if result.triage.below(self.cfg.scanning.min_interest):
            return None

        if self._match_re:
            if not self._match_re.search(result.match_haystack()):
                return None

        return result

    def check_file(
            self,
            file_path: str,
            size: int,
            mtime_epoch: float,
            ctime_epoch: float = 0.0,
            atime_epoch: float = 0.0,
    ) -> FileCheckResult:
        """Phase 1 — evaluate file rules only (zero I/O)."""
        ctx = FileContext.from_path(file_path, size, mtime_epoch, ctime_epoch, atime_epoch)

        content_rule_names: set = set()
        best_result: Optional[FileResult] = None
        needs_cert_check = False
        needs_archive_peek = False
        relay_fired = False

        logger.debug(f"Evaluating file rules: {file_path} (size={size})")

        for rule in self.rule_evaluator.file_rules:
            decision = self.rule_evaluator.evaluate_file_rule(rule, ctx)
            if not decision:
                continue

            logger.debug(f"{decision.action.name}: {file_path}")

            action = decision.action

            if action == MatchAction.DISCARD:
                return FileCheckResult(status=FileCheckStatus.DISCARD)

            if action == MatchAction.RELAY:
                relay_fired = True
                if decision.content_rule_names:
                    content_rule_names.update(decision.content_rule_names)
                continue

            if action == MatchAction.CHECK_FOR_KEYS:
                if not self.rule_evaluator.should_discard_postmatch(ctx):
                    needs_cert_check = True
                continue

            if action == MatchAction.ENTER_ARCHIVE:
                if size <= self._max_read_bytes:
                    if not self.rule_evaluator.should_discard_postmatch(ctx):
                        needs_archive_peek = True
                else:
                    logger.debug(
                        f"Skipping archive peek for {file_path}: "
                        f"size {size} > max {self._max_read_bytes}"
                    )
                continue

            if action != MatchAction.SNAFFLE:
                continue

            if self.rule_evaluator.should_discard_postmatch(ctx):
                continue

            result = FileResult(
                file_path=file_path,
                size=size,
                modified=ctx.modified,
                created=ctx.created,
                accessed=ctx.accessed,
                triage=rule.triage,
                rule_name=rule.rule_name,
                match=decision.match,
            )
            best_result = FileResult.pick_best(best_result, result)

        if best_result and best_result.triage == Triage.BLACK:
            return FileCheckResult(
                status=FileCheckStatus.SNAFFLE,
                result=best_result,
                _ctx=ctx,
                _best_result=best_result,
            )

        if needs_cert_check or needs_archive_peek:
            can_content = (relay_fired or bool(content_rule_names)) and size <= self._max_read_bytes
            status = (FileCheckStatus.CHECK_KEYS if needs_cert_check
                      else FileCheckStatus.PEEK_ARCHIVE)
            return FileCheckResult(
                status=status,
                content_rule_names=sorted(content_rule_names) if can_content else [],
                _ctx=ctx,
                _best_result=best_result,
                _needs_cert_check=needs_cert_check,
                _needs_archive_peek=needs_archive_peek,
                _can_scan_content=can_content,
            )

        if relay_fired or content_rule_names or not best_result:
            if size <= self._max_read_bytes:
                return FileCheckResult(
                    status=FileCheckStatus.NEEDS_CONTENT,
                    content_rule_names=sorted(content_rule_names),
                    _ctx=ctx,
                    _best_result=best_result,
                    _can_scan_content=True,
                )

        if best_result:
            return FileCheckResult(
                status=FileCheckStatus.SNAFFLE,
                result=best_result,
                _ctx=ctx,
                _best_result=best_result,
            )

        return FileCheckResult(status=FileCheckStatus.DISCARD)

    def scan_with_data(self, data: bytes, prior: FileCheckResult) -> Optional[FileResult]:
        """Phase 2 — run cert/archive/content checks using raw data."""
        ctx = prior._ctx
        best_result = prior._best_result

        if prior._needs_cert_check:
            cert = self._evaluate_certificate(ctx, data)
            best_result = FileResult.pick_best(best_result, cert)

        if prior._needs_archive_peek:
            archive = evaluate_archive(ctx, data, self.rule_evaluator)
            best_result = FileResult.pick_best(best_result, archive)

        if prior._can_scan_content:
            if self._skip_binary and read_magic(data):
                logger.debug(f"Skipping content scan (binary): {ctx.unc_path}")
            else:
                targeted_names = set(prior.content_rule_names)
                if targeted_names:
                    content_rules = sorted(
                        (
                            self.rule_evaluator.content_rules_by_name[n]
                            for n in targeted_names
                            if n in self.rule_evaluator.content_rules_by_name
                        ),
                        key=lambda r: r.triage.level,
                        reverse=True,
                    )
                else:
                    content_rules = self.rule_evaluator.content_rules

                content = evaluate_content(
                    ctx, data, content_rules,
                    self.rule_evaluator, self._match_context_bytes,
                )
                best_result = FileResult.pick_best(best_result, content)

        return best_result

    def scan_file(
            self,
            file_path: str,
            size: int,
            mtime_epoch: float,
            ctime_epoch: float = 0.0,
            atime_epoch: float = 0.0,
    ) -> Optional[FileResult]:
        """Full scan: check_file, optional I/O, scan_with_data, filter."""
        check = self.check_file(file_path, size, mtime_epoch, ctime_epoch, atime_epoch)

        if check.status == FileCheckStatus.DISCARD:
            return None

        if check.status == FileCheckStatus.SNAFFLE:
            return self._filter_result(check.result)

        if self.file_accessor is None:
            if check._best_result:
                return self._filter_result(check._best_result)
            return None

        data = self.file_accessor.read(
            file_path,
            max_bytes=self._max_read_bytes,
        )
        if not data:
            if check._best_result:
                return self._filter_result(check._best_result)
            return None

        try:
            result = self.scan_with_data(data, check)
            if result:
                return self._filter_result(result)
            return None
        except Exception as e:
            check_fatal_os_error(e)
            logger.warning(f"Classification error scanning {file_path}: {e}")
            return None

    def _evaluate_archive(self, ctx, data):
        return evaluate_archive(ctx, data, self.rule_evaluator)

    def _evaluate_content(self, ctx, data, content_rules):
        return evaluate_content(
            ctx, data, content_rules,
            self.rule_evaluator, self._match_context_bytes,
        )

    def _evaluate_certificate(
            self,
            ctx: FileContext,
            data: bytes,
    ) -> Optional[FileResult]:
        if not data:
            return None

        reasons = self.cert_checker.check_certificate(
            data, ctx.name
        )
        if not reasons or "HasPrivateKey" not in reasons:
            return None

        return FileResult(
            file_path=ctx.unc_path,
            size=ctx.size,
            modified=ctx.modified,
            created=ctx.created,
            accessed=ctx.accessed,
            triage=Triage.RED,
            rule_name="RelayCertByExtension",
            match=ctx.name,
            context=", ".join(reasons),
        )
