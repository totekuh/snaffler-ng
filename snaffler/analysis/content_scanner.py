"""Content rule evaluation against raw file data."""

import logging
from typing import Optional

from snaffler.analysis.model.file_context import FileContext
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.rules import Triage

logger = logging.getLogger("snaffler")


def evaluate_content(
        ctx: FileContext,
        data: bytes,
        content_rules,
        rule_evaluator,
        match_context_bytes: int,
) -> Optional[FileResult]:
    if not data:
        return None

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="ignore")
        logger.debug(f"Non-UTF-8 content in {ctx.unc_path}, decoded as Latin-1")

    best_result: Optional[FileResult] = None

    postmatch_checked = False
    postmatch_discard = False

    for rule in content_rules:
        match = rule.matches(text)
        if not match:
            continue

        if not postmatch_checked:
            postmatch_checked = True
            postmatch_discard = rule_evaluator.should_discard_postmatch(ctx)
        if postmatch_discard:
            continue

        if isinstance(match, str):
            match_text = match
            pos = text.find(match)
            match_start = pos if pos >= 0 else 0
            match_end = match_start + len(match)
        else:
            match_text = match.group(0)
            match_start = match.start()
            match_end = match.end()

        start = max(0, match_start - match_context_bytes)
        end = min(len(text), match_end + match_context_bytes)

        result = FileResult(
            file_path=ctx.unc_path,
            size=ctx.size,
            modified=ctx.modified,
            created=ctx.created,
            accessed=ctx.accessed,
            triage=rule.triage,
            rule_name=rule.rule_name,
            match=match_text,
            context=text[start:end],
        )

        best_result = FileResult.pick_best(best_result, result)

        if best_result and best_result.triage == Triage.BLACK:
            break

    return best_result
