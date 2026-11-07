"""Archive member evaluation against file rules."""

import io
import logging
import os
import zipfile
from typing import Optional, List

from snaffler.analysis.model.file_context import FileContext
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.rules import MatchAction, Triage
from snaffler.utils.fatal import check_fatal_os_error

logger = logging.getLogger("snaffler")

MAX_ARCHIVE_MEMBERS = 10_000


def evaluate_archive(
        ctx: FileContext,
        data: bytes,
        rule_evaluator,
) -> Optional[FileResult]:
    try:
        with io.BytesIO(data) as bio:
            members = list_archive_members(ctx.ext, bio)
        if not members:
            return None

        best_result: Optional[FileResult] = None
        for member_name, member_size in members:
            member_name = member_name.replace("\\", "/")
            basename = os.path.basename(member_name)
            member_ext = os.path.splitext(basename)[1].lower()
            member_unc = f"{ctx.unc_path}→{member_name}"

            member_ctx = FileContext(
                unc_path=member_unc,
                name=basename,
                ext=member_ext,
                size=member_size,
                modified=ctx.modified,
                created=ctx.created,
                accessed=ctx.accessed,
            )

            for rule in rule_evaluator.file_rules:
                decision = rule_evaluator.evaluate_file_rule(
                    rule, member_ctx
                )
                if not decision:
                    continue

                action = decision.action
                if action == MatchAction.DISCARD:
                    break
                if action != MatchAction.SNAFFLE:
                    continue

                if rule_evaluator.should_discard_postmatch(member_ctx):
                    continue

                result = FileResult(
                    file_path=member_unc,
                    size=member_size,
                    modified=ctx.modified,
                    created=ctx.created,
                    accessed=ctx.accessed,
                    triage=rule.triage,
                    rule_name=rule.rule_name,
                    match=decision.match,
                )
                best_result = FileResult.pick_best(best_result, result)

                if best_result and best_result.triage == Triage.BLACK:
                    return best_result

        return best_result
    except Exception as e:
        check_fatal_os_error(e)
        logger.warning(
            f"Archive peek failed for {ctx.unc_path}: {e}"
        )
        return None


def list_archive_members(
        ext: str, bio: io.BytesIO
) -> Optional[List[tuple]]:
    ext_lower = ext.lower()
    cap = MAX_ARCHIVE_MEMBERS

    if ext_lower == ".zip":
        try:
            with zipfile.ZipFile(bio) as zf:
                members = []
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    members.append((info.filename, info.file_size))
                    if len(members) >= cap:
                        break
                return members
        except (zipfile.BadZipFile, Exception) as e:
            logger.debug(f"Cannot list archive members ({ext}): {e}")
            return None

    if ext_lower == ".7z":
        try:
            import py7zr
        except ImportError:
            logger.warning(
                "py7zr not installed — skipping 7z archive peek. "
                "Install with: pip install snaffler-ng[7z]"
            )
            return None
        try:
            with py7zr.SevenZipFile(bio, mode="r") as sz:
                members = []
                for entry in sz.list():
                    if entry.is_directory:
                        continue
                    members.append((entry.filename, entry.uncompressed or 0))
                    if len(members) >= cap:
                        break
                return members
        except Exception as e:
            logger.debug(f"Cannot list archive members ({ext}): {e}")
            return None

    if ext_lower == ".rar":
        try:
            import rarfile as _rarfile
        except ImportError:
            logger.warning(
                "rarfile not installed — skipping RAR archive peek. "
                "Install with: pip install snaffler-ng[rar]"
            )
            return None
        try:
            with _rarfile.RarFile(bio) as rf:
                members = []
                for info in rf.infolist():
                    if info.is_dir():
                        continue
                    members.append((info.filename, info.file_size))
                    if len(members) >= cap:
                        break
                return members
        except Exception as e:
            logger.debug(f"Cannot list archive members ({ext}): {e}")
            return None

    return None
