import re
from dataclasses import dataclass

from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.rules import ClassifierRule, MatchAction, MatchLocation


@dataclass
class RuleDecision:
    action: MatchAction
    match: str | None = None
    content_rule_names: list[str] | None = None


class RuleEvaluator:
    def __init__(
        self,
        file_rules: list[ClassifierRule],
        content_rules: list[ClassifierRule],
        postmatch_rules: list[ClassifierRule],
    ) -> None:
        self.file_rules = file_rules
        # Sort content rules by descending triage severity so Black (3)
        # rules are checked before Red (2), Yellow (1), Green (0).
        self.content_rules = sorted(
            content_rules,
            key=lambda r: r.triage.level,
            reverse=True,
        )
        self.postmatch_rules = postmatch_rules

        self.content_rules_by_name: dict[str, ClassifierRule] = {r.rule_name: r for r in content_rules}

    def evaluate_file_rule(self, rule: ClassifierRule, ctx: FileContext) -> RuleDecision | None:
        if rule.match_location == MatchLocation.FILE_PATH:
            match = rule.matches(ctx.unc_path)
        elif rule.match_location == MatchLocation.FILE_NAME:
            match = rule.matches(ctx.name)
        elif rule.match_location == MatchLocation.FILE_EXTENSION:
            match = rule.matches(ctx.ext)
        elif rule.match_location == MatchLocation.FILE_LENGTH:
            match = f"size == {ctx.size}" if rule.match_length == ctx.size else None
        else:
            match = None

        if not match:
            return None

        if isinstance(match, re.Match):
            match_text = match.group(0)
        else:
            match_text = match

        return RuleDecision(
            action=rule.match_action,
            match=match_text,
            content_rule_names=rule.content_rule_names,
        )

    def should_discard_postmatch(self, ctx: FileContext) -> bool:
        for rule in self.postmatch_rules:
            if rule.match_action != MatchAction.DISCARD:
                continue

            text = ctx.unc_path if rule.match_location == MatchLocation.FILE_PATH else ctx.name

            if rule.matches(text):
                return True

        return False
