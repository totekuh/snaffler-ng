from dataclasses import dataclass
from typing import Optional, Iterable

from snaffler.classifiers.rules import MatchLocation, MatchAction


@dataclass
class RuleDecision:
    action: MatchAction
    match: Optional[str] = None
    relay_targets: Optional[list] = None

# snaffler/classifiers/evaluator.py
from snaffler.classifiers.rules import MatchLocation, MatchAction


class RuleEvaluator:
    def evaluate_file_rule(self, rule, full_path, name, ext, size):
        match = None

        if rule.match_location == MatchLocation.FILE_PATH:
            match = rule.matches(full_path)
        elif rule.match_location == MatchLocation.FILE_NAME:
            match = rule.matches(name)
        elif rule.match_location == MatchLocation.FILE_EXTENSION:
            match = rule.matches(ext)
        elif rule.match_location == MatchLocation.FILE_LENGTH:
            match = f"size == {size}" if rule.match_length == size else None

        if not match:
            return None

        # 🔥 normalize HERE
        if hasattr(match, "group"):
            match = match.group(0)

        return RuleDecision(
            action=rule.match_action,
            match=match,
            relay_targets=rule.relay_targets if rule.match_action == MatchAction.RELAY else None,
        )

    def should_discard(self, rules, unc_path, name) -> bool:
        for rule in rules:
            if rule.match_action != MatchAction.DISCARD:
                continue

            text = unc_path if rule.match_location == MatchLocation.FILE_PATH else name
            if rule.matches(text):
                return True

        return False
