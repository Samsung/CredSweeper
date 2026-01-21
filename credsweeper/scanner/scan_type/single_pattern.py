from typing import List

from credsweeper.common.constants import RuleType
from credsweeper.config.config import Config
from credsweeper.credentials.candidate import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.rules.rule import Rule
from credsweeper.scanner.scan_type.scan_type import ScanType


class SinglePattern(ScanType):
    """Check if single line rule present in the line."""

    @classmethod
    def run(cls, config: Config, rule: Rule, target: AnalysisTarget) -> List[Candidate]:
        """Check if regex pattern defined in a rule is present in a line.

        Args:
            config: config object of user configs
            rule: Rule object to check current line
            target: Analysis target

        Return:
            List of Candidate objects if pattern defined in a rule is present in a line
            and filters defined in rule do not remove current line. Empty list - otherwise

        """

        if RuleType.PATTERN != rule.rule_type and RuleType.KEYWORD != rule.rule_type:
            raise ValueError(f"Rule `{rule}` provided to `{cls.__name__}`.run "
                             f"should have pattern_type equal to `{RuleType.PATTERN.value}`")

        return cls._get_candidates(config, rule, target)
