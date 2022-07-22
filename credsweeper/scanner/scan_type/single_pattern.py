from typing import Optional

from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import ScanType


class SinglePattern(ScanType):
    """Check if single line rule present in the line."""

    @classmethod
    def run(cls, config: Config, rule: Rule, target: AnalysisTarget) -> Optional[Candidate]:
        """Check if regex pattern defined in a rule is present in a line.

        Args:
            config: config object of user configs
            rule: Rule object to check current line
            target: Analysis target

        Return:
            Candidate object if pattern defined in a rule is present in a line and filters defined in rule do not
             remove current line. None otherwise

        """

        return cls._get_candidate(config, rule, target)
