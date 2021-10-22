from typing import List, Optional

from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import ScanType


class SinglePattern(ScanType):
    """Check if single line rule present in the line

    Attributes:
        MAX_LINE_LENGTH: Int constant. Max line length allowed in Scanner. All lines longer than this will be ignored
    """
    @classmethod
    def run(cls, config: Config, line: str, line_num: int, file_path: str, rule: Rule,
            lines: List[str]) -> Optional[Candidate]:
        """Check if regex pattern defined in a rule is present in a line

        Args:
            config: config object of user configs
            line: Line to check
            line_num: Line number of a current line
            file_path: Path to the file that contain current line
            rule: Rule object to check current line
            lines: All lines if the file

        Return:
            Candidate object if pattern defined in a rule is present in a line and filters defined in rule do not
             remove current line. None otherwise
        """
        line_data = cls.get_line_data(config, line, line_num, file_path, rule.patterns[0], rule.filters)

        if line_data is None:
            return None

        candidate = Candidate([line_data], rule.patterns, rule.rule_name, rule.severity, rule.validations, rule.use_ml)
        return candidate
