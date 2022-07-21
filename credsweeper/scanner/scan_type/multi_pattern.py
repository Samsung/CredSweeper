from typing import Optional

from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import ScanType


class MultiPattern(ScanType):
    """Check if line is a part of a multi-line credential and second part is present within MAX_SEARCH_MARGIN lines.

    Parameters:
        MAX_SEARCH_MARGIN: Int constant. Number of lines around current to perform search for the second part

    """

    MAX_SEARCH_MARGIN = 10

    @classmethod
    def run(cls, config: Config, rule: Rule, target: AnalysisTarget) -> Optional[Candidate]:
        """Check if multiline credential present if the file within MAX_SEARCH_MARGIN range from current line_num.

        Args:
            config: user configs
            rule: Rule object to check current line. Should be a multi-pattern rule
            target: Analysis target

        Return:
            Candidate object if pattern defined in a rule is present in a line and second part of multi-pattern rule is
                present within MAX_SEARCH_MARGIN from the line. False otherwise

        """
        assert rule.pattern_type == rule.MULTI_PATTERN, \
            "Rules provided to MultiPattern.run should have pattern_type equal to MULTI_PATTERN"

        candidate = cls._get_candidate(config, rule, target)
        if not isinstance(candidate, Candidate):
            return None

        line_num_margin = 1

        while line_num_margin <= cls.MAX_SEARCH_MARGIN:
            if 1 <= candidate.line_data_list[0].line_num - line_num_margin <= len(target.lines):
                if cls._scan(config, candidate, -line_num_margin, target, rule):
                    break
            if candidate.line_data_list[0].line_num + line_num_margin <= len(target.lines):
                if cls._scan(config, candidate, line_num_margin, target, rule):
                    break
            line_num_margin += 1

        # Check if found multi line
        if len(candidate.line_data_list) == 1:
            return None

        return candidate

    @classmethod
    def _scan(cls, config: Config, candidate: Candidate, line_num_margin: int, target: AnalysisTarget,
              rule: Rule) -> bool:
        """Search for second part of multiline rule near the current line.

        Automatically update candidate with detected line if any.

        Args:
            config: dict, scanner configuration
            candidate: Current credential candidate detected in the line
            line_num_margin: Number of lines around candidate to perform search
            target: Analysis target
            rule: Rule object to check current line. Should be a multi-pattern rule

        Return:
            Boolean. True if second part detected. False otherwise

        """
        candi_line_num = candidate.line_data_list[0].line_num + line_num_margin
        candi_line = target.lines[candi_line_num - 1]

        line_data = cls.get_line_data(config, candi_line, candi_line_num, target.file_path, rule.patterns[1],
                                      rule.filters)

        if line_data is None:
            return False

        candidate.add_line_data(line_data)
        return True
