from typing import List

from credsweeper.common.constants import RuleType
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
    def run(cls, config: Config, rule: Rule, target: AnalysisTarget) -> List[Candidate]:
        """Check if multiline credential present if the file within MAX_SEARCH_MARGIN range from current line_num.

        Args:
            config: user configs
            rule: Rule object to check current line. Should be a multi-pattern rule
            target: Analysis target

        Return:
            List of Candidates if pattern defined in a rule is present in a line
            and second part of multi-pattern rule is present within MAX_SEARCH_MARGIN from the line.
            Empty list (False) - otherwise.

        """
        assert rule.rule_type == RuleType.MULTI, \
            "Rules provided to MultiPattern.run should have pattern_type equal to MULTI_PATTERN"

        candidates = cls._get_candidates(config, rule, target)
        if not candidates:
            return candidates
        for candidate in candidates:
            line_pos_margin = 1
            while line_pos_margin <= cls.MAX_SEARCH_MARGIN:
                candi_line_pos_backward = candidate.line_data_list[0].line_pos - line_pos_margin
                if 0 <= candi_line_pos_backward < target.lines_len:
                    if cls._scan(config, candidate, candi_line_pos_backward, target, rule):
                        break
                candi_line_pos_forward = candidate.line_data_list[0].line_pos + line_pos_margin
                if candi_line_pos_forward < target.lines_len:
                    if cls._scan(config, candidate, candi_line_pos_forward, target, rule):
                        break
                line_pos_margin += 1

            # Check if found multi line
            if len(candidate.line_data_list) == 1:
                if not cls._scan(config, candidate, candidate.line_data_list[0].line_pos, target, rule):
                    # last resort - to find the credential in the same line
                    return []

        return candidates

    @classmethod
    def _scan(cls, config: Config, candidate: Candidate, candi_line_pos: int, target: AnalysisTarget,
              rule: Rule) -> bool:
        """Search for second part of multiline rule near the current line.

        Automatically update candidate with detected line if any.

        Args:
            config: dict, scanner configuration
            candidate: Current credential candidate detected in the line
            candi_line_pos: line position of lines around candidate to perform search
            target: Analysis target
            rule: Rule object to check current line. Should be a multi-pattern rule

        Return:
            Boolean. True if second part detected. False otherwise

        """
        new_target = AnalysisTarget(candi_line_pos, target.lines, target.line_nums, target.descriptor)

        line_data_list = cls.get_line_data_list(config=config,
                                                target=new_target,
                                                pattern=rule.patterns[1],
                                                filters=rule.filters)

        if not line_data_list:
            return False
        else:
            candidate.line_data_list.extend(line_data_list)
            return True
