import copy
import re
from typing import List

from credsweeper.common.constants import RuleType
from credsweeper.config.config import Config
from credsweeper.credentials.candidate import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import ValueSearchCheck
from credsweeper.filters.filter import Filter
from credsweeper.rules.rule import Rule
from credsweeper.scanner.scan_type.scan_type import ScanType


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

        for candidate in candidates:
            # use additional filter to skip the value in first line_data and continues scan
            filters = copy.deepcopy(rule.filters)
            filters.append(ValueSearchCheck(config, candidate.line_data_list[0].value))
            if cls._scan(config, candidate, candidate.line_data_list[0].line_pos, target, rule.patterns[1], filters):
                # the value was found in the first line - skip next scanning
                continue
            line_pos_margin = 1
            while line_pos_margin <= cls.MAX_SEARCH_MARGIN:
                candi_line_pos_backward = candidate.line_data_list[0].line_pos - line_pos_margin
                if 0 <= candi_line_pos_backward < target.lines_len:
                    if cls._scan(config, candidate, candi_line_pos_backward, target, rule.patterns[1], filters):
                        break
                candi_line_pos_forward = candidate.line_data_list[0].line_pos + line_pos_margin
                if candi_line_pos_forward < target.lines_len:
                    if cls._scan(config, candidate, candi_line_pos_forward, target, rule.patterns[1], filters):
                        break
                line_pos_margin += 1

        # return candidates with multi line_data_list only
        return [x for x in candidates if 1 < len(x.line_data_list)]

    @classmethod
    def _scan(cls, config: Config, candidate: Candidate, candi_line_pos: int, target: AnalysisTarget,
              pattern: re.Pattern,
              filters: List[Filter]) -> bool:
        """Search for second pattern in multi-pattern rule.

        Automatically update candidate with detected line if any.

        Args:
            config: dict, scanner configuration
            candidate: Current credential candidate detected in the line
            candi_line_pos: line position of lines around candidate to perform search
            target: Analysis target
            pattern: second pattern in a rule
            filters: filters to be applied on candidate

        Return:
            Boolean. True if second part detected. False otherwise

        """
        new_target = AnalysisTarget(candi_line_pos, target.lines, target.line_nums, target.descriptor)

        line_data_list = cls.get_line_data_list(config=config,
                                                target=new_target,
                                                pattern=pattern,
                                                filters=filters)

        if not line_data_list:
            return False
        else:
            candidate.line_data_list.extend(line_data_list)
            return True
