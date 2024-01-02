import logging
import re
from abc import ABC, abstractmethod
from typing import List

from credsweeper.common.constants import RuleType
from credsweeper.config import Config
from credsweeper.credentials import Candidate, LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.rules import Rule

logger = logging.getLogger(__name__)


class ScanType(ABC):
    """Base class for all Scanners.

    Scanner allow to check if regex pattern defined in a rule is present in a line.

    """

    @classmethod
    @abstractmethod
    def run(cls, config: Config, rule: Rule, target: AnalysisTarget) -> List[Candidate]:
        """Check if regex pattern defined in a rule is present in a line.

        Args:
            config: user configs
            rule: Rule object to check current line
            target: Analysis target

        Return:
            List of Candidate objects if pattern defined in a rule is present in a line
            and filters defined in rule do not remove current line. Empty list - otherwise

        """
        raise NotImplementedError()

    @classmethod
    def filtering(cls, config: Config, target: AnalysisTarget, line_data: LineData, filters: List[Filter]) -> bool:
        """Check if line data should be removed based on filters.

        If `use_filters` option is false, always return False

        Args:
            config: dict of credsweeper configuration
            target: AnalysisTarget from which `line_data` was obtained
            line_data: Line data to check with `filters`
            filters: Filters to use

        Return:
            boolean: True if line_data should be removed. False otherwise.
            If `use_filters` option is false, always return False

        """
        for filter_ in filters:
            if filter_.run(line_data, target):
                logger.debug("Filtered line with filter: %s in file: %s:%d  in line: %s", filter_.__class__.__name__,
                             line_data.path, line_data.line_num, line_data.line)
                return True
        return False

    @classmethod
    def get_line_data_list(
            cls,  #
            config: Config,  #
            target: AnalysisTarget,  #
            pattern: re.Pattern,  #
            filters: List[Filter]) -> List[LineData]:
        """Check if regex pattern is present in line, and line should not be removed by filters.

        Args:
            config: dict of credsweeper configuration
            target: AnalysisTarget with all necessary data
            pattern: Compiled regex object to be searched in line
            filters: Filters to use

        Return:
            List of LineData objects if pattern a line and filters do not remove current line. Empty otherwise

        """
        line_data_list: List[LineData] = []
        for _match in pattern.finditer(target.line):
            logger.debug("Valid line for pattern: %s in file: %s:%d in line: %s", pattern, target.file_path,
                         target.line_num, target.line)
            line_data = LineData(config, target.line, target.line_pos, target.line_num, target.file_path,
                                 target.file_type, target.info, pattern, _match)

            if config.use_filters and cls.filtering(config, target, line_data, filters):
                # may be next matched item will be not filtered
                continue
            line_data_list.append(line_data)
        return line_data_list

    @classmethod
    def _get_candidates(cls, config: Config, rule: Rule, target: AnalysisTarget) -> List[Candidate]:
        """Returns Candidate objects list.

        Args:
            config: user configs
            rule: Rule object to check current line
            target: Target for analysis

        Return:
            List of Candidate objects if pattern defined in a rule is present in a line
            and filters defined in rule do not remove current line. Empty list - otherwise

        """
        candidates: List[Candidate] = []
        if config.exclude_lines and target.line_strip in config.exclude_lines:
            return candidates

        line_data_list = cls.get_line_data_list(config=config,
                                                target=target,
                                                pattern=rule.patterns[0],
                                                filters=rule.filters)

        for line_data in line_data_list:
            if config.exclude_values and line_data.value.strip() in config.exclude_values:
                continue

            candidate = Candidate([line_data], rule.patterns, rule.rule_name, rule.severity, config, rule.validations,
                                  rule.use_ml)
            # single pattern with multiple values means all the patterns must matched in target
            if 1 < len(rule.patterns) and rule.rule_type in (RuleType.PATTERN, RuleType.KEYWORD):
                # additional check whether all patterns match
                if not cls._aux_scan(config, rule, target, candidate):
                    # cannot find secondary values for the candidate
                    continue
            candidates.append(candidate)
        return candidates

    @classmethod
    def _aux_scan(cls, config: Config, rule: Rule, target: AnalysisTarget, candidate: Candidate) -> bool:
        """check for all secondary patterns"""
        for pattern in rule.patterns[1:]:
            line_data_list = cls.get_line_data_list(config=config, target=target, pattern=pattern, filters=rule.filters)
            pattern_matched = False

            for line_data in line_data_list:
                # standard filtering of values from config
                if config.exclude_values and line_data.value.strip() in config.exclude_values:
                    continue
                candidate.line_data_list.append(line_data)
                pattern_matched = True
            if not pattern_matched:
                return False

        # all secondary patterns were matched and candidate is filled with the values
        return True
