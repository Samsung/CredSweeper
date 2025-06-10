import logging
import re
from abc import ABC, abstractmethod
from typing import List

from credsweeper.common.constants import RuleType, MIN_DATA_LEN
from credsweeper.config.config import Config
from credsweeper.credentials.candidate import Candidate, LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.rules.rule import Rule

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
    def filtering(cls, target: AnalysisTarget, line_data: LineData, filters: List[Filter]) -> bool:
        """Check if line data should be removed based on filters.

        If `use_filters` option is false, always return False

        Args:
            target: AnalysisTarget from which `line_data` was obtained
            line_data: Line data to check with `filters`
            filters: Filters to use

        Return:
            boolean: True if line_data should be removed. False otherwise.
            If `use_filters` option is false, always return False

        """
        if not line_data.value:
            logger.debug("Filtered line with empty value in file: %s:%d  in line: %s value: '%s'", line_data.path,
                         line_data.line_num, line_data.line, line_data.value)
            return True
        for filter_ in filters:
            if filter_.run(line_data, target):
                logger.debug("Filtered line with filter: %s in file: %s:%d  in line: %s value: %s",
                             filter_.__class__.__name__, line_data.path, line_data.line_num, line_data.line,
                             line_data.value)
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
        # start - end positions for continuously searching for overlapping pattern
        offsets = [(0, target.line_len)]

        while offsets:
            offset_start, offset_end = offsets.pop()
            bypass_start = bypass_end = None
            for _match in pattern.finditer(target.line, pos=offset_start, endpos=offset_end):

                logger.debug("Valid line for pattern: %s in file: %s:%d in line: %s", pattern.pattern, target.file_path,
                             target.line_num, target.line)
                line_data = LineData(config, target.line, target.line_pos, target.line_num, target.file_path,
                                     target.file_type, target.info, pattern, _match)
                if bypass_start and bypass_end:
                    if 0 < line_data.variable_start:
                        bypass_end = line_data.variable_start
                    elif 0 < line_data.value_start:
                        bypass_end = line_data.value_start
                    if bypass_start < bypass_end and bypass_end - bypass_start > MIN_DATA_LEN:
                        offsets.append((bypass_start, bypass_end))
                    bypass_start = bypass_end = None
                elif MIN_DATA_LEN < line_data.value_end < _match.end() \
                        and MIN_DATA_LEN < _match.end() - line_data.value_end:
                    # add bypass for valuable sanitized value
                    bypass_start = line_data.value_end
                    bypass_end = offset_end

                if config.use_filters and cls.filtering(target, line_data, filters):
                    if line_data.variable and 0 <= line_data.variable_start < line_data.variable_end:
                        # may be next matched item will be not filtered - let search it after variable
                        bypass_start = line_data.variable_end
                        bypass_end = offset_end
                    elif line_data.value and 0 <= line_data.value_start < line_data.value_end:
                        # may be next matched item will be not filtered - let search it after variable
                        bypass_start = line_data.value_end
                        bypass_end = offset_end
                    continue

                if target.offset is not None:
                    # the target line is a chunk of long line - offsets have to be corrected
                    if 0 <= line_data.variable_start:
                        line_data.variable_start += target.offset
                    if 0 <= line_data.variable_end:
                        line_data.variable_end += target.offset
                    if 0 <= line_data.separator_start:
                        line_data.separator_start += target.offset
                    if 0 <= line_data.separator_end:
                        line_data.separator_end += target.offset
                    # value positions are mandatory
                    line_data.value_start += target.offset
                    line_data.value_end += target.offset
                    # get the original line
                    line_data.line = target.lines[target.line_pos]

                line_data_list.append(line_data)
            if bypass_start and bypass_end:
                offsets.append((bypass_start, bypass_end))

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

        if line_data_list := cls.get_line_data_list(config=config,
                                                    target=target,
                                                    pattern=rule.patterns[0],
                                                    filters=rule.filters):
            for line_data in line_data_list:
                if config.exclude_values and line_data.value.strip() in config.exclude_values:
                    continue
                candidate = Candidate(line_data_list=[line_data],
                                      patterns=rule.patterns,
                                      rule_name=rule.rule_name,
                                      severity=rule.severity,
                                      config=config,
                                      use_ml=rule.use_ml,
                                      confidence=rule.confidence)
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
