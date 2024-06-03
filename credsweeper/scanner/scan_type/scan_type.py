import logging
import re
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Dict, Set

from credsweeper.common.constants import RuleType, MAX_LINE_LENGTH, CHUNK_STEP_SIZE, CHUNKS_OVERLAP_SIZE
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
                logger.debug("Filtered line with filter: %s in file: %s:%d  in line: %s value: %s",
                             filter_.__class__.__name__, line_data.path, line_data.line_num, line_data.line,
                             line_data.value)
                return True
        return False

    @staticmethod
    def get_chunks(line_len: int) -> Set[Tuple[int, int]]:
        """Returns chunks positions for given line length"""
        chunks = {(0, line_len if MAX_LINE_LENGTH > line_len else MAX_LINE_LENGTH)}
        # case for oversize line
        next_offset = CHUNK_STEP_SIZE
        while line_len > next_offset + CHUNKS_OVERLAP_SIZE:
            # the target is too long for single "finditer" - it will be scanned by chunks
            if line_len < next_offset + MAX_LINE_LENGTH:
                # best overlap for tail
                chunks.add((line_len - MAX_LINE_LENGTH, line_len))
                break
            else:
                # the chunk is not the last
                chunk_end = line_len if next_offset + MAX_LINE_LENGTH > line_len \
                    else next_offset + MAX_LINE_LENGTH
                chunks.add((next_offset, chunk_end))
                next_offset += CHUNK_STEP_SIZE
        return chunks

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
        offsets = cls.get_chunks(target.line_len)

        # used to avoid duplicates for overlap cases only if line is oversize
        purged_line_data: Optional[Dict[Tuple[int, int, int, int, int, int, int], LineData]] = {} if 1 < len(offsets) \
            else None

        while offsets:
            offset_start, offset_end = offsets.pop()
            for _match in pattern.finditer(target.line, pos=offset_start, endpos=offset_end):
                logger.debug("Valid line for pattern: %s in file: %s:%d in line: %s", pattern.pattern, target.file_path,
                             target.line_num, target.line)
                line_data = LineData(config, target.line, target.line_pos, target.line_num, target.file_path,
                                     target.file_type, target.info, pattern, _match)

                if config.use_filters and cls.filtering(config, target, line_data, filters):
                    if 0 < line_data.variable_end:
                        # may be next matched item will be not filtered - let search it after variable
                        offsets.add((line_data.variable_end, offset_end))
                    continue
                line_data_list.append(line_data)

        if isinstance(purged_line_data, dict) and 1 < len(line_data_list):
            # workaround for removing duplicates in case of oversize line only
            for i in line_data_list:
                ld_key = (i.line_num, i.value_start, i.value_end, i.separator_start, i.separator_end, i.variable_start,
                          i.variable_end)
                if ld_key not in purged_line_data:
                    purged_line_data[ld_key] = i
            line_data_list = [x for x in purged_line_data.values()]

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
                                  rule.use_ml, rule.confidence)
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
