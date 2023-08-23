import logging
import re
from abc import ABC, abstractmethod
from typing import List, Optional

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
    def run(cls, config: Config, rule: Rule, target: AnalysisTarget) -> Optional[Candidate]:
        """Check if regex pattern defined in a rule is present in a line.

        Args:
            config: user configs
            rule: Rule object to check current line
            target: Analysis target

        Return:
            Candidate object if pattern defined in a rule is present in a line and filters defined in rule do not
            remove current line. None otherwise

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
    def get_line_data(
            cls,  #
            config: Config,  #
            target: AnalysisTarget,  #
            pattern: re.Pattern,  #
            filters: List[Filter]) -> Optional[LineData]:
        """Check if regex pattern is present in line, and line should not be removed by filters.

        Args:
            config: dict of credsweeper configuration
            target: AnalysisTarget with all necessary data
            pattern: Compiled regex object to be searched in line
            filters: Filters to use

        Return:
            LineData object if pattern a line and filters do not remove current line. None otherwise

        """
        for _match in pattern.finditer(target.line):
            logger.debug("Valid line for pattern: %s in file: %s:%d in line: %s", pattern, target.file_path,
                         target.line_num, target.line)
            line_data = LineData(config, target.line, target.line_pos, target.line_num, target.file_path,
                                 target.file_type, target.info, pattern, _match)

            if config.use_filters and cls.filtering(config, target, line_data, filters):
                # may be next matched item will be not filtered
                continue
            return line_data
        return None

    @classmethod
    def _get_candidate(cls, config: Config, rule: Rule, target: AnalysisTarget) -> Optional[Candidate]:
        """Returns Candidate object.

        Args:
            config: user configs
            rule: Rule object to check current line
            target: Target for analysis

        Return:
            Candidate object if pattern defined in a rule is present in a line and filters defined in rule do not
            remove current line. None otherwise

        """
        if config.exclude_lines and target.line.strip() in config.exclude_lines:
            return None

        line_data = cls.get_line_data(config=config, target=target, pattern=rule.patterns[0], filters=rule.filters)

        if line_data is None:
            return None
        if len(config.exclude_values) > 0 and line_data.value.strip() in config.exclude_values:
            return None

        return Candidate([line_data], rule.patterns, rule.rule_name, rule.severity, config, rule.validations,
                         rule.use_ml)
