import logging
from abc import ABC, abstractmethod
from typing import List, Optional

from regex import regex

from credsweeper.common.constants import MAX_LINE_LENGTH
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
    def filtering(cls, config: Config, line_data: LineData, filters: List[Filter]) -> bool:
        """Check if line data should be removed based on filters.

        If `use_filters` option is false, always return False

        Args:
            config: dict of credsweeper configuration
            line_data: Line data to check with filters
            filters: Filters to use

        Return:
            boolean: True if line_data should be removed. False otherwise.
            If `use_filters` option is false, always return False

        """
        if not config.use_filters:
            return False
        for filter_ in filters:
            if filter_.run(line_data):
                logger.debug("Filtered line with filter: %s in file: %s:%d  in line: %s", filter_.__class__.__name__,
                             line_data.path, line_data.line_num, line_data.line)
                return True
        return False

    @classmethod
    def get_line_data(
            cls,  #
            config: Config,  #
            line: str,  #
            line_num: int,  #
            file_path: str,  #
            file_type: str,  #
            info: str,  #
            pattern: regex.Pattern,  #
            filters: List[Filter]) -> Optional[LineData]:
        """Check if regex pattern is present in line, and line should not be removed by filters.

        Args:
            config: dict of credsweeper configuration
            line: Line to check
            line_num: Line number of a current line
            file_path: Path to the file that contain current line
            file_type: Type of file in extension '.txt'
            info: Extended info
            pattern: Compiled regex object to be searched in line
            filters: Filters to use

        Return:
            LineData object if pattern a line and filters do not remove current line. None otherwise

        """
        if not cls.is_valid_line(line, pattern, line_num, file_path):
            return None
        logger.debug("Valid line for pattern: %s in file: %s:%d in line: %s", pattern, file_path, line_num, line)
        line_data = LineData(config, line, line_num, file_path, file_type, info, pattern)

        if cls.filtering(config, line_data, filters):
            return None
        return line_data

    @classmethod
    def is_pattern_detected_line(cls, line: str, pattern: regex.Pattern) -> bool:
        """Check if pattern present in the line.

        Args:
            line: Line to check
            pattern: Compiled regex object

        Return:
            Boolean. True if pattern is present. False otherwise

        """
        if pattern.search(line):
            return True
        return False

    @classmethod
    def is_valid_line(cls, line: str, pattern: regex.Pattern, line_num: int = -1, file_path: str = None) -> bool:
        """Check if line is not too long and pattern present in the line.

        Args:
            line: Line to check
            pattern: Compiled regex object to be searched in line
            line_num: Number of line in the file
            file_path: Path to the file

        Return:
            Boolean. True if pattern is present and line is not too long. False otherwise

        """
        if cls.is_valid_line_length(line, line_num, file_path) and cls.is_pattern_detected_line(line, pattern):
            return True
        return False

    @classmethod
    def is_valid_line_length(cls, line: str, line_num: int = -1, file_path: str = None) -> bool:
        """Check if line is not too long for the scanner.

        Args:
            line: Line to check
            line_num: Number of line in the file
            file_path: Path to the file

        Return:
            Boolean. True if line is not too long. False otherwise

        """
        if len(line) <= MAX_LINE_LENGTH:
            return True
        logger.warning(f"Oversize line in file: {file_path}:{line_num}")
        return False

    @classmethod
    def _get_candidate(cls, config: Config, rule: Rule, target: AnalysisTarget) -> Optional[Candidate]:
        """Returns Candidate object.

        Args:
            config: user configs
            rule: Rule object to check current line

        Return:
            Candidate object if pattern defined in a rule is present in a line and filters defined in rule do not
            remove current line. None otherwise

        """
        if len(config.exclude_lines) > 0 and target.line.strip() in config.exclude_lines:
            return None

        line_data = cls.get_line_data(config=config,
                                      line=target.line,
                                      line_num=target.line_num,
                                      file_path=target.file_path,
                                      file_type=target.file_type,
                                      info=target.info,
                                      pattern=rule.patterns[0],
                                      filters=rule.filters)

        if line_data is None:
            return None
        if len(config.exclude_values) > 0 and line_data.value.strip() in config.exclude_values:
            return None

        return Candidate([line_data], rule.patterns, rule.rule_name, rule.severity, config, rule.validations,
                         rule.use_ml)
