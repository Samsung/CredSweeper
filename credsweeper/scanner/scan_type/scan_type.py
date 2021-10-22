from abc import ABC, abstractmethod
from typing import List, Optional

from regex import regex

from credsweeper.config import Config
from credsweeper.credentials import Candidate, LineData
from credsweeper.filters import Filter
from credsweeper.logger.logger import logging
from credsweeper.rules import Rule


class ScanType(ABC):
    """Base class for all Scanners. Scanner allow to check if regex pattern defined in a rule is present in a line

    Attributes:
        MAX_LINE_LENGTH: Int constant. Max line length allowed in Scanner. All lines longer than this will be ignored
    """
    MAX_LINE_LENGTH = 1500

    @classmethod
    @abstractmethod
    def run(cls, config: Config, line: str, line_num: int, file_path: str, rule: Rule,
            lines: List[str]) -> Optional[Candidate]:
        """Check if regex pattern defined in a rule is present in a line

        Args:
            config: user configs
            line: Line to check
            line_num: Line number of a current line
            file_path: Path to the file that contain current line
            rule: Rule object to check current line
            lines: All lines if the file

        Return:
            Candidate object if pattern defined in a rule is present in a line and filters defined in rule do not
             remove current line. None otherwise
        """
        raise NotImplementedError()

    @classmethod
    def filtering(cls, config: Config, line_data: LineData, filters: List[Filter]) -> bool:
        """Check if line data should be removed based on filters. If `use_filters` option is false, always return False

        Attributes:
            line_data: Line data to check with filters
            filters: Filters to use

        Return:
            Boolean. True if line_data should be removed. False otherwise.
                If `use_filters` option is false, always return False
        """
        if not config.use_filters:
            return False
        for filter_ in filters:
            if filter_.run(line_data):
                logging.debug(f"Filtered line with filter: {filter_.__class__.__name__} in file: {line_data.path}:{line_data.line_num} in line: {line_data.line}")
                return True
        return False

    @classmethod
    def get_line_data(cls, config: Config, line: str, line_num: int, file_path: str, pattern: regex.Pattern,
                      filters: List[Filter]) -> Optional[LineData]:
        """Check if regex pattern is present in line, and line should not be removed by filters

        Attributes:
            line: Line to check
            line_num: Line number of a current line
            file_path: Path to the file that contain current line
            pattern: Compiled regex object to be searched in line
            filters: Filters to use

        Return:
            LineData object if pattern a line and filters do not remove current line. None otherwise
        """
        if not cls.is_valid_line(line, pattern):
            return None
        logging.debug(f"Valid line for pattern: {pattern} in file: {file_path}:{line_num} in line: {line}")
        line_data = LineData(config, line, line_num, file_path, pattern)

        if cls.filtering(config, line_data, filters):
            return None
        return line_data

    @classmethod
    def is_pattern_detected_line(cls, line: str, pattern: regex.Pattern) -> bool:
        """Check if pattern present in the line

        Attributes:
            line: Line to check
            pattern: Compiled regex object

        Return:
            Boolean. True if pattern is present. False otherwise
        """
        if pattern.search(line):
            return True
        return False

    @classmethod
    def is_valid_line(cls, line: str, pattern: regex.Pattern) -> bool:
        """Check if line is not too long and pattern present in the line

        Attributes:
            line: Line to check
            pattern: Compiled regex object to be searched in line

        Return:
            Boolean. True if pattern is present and line is not too long. False otherwise
        """
        if cls.is_valid_line_length(line) and cls.is_pattern_detected_line(line, pattern):
            return True
        return False

    @classmethod
    def is_valid_line_length(cls, line: str) -> bool:
        """Check if line is not too long for the scanner

        Attributes:
            line: Line to check

        Return:
            Boolean. True if line is not too long. False otherwise
        """
        if len(line) <= cls.MAX_LINE_LENGTH:
            return True
        return False
