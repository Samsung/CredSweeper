from functools import cached_property
from typing import List, Optional, Generator

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider


class StringContentProvider(ContentProvider):
    """Provider performs scan simple text lines"""

    def __init__(
            self,  #
            lines: List[str],  #
            line_numbers: Optional[List[int]] = None,  #
            file_path: Optional[str] = None,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        """
        Parameters:
            lines: text lines to be processed
            line_numbers: matched line numbers for lines if the order is not natural.
                Otherwise, it will be filled with natural order from 1.

        """
        super().__init__(file_path=file_path, file_type=file_type, info=info)
        self.__lines = lines
        # fill line numbers only when amounts are equal
        if line_numbers is None or len(lines) != len(line_numbers):
            self.__line_numbers = None
        else:
            self.__line_numbers = line_numbers

    @cached_property
    def data(self) -> bytes:
        """data getter for StringContentProvider"""
        raise NotImplementedError(__name__)

    def free(self) -> None:
        """free data after scan to reduce memory usage"""
        self.__lines = []
        if "lines" in self.__dict__:
            delattr(self, "lines")
        self.__line_numbers = []
        if "line_numbers" in self.__dict__:
            delattr(self, "line_numbers")

    @cached_property
    def lines(self) -> List[str]:
        """line_numbers RO getter for StringContentProvider"""
        return self.__lines

    @cached_property
    def line_numbers(self) -> List[int]:
        """line_numbers RO getter for StringContentProvider"""
        if self.__line_numbers is None or len(self.__lines) != len(self.__line_numbers):
            self.__line_numbers = list(range(1, 1 + len(self.__lines))) if self.__lines else []
        return self.__line_numbers

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return lines to scan.

        Args:
            min_len: minimal line length to scan

        Return:
            list of analysis targets based on every row in file

        """
        return self.lines_to_targets(min_len, self.lines, self.line_numbers)
