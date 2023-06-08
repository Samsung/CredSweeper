from functools import cached_property
from typing import List, Optional


class AnalysisTarget:
    """AnalysisTarget"""

    def __init__(
        self,
        line: str,
        line_num: int,
        lines: List[str],
        file_path: Optional[str] = None,
        file_type: Optional[str] = None,
        info: Optional[str] = None,
    ):
        # main
        self.__line = line
        self.__lines = lines
        self.__line_num = line_num
        # auxiliary
        self.__file_path = file_path
        self.__file_type = file_type
        self.__info = info

    def __eq__(self, other):
        return self.__line_num == other.__line_num \
            and self.__line == other.__line \
            and self.__file_path == other.__file_path \
            and self.__file_type == other.__file_type \
            and self.__info == other.__info \
            and self.__lines == other.__lines

    @cached_property
    def line(self) -> str:
        """cached_property"""
        return self.__line

    @cached_property
    def line_num(self) -> int:
        """cached_property"""
        return self.__line_num

    @cached_property
    def lines(self) -> List[str]:
        """cached_property"""
        return self.__lines

    @cached_property
    def file_path(self) -> str:
        """cached_property"""
        return self.__file_path

    @cached_property
    def file_type(self) -> str:
        """cached_property"""
        return self.__file_type

    @cached_property
    def info(self) -> str:
        """cached_property"""
        return self.__info

    # derivatives

    @cached_property
    def line_len(self) -> int:
        """cached_property"""
        return len(self.__line)

    @cached_property
    def lines_len(self) -> int:
        """cached_property"""
        return len(self.__lines)

    @cached_property
    def stripped_line(self) -> str:
        """cached_property"""
        return self.__line.strip()

    @cached_property
    def stripped_line_len(self) -> int:
        """cached_property"""
        return len(self.stripped_line)
