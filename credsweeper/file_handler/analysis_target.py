from functools import cached_property
from typing import List, Optional

from credsweeper.file_handler.descriptor import Descriptor


class AnalysisTarget:
    """AnalysisTarget"""

    def __init__(
        self,
        line_pos: int,
        lines: List[str],
        line_nums: List[int],
        descriptor: Descriptor,
    ):
        self.__line_pos = line_pos
        self.__lines = lines
        self.__line_nums = line_nums
        self.__descriptor = descriptor

    @cached_property
    def line(self) -> str:
        """cached value"""
        return self.__lines[self.__line_pos]

    @cached_property
    def line_len(self) -> int:
        """cached value"""
        return len(self.line)

    @cached_property
    def line_strip(self) -> str:
        """cached value"""
        return self.line.strip()

    @cached_property
    def line_strip_len(self) -> int:
        """cached value"""
        return len(self.line_strip)

    @cached_property
    def line_strip_lower(self) -> str:
        """cached value"""
        return self.line_strip.lower()

    @cached_property
    def lines(self) -> List[str]:
        """cached value"""
        return self.__lines

    @cached_property
    def lines_len(self) -> int:
        """cached value"""
        return len(self.__lines)

    @cached_property
    def line_pos(self) -> int:
        """cached value"""
        return self.__line_pos

    @cached_property
    def line_num(self) -> int:
        """cached value"""
        return self.__line_nums[self.__line_pos]

    @cached_property
    def line_nums(self) -> List[int]:
        """cached value"""
        return self.__line_nums

    @cached_property
    def file_path(self) -> Optional[str]:
        """cached value"""
        return self.__descriptor.path

    @cached_property
    def file_type(self) -> Optional[str]:
        """cached value"""
        return self.__descriptor.extension

    @cached_property
    def info(self) -> Optional[str]:
        """cached value"""
        return self.__descriptor.info

    @cached_property
    def descriptor(self) -> Descriptor:
        """cached value"""
        return self.__descriptor
