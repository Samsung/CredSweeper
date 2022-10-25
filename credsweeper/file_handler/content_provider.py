from abc import ABC, abstractmethod
from typing import List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.utils import Util


class ContentProvider(ABC):
    """Base class to provide access to analysis targets for scanned object."""

    def __init__(
            self,  #
            file_path: Optional[str] = None,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        self.file_path: str = file_path
        self.file_type: str = file_type if file_type is not None else Util.get_extension(file_path)
        self.info: str = info

    @abstractmethod
    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Load and preprocess file diff data to scan.

        Return:
            row objects to analysing

        """
        raise NotImplementedError()

    @property
    def file_path(self) -> str:
        """file_path getter"""
        return self.__file_path

    @file_path.setter
    def file_path(self, _file_path: str) -> None:
        """file_path setter"""
        self.__file_path = _file_path if _file_path else ""

    @property
    def file_type(self) -> str:
        """file_type getter"""
        return self.__file_type

    @file_type.setter
    def file_type(self, _file_type: str) -> None:
        """file_type setter"""
        self.__file_type = _file_type if _file_type else ""

    @property
    def info(self) -> str:
        """info getter"""
        return self.__info

    @info.setter
    def info(self, _info: str) -> None:
        """info getter"""
        self.__info = _info if _info else ""

    def lines_to_targets(self, lines: List[str], line_nums: Optional[List[int]] = None) -> List[AnalysisTarget]:
        """Creates list of targets with multiline concatenation"""
        targets = []
        if line_nums:
            for line, line_num in zip(lines, line_nums):
                target = AnalysisTarget(line, line_num, lines, self.file_path, self.file_type, self.info)
                targets.append(target)
        else:
            for i, line in enumerate(lines):
                target = AnalysisTarget(line, i + 1, lines, self.file_path, self.file_type, self.info)
                targets.append(target)
        return targets
