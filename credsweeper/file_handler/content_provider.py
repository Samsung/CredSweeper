from abc import ABC, abstractmethod
from typing import List

from credsweeper.file_handler.analysis_target import AnalysisTarget


class ContentProvider(ABC):
    """Base class to provide access to analysis targets for scanned object."""

    def __init__(self, _file_path: str) -> None:
        self.__file_path = _file_path

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

    def lines_to_targets(self, lines: List[str]) -> List[AnalysisTarget]:
        """Creates list of targets with multiline concatenation"""
        targets = []
        for i, line in enumerate(lines):
            target = AnalysisTarget(line, i + 1, lines, self.file_path)
            targets.append(target)
        return targets
