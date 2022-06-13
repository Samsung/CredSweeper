from abc import ABC, abstractmethod
from typing import List

from credsweeper.file_handler.analysis_target import AnalysisTarget


class ContentProvider(ABC):
    """Base class to provide access to analysis targets for scanned object."""

    def __init__(self, file_path: str) -> None:
        self.__file_path = file_path

    @abstractmethod
    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Load and preprocess file diff data to scan.

        Return:
            row objects to analysing

        """
        raise NotImplementedError()

    @property
    def file_path(self) -> str:
        return self.__file_path

    @file_path.setter
    def file_path(self, file_path: str) -> None:
        self.__file_path = file_path
