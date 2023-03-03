from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Union

from credsweeper.config import Config
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider


class FilesProvider(ABC):
    """Base class for all files provider objects."""

    def __init__(self, paths: List[Union[str, Path]]) -> None:
        """Initialize Files Provider object for 'paths'.

        Args:
            paths: file paths list to scan

        """
        self.paths = paths

    @property
    def paths(self) -> List[Union[str, Path]]:
        """paths getter"""
        return self.__paths

    @paths.setter
    def paths(self, paths: List[Union[str, Path]]) -> None:
        """paths setter"""
        self.__paths = paths

    @abstractmethod
    def get_scannable_files(self, config: Config) -> Union[List[DiffContentProvider], List[TextContentProvider]]:
        """Get list of file object for analysis based on attribute "paths".

        Args:
            config: dict of credsweeper configuration

        Return:
            file objects to analyse

        """
        raise NotImplementedError()
