import io
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union, Tuple, Sequence

from credsweeper.config import Config
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider


class AbstractProvider(ABC):
    """Base class for all files provider objects."""

    def __init__(self, paths: Sequence[Union[str, Path, io.BytesIO, Tuple[Union[str, Path], io.BytesIO]]]) -> None:
        """Initialize Files Provider object for 'paths'.

        Args:
            paths: file paths list to scan or io.BytesIO or tuple with both

        """
        self.paths = paths

    @property
    def paths(self) -> Sequence[Union[str, Path, io.BytesIO, Tuple[Union[str, Path], io.BytesIO]]]:
        """paths getter"""
        return self.__paths

    @paths.setter
    def paths(self, paths: Sequence[Union[str, Path, io.BytesIO, Tuple[Union[str, Path], io.BytesIO]]]) -> None:
        """paths setter"""
        self.__paths = paths

    @abstractmethod
    def get_scannable_files(self, config: Config) -> Sequence[Union[DiffContentProvider, TextContentProvider]]:
        """Get list of file object for analysis based on attribute "paths".

        Args:
            config: dict of credsweeper configuration

        Return:
            file objects to analyse

        """
        raise NotImplementedError()
