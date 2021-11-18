from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from credsweeper.file_handler.content_provider import ContentProvider


class FilesProvider(ABC):
    """Base class for all files provider objects

    Attributes:
        paths: list of string, list of path to scan
        change_type: string, type of analyses changes in patch (added or deleted)
        skip_ignored: boolean variable, Checking the directory to the list
            of ignored directories from the gitignore file
    """
    @abstractmethod
    def __init__(self,
                 paths: List[str],
                 change_type: Optional[str] = None,
                 skip_ignored: Optional[bool] = None) -> None:
        """Initialize Files Provider object for 'paths'

        Args:
            paths: file paths list to scan
            change_type: string, type of analyses changes in patch (added or deleted)
            skip_ignored: boolean variable, Checking the directory to the list
                of ignored directories from the gitignore file
        """
        raise NotImplementedError()

    @abstractmethod
    def get_scannable_files(self, config: Dict) -> List[ContentProvider]:
        """Get list of file object for analysis based on attribute "paths"

        Args:
            config: dict of credsweeper configuration

        Return:
            files: list of ContentProvider, file objects to analyse
        """
        raise NotImplementedError()
