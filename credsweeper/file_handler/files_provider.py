import io
import logging
from pathlib import Path
from typing import List, Optional, Union, Tuple, Sequence

from credsweeper.config.config import Config
from credsweeper.file_handler.abstract_provider import AbstractProvider
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.text_content_provider import TextContentProvider

logger = logging.getLogger(__name__)


class FilesProvider(AbstractProvider):
    """Provider of plain os files to be analysed."""

    def __init__(self,
                 paths: Sequence[Union[str, Path, io.BytesIO, Tuple[Union[str, Path], io.BytesIO]]],
                 skip_ignored: Optional[bool] = None) -> None:
        """Initialize Files Text Provider for files from 'paths'.

        Args:
            paths: list of parent paths of files to scan
                   OR tuple of path (info purpose) and io.BytesIO (reads the data from current pos)
            skip_ignored: boolean variable, Checking the directory to the list
                          of ignored directories from the gitignore file

        """
        super().__init__(paths)
        self.skip_ignored = skip_ignored

    def get_scannable_files(self, config: Config) -> Sequence[ContentProvider]:
        """Get list of full text file object for analysis of files with parent paths from "paths".

        Args:
            config: dict of credsweeper configuration

        Return:
            preprocessed file objects for analysis

        """
        text_content_provider_list: List[ContentProvider] = []
        for path in self.paths:
            if isinstance(path, (str, Path)):
                new_files = FilePathExtractor.get_file_paths(config, path)
                if self.skip_ignored:
                    new_files = FilePathExtractor.apply_gitignore(new_files)
                for _file in new_files:
                    text_content_provider_list.append(TextContentProvider(_file))
            elif isinstance(path, io.BytesIO):
                text_content_provider_list.append(TextContentProvider((":memory:", path)))
            elif isinstance(path, tuple) and (isinstance(path[0], (str, Path))) and isinstance(path[1], io.BytesIO):
                # suppose, all the files must be scanned
                text_content_provider_list.append(TextContentProvider(path))
            else:
                logger.error(f"Unknown path type: {path}")

        return text_content_provider_list
