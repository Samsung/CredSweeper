import io
import logging
from pathlib import Path
from typing import List, Optional, Union

from credsweeper import DiffContentProvider
from credsweeper.common.constants import DiffRowType
from credsweeper.config import Config
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider

logger = logging.getLogger(__name__)


class TextProvider(FilesProvider):
    """Provider of full text files analysing.

    Parameters:
        paths: list of string, list of parent path of files to scan
        change_type: string, type of analyses changes in patch (added or deleted)
        skip_ignored: boolean variable, Checking the directory to the list
          of ignored directories from the gitignore file

    """

    def __init__(
            self,  #
            paths: List[Union[str, Path, io.BytesIO]],  #
            change_type: Optional[DiffRowType] = None,  #
            skip_ignored: Optional[bool] = None) -> None:
        """Initialize Files Text Provider for files from 'paths'.

        Args:
            paths: list of parent paths of files to scan
            change_type: string, type of analyses changes in patch (added or deleted)
            skip_ignored: boolean variable, Checking the directory to the list
              of ignored directories from the gitignore file

        """
        super().__init__(paths)
        self.skip_ignored = skip_ignored

    def get_files_sequence(self, file_paths: List[Union[str, Path, io.BytesIO]]) -> List[TextContentProvider]:
        """Get list of paths and returns list of TextContentProviders

        Args:
            file_paths: list of paths

        Returns:
            list of files providers

        """
        files = []
        for file_path in file_paths:
            if isinstance(file_path, str):
                files.append(TextContentProvider(file_path))
            elif isinstance(file_path, Path):
                files.append(TextContentProvider((str(file_path))))
            elif isinstance(file_path, io.BytesIO):
                provider = TextContentProvider(":memory:")
                # read the data here - suppose, memory management is provided above
                provider.data = file_path.read()
                files.append(provider)
            else:
                logger.error(f"Unknown path type: {file_path}")
        return files

    def get_scannable_files(self, config: Config) -> Union[List[DiffContentProvider], List[TextContentProvider]]:
        """Get list of full text file object for analysis of files with parent paths from "paths".

        Args:
            config: dict of credsweeper configuration

        Return:
            preprocessed file objects for analysis

        """
        file_paths: List[Union[str, Path, io.BytesIO]] = []
        for path in self.paths:
            if isinstance(path, str) or isinstance(path, Path):
                new_files = FilePathExtractor.get_file_paths(config, path)
                if self.skip_ignored:
                    new_files = FilePathExtractor.apply_gitignore(new_files)
                file_paths.extend(new_files)
            elif isinstance(path, io.BytesIO):
                file_paths.append(path)
            else:
                logger.error(f"Unknown path type: {path}")

        return self.get_files_sequence(file_paths)
