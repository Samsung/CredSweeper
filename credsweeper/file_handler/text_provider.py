from typing import List, Optional, Union

from credsweeper import DiffContentProvider
from credsweeper.config import Config
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider


class TextProvider(FilesProvider):
    """Provider of full text files analysing.

    Parameters:
        paths: list of string, list of parent path of files to scan
        change_type: string, type of analyses changes in patch (added or deleted)
        skip_ignored: boolean variable, Checking the directory to the list
          of ignored directories from the gitignore file

    """

    def __init__(self,
                 paths: List[str],
                 change_type: Optional[str] = None,
                 skip_ignored: Optional[bool] = None) -> None:
        """Initialize Files Text Provider for files from 'paths'.

        Args:
            paths: list of string, list of parent paths of files to scan
            change_type: string, type of analyses changes in patch (added or deleted)
            skip_ignored: boolean variable, Checking the directory to the list
              of ignored directories from the gitignore file

        """
        self.paths = paths
        self.skip_ignored = skip_ignored

    def get_files_sequence(self, file_paths: List[str]) -> List[TextContentProvider]:
        """Get list of paths and returns list of TextContentProviders

        Args:
            file_paths: list of paths

        Returns:
            list of files providers

        """
        files = []
        for file_path in file_paths:
            files.append(TextContentProvider(file_path))
        return files

    def get_scannable_files(self, config: Config) -> Union[List[DiffContentProvider], List[TextContentProvider]]:
        """Get list of full text file object for analysis of files with parent paths from "paths".

        Args:
            config: dict of credsweeper configuration

        Return:
            preprocessed file objects for analysis

        """
        file_paths = []
        for path in self.paths:
            new_files = FilePathExtractor.get_file_paths(config, path)
            if self.skip_ignored:
                new_files = FilePathExtractor.apply_gitignore(new_files)
            file_paths.extend(new_files)
        return self.get_files_sequence(file_paths)
