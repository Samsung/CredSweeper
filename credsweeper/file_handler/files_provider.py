import io
import logging
from pathlib import Path
from typing import List, Optional, Union, Tuple, Sequence

from git import Repo, InvalidGitRepositoryError, NoSuchPathError

from credsweeper.config.config import Config
from credsweeper.file_handler.abstract_provider import AbstractProvider
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.file_handler.text_content_provider import TextContentProvider

logger = logging.getLogger(__name__)


class FilesProvider(AbstractProvider):
    """Provider of plain os files to be analyzed."""

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
        self.skip_ignored = bool(skip_ignored)
        # instance managed cache for git repo locations
        self.located_repos: dict[Path, Repo] = {}

    def is_git_ignored(self, path: str | Path) -> bool:
        """Locate nearest .git directory to the path and check if path is ignored.

        Args:
            path: path to the file or directory to check

        Return:
            True if file is ignored by git. False otherwise

        """
        parent_directory = Path(path).parent

        # Iterate over file path to find nearest ".git" directory
        while True:
            try:
                if parent_directory in self.located_repos:
                    repo = self.located_repos[parent_directory]
                else:
                    # The directory must have ".git" in it. If not it occurs error.
                    repo = Repo(parent_directory)

                    # Cache already located repositories, so we would not need to load it for each new file
                    self.located_repos[parent_directory] = repo

                # Return True if there is an ignored file in 'path' and False if any.
                return bool(repo.ignored(path))

            except (InvalidGitRepositoryError, NoSuchPathError):
                new_parent = parent_directory.parent
                # If we encountered root and cannot move further: no .git directory located in the entire path
                if new_parent == parent_directory:
                    break
                parent_directory = new_parent
        return False

    def get_scannable_files(self, config: Config) -> Sequence[ContentProvider]:
        """Get list of full text file object for analysis of files with parent paths from "paths".

        Args:
            config: dict of credsweeper configuration

        Return:
            preprocessed file objects for analysis

        """
        content_provider_list: List[ContentProvider] = []
        for path in self.paths:
            if isinstance(path, (str, Path)):
                all_files = FilePathExtractor.get_file_paths(config, path)
                # extend with all wiles except git ignored is configured
                content_provider_list.extend(
                    TextContentProvider(x) for x in all_files if not self.skip_ignored or not self.is_git_ignored(x))
            elif isinstance(path, io.BytesIO):
                content_provider_list.append(TextContentProvider((":memory:", path)))
            elif isinstance(path, tuple) and (isinstance(path[0], (str, Path))) and isinstance(path[1], io.BytesIO):
                # suppose, all the files must be scanned
                content_provider_list.append(TextContentProvider(path))
            else:
                logger.error("Unknown path type: %s", path)

        return content_provider_list
