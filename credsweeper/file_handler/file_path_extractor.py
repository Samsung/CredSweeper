import logging
import os
from pathlib import Path
from typing import List, Dict

from git import InvalidGitRepositoryError, NoSuchPathError, Repo

from credsweeper.config import Config
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class FilePathExtractor:
    """Util class to browse files in directories"""

    located_repos: Dict[Path, Repo] = {}

    @classmethod
    def apply_gitignore(cls, detected_files: List[str]) -> List[str]:
        """Apply gitignore rules for each file.

        Args:
            detected_files: list of files to be checked

        Return:
            List of files with all files ignored by git removed

        """
        filtered_files = [file_path for file_path in detected_files if FilePathExtractor.is_valid_path(file_path)]

        return filtered_files

    @classmethod
    def get_file_paths(cls, config: Config, path: str) -> List[str]:
        """Get all files in the directory. Automatically exclude files non-code or data files (such as .jpg).

        Args:
            config: credsweeper configuration
            path: path to the file or directory to be scanned

        Return:
            List all non-excluded files in the directory

        """
        path = os.path.expanduser(path)  # Replace ~ character with a full path to the home directory
        if not os.path.exists(path):
            logger.warning(f"'{path}' does not exist")
        file_paths = []
        if os.path.isfile(path):
            if not FilePathExtractor.check_exclude_file(config, path):
                file_paths.append(path)
            return file_paths

        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(f"{dirpath}", f"{filename}")
                if FilePathExtractor.check_exclude_file(config, file_path) or FilePathExtractor.check_file_size(
                        config, file_path):
                    continue
                if os.path.isfile(file_path) and 0 < os.path.getsize(file_path):
                    file_paths.append(file_path)
        return file_paths

    @classmethod
    def is_valid_path(cls, path: str) -> bool:
        """Locate nearest .git directory to the path and check if path is ignored.

        Args:
            path: path to the file or directory to check

        Return:
            False if file is ignored by git. True otherwise

        """
        parent_directory = Path(path).parent

        # Iterate over file path to find nearest ".git" directory
        while True:
            try:
                if parent_directory in cls.located_repos:
                    repo = cls.located_repos[parent_directory]
                else:
                    # The directory must have ".git" in it. If not it occurs error.
                    repo = Repo(parent_directory)

                    # Cache already located repositories, so we would not need to load it for each new file
                    cls.located_repos[parent_directory] = repo

                # Return True if there is no ignored file in 'path' and False if any.
                return len(repo.ignored(path)) == 0

            except (InvalidGitRepositoryError, NoSuchPathError):
                new_parent = parent_directory.parent
                # If we encountered root and cannot move further: no .git directory located in the entire path
                if new_parent == parent_directory:
                    return True
                parent_directory = new_parent

    @staticmethod
    def is_find_by_ext_file(config: Config, path: str) -> bool:
        """
        Checks whether file has suspicious extension

        Args:
            config: Config
            path: str - may be only file name with extension

        Return:
            True when the feature is configured and the file extension matches
        """
        return config.find_by_ext and Util.get_extension(path) in config.find_by_ext_list

    @classmethod
    def check_exclude_file(cls, config: Config, path: str) -> bool:
        """
        Checks whether file should be excluded

        Args:
            config: Config
            path: str - full path preferred

        Return:
            True when the file full path should be excluded according config
        """
        path = path.replace('\\', '/').lower()
        if config.not_allowed_path_pattern.match(path):
            return True
        if any(exclude_pattern.match(path) for exclude_pattern in config.exclude_patterns):
            return True
        if any(exclude_path in path for exclude_path in config.exclude_paths):
            return True
        file_extension = Util.get_extension(path, lower=False)
        if file_extension in config.exclude_extensions:
            return True
        if not config.depth and file_extension in config.exclude_containers:
            return True
        return False

    @classmethod
    def check_file_size(cls, config: Config, path: str) -> bool:
        """
        Checks whether the file is oversize limit

        Args:
            config: Config
            path: str - acceptable file

        Return:
            True when the file is oversize
        """
        if config.size_limit is None:
            return False
        if os.path.getsize(path) > config.size_limit:
            return True
        else:
            return False
