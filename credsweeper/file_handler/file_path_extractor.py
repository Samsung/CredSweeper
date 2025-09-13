import io
import logging
import os
from pathlib import Path
from typing import List, Dict, Union, Tuple

from git import InvalidGitRepositoryError, NoSuchPathError, Repo

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.config.config import Config
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class FilePathExtractor:
    """Util class to browse files in directories"""

    FIND_BY_EXT_RULE = "Suspicious File Extension"
    located_repos: Dict[Path, Repo] = {}

    @staticmethod
    def apply_gitignore(detected_files: List[str]) -> List[str]:
        """Apply gitignore rules for each file.

        Args:
            detected_files: list of files to be checked

        Return:
            List of files with all files ignored by git removed

        """
        filtered_files = [file_path for file_path in detected_files if FilePathExtractor.is_valid_path(file_path)]

        return filtered_files

    @staticmethod
    def get_file_paths(config: Config, path: Union[str, Path]) -> List[str]:
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
            # suppose, the file is located outside and should be scanned
            if not FilePathExtractor.check_exclude_file(config, path):
                file_paths.append(path)
        elif os.path.isdir(path):
            for dirpath, _, filenames in os.walk(path):
                for filename in filenames:
                    file_path = os.path.join(f"{dirpath}", f"{filename}")
                    if FilePathExtractor.check_exclude_file(config, file_path) or os.path.islink(file_path):
                        continue
                    if os.path.isfile(file_path) and not FilePathExtractor.check_file_size(config, file_path):
                        file_paths.append(file_path)
        else:
            pass  # symbolic links and so on
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
    def is_find_by_ext_file(config: Config, extension: str) -> bool:
        """
        Checks whether file has suspicious extension

        Args:
            config: Config
            extension: str - may be only file name with extension

        Return:
            True when the feature is configured and the file extension matches
        """
        return config.find_by_ext and extension in config.find_by_ext_list

    @staticmethod
    def check_exclude_file(config: Config, path: str) -> bool:
        """
        Checks whether file should be excluded

        Args:
            config: Config
            path: str - full path preferred

        Return:
            True when the file full path should be excluded according config
        """
        if config.pedantic:
            return False
        path = path.replace('\\', '/')
        lower_path = path.lower()
        if config.not_allowed_path_pattern.match(lower_path):
            return True
        for exclude_pattern in config.exclude_patterns:
            if exclude_pattern.match(lower_path):
                return True
        for exclude_path in config.exclude_paths:
            # must be case-sensitive
            if exclude_path in path:
                return True
        file_extension = Util.get_extension(lower_path, lower=False)
        if file_extension in config.exclude_extensions:
            return True
        if not config.depth and file_extension in config.exclude_containers:
            return True
        # --depth or --doc enables scan for all documents extensions
        if not (config.depth or config.doc) and file_extension in config.exclude_documents:
            return True
        return False

    @staticmethod
    def check_file_size(config: Config, reference: Union[str, Path, io.BytesIO, Tuple[Union[str, Path],
                                                                                      io.BytesIO]]) -> bool:
        """
        Checks whether the file is over the size limit from configuration or less MIN_DATA_LEN

        Args:
            config: Config
            reference: various types of a file reference

        Return:
            True when the file is oversize or less than MIN_DATA_LEN, or unsupported
        """
        path = reference[1] if isinstance(reference, tuple) else reference
        if isinstance(path, (str, Path)):
            file_size = os.path.getsize(path)
        elif isinstance(path, io.BytesIO):
            current_pos = path.tell()
            path.seek(0, io.SEEK_END)
            file_size = path.tell() - current_pos
            path.seek(current_pos, io.SEEK_SET)
        else:
            logger.error(f"Unknown path type: {path}")
            return True

        if MIN_DATA_LEN > file_size:
            logger.debug(f"Size ({file_size}) of the file '{path}' is too small")
            return True
        elif isinstance(config.size_limit, int) and config.size_limit < file_size:
            logger.warning(f"Size ({file_size}) of the file '{path}' is over limit ({config.size_limit})")
            return True

        return False
