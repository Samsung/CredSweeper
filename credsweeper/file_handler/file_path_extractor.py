import io
import logging
import os
from pathlib import Path
from typing import List, Union, Tuple

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.config.config import Config
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class FilePathExtractor:
    """Util class to browse files in directories"""

    FIND_BY_EXT_RULE = "Suspicious File Extension"

    @staticmethod
    def get_file_paths(config: Config, path: Union[str, Path]) -> List[str]:
        """Get all files in the directory. Automatically exclude files non-code or data files (such as .jpg).

        Args:
            config: credsweeper configuration
            path: path to the file or directory to be scanned

        Return:
            List all non-excluded files in the directory

        """
        _path = os.path.expanduser(path)  # Replace ~ character with a full path to the home directory
        if not os.path.exists(_path):
            logger.warning("Path '%s' does not exist", _path)
        file_paths = []
        if os.path.isfile(_path):
            # suppose, the file is located outside and should be scanned
            if not FilePathExtractor.check_exclude_file(config, _path) \
                    and not FilePathExtractor.check_file_size(config, _path):
                file_paths.append(_path)
        elif os.path.isdir(_path):
            for dirpath, _, filenames in os.walk(_path):
                for filename in filenames:
                    file_path = os.path.join(f"{dirpath}", f"{filename}")
                    if FilePathExtractor.check_exclude_file(config, file_path) or os.path.islink(file_path):
                        continue
                    if os.path.isfile(file_path) and not FilePathExtractor.check_file_size(config, file_path):
                        file_paths.append(file_path)
        else:
            pass  # symbolic links and so on
        return file_paths

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
            # completely ignore the path to scan the file
            return False
        path = path.replace('\\', '/')
        lower_path = path.lower()
        if config.exclude_path_pattern.match(lower_path):
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
    def check_file_size(
            config: Config,  #
            reference: Union[str, Path, io.BytesIO, Tuple[Union[str, Path], io.BytesIO]],  #
    ) -> bool:
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
            logger.error("Unknown path type: %s", path)
            return True

        if MIN_DATA_LEN > file_size:
            logger.debug("Size (%s) of the file '%s' is too small", file_size, path)
            return True
        if isinstance(config.size_limit, int) and config.size_limit < file_size:
            logger.warning("Size (%s) of the file '%s' is over limit (%s)", file_size, path, config.size_limit)
            return True

        return False
